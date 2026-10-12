"""Plan, run, collect, score and write the fix_hints recovery rounds.

    python -m benchmarks.fix_hints                        # R1 dry run: counts and cost
    python -m benchmarks.fix_hints --pilot                # dry run of the 5-request pilot
    python -m benchmarks.fix_hints --pilot --run --budget-usd 1
    python -m benchmarks.fix_hints --round r1 --run --budget-usd 60 [--no-wait]
    python -m benchmarks.fix_hints --collect RUN_ID       # wait for, collect and score
    python -m benchmarks.fix_hints --score RUN_ID         # re-score stored results ($0)
    python -m benchmarks.fix_hints --score RUN_ID --write --date 2026-10-14
    python -m benchmarks.fix_hints --score RUN_A,RUN_B --write   # one round, staged runs
    python -m benchmarks.fix_hints --round r2 [--r1-run RUN_ID[,RUN_ID]] --run --budget-usd 60

Without ``--run`` nothing is sent: the command prints request counts, the worst-case
cost and the expected cost at 0 and 1,000 thinking tokens per request. ``--run`` needs
``--budget-usd``, a clean git tree and ``ANTHROPIC_API_KEY`` for that command only; every
dollar goes through the shared ledger and budget guard in ``benchmarks._claude``. Raw
results stay in the run store (``~/.cache/agent-airlock-bench/runs/fix_hints/``);
``--write`` commits only aggregates (``RESULTS.md`` and ``summary.json``).

Exit codes: 0 done; 1 a pilot request was rejected; 2 bad arguments or environment;
3 a budget cap refused the job.
"""

from __future__ import annotations

import argparse
import copy
import functools
import hashlib
import json
import logging
import math
import random
import sys
from collections import Counter
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks._claude.batch import collect, plan_cost, record_sync_message, submit, wait
from benchmarks._claude.budget import BudgetExceededError, BudgetGuard
from benchmarks._claude.client import ClientConfigError, make_client, sdk_version
from benchmarks._claude.ledger import Ledger, default_data_dir
from benchmarks._claude.models import DEFAULT_EFFORT, MODELS, model_alias, resolve_model
from benchmarks._claude.pricing import PRICING_SNAPSHOT, estimate_usd
from benchmarks._claude.store import RunStore, git_state, new_run_id

from . import catalogue, payloads, protocol, report, scenarios, score
from .payloads import ARMS, DEFAULT_ARMS, build_payloads, payload_hashes
from .protocol import (
    ASSUMED_OUTPUTS,
    ASSUMED_THINKING,
    MAX_TOKENS,
    PROTOCOLS,
    SYSTEM_PROMPT,
    THINKING,
    RequestRow,
    pilot_requests,
    plan_requests,
)
from .scenarios import DEFAULT_SEED, GenerationReport, Scenario, generate_with_report
from .score import Outcome, score_result, with_meta

BENCH = "fix_hints"
PACKAGE_DIR = Path(__file__).resolve().parent
REPO_ROOT = PACKAGE_DIR.parents[1]
RESULTS_PATH = PACKAGE_DIR / "RESULTS.md"
SUMMARY_PATH = PACKAGE_DIR / "summary.json"
RETEST_SHARE = 0.25
DEFAULT_MODELS = "h55,s55,o55"


class UsageError(RuntimeError):
    """Bad arguments or environment (exit code 2)."""


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------


@contextmanager
def quiet_airlock_logs() -> Iterator[None]:
    """Silence airlock's per-call block logs (thousands of lines otherwise), then restore."""
    from agent_airlock._log import structlog

    stdlib = logging.getLogger("agent-airlock")
    old_level = stdlib.level
    stdlib.setLevel(logging.CRITICAL)
    get_config = getattr(structlog, "get_config", None)
    saved = get_config() if callable(get_config) else None
    if saved is not None:
        structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL))
    try:
        yield
    finally:
        stdlib.setLevel(old_level)
        if saved is not None:
            structlog.configure(**saved)


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_hashes() -> dict[str, str]:
    """sha256 of the airlock modules that produce the payloads, as imported."""
    from agent_airlock import core, self_heal, validator
    from agent_airlock.integrations import _claude_sdk_tools

    return {
        Path(str(module.__file__)).name: _sha256_file(Path(str(module.__file__)))
        for module in (validator, self_heal, core, _claude_sdk_tools)
    }


def harness_hashes() -> dict[str, str]:
    """sha256 of the harness modules that define the scenarios and score them."""
    return {
        Path(str(module.__file__)).name: _sha256_file(Path(str(module.__file__)))
        for module in (catalogue, scenarios, payloads, protocol, score)
    }


def _today() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def _parse_models(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for name in (part.strip() for part in text.split(",") if part.strip()):
        try:
            model_id = resolve_model(name)
        except ValueError as exc:
            raise UsageError(str(exc)) from exc
        out[model_alias(model_id)] = model_id
    if not out:
        raise UsageError("--models names no model")
    return out


def _parse_arms(text: str) -> list[str]:
    arms = [part.strip().lower() for part in text.split(",") if part.strip()]
    unknown = [arm for arm in arms if arm not in ARMS]
    if unknown or not arms:
        raise UsageError(f"--arms takes a subset of {','.join(ARMS)}; got {text!r}")
    return [arm for arm in ARMS if arm in arms]


@functools.cache
def _generated(seed: int) -> tuple[tuple[Scenario, ...], GenerationReport]:
    """Generation is deterministic for a seed and the loaded code: do it once per process."""
    corpus, generation = generate_with_report(seed)
    return tuple(corpus), generation


def _corpus(seed: int) -> tuple[list[Scenario], GenerationReport]:
    corpus, generation = _generated(seed)
    expected = sum(n for _, n in scenarios.CATEGORIES)
    if len(corpus) != expected:
        raise UsageError(f"generated {len(corpus)} scenarios, expected {expected}")
    return list(corpus), copy.deepcopy(generation)


def _corpus_meta(generation: GenerationReport) -> dict[str, Any]:
    return {
        "seed": generation.seed,
        "sha256": generation.corpus_sha256,
        "scenarios": generation.total,
        "counts": generation.counts,
        "rejected": {k: v for k, v in generation.rejected.items() if v},
        "duplicates": sum(generation.duplicates.values()),
    }


def _store(run_id: str) -> RunStore:
    store = RunStore(BENCH, run_id)
    if not store.exists():
        raise UsageError(f"no run {run_id!r} under {store.dir.parent}")
    return store


def _new_store(prefix: str) -> RunStore:
    """A store for a new run; refuses to reuse an id (ids have one-second resolution)."""
    store = RunStore(BENCH, new_run_id(prefix))
    if store.dir.exists():
        raise UsageError(f"run directory {store.dir} already exists; retry in a second")
    return store


def _write_scenarios(store: RunStore, corpus: list[Scenario]) -> None:
    store.dir.mkdir(parents=True, exist_ok=True)
    with (store.dir / "scenarios.jsonl").open("w", encoding="utf-8") as handle:
        for scenario in corpus:
            row = {**scenario.to_dict(), "content_sha256": scenario.content_sha256()}
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def load_scenarios(store: RunStore) -> dict[str, Scenario]:
    path = store.dir / "scenarios.jsonl"
    out: dict[str, Scenario] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            row.pop("content_sha256", None)
            scenario = Scenario.from_dict(row)
            out[scenario.sid] = scenario
    return out


def _scenario_hashes(store: RunStore) -> dict[str, str]:
    path = store.dir / "scenarios.jsonl"
    return {
        row["sid"]: row["content_sha256"]
        for row in (json.loads(line) for line in path.read_text().splitlines() if line.strip())
    }


def airlock_location() -> Path:
    """The directory ``agent_airlock`` was imported from."""
    import agent_airlock

    return Path(str(agent_airlock.__file__)).resolve().parent


def _repo_relative(path: Path) -> str:
    """``path`` relative to the checkout (no local home directory in the manifest)."""
    try:
        return str(path.relative_to(REPO_ROOT.resolve()))
    except ValueError:
        return f"outside the checkout: {path.name}"


def _require_clean_tree() -> tuple[str, bool]:
    """The checkout's git state, refusing what would make its SHA misdescribe the run.

    Raises:
        UsageError: The tree is dirty, or ``agent_airlock`` is imported from another
            checkout (an editable install elsewhere), so the payloads would come from code
            the recorded SHA does not name.
    """
    sha, dirty = git_state(REPO_ROOT)
    if dirty:
        raise UsageError(
            "refusing a paid run on a dirty tree: commit or stash first, so the run's "
            f"git SHA ({sha[:12]}) names the code that produced its payloads"
        )
    location = airlock_location()
    if REPO_ROOT.resolve() not in location.parents:
        raise UsageError(
            f"agent_airlock is imported from {location}, outside this checkout "
            f"({REPO_ROOT}); the run's git SHA would not name the code that produced its "
            'payloads. Run with PYTHONPATH="$PWD/src:$PWD" or install this checkout'
        )
    return sha, dirty


def _client() -> Any:
    try:
        return make_client()
    except ClientConfigError as exc:
        raise UsageError(str(exc)) from exc


def _manifest(
    *,
    run_id: str,
    round_: str,
    args: argparse.Namespace,
    models: Mapping[str, str],
    arms: list[str],
    generation: GenerationReport,
    planned: int,
    git: tuple[str, bool],
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    import agent_airlock

    return {
        "bench": BENCH,
        "run_id": run_id,
        "round": round_,
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "command": ["python", "-m", "benchmarks.fix_hints", *args.argv],
        "git_sha": git[0],
        "git_dirty": git[1],
        "source_sha256": source_hashes(),
        "harness_sha256": harness_hashes(),
        "airlock_version": getattr(agent_airlock, "__version__", "unknown"),
        "airlock_path": _repo_relative(airlock_location()),
        "sdk_version": sdk_version(),
        "pricing_snapshot": PRICING_SNAPSHOT,
        "protocol": args.protocol,
        "models": dict(models),
        "arms": arms,
        "request_template": {
            "system": SYSTEM_PROMPT,
            "max_tokens": MAX_TOKENS,
            "thinking": THINKING,
            "effort": {alias: DEFAULT_EFFORT[model_id] for alias, model_id in models.items()},
            "tool_choice": None,
            "temperature": None,
            "fallbacks": None,
        },
        "corpus": _corpus_meta(generation),
        "planned_requests": planned,
        **(extra or {}),
    }


def _write_run(
    store: RunStore,
    manifest: Mapping[str, Any],
    rows: list[RequestRow],
    corpus: list[Scenario],
    hashes: Mapping[str, Mapping[str, str]],
) -> None:
    store.write_manifest(manifest)
    store.write_requests(row.to_row() for row in rows)
    _write_scenarios(store, corpus)
    (store.dir / "payload_hashes.json").write_text(json.dumps(hashes, indent=1, sort_keys=True))


# --------------------------------------------------------------------------------------
# Cost table
# --------------------------------------------------------------------------------------


def _usd(value: float) -> str:
    return f"${value:,.2f}" if value >= 1 else f"${value:.4f}"


def print_cost_table(rows: list[RequestRow], *, batch: bool) -> None:
    """Requests, estimated input tokens, worst case and expected cost, per model."""
    by_model: dict[str, list[RequestRow]] = {}
    for row in rows:
        by_model.setdefault(row.model, []).append(row)
    labels = [f"expected, {t:,} thinking" for t in ASSUMED_THINKING]
    print(
        f"{'model':<8}{'requests':>10}{'est. input tok':>16}{'worst case':>13}"
        + "".join(f"{label:>27}" for label in labels)
    )
    totals = [0.0] * (len(ASSUMED_OUTPUTS) + 1)
    total_requests = total_tokens = 0
    for alias, items in by_model.items():
        plan = plan_cost([r.planned() for r in items], batch=batch, assumed_outputs=ASSUMED_OUTPUTS)
        values = [plan.worst_case_usd, *(plan.expected_usd[out] for out in ASSUMED_OUTPUTS)]
        totals = [a + b for a, b in zip(totals, values, strict=True)]
        total_requests += plan.requests
        total_tokens += plan.input_tokens
        print(
            f"{alias:<8}{plan.requests:>10,}{plan.input_tokens:>16,}{_usd(values[0]):>13}"
            + "".join(f"{_usd(value):>27}" for value in values[1:])
        )
    print(
        f"{'total':<8}{total_requests:>10,}{total_tokens:>16,}{_usd(totals[0]):>13}"
        + "".join(f"{_usd(value):>27}" for value in totals[1:])
    )
    rate = "Batch rates (50% off)" if batch else "standard rates"
    print(
        f"{rate}. Worst case: every input token uncached and max_tokens ({MAX_TOKENS:,}) spent "
        f"on every request. Expected: {protocol.ASSUMED_VISIBLE_OUTPUT} visible output tokens "
        "plus 0 or 1,000 thinking tokens per request. Input tokens are estimated "
        f"({protocol.CHARS_PER_TOKEN:g} chars per token + {protocol.TOOL_USE_OVERHEAD_TOKENS} "
        "tool-use overhead); the pilot measures them."
    )


def print_corpus(generation: GenerationReport) -> None:
    print(
        f"corpus: seed {generation.seed}, {generation.total} scenarios "
        f"(sha256 {generation.corpus_sha256[:12]}), {generation.total_rejected} candidates "
        f"rejected by the self-check, {sum(generation.duplicates.values())} duplicate draws"
    )
    print("  " + " | ".join(f"{k} {v}" for k, v in generation.counts.items()))
    for category, reasons in generation.rejected.items():
        for reason, count in reasons.items():
            print(f"  rejected: {category}: {count} {reason}")


# --------------------------------------------------------------------------------------
# R2 planning
# --------------------------------------------------------------------------------------


def _run_ids(text: str) -> list[str]:
    ids = [part.strip() for part in text.split(",") if part.strip()]
    if not ids:
        raise UsageError("no run id given")
    return ids


def find_r1_runs(explicit: str | None) -> list[RunStore]:
    """The R1 run(s) an R2 round pairs with.

    ``--r1-run`` names them (comma-separated when R1 was staged across runs, e.g. one per
    model). Otherwise: the newest R1 run plus every other R1 run that measured the same
    hint code (same source hashes and protocol), oldest first.
    """
    if explicit:
        return [_store(run_id) for run_id in _run_ids(explicit)]
    root = default_data_dir() / "runs" / BENCH
    runs = sorted(
        path.name for path in root.glob("fh-r1-*") if (path / "payload_hashes.json").exists()
    )
    if not runs:
        raise UsageError(f"R2 is planned against an R1 run, and none was found under {root}")

    def code(run_id: str) -> tuple[str, str]:
        manifest = RunStore(BENCH, run_id).read_manifest()
        return (
            json.dumps(manifest.get("source_sha256"), sort_keys=True),
            str(manifest.get("protocol", "tool")),
        )

    newest = code(runs[-1])
    return [RunStore(BENCH, run_id) for run_id in runs if code(run_id) == newest]


def plan_r2(
    corpus: list[Scenario],
    current: Mapping[str, Mapping[str, str]],
    r1_stores: RunStore | list[RunStore],
    arms: list[str],
    seed: int,
    protocol_name: str = "tool",
) -> tuple[list[Scenario], dict[str, Any]]:
    """Scenarios whose payload changed since R1, plus a seeded 25% of the unchanged.

    Raises:
        UsageError: The corpus or the protocol differs from R1's, the R1 runs disagree on a
            payload, or R1 ran none of these arms: an R2 that cannot be paired with its R1
            measures nothing.
    """
    stores = [r1_stores] if isinstance(r1_stores, RunStore) else list(r1_stores)
    now = {s.sid: s.content_sha256() for s in corpus}
    r1_hashes: dict[str, dict[str, str]] = {}
    r1_arms: set[str] = set()
    for store in stores:
        manifest = store.read_manifest()
        r1_protocol = manifest.get("protocol", "tool")
        if r1_protocol != protocol_name:
            raise UsageError(
                f"R1 ({store.run_id}) ran protocol {r1_protocol!r}; R2 must run it too "
                f"(--protocol {r1_protocol})"
            )
        r1_scenarios = _scenario_hashes(store)
        if r1_scenarios != now:
            moved = sorted(
                sid for sid in set(now) | set(r1_scenarios) if now.get(sid) != r1_scenarios.get(sid)
            )
            raise UsageError(
                f"the scenario corpus differs from R1's ({len(moved)} scenarios, e.g. "
                f"{', '.join(moved[:3])}); R2 cannot be paired with {store.run_id}"
            )
        run_arms = list(manifest.get("arms") or [])
        r1_arms.update(run_arms)
        for sid, by_arm in json.loads((store.dir / "payload_hashes.json").read_text()).items():
            merged = r1_hashes.setdefault(sid, {})
            for arm in run_arms:
                if arm not in by_arm:
                    continue
                if merged.setdefault(arm, by_arm[arm]) != by_arm[arm]:
                    raise UsageError(
                        f"R1 runs disagree on the {arm.upper()} payload of {sid}: they did "
                        "not measure the same hint code"
                    )
    shared = [arm for arm in arms if arm in r1_arms]
    if not shared:
        raise UsageError(f"R1 ran arms {sorted(r1_arms)}; none of {arms} can be paired")
    dropped = [arm for arm in arms if arm not in shared]
    if dropped:
        print(f"note: R1 did not run arm(s) {', '.join(dropped)}; R2 leaves them out")
    changed = {
        arm: sorted(sid for sid in now if current[sid][arm] != r1_hashes[sid][arm])
        for arm in shared
    }
    changed_sids = set().union(*changed.values())
    unchanged = sorted(set(now) - changed_sids)
    k = math.ceil(RETEST_SHARE * len(unchanged))
    retest = sorted(random.Random(f"{seed}:r2-retest").sample(unchanged, k)) if k else []
    selected = [s for s in corpus if s.sid in changed_sids or s.sid in set(retest)]
    plan = {
        "r1_run_id": "+".join(store.run_id for store in stores),
        "r1_run_ids": [store.run_id for store in stores],
        "arms": shared,
        "changed": changed,
        "retest": retest,
        "retest_share": RETEST_SHARE,
    }
    return selected, plan


# --------------------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------------------


def command_round(args: argparse.Namespace) -> int:
    models = _parse_models(args.models)
    arms = _parse_arms(args.arms)
    corpus, generation = _corpus(args.seed)
    all_payloads = build_payloads(corpus, arms)
    hashes = payload_hashes(all_payloads)
    selected, r2 = corpus, None
    if args.round == "r2":
        r1_stores = find_r1_runs(args.r1_run)
        selected, r2 = plan_r2(corpus, hashes, r1_stores, arms, args.seed, args.protocol)
        arms = list(r2["arms"])
        r1_models = {
            alias for store in r1_stores for alias in (store.read_manifest().get("models") or {})
        }
        unpaired = [alias for alias in models if alias not in r1_models]
        if unpaired:
            print(f"note: R1 did not run {', '.join(unpaired)}; their R2 results have no pair")
    rows = plan_requests(selected, all_payloads, models.values(), arms, args.round, args.protocol)
    mode = (
        "PAID RUN" if args.run else "DRY RUN (nothing is sent; add --run --budget-usd N to submit)"
    )
    print(f"fix_hints round {args.round.upper()} · {mode}")
    print_corpus(generation)
    if r2 is not None:
        changed = ", ".join(f"{a.upper()} {len(s)}" for a, s in r2["changed"].items())
        print(
            f"R2 against {r2['r1_run_id']}: payload changed per arm: {changed}; "
            f"retest control: {len(r2['retest'])} unchanged scenarios; "
            f"{len(selected)} scenarios in this round"
        )
    print(
        f"protocol: {args.protocol} · arms: {' '.join(a.upper() for a in arms)} · models: "
        f"{' '.join(models)} · max_tokens {MAX_TOKENS:,} · adaptive thinking · effort "
        + ", ".join(f"{alias} {DEFAULT_EFFORT[mid]}" for alias, mid in models.items())
    )
    print_cost_table(rows, batch=True)
    if not args.run:
        return 0
    if args.budget_usd is None:
        raise UsageError("--run needs --budget-usd")
    git = _require_clean_tree()
    client = _client()
    ledger = Ledger()
    guard = BudgetGuard(args.budget_usd, ledger)
    # One batch per model is admitted at a time; check the whole round first, so a cap
    # cannot leave the round half-submitted (the earlier models run, the later refused).
    worst = plan_cost([row.planned() for row in rows], batch=True).worst_case_usd
    if worst > guard.headroom():
        raise BudgetExceededError(
            f"this round's worst case ${worst:.2f} exceeds the remaining budget "
            f"${guard.headroom():.2f}; raise --budget-usd, or stage it with --models and "
            "score the runs together (--score RUN_A,RUN_B)"
        )
    store = _new_store(f"fh-{args.round}")
    run_id = store.run_id
    extra = {"r2": r2} if r2 is not None else None
    manifest = _manifest(
        run_id=run_id,
        round_=args.round,
        args=args,
        models=models,
        arms=arms,
        generation=generation,
        planned=len(rows),
        git=git,
        extra=extra,
    )
    _write_run(store, manifest, rows, corpus, hashes)
    print(f"run {run_id}: {store.dir}")
    for alias in models:
        requests = [row.planned() for row in rows if row.model == alias]
        job = f"{BENCH}/{run_id}/{alias}"
        try:
            batch_id = submit(
                client,
                requests,
                job=job,
                guard=guard,
                store=store,
                force_resubmit=args.force_resubmit,
            )
        except BudgetExceededError as exc:
            print(f"error: {exc}", file=sys.stderr)
            print(f"batches submitted before the cap: {store.batches()}", file=sys.stderr)
            return exc.exit_code
        print(f"  {alias}: {len(requests):,} requests -> batch {batch_id}")
    if args.no_wait:
        print(f"collect later: python -m benchmarks.fix_hints --collect {run_id}")
        return 0
    return collect_store(store, client, ledger, args)


def _collected_marker(store: RunStore, batch_id: str) -> Path:
    return store.dir / "collected" / f"{batch_id}.done"


def collect_batch(
    store: RunStore, client: Any, ledger: Ledger, batch_id: str, job: str
) -> dict[str, int]:
    """Collect one ended batch into the store and ledger, then mark it collected."""
    outcome = collect(client, batch_id, job=job, ledger=ledger, store=store)
    tally = dict(Counter(outcome.values()))
    marker = _collected_marker(store, batch_id)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text(json.dumps(tally, sort_keys=True))
    return tally


def collect_store(store: RunStore, client: Any, ledger: Ledger, args: argparse.Namespace) -> int:
    """Collect every batch of a run that has ended, then score the run.

    A batch is collected once: its results are priced into the ledger as they stream, so
    a second collection would record the spend twice. A results file with no completion
    marker (a collection that crashed part-way) is reported and left alone.
    """
    pending = partial = 0
    for entry in store.batches():
        batch_id = entry.get("batch_id")
        if batch_id is None:
            print(f"  dangling submit intent for job {entry['job']}: check the Console's batches")
            continue
        if _collected_marker(store, batch_id).exists():
            print(f"  {batch_id}: already collected")
            continue
        if store.results_path(batch_id).exists():
            partial += 1
            print(
                f"  {batch_id}: a partial collection is on disk ({store.results_path(batch_id)}); "
                "compare it with the ledger before moving it aside and collecting again"
            )
            continue
        if args.no_wait:
            status = client.messages.batches.retrieve(batch_id).processing_status
            if status != "ended":
                pending += 1
                print(f"  {batch_id}: {status}")
                continue
        else:
            wait(client, batch_id)
        tally = collect_batch(store, client, ledger, batch_id, str(entry["job"]))
        print(f"  {batch_id}: {tally}")
    if pending or partial:
        print(f"{pending + partial} batch(es) not collected; run --collect {store.run_id} again")
        return 0
    return score_store_command(store, args)


def command_collect(args: argparse.Namespace) -> int:
    store = _store(args.collect)
    return collect_store(store, _client(), Ledger(), args)


def score_store(store: RunStore) -> list[Outcome]:
    """Score every stored result of a run against the scenarios it recorded ($0)."""
    corpus = load_scenarios(store)
    requests = {row["custom_id"]: RequestRow.from_row(row) for row in store.read_requests()}
    latest: dict[str, Mapping[str, Any]] = {}
    for row in store.iter_results():
        custom_id = str(row.get("custom_id"))
        if custom_id in requests:
            latest[custom_id] = row
    outcomes = []
    for custom_id, result_row in latest.items():
        request = requests[custom_id]
        scenario = corpus[request.sid]
        outcomes.append(
            with_meta(
                score_result(scenario, result_row),
                custom_id=custom_id,
                arm=request.arm,
                model=request.model,
                round=request.round,
            )
        )
    return sorted(outcomes, key=lambda o: o.custom_id)


def identical_hn(store: RunStore) -> set[str]:
    """sids whose H and N payloads are byte-identical in this run (nothing to strip)."""
    path = store.dir / "payload_hashes.json"
    if not path.exists():
        return set()
    hashes = json.loads(path.read_text())
    return {
        sid
        for sid, arms in hashes.items()
        if arms.get("h") is not None and arms.get("h") == arms.get("n")
    }


def _batch_map(store: RunStore) -> dict[str, str]:
    return {
        str(entry["job"]).rsplit("/", 1)[-1]: str(entry["batch_id"])
        for entry in store.batches()
        if entry.get("batch_id")
    }


def print_quick_table(outcomes: list[Outcome]) -> None:
    rows: dict[tuple[str, str], list[Outcome]] = {}
    for outcome in outcomes:
        rows.setdefault((outcome.model, outcome.arm), []).append(outcome)
    print(
        f"{'model':<6} {'arm':<4} {'repair n':>9} {'RR':>7} {'SR':>7} {'control n':>10} {'not retried':>12}"
    )
    for (model, arm), items in sorted(rows.items()):
        repair = [o for o in items if o.counted and not o.is_control]
        control = [o for o in items if o.counted and o.is_control]
        rr = sum(o.success for o in repair) / len(repair) if repair else float("nan")
        sr = sum(o.semantic_success for o in repair) / len(repair) if repair else float("nan")
        ok = sum(o.success for o in control) / len(control) if control else float("nan")
        print(
            f"{model:<6} {arm.upper():<4} {len(repair):>9} {rr:>7.1%} {sr:>7.1%} "
            f"{len(control):>10} {ok:>12.1%}"
        )
    excluded = Counter(o.outcome for o in outcomes if not o.counted)
    if excluded:
        print(f"excluded from every denominator: {dict(excluded)}")


def _scored(store: RunStore) -> list[Outcome]:
    """Score one run, warn if the harness changed since it ran, keep the scores beside it."""
    recorded = store.read_manifest().get("harness_sha256") or {}
    drift = sorted(
        name for name, sha in harness_hashes().items() if recorded.get(name) not in (None, sha)
    )
    if drift:
        print(f"warning: {store.run_id}: harness modules changed since it ran: {', '.join(drift)}")
    outcomes = score_store(store)
    with (store.dir / "scores.jsonl").open("w", encoding="utf-8") as handle:
        for outcome in outcomes:
            handle.write(json.dumps(outcome.to_dict(), sort_keys=True) + "\n")
    planned = len(store.read_requests())
    print(f"{store.run_id}: scored {len(outcomes):,} of {planned:,} planned requests")
    return outcomes


def merge_manifests(stores: list[RunStore]) -> dict[str, Any]:
    """One round's metadata from the runs it was staged across.

    Raises:
        UsageError: The runs disagree on the round, protocol, corpus, hint code or (for
            R2) the R1 they pair with, so they do not measure one thing.
    """
    manifests = [store.read_manifest() for store in stores]
    first = manifests[0]

    def facts(manifest: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "round": manifest.get("round"),
            "protocol": manifest.get("protocol"),
            "corpus": (manifest.get("corpus") or {}).get("sha256"),
            "hint code": manifest.get("source_sha256"),
            "R1 pairing": manifest.get("r2"),
        }

    for store, manifest in zip(stores[1:], manifests[1:], strict=True):
        for key, value in facts(manifest).items():
            if value != facts(first)[key]:
                raise UsageError(
                    f"{store.run_id} and {stores[0].run_id} differ in {key}; the runs of one "
                    "round must agree on it"
                )
    merged = dict(first)
    merged["run_ids"] = [store.run_id for store in stores]
    merged["run_id"] = "+".join(merged["run_ids"])
    merged["models"] = {k: v for m in manifests for k, v in (m.get("models") or {}).items()}
    arms = {arm for m in manifests for arm in (m.get("arms") or [])}
    merged["arms"] = [arm for arm in ARMS if arm in arms]
    shas = sorted({str(m.get("git_sha")) for m in manifests})
    merged["git_sha"] = shas[0] if len(shas) == 1 else ", ".join(shas)
    merged["git_dirty"] = any(m.get("git_dirty") for m in manifests)
    effort = {
        k: v
        for m in manifests
        for k, v in (m.get("request_template") or {}).get("effort", {}).items()
    }
    merged["request_template"] = {**(first.get("request_template") or {}), "effort": effort}
    return merged


def score_runs(stores: list[RunStore], args: argparse.Namespace) -> int:
    """Score one or more runs of a round; print, and with ``--write`` publish, its block."""
    meta = merge_manifests(stores)
    outcomes: list[Outcome] = []
    for store in stores:
        outcomes += _scored(store)
    keys = Counter((o.model, o.arm, o.sid) for o in outcomes)
    overlap = sum(1 for count in keys.values() if count > 1)
    if overlap:
        raise UsageError(f"the runs overlap on {overlap} (model, arm, scenario) requests")
    print_quick_table(outcomes)
    round_ = str(meta.get("round"))
    if round_ not in protocol.ROUNDS:
        if args.write:
            raise UsageError(f"{meta['run_id']} is a {round_} run; only r1 and r2 are written")
        return 0
    r1_outcomes = None
    if round_ == "r2":
        plan = meta.get("r2") or {}
        r1_ids = plan.get("r1_run_ids") or [plan.get("r1_run_id")]
        r1_outcomes = [o for run_id in r1_ids for o in score_store(_store(str(run_id)))]
    batches: dict[str, str] = {}
    for store in stores:
        for alias, batch_id in _batch_map(store).items():
            label = alias if alias not in batches else f"{alias} ({store.run_id})"
            batches[label] = batch_id
    summary = report.summarize_round(
        outcomes,
        {**meta, "date": args.date, "batches": batches},
        identical_hn=set().union(*(identical_hn(store) for store in stores)),
        planned=sum(len(store.read_requests()) for store in stores),
        r1_outcomes=r1_outcomes,
    )
    block = report.render_block(summary)
    print()
    print(block)
    if args.write:
        try:
            report.append_block(Path(args.results), block, force=args.force)
        except ValueError as exc:
            raise UsageError(str(exc)) from exc
        report.write_summary(Path(args.summary), summary)
        print(f"wrote {args.results} and {args.summary}")
    return 0


def score_store_command(store: RunStore, args: argparse.Namespace) -> int:
    return score_runs([store], args)


def command_score(args: argparse.Namespace) -> int:
    return score_runs([_store(run_id) for run_id in _run_ids(args.score)], args)


def _rejection_hint(message: str) -> bool:
    text = message.lower()
    return any(word in text for word in ("thinking", "tool_use", "tool_result"))


def command_pilot(args: argparse.Namespace) -> int:
    corpus, generation = _corpus(args.seed)
    pilot = pilot_requests(corpus, args.protocol)
    by_sid = {s.sid: s for s in corpus}
    print(f"fix_hints pilot · {'PAID RUN' if args.run else 'DRY RUN (nothing is sent)'}")
    print(f"protocol: {args.protocol} · corpus sha256 {generation.corpus_sha256[:12]}")
    for item in pilot:
        print(f"  {item.row.custom_id:<34} {item.mode:<5} {item.label}")
    sync = [item for item in pilot if item.mode == "sync"]
    batched = [item for item in pilot if item.mode == "batch"]
    print("synchronous requests:")
    print_cost_table([item.row for item in sync], batch=False)
    print("one-request batch:")
    print_cost_table([item.row for item in batched], batch=True)
    if not args.run:
        return 0
    if args.budget_usd is None:
        raise UsageError("--run needs --budget-usd")
    git = _require_clean_tree()
    client = _client()
    import anthropic

    ledger = Ledger()
    guard = BudgetGuard(args.budget_usd, ledger)
    store = _new_store("fh-pilot")
    run_id = store.run_id
    models = {item.row.model: MODELS[item.row.model] for item in pilot}
    manifest = _manifest(
        run_id=run_id,
        round_="pilot",
        args=args,
        models=models,
        arms=sorted({item.row.arm for item in pilot}),
        generation=generation,
        planned=len(pilot),
        git=git,
    )
    rows = [item.row for item in pilot]
    hashes: dict[str, dict[str, str]] = {}
    for row in rows:
        hashes.setdefault(row.sid, {})[row.arm] = row.payload_sha256
    _write_run(store, manifest, rows, corpus, hashes)
    print(f"run {run_id}: {store.dir}")
    job_sync = f"{BENCH}/{run_id}/sync"
    guard.admit(job_sync, plan_cost([i.row.planned() for i in sync], batch=False).worst_case_usd)
    rejected: list[str] = []
    measured: dict[str, list[dict[str, int]]] = {}
    try:
        for item in sync:
            scenario = by_sid[item.row.sid]
            try:
                message = client.messages.create(**item.row.params)
            except anthropic.APIError as exc:
                status = getattr(exc, "status_code", None)
                text = str(getattr(exc, "message", exc))[:500]
                store.append_sync(
                    {
                        "custom_id": item.row.custom_id,
                        "result": {"type": "errored", "error": {"status": status, "message": text}},
                    }
                )
                rejected.append(item.row.custom_id)
                hint = (
                    " (cites thinking/tool_use: rerun with --protocol text)"
                    if _rejection_hint(text)
                    else ""
                )
                print(f"  {item.row.custom_id}: REJECTED {status}: {text}{hint}")
                continue
            usd = record_sync_message(
                message, job=job_sync, custom_id=item.row.custom_id, ledger=ledger, store=store
            )
            data = message.to_dict()
            outcome = score.score(scenario, data)
            usage = data.get("usage") or {}
            measured.setdefault(item.row.model, []).append(
                {
                    "input": int(usage.get("input_tokens") or 0),
                    "output": int(usage.get("output_tokens") or 0),
                }
            )
            print(
                f"  {item.row.custom_id}: accepted, model {data.get('model')}, stop "
                f"{data.get('stop_reason')}, outcome {outcome.outcome}, tokens in "
                f"{usage.get('input_tokens')} out {usage.get('output_tokens')}, ${usd:.4f}"
            )
    finally:
        guard.settle(job_sync)
    for item in batched:
        job = f"{BENCH}/{run_id}/batch"
        batch_id = submit(client, [item.row.planned()], job=job, guard=guard, store=store)
        print(f"  {item.row.custom_id}: batch {batch_id}")
        if args.no_wait:
            print(f"  collect later: python -m benchmarks.fix_hints --collect {run_id}")
            continue
        wait(client, batch_id, poll_s=15.0, timeout_s=3600.0)
        tally = collect_batch(store, client, ledger, batch_id, job)
        print(f"  {item.row.custom_id}: batch result {tally}")
    projection(measured, args)
    if rejected:
        print(f"{len(rejected)} pilot request(s) rejected: {', '.join(rejected)}")
        return 1
    return 0


def projection(measured: Mapping[str, list[dict[str, int]]], args: argparse.Namespace) -> None:
    """A full round's cost from the pilot's measured tokens (indicative: n is 1-2 per model)."""
    if not measured:
        return
    arms = _parse_arms(args.arms)
    per_model = sum(n for _, n in scenarios.CATEGORIES) * len(arms)
    print(f"projection for one full round ({per_model:,} requests per model, Batch rates):")
    total = 0.0
    for alias, samples in sorted(measured.items()):
        mean_in = sum(s["input"] for s in samples) / len(samples)
        mean_out = sum(s["output"] for s in samples) / len(samples)
        usd = per_model * estimate_usd(MODELS[alias], round(mean_in), round(mean_out), batch=True)
        total += usd
        print(f"  {alias}: mean in {mean_in:,.0f} out {mean_out:,.0f} tokens -> ${usd:,.2f}")
    print(f"  total ${total:,.2f} (indicative: n={sum(len(s) for s in measured.values())})")


# --------------------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m benchmarks.fix_hints",
        description="fix_hints recovery benchmark (dry run unless --run).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--round", choices=protocol.ROUNDS, default="r1")
    parser.add_argument("--models", default=DEFAULT_MODELS, help="aliases or ids, comma-separated")
    parser.add_argument("--arms", default=",".join(DEFAULT_ARMS), help="subset of h,n,s,g")
    parser.add_argument("--protocol", choices=PROTOCOLS, default="tool")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--pilot", action="store_true", help="the 5-request acceptance pilot")
    parser.add_argument("--run", action="store_true", help="actually send requests (paid)")
    parser.add_argument("--budget-usd", type=float, default=None, help="per-command cap")
    parser.add_argument("--no-wait", action="store_true", help="submit (or check) and exit")
    parser.add_argument("--collect", metavar="RUN_ID", help="wait for, collect and score a run")
    parser.add_argument("--score", metavar="RUN_ID[,RUN_ID]", help="re-score stored runs ($0)")
    parser.add_argument("--write", action="store_true", help="append the round to RESULTS.md")
    parser.add_argument("--date", default=_today(), help="UTC date the round block names")
    parser.add_argument("--r1-run", metavar="RUN_ID[,RUN_ID]", help="the R1 run(s) R2 pairs with")
    parser.add_argument("--force", action="store_true", help="append a block under a used heading")
    parser.add_argument(
        "--force-resubmit", action="store_true", help="resubmit over a dangling intent"
    )
    parser.add_argument("--results", default=str(RESULTS_PATH), help=argparse.SUPPRESS)
    parser.add_argument("--summary", default=str(SUMMARY_PATH), help=argparse.SUPPRESS)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    args.argv = list(sys.argv[1:] if argv is None else argv)
    try:
        if args.run and (args.budget_usd is None or args.budget_usd <= 0):
            raise UsageError("--run needs a positive --budget-usd (the per-command cap in USD)")
        if args.run and (args.collect or args.score):
            raise UsageError("--run submits new requests; --collect and --score never do")
        with quiet_airlock_logs():
            if args.collect:
                return command_collect(args)
            if args.score:
                return command_score(args)
            if args.write:
                raise UsageError("--write needs --score RUN_ID or --collect RUN_ID")
            if args.pilot:
                return command_pilot(args)
            return command_round(args)
    except UsageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except BudgetExceededError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
