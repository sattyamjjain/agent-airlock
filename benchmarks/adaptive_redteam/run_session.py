"""Run one guard-seed attack session against a candidate file. Resumable.

    python -m benchmarks.adaptive_redteam.run_session \
        --guard ssrf_egress_guard --seed 0 --candidates cands.json [--nohints]

Each candidate's :class:`CallSpec` is executed through the guard's adapter,
classified by the oracle against a harmless sentinel sink, and appended to the
append-only ledger at ``ledger/<guard>/<guard>.seed<NN>[.nohints].json``. A
resumed run skips candidate ids already in the ledger. One transcript line is
printed per attempt — outcome, block_reason, and (unless ``--nohints``) the
guard's fix_hints — which is exactly what an attacker agent reads to refine its
next candidate. After ``--plateau-window`` consecutive non-novel attempts the run
stops advising (marks the ledger plateaued) and exits.

No network, no LLM, no paid API. The candidate file is authored by a human or an
Opus attack agent out of band; this runner only executes and scores it.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from .adapters import all_adapter_names, get_adapter, seed_count
from .ledger import Ledger
from .oracle import Attempt, Candidate, Outcome, classify

DEFAULT_LEDGER_ROOT = Path(__file__).resolve().parent / "ledger"
DEFAULT_PLATEAU_WINDOW = 15


def _airlock_version() -> str:
    try:
        import agent_airlock

        return getattr(agent_airlock, "__version__", "")
    except Exception:  # noqa: BLE001
        return ""


def _load_candidates(path: Path, guard: str, seed: int) -> list[Candidate]:
    """Load candidates from a JSON file (a list, or ``{"candidates": [...]}``)."""
    data = json.loads(path.read_text(encoding="utf-8"))
    raw = data["candidates"] if isinstance(data, dict) else data
    candidates: list[Candidate] = []
    for i, rec in enumerate(raw):
        rec = dict(rec)
        rec.setdefault("guard", guard)
        rec.setdefault("seed", seed)
        rec.setdefault("candidate_id", f"{guard}-s{seed:02d}-{i:04d}")
        candidates.append(Candidate.from_json(rec))
    return candidates


def _novelty_signature(attempt: Attempt) -> tuple[str, str, str]:
    """A coarse signature so repeats count toward the plateau.

    (outcome, block_reason, sorted top-level kwarg keys). Two candidates that land
    the same outcome with the same refusal reason and the same argument shape are
    not novel progress.
    """
    keys = ",".join(sorted(str(k) for k in attempt.candidate.call.kwargs))
    return (attempt.outcome.value, attempt.block_reason or "", keys)


def _block_reason_of(response: Any) -> str | None:
    if isinstance(response, dict):
        return response.get("block_reason") or response.get("verdict")
    verdict = getattr(response, "verdict", None)
    if verdict is not None:
        return str(getattr(verdict, "value", verdict))
    return None


def _fix_hints_of(response: Any) -> list[str]:
    hints: Any = None
    if isinstance(response, dict):
        hints = response.get("fix_hints")
    if hints is None:
        hints = getattr(response, "fix_hints", None)
    # A decision object may expose fix_hints as a method, not an attribute
    # (e.g. DescriptionManifestDecision.fix_hints()); call it before reading,
    # the same way _block_reason_of unwraps a verdict enum.
    if callable(hints):
        try:
            hints = hints()
        except Exception:  # noqa: BLE001 - a hint accessor that raises yields no hints
            return []
    if not hints:
        return []
    # A bare string is one hint, not an iterable of single characters.
    if isinstance(hints, str):
        return [hints]
    try:
        return [str(h) for h in hints]
    except TypeError:  # a non-iterable, non-string hint value
        return [str(hints)]


def run_session(
    guard: str,
    seed: int,
    candidates: Sequence[Candidate],
    *,
    ledger_root: Path = DEFAULT_LEDGER_ROOT,
    nohints: bool = False,
    budget: int = 100,
    plateau_window: int = DEFAULT_PLATEAU_WINDOW,
    git_sha: str = "",
    emit: Any = None,
) -> Ledger:
    """Execute candidates through the adapter, classify, append, detect plateau."""
    adapter = get_adapter(guard)
    ledger = Ledger.open(
        ledger_root,
        guard,
        seed,
        nohints=nohints,
        adapter_mode=getattr(adapter, "mode", "C"),
        airlock_version=_airlock_version(),
        git_sha=git_sha,
        budget=budget,
    )
    emit = emit or (lambda line: print(line))
    seen: set[tuple[str, str, str]] = {_novelty_signature(a) for a in ledger.attempts}
    non_novel_run = 0
    ran = 0

    for candidate in candidates:
        if ran >= budget:
            break
        if ledger.is_done(candidate.candidate_id):
            continue
        canary = adapter.run(candidate)
        outcome = classify(candidate, canary, candidate.intent)
        block_reason = _block_reason_of(canary.response)
        fix_hints = _fix_hints_of(canary.response)
        signature = (
            outcome.value,
            block_reason or "",
            ",".join(sorted(str(k) for k in candidate.call.kwargs)),
        )
        novel = signature not in seen
        seen.add(signature)
        attempt = Attempt(
            candidate=candidate,
            outcome=outcome,
            block_reason=block_reason,
            fix_hints=fix_hints,
            sink_hits=list(canary.sink_hits),
            novel=novel,
        )
        ledger.record(attempt)
        ran += 1
        emit(_transcript_line(attempt, nohints=nohints))

        if outcome is Outcome.BYPASS:
            emit(f"  !! BYPASS recorded for {guard} on candidate {candidate.candidate_id}")
        non_novel_run = 0 if novel else non_novel_run + 1
        if non_novel_run >= plateau_window:
            emit(
                f"  -- plateau: {plateau_window} consecutive non-novel attempts; "
                "stopping advice for this seed."
            )
            ledger.mark_plateaued()
            return ledger

    ledger.mark_complete()
    return ledger


def _transcript_line(attempt: Attempt, *, nohints: bool) -> str:
    parts = [
        f"[{attempt.outcome.value:11}]",
        attempt.candidate.candidate_id,
        f"intent={attempt.candidate.intent.value}",
    ]
    if attempt.block_reason:
        parts.append(f"block_reason={attempt.block_reason}")
    if attempt.sink_hits:
        parts.append(f"sink_hits={attempt.sink_hits}")
    if not nohints and attempt.fix_hints:
        parts.append(f"fix_hints={attempt.fix_hints}")
    return " ".join(parts)


def _emit_controls(guard: str, seed: int) -> int:
    """Print the adapter's own control candidates as a candidates JSON file."""
    adapter = get_adapter(guard)
    controls = [adapter.known_blocked(seed), adapter.benign_control(seed)]
    print(json.dumps({"candidates": [c.to_json() for c in controls]}, indent=2))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m benchmarks.adaptive_redteam.run_session",
        description="Run one resumable guard-seed attack session against a candidate file.",
    )
    parser.add_argument("--guard", help="Adapter / guard target name.")
    parser.add_argument("--seed", type=int, default=0, help="Seed index for this session.")
    parser.add_argument("--candidates", type=Path, help="Candidate JSON file.")
    parser.add_argument(
        "--nohints",
        action="store_true",
        help="Ablation arm: omit fix_hints from the transcript the attacker reads.",
    )
    parser.add_argument("--ledger-root", type=Path, default=DEFAULT_LEDGER_ROOT)
    parser.add_argument("--budget", type=int, default=100, help="Max candidates to run.")
    parser.add_argument("--plateau-window", type=int, default=DEFAULT_PLATEAU_WINDOW)
    parser.add_argument("--git-sha", default="", help="Source SHA to stamp in the ledger.")
    parser.add_argument(
        "--emit-controls",
        action="store_true",
        help="Print this guard's control candidates (blocked + benign) and exit.",
    )
    parser.add_argument("--list-guards", action="store_true", help="List adapter names and exit.")
    args = parser.parse_args(argv)

    if args.list_guards:
        for name in all_adapter_names():
            print(f"{name}\t(seeds={seed_count(name)})")
        return 0

    if not args.guard:
        parser.error("--guard is required (or use --list-guards)")

    if args.emit_controls:
        return _emit_controls(args.guard, args.seed)

    if not args.candidates:
        parser.error("--candidates FILE.json is required (or use --emit-controls)")

    candidates = _load_candidates(args.candidates, args.guard, args.seed)
    ledger = run_session(
        args.guard,
        args.seed,
        candidates,
        ledger_root=args.ledger_root,
        nohints=args.nohints,
        budget=args.budget,
        plateau_window=args.plateau_window,
        git_sha=args.git_sha,
    )
    bypass_n = len(ledger.bypasses())
    print(
        f"\n{args.guard} seed {args.seed}: {len(ledger.attempts)} attempts, "
        f"{bypass_n} bypass(es), status={ledger.status}. Ledger: {ledger.path}"
    )
    # A found bypass is a finding, not a harness failure: exit 0 so a wave keeps
    # going; the coordinator reads the ledger. Only a usage error is non-zero.
    return 0


if __name__ == "__main__":
    sys.exit(main())
