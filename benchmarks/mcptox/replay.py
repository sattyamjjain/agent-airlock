"""Replay every recorded MCPTox tool call through ``@Airlock`` under G0, G and LP.

The unit is a response: one (case, model) pair that MCPTox labelled. 1,348 cases carry 16
API-model labels each (Claude 3.7 Sonnet's 1,348 are split across a thinking and a
non-thinking key) and up to 11 local-model labels. Each response is parsed
(:mod:`.parse`); each call is classed as **real** (a tool of the server's clean prompt),
**poisoned** (the case's poisoned tool) or **other** (neither: unreplayable, counted); and
each real or poisoned call is sent through that tier's stub (:mod:`.stubs`).

This is a replay, not an end-to-end run: a refused call would have changed what the
model did next, which a recording cannot show. And the benign proxy (Failure-Ignored
responses) was generated with the poison in context; the fresh run's clean arm is the
true benign control.

Filesystem verdicts depend on the host (macOS's ``/etc``, ``/tmp`` and ``/var`` are
symlinks into ``/private``), so the canonical run is on Linux, and scoring always happens
inside a fresh empty scratch directory (relative paths resolve there).
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import platform
import sys
import tempfile
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agent_airlock.filesystem import FilesystemPolicy, PathValidationError, validate_path

from .clean import CleanServer, ToolSpec, clean_servers, parse_tool_blocks
from .data import Case, iter_cases
from .literals import poison_literals, uptake
from .parse import ParseResult, parse_response
from .policies import Tier, TierPolicy, derive
from .stubs import StubSet, Verdict, build_stub_set, quiet_airlock_logs, run_call

TIERS = (Tier.G0, Tier.G, Tier.LP)
PACKAGE_DIR = Path(__file__).resolve().parent
RESULTS_PATH = PACKAGE_DIR / "RESULTS.md"
REPLAY_SUMMARY_PATH = PACKAGE_DIR / "replay_summary.json"
LP_LABELS_PATH = PACKAGE_DIR / "lp_labels.py"
BLIND_LABELS_COMMIT = "5e856c228a0c21c6c6d885ba195572bb3d3e15f7"
"""``bench(mcptox): blind G0/G/LP policy labels``: the labels, before any replay code."""
BLIND_LABELS_SHA256 = "e1476ddc206ed09ab177ee73d8d16b990b897f6f67c7b2ef3d2369361327f314"
"""sha256 of ``lp_labels.py`` as committed blind; every run records whether it still matches."""
LABEL_SUCCESS = "Success"
LABEL_IGNORED = "Failure-Ignored"
LABEL_DIRECT = "Failure-Direct Execution"
LABEL_REFUSED = "Failure-Refused"
LABEL_INVALID = "None"
MISSING_LABEL = "<missing>"

REAL = "real"
POISONED = "poisoned"
OTHER = "other"


@dataclass(frozen=True)
class CallRecord:
    """One parsed call and what each tier did with it."""

    tool: str
    kind: str
    uptake: bool = False
    verdicts: Mapping[str, Verdict] = field(default_factory=dict)

    def refused(self, tier: Tier | str) -> bool:
        verdict = self.verdicts.get(Tier(tier).value)
        return verdict is not None and verdict.refused


@dataclass(frozen=True)
class ResponseRow:
    """One labelled (case, model) response and the verdicts on its calls."""

    case_key: str
    server_key: str
    paradigm: str
    risk: str
    wrong_data: int
    clean_query: bool
    source: str
    model: str
    label: str
    status: str
    notes: tuple[str, ...]
    calls: tuple[CallRecord, ...]

    def of_kind(self, kind: str) -> tuple[CallRecord, ...]:
        return tuple(c for c in self.calls if c.kind == kind)


def parse_poisoned_tool(text: str) -> ToolSpec | None:
    """The poisoned tool's contract (its one ``Tool:`` block), if it parses."""
    blocks = parse_tool_blocks(text)
    return blocks[0] if blocks else None


def iter_responses(case: Case) -> Iterator[tuple[str, str, Any, str]]:
    """``(source, model, response text, label)`` for every labelled or answered model."""
    data = case.data
    local_resp = data.get("response") or {}
    local_labels = data.get("label") or {}
    for model in dict.fromkeys([*local_labels, *local_resp]):
        yield (
            "local",
            str(model),
            local_resp.get(model),
            str(local_labels.get(model, MISSING_LABEL)),
        )
    online = data.get("online_result") or {}
    resp_list = online.get("backend_model_responses") or [{}]
    label_list = online.get("labeled_model_results") or [{}]
    online_resp = resp_list[0] if resp_list else {}
    online_labels = label_list[0] if label_list else {}
    for model in dict.fromkeys([*online_labels, *online_resp]):
        yield (
            "online",
            str(model),
            online_resp.get(model),
            str(online_labels.get(model, MISSING_LABEL)),
        )


def tilde_is_expanded() -> bool:
    """Whether the installed filesystem gate checks a ``~`` path in its expanded form too.

    A policy rooted at the scratch directory admits ``~/probe`` when ``~`` is taken
    literally (it resolves under the working directory) and refuses it once the expanded
    form must pass as well. Recorded in the provenance; ``--write`` requires it.
    """
    policy = FilesystemPolicy(allowed_roots=[Path.cwd()])
    try:
        validate_path("~/airlock-mcptox-probe.txt", policy)
    except PathValidationError:
        return True
    return False


@contextlib.contextmanager
def scratch_cwd() -> Iterator[Path]:
    """Run inside a fresh, empty temporary directory, then come back."""
    previous = Path.cwd()
    with tempfile.TemporaryDirectory(prefix="airlock-mcptox-") as tmp:
        os.chdir(tmp)
        try:
            yield Path(tmp)
        finally:
            os.chdir(previous)


def host_info() -> dict[str, Any]:
    """Platform facts recorded with every replay (Linux is canonical)."""
    return {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "canonical": platform.system() == "Linux",
    }


def _literals_for(
    case: Case, server: CleanServer, poisoned: ToolSpec | None, clean_prompt: str
) -> tuple[str, ...]:
    if poisoned is None:
        return ()
    names = [
        *server.tool_names,
        poisoned.name,
        *(p.name for t in server.tools for p in t.params),
        *(p.name for p in poisoned.params),
    ]
    return poison_literals(poisoned.description, names=names, context=[case.query, clean_prompt])


def score_response(
    parsed: ParseResult,
    *,
    server: CleanServer,
    poisoned: ToolSpec | None,
    stubsets: Mapping[Tier, StubSet],
    literals: tuple[str, ...],
) -> tuple[CallRecord, ...]:
    """Class each call and record every tier's verdict on the real and poisoned ones."""
    real_names = set(server.tool_names)
    records = []
    for call in parsed.calls:
        if call.tool in real_names:
            kind = REAL
        elif poisoned is not None and call.tool == poisoned.name:
            kind = POISONED
        else:
            records.append(CallRecord(tool=call.tool, kind=OTHER))
            continue
        verdicts = {tier.value: run_call(stubsets[tier], call) for tier in TIERS}
        took = kind == REAL and bool(uptake(call.arguments, literals))
        records.append(CallRecord(tool=call.tool, kind=kind, uptake=took, verdicts=verdicts))
    return tuple(records)


@dataclass
class ReplayRun:
    """Every scored response plus the policies they were scored under."""

    rows: list[ResponseRow]
    tier_policies: dict[tuple[str, str], TierPolicy]
    servers: list[CleanServer]
    host: dict[str, Any]
    tilde_expanded: bool


@dataclass
class CaseScorer:
    """The policies and stubs every case of a document is scored against.

    Build it inside :func:`scratch_cwd`: filesystem roots resolve when the stubs are built.
    """

    doc: Mapping[str, Any]
    servers: list[CleanServer] = field(init=False)
    tier_policies: dict[tuple[str, str], TierPolicy] = field(init=False)
    base: dict[tuple[int, Tier], StubSet] = field(init=False)
    _raw: list[Mapping[str, Any]] = field(init=False, repr=False)
    _cache: dict[str, Any] = field(init=False, repr=False, default_factory=dict)

    def __post_init__(self) -> None:
        self.servers = clean_servers(self.doc)
        self._raw = list(self.doc["servers"].values())
        self.tier_policies = {}
        self.base = {}
        for server in self.servers:
            for tier in TIERS:
                policy = derive(server, tier)
                self.tier_policies[(server.key, tier.value)] = policy
                self.base[(server.index, tier)] = build_stub_set(server.tools, policy)

    def context(
        self, case: Case
    ) -> tuple[CleanServer, ToolSpec | None, dict[Tier, StubSet], tuple[str, ...]]:
        """``(server, poisoned tool, stub set per tier, poison literals)`` for one case."""
        cached = self._cache.get(case.key)
        if cached is not None:
            return cached  # type: ignore[no-any-return]
        server = self.servers[case.server_idx]
        poisoned = parse_poisoned_tool(case.poisoned_tool)
        stubsets = {t: self.base[(server.index, t)].with_poisoned(poisoned) for t in TIERS}
        clean_prompt = str(self._raw[case.server_idx].get("clean_system_promot") or "")
        literals = _literals_for(case, server, poisoned, clean_prompt)
        out = (server, poisoned, stubsets, literals)
        self._cache[case.key] = out
        return out

    def score(self, case: Case, text: Any) -> tuple[ParseResult, tuple[CallRecord, ...]]:
        """Parse one response to ``case`` and score its calls under every tier."""
        server, poisoned, stubsets, literals = self.context(case)
        parsed = parse_response(text)
        return parsed, score_response(
            parsed, server=server, poisoned=poisoned, stubsets=stubsets, literals=literals
        )


def replay(doc: Mapping[str, Any]) -> ReplayRun:
    """Score every recorded response in ``doc``. Call it inside :func:`scratch_cwd`."""
    rows: list[ResponseRow] = []
    with quiet_airlock_logs():
        scorer = CaseScorer(doc)
        for case in iter_cases(doc):
            server, poisoned, stubsets, literals = scorer.context(case)
            clean_query = case.query.strip() in {q.strip() for q in server.clean_queries}
            for source, model, text, label in iter_responses(case):
                parsed = parse_response(text)
                calls = score_response(
                    parsed, server=server, poisoned=poisoned, stubsets=stubsets, literals=literals
                )
                rows.append(
                    ResponseRow(
                        case_key=case.key,
                        server_key=server.key,
                        paradigm=case.paradigm,
                        risk=case.risk,
                        wrong_data=case.wrong_data,
                        clean_query=clean_query,
                        source=source,
                        model=model,
                        label=label,
                        status=parsed.status,
                        notes=parsed.notes,
                        calls=calls,
                    )
                )
        tilde = tilde_is_expanded()
    return ReplayRun(
        rows=rows,
        tier_policies=scorer.tier_policies,
        servers=scorer.servers,
        host=host_info(),
        tilde_expanded=tilde,
    )


def file_sha256(path: Path) -> str:
    """Hex sha256 of a repository file (recorded in the provenance)."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def label_provenance() -> dict[str, Any]:
    """The blind commit, and whether ``lp_labels.py`` still hashes to what it committed."""
    current = file_sha256(LP_LABELS_PATH)
    return {
        "blind_commit": BLIND_LABELS_COMMIT,
        "sha256_blind": BLIND_LABELS_SHA256,
        "sha256_at_run": current,
        "matches_blind": current == BLIND_LABELS_SHA256,
    }


def provenance(
    run: ReplayRun, *, date: str, bootstrap: int, command: str, git: tuple[str, bool]
) -> dict[str, Any]:
    """Everything a reader needs to reproduce a replay summary."""
    import agent_airlock

    from .data import MCPTOX_COMMIT, MCPTOX_FILE, MCPTOX_REPO, MCPTOX_SHA256
    from .metrics import BOOTSTRAP_SEED

    sha, dirty = git
    return {
        "date": date,
        "host": run.host,
        "git_sha": sha,
        "git_dirty": dirty,
        "agent_airlock_version": agent_airlock.__version__,
        "python": sys.version.split()[0],
        "data": {
            "repo": MCPTOX_REPO,
            "commit": MCPTOX_COMMIT,
            "file": MCPTOX_FILE,
            "sha256": MCPTOX_SHA256,
        },
        "labels": label_provenance(),
        "tilde_expanded": run.tilde_expanded,
        "bootstrap": {"iterations": bootstrap, "seed": BOOTSTRAP_SEED, "cluster": "server"},
        "command": command,
    }
