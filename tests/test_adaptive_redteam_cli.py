"""run_session CLI end-to-end on one guard with a tiny candidate file."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
for _p in (str(_ROOT / "src"), str(_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from benchmarks.adaptive_redteam.ledger import ledger_path  # noqa: E402
from benchmarks.adaptive_redteam.oracle import CallSpec, Candidate, Intent, Outcome  # noqa: E402
from benchmarks.adaptive_redteam.run_session import main  # noqa: E402


def _write_candidates(path: Path) -> None:
    # metadata URL (blocked) + public URL (benign control), plus a private IP probe.
    path.write_text(
        json.dumps(
            {
                "candidates": [
                    {
                        "candidate_id": "ssrf-block",
                        "intent": "attack",
                        "call": {"kwargs": {"url": "http://169.254.169.254/"}},
                    },
                    {
                        "candidate_id": "ssrf-benign",
                        "intent": "benign",
                        "call": {"kwargs": {"url": "https://api.public.example/v1"}},
                    },
                ]
            }
        )
    )


def test_cli_runs_and_writes_ledger(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cands = tmp_path / "cands.json"
    _write_candidates(cands)
    ledger_root = tmp_path / "ledger"

    rc = main(
        [
            "--guard",
            "ssrf_egress_guard",
            "--seed",
            "0",
            "--candidates",
            str(cands),
            "--ledger-root",
            str(ledger_root),
            "--plateau-window",
            "99",
        ]
    )
    assert rc == 0

    path = ledger_path(ledger_root, "ssrf_egress_guard", 0, nohints=False)
    assert path.exists()
    data = json.loads(path.read_text())
    outcomes = {a["candidate_id"]: a["outcome"] for a in data["attempts"]}
    assert outcomes["ssrf-block"] == Outcome.HARD_BLOCK.value
    assert outcomes["ssrf-benign"] == Outcome.BENIGN_PASS.value
    assert data["bypasses"] == []

    out = capsys.readouterr().out
    assert "hard_block" in out
    assert "benign_pass" in out


def test_cli_resume_skips_completed(tmp_path: Path) -> None:
    cands = tmp_path / "cands.json"
    _write_candidates(cands)
    ledger_root = tmp_path / "ledger"
    args = [
        "--guard",
        "ssrf_egress_guard",
        "--seed",
        "0",
        "--candidates",
        str(cands),
        "--ledger-root",
        str(ledger_root),
        "--plateau-window",
        "99",
    ]
    main(args)
    path = ledger_path(ledger_root, "ssrf_egress_guard", 0, nohints=False)
    first = json.loads(path.read_text())["attempts"]
    main(args)  # resume: everything already done
    second = json.loads(path.read_text())["attempts"]
    assert len(first) == len(second) == 2


def test_run_session_records_a_physical_bypass_if_guard_admits(tmp_path: Path) -> None:
    # Sanity: the oracle+adapter would record a BYPASS if the guard ever admitted
    # a forbidden egress. We force it by allow-listing the metadata host, proving
    # the pipeline can detect a real fail-open (not just always hard_block).
    from benchmarks.adaptive_redteam import adapters as adapters_pkg
    from benchmarks.adaptive_redteam.adapters.standalone import StandaloneAdapter
    from benchmarks.adaptive_redteam.oracle import ForbiddenEffect

    from agent_airlock.ssrf_egress_guard import SSRFEgressGuard

    registry = adapters_pkg.get_registry()
    weakened = StandaloneAdapter(
        name="ssrf_weakened",
        build_guard=lambda: SSRFEgressGuard(allow_internal_hosts=["169.254.169.254"]),
        entry=lambda g, c: g.check_url(str(c.kwargs["url"])),
        forbidden=ForbiddenEffect("egress", frozenset(), "169.254.169.254"),
        blocked=lambda s: CallSpec(kwargs={"url": "http://169.254.169.254/"}),
        benign=lambda s: CallSpec(kwargs={"url": "https://api.public.example/v1"}),
        reference=lambda c: True,
    )
    candidate = Candidate(
        guard="ssrf_weakened",
        seed=0,
        candidate_id="weak-0",
        call=CallSpec(kwargs={"url": "http://169.254.169.254/"}),
        intent=Intent.ATTACK,
    )
    canary = weakened.run(candidate)
    from benchmarks.adaptive_redteam.oracle import classify

    assert classify(candidate, canary, Intent.ATTACK) is Outcome.BYPASS
    # the real registry adapter still blocks it
    assert "ssrf_weakened" not in registry


def test_fix_hints_of_handles_method_string_and_non_iterable() -> None:
    # Regression (adaptive red-team wave 3): a decision object may expose
    # fix_hints as a *method* (DescriptionManifestDecision.fix_hints()), a bare
    # string, or a non-iterable. _fix_hints_of once did `[str(h) for h in hints]`
    # unconditionally and crashed with "TypeError: 'method' object is not
    # iterable". It must tolerate the whole heterogeneous decision family.
    from benchmarks.adaptive_redteam.run_session import _fix_hints_of

    class _MethodHints:
        def fix_hints(self) -> list[str]:
            return ["do the thing differently"]

    class _StringHints:
        fix_hints = "one hint, not six characters"

    class _RaisingHints:
        def fix_hints(self) -> list[str]:
            raise RuntimeError("accessor blew up")

    class _IntHints:
        fix_hints = 7

    assert _fix_hints_of(_MethodHints()) == ["do the thing differently"]
    assert _fix_hints_of(_StringHints()) == ["one hint, not six characters"]
    assert _fix_hints_of(_RaisingHints()) == []
    assert _fix_hints_of(_IntHints()) == ["7"]
    assert _fix_hints_of({"fix_hints": ["a", "b"]}) == ["a", "b"]
    assert _fix_hints_of({"fix_hints": None}) == []
    assert _fix_hints_of(object()) == []


def test_cli_runs_on_guard_whose_decision_exposes_fix_hints_method(tmp_path: Path) -> None:
    # Regression (adaptive red-team wave 3): description_manifest_guard's decision
    # object carries fix_hints as a method, so a full session crashed before
    # recording any attempt. The session must now complete and capture the hints.
    cands = tmp_path / "cands.json"
    cands.write_text(
        json.dumps(
            {
                "candidates": [
                    {
                        "candidate_id": "dm-block",
                        "intent": "attack",
                        "call": {"kwargs": {"name": "t", "described_args": ["x", "secret_exfil"]}},
                    },
                    {
                        "candidate_id": "dm-benign",
                        "intent": "benign",
                        "call": {"kwargs": {"name": "t", "described_args": ["x"]}},
                    },
                ]
            }
        )
    )
    ledger_root = tmp_path / "ledger"
    rc = main(
        [
            "--guard",
            "description_manifest_guard",
            "--seed",
            "0",
            "--candidates",
            str(cands),
            "--ledger-root",
            str(ledger_root),
            "--plateau-window",
            "99",
        ]
    )
    assert rc == 0
    path = ledger_path(ledger_root, "description_manifest_guard", 0, nohints=False)
    data = json.loads(path.read_text())
    outcomes = {a["candidate_id"]: a["outcome"] for a in data["attempts"]}
    assert outcomes["dm-block"] == Outcome.HARD_BLOCK.value
    assert outcomes["dm-benign"] == Outcome.BENIGN_PASS.value
    blocked = next(a for a in data["attempts"] if a["candidate_id"] == "dm-block")
    assert blocked["fix_hints"] and any("manifest" in h for h in blocked["fix_hints"])
    assert data["bypasses"] == []
