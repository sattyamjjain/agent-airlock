"""The append-only, resumable schema-1 ledger."""

from __future__ import annotations

import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
for _p in (str(_ROOT / "src"), str(_ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from benchmarks.adaptive_redteam.ledger import Ledger, ledger_path  # noqa: E402
from benchmarks.adaptive_redteam.oracle import (  # noqa: E402
    Attempt,
    CallSpec,
    Candidate,
    Intent,
    Outcome,
)


def _attempt(cid: str, outcome: Outcome, intent: Intent = Intent.ATTACK) -> Attempt:
    return Attempt(
        candidate=Candidate(
            guard="g", seed=0, candidate_id=cid, call=CallSpec(kwargs={"x": cid}), intent=intent
        ),
        outcome=outcome,
        block_reason="deny_x" if outcome is Outcome.HARD_BLOCK else None,
        fix_hints=["do the thing"] if outcome is Outcome.HARD_BLOCK else [],
        sink_hits=["egress:x"] if outcome is Outcome.BYPASS else [],
        novel=True,
    )


def test_path_naming(tmp_path: Path) -> None:
    assert ledger_path(tmp_path, "g", 3, nohints=False).name == "g.seed03.json"
    assert ledger_path(tmp_path, "g", 3, nohints=True).name == "g.seed03.nohints.json"


def test_record_and_reload(tmp_path: Path) -> None:
    led = Ledger.open(tmp_path, "g", 0, airlock_version="9.9.9", git_sha="abc123")
    led.record(_attempt("g-0", Outcome.HARD_BLOCK))
    led.record(_attempt("g-1", Outcome.BYPASS))
    led.record(_attempt("g-2", Outcome.BENIGN_PASS, Intent.BENIGN))

    data = json.loads(led.path.read_text())
    assert data["schema"] == 1
    assert data["guard"] == "g"
    assert data["airlock_version"] == "9.9.9"
    assert data["git_sha"] == "abc123"
    assert data["fix_hints"] is True
    assert data["bypasses"] == ["g-1"]
    assert data["refusals"] == ["g-0"]

    reopened = Ledger.open(tmp_path, "g", 0)
    assert reopened.completed_ids() == {"g-0", "g-1", "g-2"}
    assert len(reopened.bypasses()) == 1


def test_resume_skips_completed(tmp_path: Path) -> None:
    led = Ledger.open(tmp_path, "g", 0)
    led.record(_attempt("g-0", Outcome.HARD_BLOCK))
    assert led.is_done("g-0")
    # Recording the same id again is a no-op (append-only, idempotent).
    led.record(_attempt("g-0", Outcome.BYPASS))
    assert len(led.attempts) == 1
    assert led.attempts[0].outcome is Outcome.HARD_BLOCK


def test_nohints_arm_is_separate_file(tmp_path: Path) -> None:
    hints = Ledger.open(tmp_path, "g", 0, nohints=False)
    nohints = Ledger.open(tmp_path, "g", 0, nohints=True)
    assert hints.path != nohints.path
    nohints.record(_attempt("g-0", Outcome.HARD_BLOCK))
    data = json.loads(nohints.path.read_text())
    assert data["fix_hints"] is False


def test_mark_status(tmp_path: Path) -> None:
    led = Ledger.open(tmp_path, "g", 0)
    led.mark_plateaued()
    assert json.loads(led.path.read_text())["status"] == "plateaued"
    led.mark_complete()
    assert json.loads(led.path.read_text())["status"] == "complete"
