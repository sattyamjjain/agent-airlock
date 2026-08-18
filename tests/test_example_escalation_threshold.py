"""`examples/escalation_threshold.py` must actually run, and produce every verdict.

An example that stops working is worse than no example: it is the first thing a reader
tries, and a traceback there costs more trust than the feature earns. This drives the file
two ways — imported, so the verdicts can be asserted individually, and as a subprocess, so
the advertised one-liner is the thing under test rather than an approximation of it.

The scenario is the one the v0.8.74 changelog names as previously inexpressible: transfers
under a threshold proceed, transfers over it ask a human.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

from agent_airlock.oversight import OversightVerdict

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))

from escalation_threshold import (  # noqa: E402
    THRESHOLD_USD,
    RunContext,
    StubApprover,
    TransferRequest,
    main,
    make_tool,
)

_EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "escalation_threshold.py"

#: structlog emits "<date> <time> [level] event ..." lines onto the same stream the demo
#: prints to. They carry a wall-clock timestamp, so they can never be compared across runs.
_LOG_LINE = re.compile(r"^\s*\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}")


def _strip_log_lines(out: str) -> str:
    return "\n".join(line for line in out.splitlines() if not _LOG_LINE.match(line))


def _call(amount: int, approver: StubApprover | None):
    tool = make_tool(approver)
    return tool(RunContext(context=TransferRequest(amount_usd=amount)), amount_usd=amount)


class TestBothVerdictsAreProduced:
    """Allow and escalate, from one policy, decided by the argument value."""

    def test_under_the_threshold_proceeds(self) -> None:
        result = _call(THRESHOLD_USD - 1, StubApprover(verdict=OversightVerdict.GRANT))
        assert result == f"TRANSFERRED ${THRESHOLD_USD - 1:,}"

    def test_at_the_threshold_proceeds(self) -> None:
        """The boundary is inclusive — `<= THRESHOLD` auto-approves."""
        approver = StubApprover(verdict=OversightVerdict.GRANT)
        assert _call(THRESHOLD_USD, approver) == f"TRANSFERRED ${THRESHOLD_USD:,}"
        assert approver.seen == [], "the threshold amount should not have asked a human"

    def test_over_the_threshold_escalates_and_a_grant_lets_it_through(self) -> None:
        approver = StubApprover(verdict=OversightVerdict.GRANT)
        result = _call(THRESHOLD_USD + 1, approver)

        assert result == f"TRANSFERRED ${THRESHOLD_USD + 1:,}"
        assert len(approver.seen) == 1, "the human was not asked"

    def test_over_the_threshold_with_a_denial_blocks(self) -> None:
        result = _call(5_000, StubApprover(verdict=OversightVerdict.DENY))
        assert isinstance(result, dict)
        assert result["block_reason"] == "escalation_denied"

    def test_the_human_is_told_why_and_by_which_rule(self) -> None:
        approver = StubApprover(verdict=OversightVerdict.GRANT)
        _call(5_000, approver)

        asked = approver.seen[-1]
        assert asked.args["escalation_rule"] == "transfer_funds"
        assert "5,000" in asked.args["escalation_reason"]
        assert asked.channel == "finance"


class TestTheDenyByDefaultScenarioHolds:
    """Scenario 4. The example would be misleading if this ever passed the call."""

    def test_no_approver_blocks(self) -> None:
        result = _call(5_000, approver=None)
        assert isinstance(result, dict), "an escalation with no approver returned a value"
        assert result["success"] is False
        assert result["block_reason"] == "escalation_required"

    def test_no_approver_does_not_run_the_transfer(self) -> None:
        result = _call(5_000, approver=None)
        assert "TRANSFERRED" not in str(result)


class TestTheAdvertisedCommandWorks:
    """`python examples/escalation_threshold.py` — the exact line the README prints."""

    @pytest.fixture(scope="class")
    def run(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603
            [sys.executable, str(_EXAMPLE)],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )

    def test_it_exits_clean(self, run: subprocess.CompletedProcess[str]) -> None:
        assert run.returncode == 0, f"example failed:\n{run.stderr[-2000:]}"

    def test_it_prints_both_verdicts(self, run: subprocess.CompletedProcess[str]) -> None:
        assert "ALLOWED" in run.stdout
        assert "BLOCKED" in run.stdout

    def test_it_prints_all_four_scenarios(self, run: subprocess.CompletedProcess[str]) -> None:
        for n in ("1.", "2.", "3.", "4."):
            assert n in run.stdout, f"scenario {n} missing from the output"

    def test_it_is_deterministic(self) -> None:
        """Two runs produce identical *demo* output.

        Structlog interleaves its own timestamped lines into stdout, so those are stripped
        before comparing — the claim under test is that the example's own printed result is
        the same on every run (no clock, no randomness, no network in the decision path),
        not that the log stream is byte-stable, which it obviously is not.
        """
        runs = [
            subprocess.run(  # noqa: S603
                [sys.executable, str(_EXAMPLE)],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            ).stdout
            for _ in range(2)
        ]
        demo = [_strip_log_lines(out) for out in runs]
        assert demo[0] == demo[1], "the example's own output is not deterministic"
        assert "TRANSFERRED $250" in demo[0], "stripping removed the demo output too"

    def test_main_is_importable_and_runs(self, capsys: pytest.CaptureFixture[str]) -> None:
        main()
        assert "Escalation threshold demo" in capsys.readouterr().out
