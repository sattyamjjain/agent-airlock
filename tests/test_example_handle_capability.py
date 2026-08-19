"""`examples/handle_capability.py` must actually run, and produce every verdict.

An example that stops working is worse than no example: it is the first thing a reader
tries, and a traceback there costs more trust than the feature earns. This drives the file
two ways — imported, so each verdict can be asserted individually, and as a subprocess, so
the advertised one-liner is the thing under test rather than an approximation of it.

The example self-checks: ``main()`` compares every verdict against the one the scenario
declares and returns a non-zero exit code on a mismatch. So the subprocess test below is not
only asserting "it did not crash" — a wrong verdict fails it too.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))

from handle_capability import (  # noqa: E402
    CHECKPOINT_ISSUER,
    EXPORT_ISSUER,
    HOME_WORKSPACE,
    OTHER_WORKSPACE,
    Call,
    build_calls,
    main,
    open_session,
    read_checkpoint,
    start_export,
)

from agent_airlock import HandleLedger, handle_run  # noqa: E402

_EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "handle_capability.py"

#: structlog writes "<date> <time> [level] event ..." onto the same stream the demo prints
#: to. Those lines carry a wall-clock timestamp and can never be compared across runs.
_LOG_LINE = re.compile(r"^\s*\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}")


def _strip_log_lines(out: str) -> str:
    return "\n".join(line for line in out.splitlines() if not _LOG_LINE.match(line))


def _verdict(handle: str) -> str:
    result = read_checkpoint(session=handle)
    return result["block_reason"] if isinstance(result, dict) else "allow"


class TestEveryVerdictIsProduced:
    """The accept case and all four rejections, from one declared field."""

    def test_a_correctly_issued_handle_is_accepted(self) -> None:
        with handle_run("t"):
            handle = open_session(workspace=HOME_WORKSPACE)
            assert isinstance(handle, str)
            assert _verdict(handle) == "allow"

    def test_a_handle_never_issued_here_is_refused(self) -> None:
        with handle_run("t"):
            assert _verdict("ah_from-a-transcript") == "handle_not_issued"

    def test_a_handle_from_another_tool_is_refused(self) -> None:
        with handle_run("t"):
            handle = start_export(workspace=HOME_WORKSPACE)
            assert isinstance(handle, str)
            assert _verdict(handle) == "handle_wrong_issuer"

    def test_a_handle_for_another_workspace_is_refused(self) -> None:
        with handle_run("t"):
            handle = open_session(workspace=OTHER_WORKSPACE)
            assert isinstance(handle, str)
            assert _verdict(handle) == "handle_wrong_scope"

    def test_an_expired_handle_is_refused(self) -> None:
        import time

        from handle_capability import EXPIRING_TTL_SECONDS

        with handle_run("t") as ledger:
            handle = ledger.issue(
                issuer=CHECKPOINT_ISSUER,
                scope=HOME_WORKSPACE,
                ttl_seconds=EXPIRING_TTL_SECONDS,
            )
            time.sleep(EXPIRING_TTL_SECONDS * 2)
            assert _verdict(handle) == "handle_expired"

    def test_with_no_ledger_bound_the_call_is_refused(self) -> None:
        """The scenario the example ends on: an unconfigured layer must still be closed."""
        assert _verdict("ah_anything") == "handle_not_issued"


class TestTheScenariosMatchTheirLabels:
    """`build_calls` declares an expected verdict per scenario; they must be the real ones."""

    def test_every_declared_expectation_holds(self) -> None:
        with handle_run("t") as ledger:
            calls = build_calls(ledger)
            for call in calls:
                assert _verdict(call.handle) == call.expected, call.label

    def test_all_four_rejection_reasons_are_covered(self) -> None:
        with handle_run("t") as ledger:
            expected = {call.expected for call in build_calls(ledger)}
        assert expected == {
            "allow",
            "handle_not_issued",
            "handle_wrong_issuer",
            "handle_wrong_scope",
            "handle_expired",
        }

    def test_the_two_issuers_are_actually_different(self) -> None:
        """Otherwise scenario 3 would be testing nothing."""
        assert CHECKPOINT_ISSUER != EXPORT_ISSUER
        assert HOME_WORKSPACE != OTHER_WORKSPACE


class TestItRunsAsAdvertised:
    def test_the_documented_command_exits_zero(self) -> None:
        """`main()` returns non-zero if any verdict was wrong, so this asserts correctness."""
        proc = subprocess.run(
            [sys.executable, str(_EXAMPLE)],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr

    def test_the_output_names_every_verdict(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(_EXAMPLE)],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        out = _strip_log_lines(proc.stdout)
        for expected in (
            "ALLOW",
            "HANDLE_NOT_ISSUED",
            "HANDLE_WRONG_ISSUER",
            "HANDLE_WRONG_SCOPE",
            "HANDLE_EXPIRED",
        ):
            assert expected in out, f"{expected} missing from example output"

    def test_no_full_handle_is_printed(self) -> None:
        """The demo prints handles; a bearer capability must not be echoed at full length."""
        proc = subprocess.run(
            [sys.executable, str(_EXAMPLE)],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        # A minted handle is 46 chars. The demo truncates to 9 plus an ellipsis, so no line
        # should carry a long ah_ token.
        assert not re.search(r"ah_[A-Za-z0-9_-]{20,}", proc.stdout)

    def test_main_is_importable_and_returns_zero(self) -> None:
        assert main() == 0


class TestExampleShape:
    def test_build_calls_returns_call_records(self) -> None:
        with handle_run("t") as ledger:
            calls = build_calls(ledger)
        assert calls and all(isinstance(call, Call) for call in calls)

    def test_the_ledger_is_per_run_and_does_not_persist(self) -> None:
        with handle_run("run-one") as first:
            open_session(workspace=HOME_WORKSPACE)
            assert len(first) == 1
        with handle_run("run-two") as second:
            assert isinstance(second, HandleLedger)
            assert len(second) == 0
