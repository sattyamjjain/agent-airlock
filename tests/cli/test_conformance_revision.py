"""``airlock conformance --revision <rev>`` — MCP transport-contract conformance CLI.

Added alongside the shipped ``agent_airlock.mcp_spec.conformance`` runner so the wheel
carries a first-class way to report airlock's conformance for a revision (the Art. 12
record/verify/export subcommands are unchanged).
"""

from __future__ import annotations

import pytest

from agent_airlock.cli.conformance import main


class TestConformanceRevision:
    def test_current_revision_exits_zero_and_prints_tally(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rc = main(["--revision", "2026-07-28"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "22/22 normative cases pass" in out
        assert "revision 2026-07-28" in out

    def test_legacy_revision_supported(self, capsys: pytest.CaptureFixture[str]) -> None:
        rc = main(["--revision", "2025-11-25"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "revision 2025-11-25" in out

    def test_unknown_revision_is_a_usage_error(self) -> None:
        # argparse choices -> SystemExit(2), not a crash.
        with pytest.raises(SystemExit) as exc:
            main(["--revision", "1999-01-01"])
        assert exc.value.code == 2

    def test_no_subcommand_and_no_revision_errors(self) -> None:
        with pytest.raises(SystemExit) as exc:
            main([])
        assert exc.value.code == 2

    def test_record_subcommand_still_available(self) -> None:
        # The Art. 12 decision-log path is unchanged: missing --log is a usage error.
        with pytest.raises(SystemExit) as exc:
            main(["verify"])
        assert exc.value.code == 2
