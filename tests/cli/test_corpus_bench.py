"""Tests for the v0.8.2 ``airlock corpus-bench`` CLI.

Honest framing: this CLI runs a deterministic exploit-shape corpus
through the default guard chain and prints a block-rate report. It
does NOT reproduce the Metis paper's POMDP attacker or report
Metis-paper-comparable ASR numbers — see ``regression_corpus.py`` for
the full scope statement.

Usage:

    python -m agent_airlock.cli.corpus_bench \\
        --corpus-path tests/cves/fixtures/metis_inspired_corpus_2026_05_18.json \\
        --report json
"""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from agent_airlock.cli.corpus_bench import main

FIXTURE = (
    Path(__file__).parent.parent / "cves" / "fixtures" / "metis_inspired_corpus_2026_05_18.json"
)


class TestCorpusBenchInvocation:
    """The CLI runs to completion and emits the expected report formats."""

    def test_missing_corpus_path_returns_nonzero(self) -> None:
        # No --corpus-path => argparse should fail with exit code 2.
        with pytest.raises(SystemExit) as exc_info:
            main([])
        assert exc_info.value.code == 2

    def test_nonexistent_corpus_returns_error(self) -> None:
        rc = main(["--corpus-path", "/nonexistent/no.json"])
        assert rc != 0

    def test_json_report_emits_parseable_json(self) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["--corpus-path", str(FIXTURE), "--report", "json"])
        assert rc == 0
        payload = json.loads(buf.getvalue())
        # Required top-level keys.
        for key in (
            "preset_id",
            "block_rate",
            "baseline_block_rate",
            "drift_delta",
            "threshold",
            "allowed",
            "verdict",
            "total_prompts",
            "blocked_count",
            "outcomes",
        ):
            assert key in payload, f"missing key {key} in JSON report"
        # The fixture's locked baseline + chain should pass the gate.
        assert payload["allowed"] is True
        assert payload["total_prompts"] >= 20
        assert isinstance(payload["outcomes"], list)
        # Each outcome has prompt_id / blocked / anchor / expected_block.
        for o in payload["outcomes"]:
            assert "prompt_id" in o
            assert "blocked" in o
            assert "anchor" in o
            assert "expected_block" in o

    def test_markdown_report_emits_table(self) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["--corpus-path", str(FIXTURE), "--report", "md"])
        assert rc == 0
        out = buf.getvalue()
        # Markdown report has a header line + a table row per outcome.
        assert "block_rate" in out
        assert "|" in out  # table separator
        assert "prompt_id" in out

    def test_default_report_is_text(self) -> None:
        """Without --report the CLI defaults to a one-line text summary."""
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["--corpus-path", str(FIXTURE)])
        assert rc == 0
        out = buf.getvalue().strip()
        # One-line summary contains the key numbers and verdict.
        assert "block_rate=" in out
        assert "baseline=" in out
        assert "drift=" in out


class TestCorpusBenchGateExitCodes:
    """The CLI returns a non-zero exit code when the gate trips."""

    def test_gate_pass_returns_zero(self) -> None:
        rc = main(["--corpus-path", str(FIXTURE)])
        assert rc == 0

    def test_baseline_override_can_trip_gate(self, tmp_path: Path) -> None:
        """Raise the baseline so the gate trips deterministically."""
        # Use --baseline 1.0 → drift = -0.32 → far below -0.05 threshold → deny.
        rc = main(
            [
                "--corpus-path",
                str(FIXTURE),
                "--baseline",
                "1.0",
                "--threshold",
                "0.05",
            ]
        )
        # Convention: gate-fail returns exit code 3 (reserved; argparse
        # uses 2, generic error uses 1, app success uses 0).
        assert rc == 3
