"""Tests for ``airlock console`` (Task 4 — interactive TUI)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from agent_airlock.cli.console import (
    INSTALL_HINT,
    ConsoleState,
    VerdictEntry,
    main,
)


class TestConsoleState:
    def test_toggle_preset(self) -> None:
        state = ConsoleState()
        assert state.toggle_preset("p1") is True
        assert "p1" in state.active_presets
        assert state.toggle_preset("p1") is False
        assert "p1" not in state.active_presets

    def test_ingest_jsonl(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        records = [
            {
                "ts": "2026-04-29T00:00:00Z",
                "guard": "stdio_meta_guard",
                "verdict": "block",
                "tool_name": "exec",
            },
            {
                "ts": "2026-04-29T00:00:01Z",
                "guard": "elicitation_guard",
                "verdict": "allow",
                "tool_name": "fetch",
            },
        ]
        path.write_text("\n".join(json.dumps(r) for r in records), encoding="utf-8")
        state = ConsoleState(audit_log_path=path)
        n = state.ingest_jsonl()
        assert n == 2
        assert len(state.last_verdicts) == 2
        assert state.last_verdicts[0].guard == "stdio_meta_guard"

    def test_replay_buffer_capped_at_50(self) -> None:
        state = ConsoleState()
        for i in range(75):
            state.last_verdicts.append(
                VerdictEntry(
                    ts="x",
                    guard="g",
                    verdict="allow",
                    tool_name=f"tool-{i}",
                )
            )
        assert len(state.last_verdicts) == 50

    def test_snapshot_shape(self) -> None:
        state = ConsoleState(active_presets=["p1", "p2"])
        snap = state.snapshot()
        assert snap["active_presets"] == ["p1", "p2"]
        assert snap["verdicts"] == []


class TestNoTUIMode:
    """``--no-tui`` emits a single JSON snapshot — used by CI smoke."""

    def test_no_tui_emits_json(self, tmp_path: Path, capsys) -> None:
        path = tmp_path / "audit.jsonl"
        path.write_text(
            json.dumps(
                {
                    "ts": "2026-04-29T00:00:00Z",
                    "guard": "stdio_meta_guard",
                    "verdict": "block",
                    "tool_name": "exec",
                }
            ),
            encoding="utf-8",
        )
        rc = main(["--no-tui", "--audit-log", str(path)])
        assert rc == 0
        captured = capsys.readouterr()
        snap = json.loads(captured.out)
        assert snap["active_presets"] == []
        assert snap["verdicts"][0]["guard"] == "stdio_meta_guard"


class TestSubprocessSmoke:
    def test_no_tui_smoke(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        path.write_text(
            json.dumps({"ts": "x", "guard": "g", "verdict": "allow", "tool_name": "t"}),
            encoding="utf-8",
        )
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "agent_airlock.cli.console",
                "--no-tui",
                "--audit-log",
                str(path),
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        snap = json.loads(result.stdout)
        assert snap["verdicts"][0]["tool_name"] == "t"


class TestInstallHint:
    """When Textual is missing, the install hint is emitted on the TUI path."""

    def test_install_hint_string(self) -> None:
        # The hint is a constant; we don't actually run the Textual path
        # in CI (no `textual` install). Asserting the constant is the
        # documented contract that the CLI surfaces it on import failure.
        assert "agent-airlock[console]" in INSTALL_HINT

    def test_tui_returns_2_without_textual(self) -> None:
        try:
            import textual  # noqa: F401
        except ImportError:
            pass
        else:  # pragma: no cover
            import pytest as _pytest

            _pytest.skip("textual is installed in this environment")
        rc = main([])
        assert rc == 2
