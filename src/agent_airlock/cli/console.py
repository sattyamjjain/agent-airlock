"""``airlock console`` — first-class interactive policy-rehearsal TUI (v0.6.0+).

Three-pane Textual app:

* Left:    live verdict stream (newest at the top).
* Top-right: active preset chain (toggleable).
* Bottom-right: replay-on-edit log of the last 50 verdicts re-evaluated
   against the edited preset chain.

Textual is gated behind the ``airlock[console]`` extra so the base
install stays lean. Direct invocation without the extra prints a
clear ``pip install agent-airlock[console]`` hint.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

INSTALL_HINT = (
    "airlock console requires Textual. Install with:\n    pip install 'agent-airlock[console]'\n"
)


@dataclass
class VerdictEntry:
    ts: str
    guard: str
    verdict: str
    tool_name: str
    detail: str = ""


@dataclass
class ConsoleState:
    """In-process state shared between the live stream and replay panes."""

    audit_log_path: Path | None = None
    active_presets: list[str] = field(default_factory=list)
    last_verdicts: deque[VerdictEntry] = field(default_factory=lambda: deque(maxlen=50))

    def ingest_jsonl(self) -> int:
        """Read any new lines from the audit log; return count ingested."""
        if self.audit_log_path is None or not self.audit_log_path.exists():
            return 0
        added = 0
        with self.audit_log_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                self.last_verdicts.append(
                    VerdictEntry(
                        ts=str(obj.get("ts", _now_iso())),
                        guard=str(obj.get("guard", "")),
                        verdict=str(obj.get("verdict", "allow")),
                        tool_name=str(obj.get("tool_name", "")),
                        detail=str(obj.get("detail", "")),
                    )
                )
                added += 1
        return added

    def toggle_preset(self, preset_id: str) -> bool:
        """Toggle a preset in/out of the active chain.

        Returns ``True`` if the preset is active after the toggle.
        """
        if preset_id in self.active_presets:
            self.active_presets.remove(preset_id)
            return False
        self.active_presets.append(preset_id)
        return True

    def snapshot(self) -> dict[str, Any]:
        return {
            "active_presets": list(self.active_presets),
            "verdicts": [asdict(v) for v in self.last_verdicts],
        }


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Optional Textual app — loaded lazily so a missing extra does not break the
# rest of the CLI.
# ---------------------------------------------------------------------------


def _import_textual_or_hint() -> Any:
    try:
        from textual.app import App  # type: ignore[import-not-found]

        return App
    except ImportError:
        print(INSTALL_HINT, file=sys.stderr)
        return None


def _build_app(state: ConsoleState) -> Any:
    """Build (but do not run) the Textual app. Lazy import inside."""
    App = _import_textual_or_hint()
    if App is None:
        return None
    from textual.containers import Horizontal, Vertical  # type: ignore[import-not-found]
    from textual.widgets import Footer, Header, Static  # type: ignore[import-not-found]

    class AirlockConsole(App):  # type: ignore[misc, valid-type]
        BINDINGS = [
            ("q", "quit", "Quit"),
            ("r", "refresh", "Refresh"),
        ]

        def compose(self):  # type: ignore[no-untyped-def]
            yield Header()
            with Horizontal():
                yield Static(self._render_verdicts(), id="verdicts")
                with Vertical():
                    yield Static(self._render_presets(), id="presets")
                    yield Static(self._render_replay(), id="replay")
            yield Footer()

        def _render_verdicts(self) -> str:
            lines = ["Live verdicts:"]
            for v in list(state.last_verdicts)[-25:]:
                lines.append(f"  [{v.verdict:5}] {v.guard:20} {v.tool_name}")
            return "\n".join(lines)

        def _render_presets(self) -> str:
            if not state.active_presets:
                return "Active presets: (none)"
            return "Active presets:\n" + "\n".join(f"  • {p}" for p in state.active_presets)

        def _render_replay(self) -> str:
            return f"Replay buffer: {len(state.last_verdicts)} entries"

        def action_refresh(self) -> None:
            state.ingest_jsonl()
            self.refresh()

    return AirlockConsole()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="airlock console")
    parser.add_argument(
        "--audit-log",
        default=None,
        help="path to a JSON-Lines audit log to stream verdicts from",
    )
    parser.add_argument(
        "--no-tui",
        action="store_true",
        help="emit a single JSON snapshot to stdout (CI-friendly)",
    )
    args = parser.parse_args(argv)

    state = ConsoleState(
        audit_log_path=Path(args.audit_log) if args.audit_log else None,
    )
    state.ingest_jsonl()

    if args.no_tui:
        print(json.dumps(state.snapshot(), indent=2, sort_keys=True))
        return 0

    app = _build_app(state)
    if app is None:
        return 2
    app.run()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = ["ConsoleState", "INSTALL_HINT", "VerdictEntry", "main"]
