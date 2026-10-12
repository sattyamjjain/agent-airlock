"""Shared pieces of the live API contract tests.

No SDK is imported here at module level: ``anthropic`` and ``claude_agent_sdk`` are
imported inside fixtures and tests, so collecting ``tests/live`` needs neither
(``tests/test_live_suite_0_10_25.py`` enforces it).
"""

from __future__ import annotations

import datetime
import importlib.metadata
import json
import platform
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import agent_airlock
from agent_airlock.integrations.claude_managed_agents import redact_sse_event

LIVE_MODEL = "claude-haiku-5-5"
"""Every live test runs on Claude Haiku 5.5, the cheapest current model. No sampling
parameter is ever sent: Haiku 5.5 rejects a non-default temperature or top_p, and any
top_k."""

RESULTS_DIR = Path(__file__).resolve().parent / ".results"
"""Where each run's record is written (gitignored)."""

#: Removed for the whole live session, so nothing but ``ANTHROPIC_API_KEY`` authenticates
#: a request (no ``ANTHROPIC_AUTH_TOKEN``, no ``ANTHROPIC_BASE_URL`` reroute, no
#: subscription login through ``CLAUDE_CODE_OAUTH_TOKEN``) and no Claude Code session
#: marker reaches a child CLI.
REMOVED_PREFIXES: tuple[str, ...] = ("ANTHROPIC_", "CLAUDE_CODE_")
REMOVED_NAMES: tuple[str, ...] = (
    "CLAUDECODE",
    "CLAUDE_EFFORT",
    "CLAUDE_PID",
    "ENABLE_TOOL_SEARCH",
    "ENABLE_LSP_TOOL",
    "MAX_THINKING_TOKENS",
)
KEPT_NAMES: tuple[str, ...] = ("ANTHROPIC_API_KEY",)


def session_env_to_remove(names: Iterable[str]) -> list[str]:
    """The names among ``names`` the live session removes."""
    return sorted(
        name
        for name in names
        if name not in KEPT_NAMES and (name in REMOVED_NAMES or name.startswith(REMOVED_PREFIXES))
    )


def _version(distribution: str) -> str:
    try:
        return importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        return "not installed"


def versions() -> dict[str, str]:
    """What the run used, for the record."""
    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "agent_airlock": agent_airlock.__version__,
        "anthropic": _version("anthropic"),
        "claude_agent_sdk": _version("claude-agent-sdk"),
    }


def event_keys(event: Any) -> list[str]:
    """The field names of an SDK event or dict, never their values."""
    if isinstance(event, dict):
        return sorted(str(key) for key in event)
    dump = getattr(event, "model_dump", None)
    if callable(dump):
        data = dump(exclude_none=True)
        if isinstance(data, dict):
            return sorted(str(key) for key in data)
    return sorted(key for key in vars(event) if not key.startswith("_"))


class LiveRecorder:
    """Collects what each live test observed and writes it under ``RESULTS_DIR``.

    Every string goes through ``redact_sse_event`` and has the API key replaced, so a
    record never carries a credential.
    """

    def __init__(self, secret: str) -> None:
        self._secret = secret
        self.started_at = datetime.datetime.now(datetime.timezone.utc)
        self.records: list[dict[str, Any]] = []

    def record(self, test: str, **fields: Any) -> None:
        self.records.append(self._scrub({"test": test, **fields}))

    def _scrub(self, value: Any) -> Any:
        if isinstance(value, str):
            text = value.replace(self._secret, "[REDACTED]") if self._secret else value
            return redact_sse_event(text)
        if isinstance(value, dict):
            return {str(key): self._scrub(item) for key, item in value.items()}
        if isinstance(value, list | tuple | set | frozenset):
            return [self._scrub(item) for item in value]
        if value is None or isinstance(value, bool | int | float):
            return value
        return self._scrub(str(value))

    def write(self) -> Path:
        """Append this run to today's (UTC) file and return its path."""
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        path = RESULTS_DIR / f"{self.started_at.date().isoformat()}.json"
        runs: list[Any] = []
        if path.exists():
            try:
                runs = list(json.loads(path.read_text(encoding="utf-8")).get("runs", []))
            except (ValueError, AttributeError, TypeError):
                runs = []
        runs.append(
            {
                "started_at": self.started_at.isoformat(),
                "finished_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "live_model": LIVE_MODEL,
                "versions": versions(),
                "records": self.records,
            }
        )
        path.write_text(json.dumps({"runs": runs}, indent=2) + "\n", encoding="utf-8")
        return path
