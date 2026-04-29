"""LangChain 0.4.0 ``tool_call_id`` fixture migration helper (Issue #1, v0.6.0+).

LangChain 0.4.0 (2026-04-26) made ``tool_call_id`` mandatory on every
``ToolMessage``. Historical fixtures stored as JSON (or constructed
inline in tests) that omit the field will fail under 0.4.0. This
helper rewrites a fixture in place: any ``role == "tool"`` message
without a ``tool_call_id`` gets a deterministic synthesised id of the
form ``synth-tcid-<index>``.

The migration is idempotent and pure — it does not import LangChain
itself, so it stays fast and dependency-free.

Reference
---------
* LangChain 0.4.0 release notes (2026-04-26):
  https://github.com/langchain-ai/langchain/releases/tag/v0.4.0
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

DEFAULT_PREFIX = "synth-tcid"


def migrate_messages(
    messages: list[dict[str, Any]],
    *,
    prefix: str = DEFAULT_PREFIX,
) -> list[dict[str, Any]]:
    """Return ``messages`` with ``tool_call_id`` filled in on tool turns.

    A ``ToolMessage`` is identified by ``role == "tool"`` (LangChain
    surface) or ``type == "tool"`` (langchain_core surface). Either
    shape is tolerated.
    """
    out: list[dict[str, Any]] = []
    counter = 0
    for msg in messages:
        if not isinstance(msg, dict):
            out.append(msg)
            continue
        role = msg.get("role") or msg.get("type")
        if role == "tool" and not msg.get("tool_call_id"):
            new = dict(msg)
            new["tool_call_id"] = f"{prefix}-{counter:04d}"
            out.append(new)
            counter += 1
        else:
            out.append(msg)
    return out


def migrate_fixture_file(path: Path, *, prefix: str = DEFAULT_PREFIX) -> int:
    """Migrate a JSON fixture file in place; return the count rewritten.

    Supports two on-disk shapes:
    - top-level list of messages
    - top-level dict with a ``"messages"`` key
    """
    raw = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, list):
        migrated = migrate_messages(raw, prefix=prefix)
        rewrites = sum(1 for a, b in zip(raw, migrated, strict=True) if a != b)
        if rewrites:
            path.write_text(
                json.dumps(migrated, indent=2, sort_keys=True),
                encoding="utf-8",
            )
        return rewrites
    if isinstance(raw, dict) and isinstance(raw.get("messages"), list):
        migrated = migrate_messages(raw["messages"], prefix=prefix)
        rewrites = sum(1 for a, b in zip(raw["messages"], migrated, strict=True) if a != b)
        if rewrites:
            new = dict(raw)
            new["messages"] = migrated
            path.write_text(
                json.dumps(new, indent=2, sort_keys=True),
                encoding="utf-8",
            )
        return rewrites
    return 0


__all__ = [
    "DEFAULT_PREFIX",
    "migrate_fixture_file",
    "migrate_messages",
]
