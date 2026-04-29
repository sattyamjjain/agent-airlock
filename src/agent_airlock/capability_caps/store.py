"""SQLite-backed capability ledger.

Records every grant + use event so the engine can reconstruct
"how many invocations of capability X has agent Y consumed in the
last window?" deterministically across restarts.

Schema (one table — keeps writes and reads cheap):

    CREATE TABLE capability_events (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id     TEXT    NOT NULL,
        capability   TEXT    NOT NULL,
        target       TEXT    NOT NULL,
        amount       INTEGER NOT NULL,
        kind         TEXT    NOT NULL CHECK (kind IN ('grant','use','revoke')),
        ts_epoch     REAL    NOT NULL
    );
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path
from typing import Any, Protocol

from .enums import Capability


class CapabilityLedgerStore(Protocol):
    """Minimum surface a capability-cap store must expose."""

    def total_used(
        self,
        agent_id: str,
        capability: Capability,
        target: str | None,
        since_epoch: float,
    ) -> int: ...

    def append_event(
        self,
        agent_id: str,
        capability: Capability,
        target: str,
        amount: int,
        kind: str,
        ts_epoch: float,
    ) -> int: ...

    def begin_immediate(self) -> Any: ...

    def close(self) -> None: ...


class SQLiteCapabilityLedgerStore:
    """Default sqlite3 store with WAL journal mode + a process-wide lock."""

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS capability_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id TEXT NOT NULL,
        capability TEXT NOT NULL,
        target TEXT NOT NULL,
        amount INTEGER NOT NULL,
        kind TEXT NOT NULL CHECK (kind IN ('grant','use','revoke')),
        ts_epoch REAL NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_cap_events_agent_cap_ts
        ON capability_events (agent_id, capability, ts_epoch);
    CREATE INDEX IF NOT EXISTS idx_cap_events_target
        ON capability_events (target);
    """

    def __init__(self, path: str | Path = ":memory:") -> None:
        self._path = str(path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(
            self._path, isolation_level=None, check_same_thread=False
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(self._SCHEMA)

    def begin_immediate(self) -> Any:
        return self._lock

    def total_used(
        self,
        agent_id: str,
        capability: Capability,
        target: str | None,
        since_epoch: float,
    ) -> int:
        if target is None:
            cur = self._conn.execute(
                "SELECT COALESCE(SUM(amount), 0) FROM capability_events "
                "WHERE agent_id=? AND capability=? AND kind='use' AND ts_epoch>=?",
                (agent_id, capability.value, since_epoch),
            )
        else:
            cur = self._conn.execute(
                "SELECT COALESCE(SUM(amount), 0) FROM capability_events "
                "WHERE agent_id=? AND capability=? AND target=? "
                "AND kind='use' AND ts_epoch>=?",
                (agent_id, capability.value, target, since_epoch),
            )
        row = cur.fetchone()
        return int(row[0]) if row else 0

    def append_event(
        self,
        agent_id: str,
        capability: Capability,
        target: str,
        amount: int,
        kind: str,
        ts_epoch: float,
    ) -> int:
        if kind not in {"grant", "use", "revoke"}:
            raise ValueError(f"invalid kind: {kind!r}")
        cur = self._conn.execute(
            "INSERT INTO capability_events "
            "(agent_id, capability, target, amount, kind, ts_epoch) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (agent_id, capability.value, target, amount, kind, ts_epoch),
        )
        return int(cur.lastrowid or 0)

    def latest_revocation_ts(
        self, agent_id: str, capability: Capability
    ) -> float | None:
        """Return the most recent revoke event ts for ``(agent, capability)``."""
        cur = self._conn.execute(
            "SELECT ts_epoch FROM capability_events "
            "WHERE agent_id=? AND capability=? AND kind='revoke' "
            "ORDER BY ts_epoch DESC LIMIT 1",
            (agent_id, capability.value),
        )
        row = cur.fetchone()
        return float(row[0]) if row else None

    def close(self) -> None:
        self._conn.close()


__all__ = ["CapabilityLedgerStore", "SQLiteCapabilityLedgerStore"]
