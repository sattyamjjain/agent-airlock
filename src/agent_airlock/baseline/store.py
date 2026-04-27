"""SQLite-backed event store for per-agent baselines (v0.5.8+)."""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class Event:
    """One observed tool call."""

    agent_id: str
    ts_epoch: float
    tool_name: str
    egress_host: str
    tokens: int
    latency_ms: float


class BaselineStore(Protocol):
    def append_event(self, event: Event) -> None: ...

    def events_since(self, agent_id: str, since_epoch: float) -> list[Event]: ...

    def close(self) -> None: ...


class SQLiteBaselineStore:
    """Default sqlite3-backed store. WAL journal + thread lock."""

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id TEXT NOT NULL,
        ts_epoch REAL NOT NULL,
        tool_name TEXT NOT NULL,
        egress_host TEXT,
        tokens INTEGER,
        latency_ms REAL
    );
    CREATE INDEX IF NOT EXISTS idx_events_agent_ts ON events (agent_id, ts_epoch);
    """

    def __init__(self, path: str | Path = ":memory:") -> None:
        self._path = str(path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self._path, isolation_level=None, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(self._SCHEMA)

    def append_event(self, event: Event) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO events "
                "(agent_id, ts_epoch, tool_name, egress_host, tokens, latency_ms) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    event.agent_id,
                    event.ts_epoch,
                    event.tool_name,
                    event.egress_host,
                    event.tokens,
                    event.latency_ms,
                ),
            )

    def events_since(self, agent_id: str, since_epoch: float) -> list[Event]:
        cur = self._conn.execute(
            "SELECT agent_id, ts_epoch, tool_name, egress_host, tokens, latency_ms "
            "FROM events WHERE agent_id = ? AND ts_epoch >= ? ORDER BY ts_epoch",
            (agent_id, since_epoch),
        )
        out: list[Event] = []
        for row in cur.fetchall():
            out.append(
                Event(
                    agent_id=row[0],
                    ts_epoch=row[1],
                    tool_name=row[2],
                    egress_host=row[3] or "",
                    tokens=row[4] or 0,
                    latency_ms=row[5] or 0.0,
                )
            )
        return out

    def close(self) -> None:
        self._conn.close()


__all__ = ["BaselineStore", "Event", "SQLiteBaselineStore"]
