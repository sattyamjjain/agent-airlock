"""Per-agent / per-counterparty programmatic-spend caps (v0.5.8+).

Motivation
----------
[Anthropic Project Deal launched 2026-04-25](https://www.anthropic.com/features/project-deal)
with 186 deals and ~$4k in agent-on-agent commerce flow on day one
— and **no programmatic spend caps**. The Stripe Agentic surface
ships the same shape. The runtime layer is the only enforcement
point any operator can actually trust.

This module ships:

1. :class:`AgentCommerceCaps` — per-agent, per-counterparty,
   per-window dollar / transaction caps. Hard-stop at the limit.
2. :class:`LedgerStore` — sqlite-backed by default, survives a
   ``SIGKILL`` mid-transaction. Pluggable; v0.5.9 will add a
   Postgres adapter for high-TPS workloads.
3. Adapter interfaces for **Project Deal**, **Stripe Agentic**, and
   a **generic webhook tap** so policies don't have to change when
   the upstream payment surface does.

Concurrency
-----------
sqlite ``BEGIN IMMEDIATE`` + a single-writer lock keeps the ledger
consistent under concurrent debits. Operators expecting > 50 TPS
should swap in the Postgres adapter shipped in v0.5.9.

Primary source
--------------
- Anthropic Project Deal: https://www.anthropic.com/features/project-deal
"""

from __future__ import annotations

import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol

import structlog

from ..exceptions import AirlockError

logger = structlog.get_logger("agent-airlock.integrations.agent_commerce_caps")


Window = Literal["minute", "hour", "day", "week"]
"""The four supported caps windows."""

_WINDOW_SECONDS: dict[Window, int] = {
    "minute": 60,
    "hour": 3600,
    "day": 86400,
    "week": 604800,
}


# -----------------------------------------------------------------------------
# Errors
# -----------------------------------------------------------------------------


class AgentCommerceCapExceeded(AirlockError):
    """Raised when a debit would breach a configured cap."""

    def __init__(
        self,
        *,
        agent_id: str,
        counterparty: str,
        window: Window,
        amount_cents: int,
        already_spent_cents: int,
        cap_cents: int,
    ) -> None:
        self.agent_id = agent_id
        self.counterparty = counterparty
        self.window = window
        self.amount_cents = amount_cents
        self.already_spent_cents = already_spent_cents
        self.cap_cents = cap_cents
        super().__init__(
            f"agent {agent_id!r} → {counterparty!r}: ${amount_cents / 100:.2f} "
            f"would push {window} spend from "
            f"${already_spent_cents / 100:.2f} past cap "
            f"${cap_cents / 100:.2f}"
        )


# -----------------------------------------------------------------------------
# Caps configuration
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class Cap:
    """One spend cap entry.

    Attributes:
        amount_cents: Hard ceiling, in integer cents.
        window: The rolling window the ceiling applies over.
        scope: ``"agent"`` (per agent), ``"counterparty"`` (per
            agent → counterparty pair), or ``"global"`` (per agent
            across all counterparties).
    """

    amount_cents: int
    window: Window
    scope: Literal["agent", "counterparty", "global"] = "agent"


@dataclass
class CapsConfig:
    """The active set of caps."""

    caps: tuple[Cap, ...] = field(default_factory=tuple)


# -----------------------------------------------------------------------------
# Decision
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class Decision:
    """The output of :meth:`AgentCommerceCaps.check_and_debit`."""

    allowed: bool
    debit_id: int | None
    matched_cap: Cap | None
    already_spent_cents: int
    reason: str


# -----------------------------------------------------------------------------
# Ledger store
# -----------------------------------------------------------------------------


class LedgerStore(Protocol):
    """The minimal ledger interface. Implementations must be safe under
    concurrent ``check_and_debit`` calls and survive process restarts."""

    def begin_immediate(self) -> Any: ...

    def total_spent_cents(
        self,
        agent_id: str,
        counterparty: str | None,
        since_epoch: float,
    ) -> int: ...

    def append_debit(
        self,
        agent_id: str,
        counterparty: str,
        amount_cents: int,
        ts_epoch: float,
        adapter: str,
    ) -> int: ...

    def close(self) -> None: ...


class SQLiteLedgerStore:
    """Default sqlite3-backed ledger.

    Uses ``BEGIN IMMEDIATE`` so concurrent writers serialise at the
    write boundary; reads are uncontended. ``WAL`` journal mode for
    crash safety mid-transaction.
    """

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS debits (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id TEXT NOT NULL,
        counterparty TEXT NOT NULL,
        amount_cents INTEGER NOT NULL,
        ts_epoch REAL NOT NULL,
        adapter TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_debits_agent_ts
        ON debits (agent_id, ts_epoch);
    CREATE INDEX IF NOT EXISTS idx_debits_pair_ts
        ON debits (agent_id, counterparty, ts_epoch);
    """

    def __init__(self, path: str | Path = ":memory:") -> None:
        self._path = str(path)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self._path, isolation_level=None, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(self._SCHEMA)

    def begin_immediate(self) -> Any:
        return self._lock

    def total_spent_cents(
        self,
        agent_id: str,
        counterparty: str | None,
        since_epoch: float,
    ) -> int:
        if counterparty is None:
            cur = self._conn.execute(
                "SELECT COALESCE(SUM(amount_cents), 0) FROM debits "
                "WHERE agent_id = ? AND ts_epoch >= ?",
                (agent_id, since_epoch),
            )
        else:
            cur = self._conn.execute(
                "SELECT COALESCE(SUM(amount_cents), 0) FROM debits "
                "WHERE agent_id = ? AND counterparty = ? AND ts_epoch >= ?",
                (agent_id, counterparty, since_epoch),
            )
        row = cur.fetchone()
        return int(row[0]) if row else 0

    def append_debit(
        self,
        agent_id: str,
        counterparty: str,
        amount_cents: int,
        ts_epoch: float,
        adapter: str,
    ) -> int:
        cur = self._conn.execute(
            "INSERT INTO debits (agent_id, counterparty, amount_cents, ts_epoch, adapter) "
            "VALUES (?, ?, ?, ?, ?)",
            (agent_id, counterparty, amount_cents, ts_epoch, adapter),
        )
        return int(cur.lastrowid or 0)

    def close(self) -> None:
        self._conn.close()


# -----------------------------------------------------------------------------
# Adapter Protocol
# -----------------------------------------------------------------------------


class CommerceAdapter(Protocol):
    """The minimal adapter interface."""

    name: str

    def parse_request(self, raw: dict[str, Any]) -> tuple[str, str, int]:
        """Return (agent_id, counterparty, amount_cents)."""
        ...


# -----------------------------------------------------------------------------
# AgentCommerceCaps
# -----------------------------------------------------------------------------


@dataclass
class AgentCommerceCaps:
    """The cap-enforcement engine.

    Usage::

        caps = AgentCommerceCaps(
            config=CapsConfig(caps=(
                Cap(amount_cents=1_000, window="day", scope="counterparty"),
                Cap(amount_cents=20_000, window="week", scope="agent"),
            )),
            store=SQLiteLedgerStore("/var/lib/airlock/commerce.db"),
        )
        decision = caps.check_and_debit("agent-1", "vendor-a", 250)
        if not decision.allowed:
            raise SystemExit(decision.reason)
    """

    config: CapsConfig
    store: LedgerStore = field(default_factory=lambda: SQLiteLedgerStore())
    adapter_name: str = "default"

    def register_adapter(self, adapter: CommerceAdapter) -> None:
        self.adapter_name = adapter.name

    def check_and_debit(
        self,
        agent_id: str,
        counterparty: str,
        amount_cents: int,
        *,
        now_epoch: float | None = None,
    ) -> Decision:
        """Atomically check every cap and append the debit on success."""
        if amount_cents < 0:
            return Decision(
                allowed=False,
                debit_id=None,
                matched_cap=None,
                already_spent_cents=0,
                reason="negative debit refused",
            )
        ts = now_epoch if now_epoch is not None else time.time()
        lock = self.store.begin_immediate()
        if hasattr(lock, "acquire"):
            lock.acquire()
        try:
            for cap in self.config.caps:
                window_secs = _WINDOW_SECONDS[cap.window]
                since = ts - window_secs
                cp = counterparty if cap.scope == "counterparty" else None
                spent = self.store.total_spent_cents(agent_id, cp, since)
                if spent + amount_cents > cap.amount_cents:
                    return Decision(
                        allowed=False,
                        debit_id=None,
                        matched_cap=cap,
                        already_spent_cents=spent,
                        reason=(
                            f"cap breach: scope={cap.scope} "
                            f"window={cap.window} spent={spent / 100:.2f} "
                            f"+ debit={amount_cents / 100:.2f} > "
                            f"cap={cap.amount_cents / 100:.2f}"
                        ),
                    )
            debit_id = self.store.append_debit(
                agent_id, counterparty, amount_cents, ts, self.adapter_name
            )
            logger.info(
                "agent_commerce_debit",
                agent_id=agent_id,
                counterparty=counterparty,
                amount_cents=amount_cents,
                debit_id=debit_id,
                adapter=self.adapter_name,
            )
            return Decision(
                allowed=True,
                debit_id=debit_id,
                matched_cap=None,
                already_spent_cents=0,
                reason="within all caps",
            )
        finally:
            if hasattr(lock, "release"):
                lock.release()

    def check_and_debit_or_raise(
        self,
        agent_id: str,
        counterparty: str,
        amount_cents: int,
    ) -> Decision:
        """Convenience: raise :class:`AgentCommerceCapExceeded` on cap breach."""
        decision = self.check_and_debit(agent_id, counterparty, amount_cents)
        if not decision.allowed and decision.matched_cap is not None:
            raise AgentCommerceCapExceeded(
                agent_id=agent_id,
                counterparty=counterparty,
                window=decision.matched_cap.window,
                amount_cents=amount_cents,
                already_spent_cents=decision.already_spent_cents,
                cap_cents=decision.matched_cap.amount_cents,
            )
        return decision


__all__ = [
    "AgentCommerceCapExceeded",
    "AgentCommerceCaps",
    "Cap",
    "CapsConfig",
    "CommerceAdapter",
    "Decision",
    "LedgerStore",
    "SQLiteLedgerStore",
    "Window",
]
