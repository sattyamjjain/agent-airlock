"""Approvals bound to the call they approve (V0.10.29).

Until 0.10.29 an escalation's :class:`~agent_airlock.oversight.OversightRequest` carried
only the escalation's reason and rule, so an approver could not see what it approved,
and ``AirlockContext.authorize_once`` was a set of tool names: a grant admitted the next
call of that tool with any arguments, and was checked and then discarded without a lock.
This module holds what binds an approval to one call:

* :func:`args_digest`, the sha256 of a call's bound arguments in canonical JSON, which an
  :class:`~agent_airlock.oversight.OversightRequest` carries and a grant can name;
* :class:`GrantStore`, the one-shot ``authorize_once`` grants, each optionally bound to a
  digest and a time to live, consumed under a lock and shared by a context's clones;
* :class:`ApprovalLedger`, with :class:`InMemoryApprovalLedger` and
  :class:`SQLiteApprovalLedger`: approvals recorded ahead of a call and claimed by exactly
  one call, across processes in the SQLite case;
* :class:`StandingGrant`, an operator's standing approval of one tool called with exact
  target argument values.

Raised in agno-agi/agno#10600 (an approved call ran with other arguments), crewAIInc/crewAI
#6859 and google/adk-python#7148 (an in-memory claim let two replicas both run a call).
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import decimal
import enum
import hashlib
import json
import math
import sqlite3
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from pathlib import Path, PurePath
from typing import Any, Protocol, runtime_checkable

from pydantic import BaseModel

from ._log import structlog

logger = structlog.get_logger("agent-airlock.approvals")

__all__ = [
    "ApprovalLedger",
    "GrantStore",
    "InMemoryApprovalLedger",
    "SQLiteApprovalLedger",
    "StandingGrant",
    "args_digest",
    "consume_grant",
]

#: How deep :func:`args_digest` reads, the depth the argument gates read to.
_MAX_DEPTH = 32


def args_digest(arguments: Mapping[str, Any]) -> str:
    """The sha256 hex digest of a call's bound arguments, as canonical JSON.

    Keys are sorted, a non-finite float is spelled out rather than written as NaN, and a
    value JSON cannot encode is tagged by kind: bytes as hex, a set sorted, a pydantic model
    or dataclass by its class and fields (so two models with different field values never
    share a digest), and anything else as ``{"__unserializable__": type(value).__name__}``.
    Only host code passes such an object (model JSON cannot build one), which is why its
    type stands in for it. A mapping with a key shaped like a tag (``__bytes__``) is
    written as key-value pairs, so a plain dict cannot spell the value a tag stands for.

    Args:
        arguments: The call's arguments by parameter name.

    Returns:
        64 lowercase hex characters.

    Raises:
        ValueError: The arguments nest deeper than 32 levels or contain themselves, so
            they cannot be read to bind an approval to.
    """
    return hashlib.sha256(_canonical_json(dict(arguments)).encode("utf-8")).hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(
        _canonical(value, 0, frozenset()),
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        ensure_ascii=True,
    )


def _canonical(value: Any, depth: int, seen: frozenset[int]) -> Any:
    """``value`` as plain JSON data, tagged where JSON would merge two values."""
    if depth > _MAX_DEPTH:
        raise ValueError(f"the arguments nest deeper than {_MAX_DEPTH} levels")
    if isinstance(value, enum.Enum):
        return {"__enum__": _qualname(value), "value": _canonical(value.value, depth + 1, seen)}
    if value is None or isinstance(value, bool | int | str):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else {"__float__": repr(value)}
    if isinstance(value, bytes | bytearray | memoryview):
        return {"__bytes__": bytes(value).hex()}
    scalar = _canonical_scalar(value)
    if scalar is not None:
        return scalar
    if id(value) in seen:
        raise ValueError("the arguments contain themselves")
    return _canonical_container(value, depth + 1, seen | {id(value)})


def _canonical_scalar(value: Any) -> dict[str, str] | None:
    """A tagged string for the standard library's value types; None for anything else."""
    if isinstance(value, _dt.datetime | _dt.date | _dt.time):
        return {"__datetime__": value.isoformat()}
    if isinstance(value, decimal.Decimal):
        return {"__decimal__": str(value)}
    if isinstance(value, uuid.UUID):
        return {"__uuid__": str(value)}
    if isinstance(value, PurePath):
        return {"__path__": str(value)}
    if isinstance(value, complex):
        return {"__complex__": repr(value)}
    return None


def _canonical_container(value: Any, depth: int, seen: frozenset[int]) -> Any:
    if isinstance(value, Mapping):
        items = [(key, _canonical(item, depth, seen)) for key, item in value.items()]
        if all(type(key) is str and not _is_tag(key) for key, _ in items):
            return dict(items)
        pairs = [[_canonical(key, depth, seen), item] for key, item in items]
        return {"__map__": sorted(pairs, key=lambda pair: _dumps(pair[0]))}
    if isinstance(value, list | tuple):
        return [_canonical(item, depth, seen) for item in value]
    if isinstance(value, set | frozenset):
        return {"__set__": sorted((_canonical(item, depth, seen) for item in value), key=_dumps)}
    if isinstance(value, BaseModel):
        fields = {name: _canonical(item, depth, seen) for name, item in BaseModel.__iter__(value)}
        return {"__model__": _qualname(value), "fields": fields}
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        fields = {
            spec.name: _canonical(getattr(value, spec.name), depth, seen)
            for spec in dataclasses.fields(value)
        }
        return {"__dataclass__": _qualname(value), "fields": fields}
    return {"__unserializable__": type(value).__name__}


def _is_tag(key: str) -> bool:
    """A key shaped like one of this encoder's tags. Until 0.10.29's review a dict such as
    ``{"__bytes__": "6869"}``, which model JSON can build, was written exactly as ``b"hi"``,
    so the two shared a digest and one's approval or standing grant admitted the other."""
    return key.startswith("__") and key.endswith("__")


def _dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _qualname(value: Any) -> str:
    kind = type(value)
    return f"{kind.__module__}.{kind.__qualname__}"


# --------------------------------------------------------------------------- #
# One-shot grants (AirlockContext.authorize_once)
# --------------------------------------------------------------------------- #


@dataclasses.dataclass(frozen=True)
class _Grant:
    tool_name: str
    args_digest: str | None
    expires_at: float | None

    def live(self, now: float) -> bool:
        return self.expires_at is None or now < self.expires_at


class GrantStore:
    """The ``authorize_once`` grants of one run, consumed under a lock.

    A grant admits one call of its tool: any call when it names no digest, else only a
    call whose arguments hash to it, and none once its time to live has passed (expired at
    ``now >= expires_at``). A context's clones share one store
    (``AirlockContext.with_metadata``), so a grant spent through a clone is spent.

    Args:
        clock: Seconds on a monotonic clock; injectable for tests.
    """

    def __init__(self, clock: Callable[[], float] | None = None) -> None:
        self._lock = threading.Lock()
        self._grants: list[_Grant] = []
        self._clock = clock or time.monotonic

    def add(
        self, tool_name: str, *, args_digest: str | None = None, ttl_seconds: float | None = None
    ) -> None:
        """Grant one call of ``tool_name``.

        Raises:
            ValueError: ``ttl_seconds`` is not a positive number.
        """
        if ttl_seconds is not None and not (math.isfinite(ttl_seconds) and ttl_seconds > 0):
            raise ValueError(f"ttl_seconds must be a positive number; got {ttl_seconds!r}")
        expires_at = None if ttl_seconds is None else self._clock() + ttl_seconds
        with self._lock:
            self._grants.append(_Grant(tool_name, args_digest, expires_at))

    def consume(self, tool_name: str, args_digest: str | None = None) -> bool:
        """Spend one live grant for this call, one bound to its digest first.

        Args:
            tool_name: The tool being called.
            args_digest: The call's :func:`args_digest`, or None when it could not be read
                (then only a grant that names no digest admits it).

        Returns:
            Whether a grant was spent.
        """
        with self._lock:
            now = self._clock()
            self._grants = [grant for grant in self._grants if grant.live(now)]
            mine = [grant for grant in self._grants if grant.tool_name == tool_name]
            bound = [g for g in mine if args_digest is not None and g.args_digest == args_digest]
            candidates = bound or [g for g in mine if g.args_digest is None]
            if not candidates:
                return False
            self._grants.remove(candidates[0])
            return True

    def __contains__(self, tool_name: object) -> bool:
        """Whether a live grant names ``tool_name``, the test the 0.10.28 set answered."""
        with self._lock:
            now = self._clock()
            return any(g.tool_name == tool_name and g.live(now) for g in self._grants)

    def __len__(self) -> int:
        with self._lock:
            now = self._clock()
            return sum(1 for grant in self._grants if grant.live(now))


def consume_grant(context: Any, tool_name: str, args_digest: str | None = None) -> bool:
    """Spend one ``authorize_once`` grant of ``context`` for this call.

    ``context`` is duck-typed, as the guards that call this read it: a context still
    holding the 0.10.28 ``set`` of tool names spends that name.
    """
    store = getattr(context, "_authorized_once", None)
    if isinstance(store, GrantStore):
        return store.consume(tool_name, args_digest)
    if isinstance(store, set) and tool_name in store:
        store.discard(tool_name)
        return True
    return False


# --------------------------------------------------------------------------- #
# Approval ledger: approvals recorded ahead of a call, claimed by one call
# --------------------------------------------------------------------------- #


@runtime_checkable
class ApprovalLedger(Protocol):
    """Approvals of exact calls, each claimed by at most one call.

    ``grant`` records one approval of ``tool_name`` called with arguments that hash to
    ``args_digest``, until ``expires_at`` (seconds since the epoch). ``claim`` spends one
    unexpired, unclaimed approval atomically and records ``call_id`` against it; two
    claimers of one approval, in any processes sharing the ledger, see exactly one True.
    An approval is expired at ``now >= expires_at``.
    """

    def grant(self, tool_name: str, args_digest: str, *, expires_at: float) -> None: ...

    def claim(self, tool_name: str, args_digest: str, call_id: str) -> bool: ...


@dataclasses.dataclass
class _LedgerEntry:
    tool_name: str
    args_digest: str
    expires_at: float
    claimed_by: str | None = None


class InMemoryApprovalLedger:
    """An :class:`ApprovalLedger` held in this process: one replica's approvals only.

    Args:
        clock: Seconds since the epoch; injectable for tests.
    """

    def __init__(self, clock: Callable[[], float] | None = None) -> None:
        self._lock = threading.Lock()
        self._entries: list[_LedgerEntry] = []
        self._clock = clock or time.time

    def grant(self, tool_name: str, args_digest: str, *, expires_at: float) -> None:
        with self._lock:
            self._entries.append(_LedgerEntry(tool_name, args_digest, float(expires_at)))

    def claim(self, tool_name: str, args_digest: str, call_id: str) -> bool:
        with self._lock:
            now = self._clock()
            for entry in self._entries:
                if (
                    entry.claimed_by is None
                    and entry.tool_name == tool_name
                    and entry.args_digest == args_digest
                    and now < entry.expires_at
                ):
                    entry.claimed_by = call_id
                    return True
            return False


class SQLiteApprovalLedger:
    """An :class:`ApprovalLedger` in a SQLite file, so replicas sharing it share approvals.

    A claim runs in a ``BEGIN IMMEDIATE`` transaction, which takes the database's write
    lock before it reads, so two processes claiming one approval serialise and the second
    finds it claimed (the pattern ``agent_commerce_caps.SQLiteLedgerStore`` uses).

    Args:
        path: The database file, created when missing.
        clock: Seconds since the epoch; injectable for tests.
        busy_timeout: Seconds a claim waits for another process's transaction.
    """

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS approvals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tool_name TEXT NOT NULL,
        args_digest TEXT NOT NULL,
        expires_at REAL NOT NULL,
        claimed_by TEXT,
        claimed_at REAL
    );
    CREATE INDEX IF NOT EXISTS idx_approvals_call ON approvals (tool_name, args_digest);
    """

    def __init__(
        self,
        path: str | Path,
        *,
        clock: Callable[[], float] | None = None,
        busy_timeout: float = 5.0,
    ) -> None:
        self._lock = threading.Lock()
        self._clock = clock or time.time
        self._conn = sqlite3.connect(
            str(path), timeout=busy_timeout, isolation_level=None, check_same_thread=False
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(self._SCHEMA)

    def grant(self, tool_name: str, args_digest: str, *, expires_at: float) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO approvals (tool_name, args_digest, expires_at) VALUES (?, ?, ?)",
                (tool_name, args_digest, float(expires_at)),
            )

    def claim(self, tool_name: str, args_digest: str, call_id: str) -> bool:
        with self._lock:
            now = self._clock()
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT id FROM approvals WHERE tool_name = ? AND args_digest = ? "
                    "AND claimed_by IS NULL AND expires_at > ? ORDER BY id LIMIT 1",
                    (tool_name, args_digest, now),
                ).fetchone()
                if row is not None:
                    self._conn.execute(
                        "UPDATE approvals SET claimed_by = ?, claimed_at = ? WHERE id = ?",
                        (call_id, now, row[0]),
                    )
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            return row is not None

    def close(self) -> None:
        with self._lock:
            self._conn.close()


# --------------------------------------------------------------------------- #
# Standing grants: operator-made, exact tool and target arguments, revocable
# --------------------------------------------------------------------------- #

_GLOB_CHARACTERS = frozenset("*?[")


@dataclasses.dataclass(frozen=True)
class StandingGrant:
    """An operator's standing approval of one tool called with exact target arguments.

    An escalated call of ``tool`` whose arguments include every name in ``arguments``
    with an equal value (compared as :func:`args_digest` encodes them, so ``1`` is not
    ``True`` or ``1.0``) runs without asking the approver, and its audit record names the
    grant. Only host code makes one, on ``SecurityPolicy.standing_grants``: an approver's
    ``GRANT`` or an ``authorize_once`` never turns into one. Revoke it with
    ``SecurityPolicy.revoke_standing_grant(grant_id)``.

    Args:
        tool: The exact tool name; a glob pattern is refused.
        arguments: The target argument values, at least one. Read once, here: changing the
            mapping afterwards changes nothing the grant admits.
        grant_id: How the audit record and a revocation name it; by default ``sg-`` and
            the first 12 hex characters of the digest of ``tool`` and ``arguments``.

    Raises:
        ValueError: ``tool`` is empty or a pattern, ``arguments`` is empty, or a value in it
            cannot be read.
    """

    tool: str
    arguments: Mapping[str, Any]
    grant_id: str = ""
    _target: tuple[tuple[str, str], ...] = dataclasses.field(
        init=False, repr=False, compare=False, default=()
    )

    def __post_init__(self) -> None:
        if not self.tool or _GLOB_CHARACTERS & set(self.tool):
            raise ValueError(f"a standing grant names one exact tool; got {self.tool!r}")
        if not self.arguments:
            raise ValueError(
                "a standing grant names at least one target argument; to stop asking for "
                "a tool, take it out of escalate_tools"
            )
        target = tuple(
            sorted((str(name), _canonical_json(value)) for name, value in self.arguments.items())
        )
        object.__setattr__(self, "_target", target)
        if not self.grant_id:
            digest = hashlib.sha256(_dumps([self.tool, target]).encode("utf-8")).hexdigest()
            object.__setattr__(self, "grant_id", f"sg-{digest[:12]}")

    def __deepcopy__(self, memo: dict[int, Any]) -> StandingGrant:
        """Immutable in what it admits, so a frozen policy shares it."""
        return self

    def canonical(self) -> list[Any]:
        """What the grant admits, for the policy digest."""
        return [self.grant_id, self.tool, [list(pair) for pair in self._target]]

    def matches(self, tool_name: str, arguments: Mapping[str, Any]) -> bool:
        """Whether a call of ``tool_name`` with ``arguments`` is one this grant admits."""
        if tool_name != self.tool:
            return False
        for name, expected in self._target:
            if name not in arguments:
                return False
            try:
                if _canonical_json(arguments[name]) != expected:
                    return False
            except ValueError:
                return False
        return True
