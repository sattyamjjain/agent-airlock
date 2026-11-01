"""Run each side-effecting tool call at most once (V0.10.29).

A tool call whose response is lost after the tool took effect looks, to the caller, like a
call that failed: it times out, and the retry runs the tool again. Nothing on the
``@Airlock`` call path told the two apart. Raised in modelcontextprotocol/
modelcontextprotocol#3394 (arjun2075's reproduction: one logical ``tools/call``, two
external effects), BerriAI/litellm#43153, langchain-ai/langgraph#9185 and
langchain-ai/langchain#40688 (10 of 10 retries wrote twice; 0 of 10 with the call id as
the key).

``SecurityPolicy(effect_guard=EffectGuard())`` keys each call on the ``tool_call_id``
the host or adapter puts on the call's context metadata, never on an argument:

* before the tool runs, the call is recorded ``pending``; when it returns, ``committed``
  with the value it returned; when it raises an error that leaves the effect in doubt
  (a timeout or a connection reset after the request went out), ``unknown``;
* a call whose ``tool_call_id`` is ``committed`` returns the stored value without running,
  after every gate has run again (the first attempt's approval is never reused);
* one whose ``tool_call_id`` is ``pending`` or ``unknown`` is refused with
  ``effect_status_unknown`` unless the tool is tagged ``@reversibility("reversible")``,
  which may run again.

Each call also gets an ``idempotency_key``, the sha256 of the tool's name and its
canonical arguments, which the tool reads from ``get_current_context().idempotency_key``
to send to its backend: it is the same for the same business input whatever the
``tool_call_id``.
"""

from __future__ import annotations

import enum
import hashlib
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, TypeVar, runtime_checkable

from ._log import structlog
from .approvals import args_digest
from .exceptions import AirlockError

logger = structlog.get_logger("agent-airlock.effect_guard")

__all__ = [
    "EffectGuard",
    "EffectOutcomeUnknown",
    "EffectRecord",
    "EffectStatus",
    "EffectStore",
    "EffectTicket",
    "InMemoryEffectStore",
    "Reversibility",
    "get_reversibility",
    "idempotency_key",
    "reversibility",
]

F = TypeVar("F", bound=Callable[..., Any])

Reversibility = Literal["reversible", "costly", "irreversible"]

#: Strictness, so the strictest tag on a tool's decorator chain wins.
_RANK: dict[str, int] = {"reversible": 0, "costly": 1, "irreversible": 2}
_ATTRIBUTE = "__airlock_reversibility__"


def reversibility(kind: Reversibility) -> Callable[[F], F]:
    """Declare how a tool's effect can be undone: static metadata, not inferred intent.

    ``"reversible"`` (re-running is harmless or undoable), ``"costly"`` (undoable at a
    price, such as a refund) or ``"irreversible"``. Read through the ``__wrapped__``
    chain like ``@requires``, above or below ``@Airlock``; the strictest tag found wins,
    and an untagged tool is irreversible to the effect guard. It is separate from the
    capability a tool needs: a refusal from either stands.

    Raises:
        ValueError: ``kind`` is not one of the three.
    """
    if kind not in _RANK:
        raise ValueError(f"reversibility must be one of {sorted(_RANK)}; got {kind!r}")

    def decorator(func: F) -> F:
        setattr(func, _ATTRIBUTE, kind)
        return func

    return decorator


def get_reversibility(func: Callable[..., Any]) -> Reversibility:
    """The strictest reversibility on ``func`` and its ``__wrapped__`` chain.

    Returns:
        ``"irreversible"`` when nothing on the chain is tagged.
    """
    found: list[Reversibility] = []
    seen: set[int] = set()
    current: Any = func
    for _ in range(33):
        tag = getattr(current, _ATTRIBUTE, None)
        if tag in _RANK:
            found.append(tag)
        inner = getattr(current, "__wrapped__", None)
        if inner is None or id(inner) in seen:
            break
        seen.add(id(inner))
        current = inner
    return max(found, key=_RANK.__getitem__) if found else "irreversible"


def idempotency_key(tool_name: str, arguments: Mapping[str, Any]) -> str:
    """The sha256 of ``tool_name`` and the canonical arguments: one per business input.

    Raises:
        ValueError: The arguments nest deeper than 32 levels or contain themselves.
    """
    material = f"{tool_name}\n{args_digest(arguments)}".encode()
    return hashlib.sha256(material).hexdigest()


class EffectOutcomeUnknown(AirlockError):
    """Raise from a tool whose effect may or may not have happened.

    The effect guard records the call ``unknown``, as it does for a timeout or a
    connection reset after the request went out, so a replay of an irreversible call is
    refused instead of run.
    """


class EffectStatus(str, enum.Enum):
    """Where a call's effect stands in the store."""

    PENDING = "pending"
    COMMITTED = "committed"
    UNKNOWN = "unknown"


@dataclass
class EffectRecord:
    """One ``tool_call_id``'s entry in an :class:`EffectStore`."""

    tool_call_id: str
    tool_name: str
    idempotency_key: str
    status: EffectStatus = EffectStatus.PENDING
    result: Any = None
    updated_at: float = field(default_factory=time.time)


@runtime_checkable
class EffectStore(Protocol):
    """Where the effect guard keeps each call's status.

    ``begin`` is the one operation that must be atomic: it records ``record`` as
    pending unless its ``tool_call_id`` is held, and returns None when the caller should
    run the tool. It also returns None, recording ``record`` again, for a held ``pending``
    or ``unknown`` entry with the same ``idempotency_key`` when ``rerun`` is True.
    Otherwise it returns the held entry unchanged.
    """

    def begin(self, record: EffectRecord, *, rerun: bool) -> EffectRecord | None: ...

    def finish(self, tool_call_id: str, status: EffectStatus, result: Any = None) -> None: ...

    def release(self, tool_call_id: str) -> None: ...


class InMemoryEffectStore:
    """An :class:`EffectStore` in this process, guarded by a lock."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: dict[str, EffectRecord] = {}

    def begin(self, record: EffectRecord, *, rerun: bool) -> EffectRecord | None:
        with self._lock:
            held = self._records.get(record.tool_call_id)
            if held is None or (
                rerun
                and held.status is not EffectStatus.COMMITTED
                and held.idempotency_key == record.idempotency_key
            ):
                self._records[record.tool_call_id] = record
                return None
            return held

    def finish(self, tool_call_id: str, status: EffectStatus, result: Any = None) -> None:
        with self._lock:
            held = self._records.get(tool_call_id)
            if held is not None:
                held.status, held.result, held.updated_at = status, result, time.time()

    def release(self, tool_call_id: str) -> None:
        with self._lock:
            self._records.pop(tool_call_id, None)

    def get(self, tool_call_id: str) -> EffectRecord | None:
        """The held entry for ``tool_call_id``, for inspection."""
        with self._lock:
            return self._records.get(tool_call_id)


#: Errors that leave the effect in doubt: the request may have gone out.
DEFAULT_AMBIGUOUS_ERRORS: tuple[type[BaseException], ...] = (
    TimeoutError,
    ConnectionResetError,
    ConnectionAbortedError,
    BrokenPipeError,
    EffectOutcomeUnknown,
)


@dataclass(frozen=True)
class EffectGuard:
    """At-most-once dispatch for the tools of one policy.

    Attributes:
        store: Where call statuses live. :class:`InMemoryEffectStore` holds one process's;
            pass a shared one to cover replicas.
        require_tool_call_id: Refuse a call to a tool that is not reversible when its
            context carries no ``tool_call_id``, since it cannot be run at most once.
        require_approval_for_irreversible: Escalate every call to an irreversible tool to
            the policy's approver, whatever ``escalate_tools`` says.
        target_args: When set, a call to an irreversible tool must pass at least one of
            these arguments with a value (a ``--project`` that a destructive command
            would otherwise default).
        ambiguous_errors: The errors recorded ``unknown`` rather than released.
    """

    store: EffectStore = field(default_factory=InMemoryEffectStore)
    require_tool_call_id: bool = True
    require_approval_for_irreversible: bool = False
    target_args: tuple[str, ...] = ()
    ambiguous_errors: tuple[type[BaseException], ...] = DEFAULT_AMBIGUOUS_ERRORS

    def __post_init__(self) -> None:
        if isinstance(self.target_args, str) or not all(
            isinstance(name, str) and name for name in self.target_args
        ):
            raise TypeError("EffectGuard.target_args must be a tuple of argument names")
        object.__setattr__(self, "target_args", tuple(self.target_args))

    def canonical(self) -> dict[str, Any]:
        """The guard's settings, for the policy digest."""
        return {
            "require_tool_call_id": self.require_tool_call_id,
            "require_approval_for_irreversible": self.require_approval_for_irreversible,
            "target_args": sorted(self.target_args),
            "ambiguous_errors": sorted(e.__qualname__ for e in self.ambiguous_errors),
        }

    def admit(
        self,
        *,
        tool_name: str,
        tool_call_id: str | None,
        arguments: Mapping[str, Any],
        kind: Reversibility,
    ) -> EffectTicket:
        """Decide what this call does: run, return a stored value, or be refused.

        Raises:
            ValueError: The arguments cannot be read to build the idempotency key.
        """
        key = idempotency_key(tool_name, arguments)
        ticket = EffectTicket(self, tool_name, tool_call_id, key, kind)
        if (
            kind == "irreversible"
            and self.target_args
            and not _names_a_target(arguments, self.target_args)
        ):
            ticket.refusal = "no_target"
            return ticket
        if tool_call_id is None:
            if self.require_tool_call_id and kind != "reversible":
                ticket.refusal = "no_call_id"
            return ticket
        record = EffectRecord(tool_call_id, tool_name, key)
        held = self.store.begin(record, rerun=kind == "reversible")
        if held is not None:
            ticket.held = held
            if held.idempotency_key != key or held.tool_name != tool_name:
                ticket.refusal = "call_id_reused"
            elif held.status is not EffectStatus.COMMITTED:
                ticket.refusal = "status_unknown"
        return ticket


def _names_a_target(arguments: Mapping[str, Any], names: tuple[str, ...]) -> bool:
    return any(arguments.get(name) not in (None, "") for name in names)


@dataclass
class EffectTicket:
    """One call's place in the effect store, from the gate to its result.

    ``refusal`` names why the call is refused (``no_target``, ``no_call_id``,
    ``call_id_reused`` or ``status_unknown``); ``held`` is the store's entry when the
    ``tool_call_id`` was already known, and a committed one is a replay.
    """

    guard: EffectGuard
    tool_name: str
    tool_call_id: str | None
    idempotency_key: str
    kind: Reversibility
    refusal: str | None = None
    held: EffectRecord | None = None

    @property
    def replay(self) -> EffectRecord | None:
        """The committed entry this call returns instead of running, if any."""
        held = self.held
        if self.refusal is None and held is not None and held.status is EffectStatus.COMMITTED:
            return held
        return None

    @property
    def recorded(self) -> bool:
        """Whether the store holds this call as pending, waiting for its outcome."""
        return self.tool_call_id is not None and self.refusal is None and self.held is None

    def committed(self, result: Any, *, deferred: bool = False) -> None:
        """Record the value the call returned; a deferred one leaves the effect unknown."""
        if self.recorded and self.tool_call_id is not None:
            status = EffectStatus.UNKNOWN if deferred else EffectStatus.COMMITTED
            self.guard.store.finish(self.tool_call_id, status, None if deferred else result)

    def released(self) -> None:
        """Give back the entry of a call refused before it ran: a retry is a first attempt."""
        if self.recorded and self.tool_call_id is not None:
            self.guard.store.release(self.tool_call_id)

    def failed(self, error: BaseException) -> None:
        """Record a call that raised: unknown when the error leaves the effect in doubt."""
        if not self.recorded or self.tool_call_id is None:
            return
        if isinstance(error, self.guard.ambiguous_errors):
            self.guard.store.finish(self.tool_call_id, EffectStatus.UNKNOWN)
            logger.warning(
                "effect_status_unknown",
                tool=self.tool_name,
                tool_call_id=self.tool_call_id,
                error_type=type(error).__name__,
            )
        else:
            self.guard.store.release(self.tool_call_id)
