"""pydantic-ai deferred approvals and rejected tool calls (V0.10.29).

Two things :class:`~agent_airlock.integrations.pydantic_ai.PydanticAIAdapter` does for an
agent besides guarding each tool:

* With ``defer_escalations=True``, a call the policy escalates becomes a pydantic-ai
  deferred approval. ``ApprovalRequired`` is raised before Airlock runs, so the run ends
  with (or a ``HandleDeferredToolCalls`` handler receives) a ``DeferredToolRequests`` naming
  the call, and nothing is spent on it. When a run resumes with the call approved, the
  adapter records one approval of exactly those arguments in the policy's
  ``approval_ledger``, which the call claims at step 2: it then counts against rate limits
  and budgets like any call. An approval replayed for a tool call id already used is not
  recorded, so the call meets the policy as if nobody had approved it.
* A call pydantic-ai rejects before any tool runs (a tool that does not exist,
  ``unknown_tool``, or one not available at this step, ``unavailable_tool``) never reaches
  Airlock. :func:`log_tool_rejections` logs those from a run's messages, with the retry
  count and a final record once the model has no retry left; the run toolset the adapter
  wraps does it as each step starts.

Raised in pydantic/pydantic-ai#9015 ("ask" with no approver attached fails closed, since the
escalation type subclasses the violation), pydantic/pydantic-ai#9085 (the retry ``cause``)
and pydantic/pydantic-ai#8839 (an approval says the call is allowed, not that it is free).
"""

from __future__ import annotations

import functools
import inspect
import threading
import time
from collections import Counter, OrderedDict
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any

from .._arg_walk import bind_arguments, injected_params, signature_of, without_injected
from .._log import structlog
from ..approvals import args_digest
from ..policy import PolicyEscalation, PolicyViolation, SecurityPolicy

logger = structlog.get_logger("agent-airlock.integrations.pydantic_ai_approvals")

__all__ = [
    "REJECTION_CAUSES",
    "Deferral",
    "RejectionTracker",
    "ToolRejection",
    "log_tool_rejections",
]

#: The tool call in progress, for a tool pydantic-ai hands no ``RunContext``
#: (``tool_plain``): set by the run toolset the adapter wraps.
_RUN_CONTEXT: ContextVar[Any] = ContextVar("airlock_pydantic_ai_run_context", default=None)

#: Retry causes that are rejections: pydantic-ai refused the call before any tool ran.
REJECTION_CAUSES = frozenset({"unknown_tool", "unavailable_tool"})


def escalation_for(
    policy: SecurityPolicy, name: str, arguments: Mapping[str, Any]
) -> PolicyEscalation | None:
    """The escalation step 2 would raise for this call, when nothing refuses it first.

    Read without spending anything: the tool lists and time windows, then the escalation
    rules (a rate limit is spent when the call is made). A call a standing grant admits is
    not escalated, and one the policy refuses is left to be refused on the call path rather
    than put to a human first.
    """
    try:
        policy.check_tool_allowed(name)
        policy.check_time_restriction(name)
        policy.check_escalation(name)
    except PolicyEscalation as escalation:
        return None if policy.standing_grant_for(name, arguments) is not None else escalation
    except PolicyViolation:
        return None
    return None


def approval_required(escalation: PolicyEscalation) -> Exception:
    """pydantic-ai's ``ApprovalRequired``, with the Airlock rule and reason as its metadata."""
    from pydantic_ai.exceptions import ApprovalRequired

    error: Exception = ApprovalRequired(
        metadata={"airlock": {"rule": escalation.rule, "reason": escalation.reason}}
    )
    return error


class _Seen:
    """Keys already handled, the most recent ``limit`` of them."""

    def __init__(self, limit: int = 10_000) -> None:
        self._keys: OrderedDict[str, None] = OrderedDict()
        self._limit = limit
        self._lock = threading.Lock()

    def first(self, key: str) -> bool:
        """True the first time ``key`` is seen (within the last ``limit``), False after."""
        with self._lock:
            if key in self._keys:
                return False
            self._keys[key] = None
            if len(self._keys) > self._limit:
                self._keys.popitem(last=False)
            return True


@dataclass(eq=False)
class Deferral:
    """How a :class:`PydanticAIAdapter` turns escalations into deferred approvals.

    Attributes:
        grant_ttl_seconds: How long the approval recorded for a resumed call stays
            claimable; the call claims it at once, so a short life is enough.
    """

    grant_ttl_seconds: float = 60.0
    _used: _Seen = field(default_factory=_Seen, repr=False)

    def before_call(
        self, name: str, policy: SecurityPolicy, ctx: Any, arguments: Mapping[str, Any]
    ) -> None:
        """Defer an escalated call nobody approved yet; record the approval of one resumed.

        A call with no run context (a tool pydantic-ai called outside a run toolset the
        adapter wraps) is left to step 2, which asks the policy's approver or refuses.

        Raises:
            ApprovalRequired: The call escalates and pydantic-ai has not approved it.
        """
        escalation = escalation_for(policy, name, arguments)
        if escalation is None or ctx is None:
            return
        call_id = getattr(ctx, "tool_call_id", None)
        if not getattr(ctx, "tool_call_approved", False):
            logger.info(
                "pydantic_ai_escalation_deferred",
                tool=name,
                rule=escalation.rule,
                tool_call_id=call_id,
            )
            raise approval_required(escalation)
        self._record(name, policy, call_id, arguments, escalation)

    def _record(
        self,
        name: str,
        policy: SecurityPolicy,
        call_id: Any,
        arguments: Mapping[str, Any],
        escalation: PolicyEscalation,
    ) -> None:
        ledger = policy.approval_ledger
        if ledger is None or not isinstance(call_id, str) or not self._used.first(call_id):
            logger.warning(
                "pydantic_ai_approval_not_recorded",
                tool=name,
                tool_call_id=call_id,
                reason="no approval ledger" if ledger is None else "replayed or unnamed call",
            )
            return
        try:
            digest = args_digest(arguments)
        except ValueError:
            return  # arguments that cannot be read: step 2 refuses the call
        ledger.grant(name, digest, expires_at=time.time() + self.grant_ttl_seconds)
        logger.info(
            "pydantic_ai_approval_recorded", tool=name, tool_call_id=call_id, rule=escalation.rule
        )


def deferring(
    guarded: Callable[..., Any],
    *,
    proxy: Callable[..., Any],
    name: str,
    policy: SecurityPolicy,
    takes_ctx: bool,
    deferral: Deferral,
) -> Callable[..., Any]:
    """``guarded`` (an Airlock-wrapped tool) behind :meth:`Deferral.before_call`.

    The arguments are bound as step 2 binds them, through the proxy's signature and without
    the run context pydantic-ai injects, so the recorded approval is the one step 2 claims.
    """
    signature = signature_of(proxy)
    injected = injected_params(proxy)

    def before(args: tuple[Any, ...], kwargs: dict[str, Any]) -> None:
        ctx = args[0] if takes_ctx and args else _RUN_CONTEXT.get()
        arguments = without_injected(bind_arguments(signature, args, kwargs), injected)
        deferral.before_call(name, policy, ctx, arguments)

    if inspect.iscoroutinefunction(guarded):

        @functools.wraps(guarded)
        async def async_shim(*args: Any, **kwargs: Any) -> Any:
            before(args, kwargs)
            return await guarded(*args, **kwargs)

        return async_shim

    @functools.wraps(guarded)
    def shim(*args: Any, **kwargs: Any) -> Any:
        before(args, kwargs)
        return guarded(*args, **kwargs)

    return shim


@dataclass(frozen=True)
class ToolRejection:
    """A tool call pydantic-ai refused before any tool ran.

    Attributes:
        tool_name: The name the model called.
        tool_call_id: The call it answered.
        cause: ``unknown_tool`` or ``unavailable_tool``.
        attempt: pydantic-ai's retry count for the tool, from 1; None when it is not
            counted (the first ``unavailable_tool`` refusal is free).
        max_retries: The limit ``attempt`` is checked against, or None.
        retries: How many rejections answered this tool call id in the messages.
        final: The model has no retry left for the tool: the next one ends the run.
    """

    tool_name: str
    tool_call_id: str | None
    cause: str
    attempt: int | None
    max_retries: int | None
    retries: int
    final: bool


def _count(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _rejected_parts(messages: Iterable[Any]) -> Iterator[tuple[Any, Any]]:
    """``(part, retry)`` for each tool return pydantic-ai retried as a rejection."""
    for message in messages:
        for part in getattr(message, "parts", None) or ():
            if getattr(part, "part_kind", None) != "tool-return":
                continue
            retry = getattr(part, "retry", None)
            if getattr(part, "outcome", None) == "retried" and (
                getattr(retry, "cause", None) in REJECTION_CAUSES
            ):
                yield part, retry


def _rejections(messages: Iterable[Any]) -> list[ToolRejection]:
    found = list(_rejected_parts(messages))
    per_call = Counter(str(getattr(part, "tool_call_id", "")) for part, _ in found)
    rejections: list[ToolRejection] = []
    for part, retry in found:
        attempt, limit = (
            _count(getattr(retry, "attempt", None)),
            _count(getattr(retry, "max_retries", None)),
        )
        call_id = getattr(part, "tool_call_id", None)
        rejections.append(
            ToolRejection(
                tool_name=str(getattr(part, "tool_name", "")),
                tool_call_id=call_id if isinstance(call_id, str) else None,
                cause=str(retry.cause),
                attempt=attempt,
                max_retries=limit,
                retries=per_call[str(call_id or "")],
                final=attempt is not None and limit is not None and attempt >= limit,
            )
        )
    return rejections


def _log(rejection: ToolRejection) -> None:
    fields = {
        "tool": rejection.tool_name,
        "tool_call_id": rejection.tool_call_id,
        "outcome": "retried",
        "cause": rejection.cause,
        "attempt": rejection.attempt,
        "max_retries": rejection.max_retries,
        "retries": rejection.retries,
    }
    logger.warning("pydantic_ai_tool_rejected", **fields)
    if rejection.final:
        logger.warning("pydantic_ai_tool_rejected_final", **fields)


class RejectionTracker:
    """Logs each rejected tool call once, as a run's messages show it.

    Args:
        limit: How many tool call ids it remembers, so a long-lived adapter stays bounded.
    """

    def __init__(self, limit: int = 10_000) -> None:
        self._seen = _Seen(limit)

    def scan(self, messages: Iterable[Any]) -> list[ToolRejection]:
        """Log the rejections in ``messages`` not logged before; return them."""
        fresh = [
            rejection
            for rejection in _rejections(messages)
            if self._seen.first(
                rejection.tool_call_id or f"{rejection.tool_name}#{rejection.attempt}"
            )
        ]
        for rejection in fresh:
            _log(rejection)
        return fresh


def log_tool_rejections(messages: Iterable[Any]) -> list[ToolRejection]:
    """Log every tool call in ``messages`` that pydantic-ai rejected before any tool ran.

    Pass a run's ``all_messages()`` or ``new_messages()``. Each rejection is a
    ``ToolReturnPart`` whose ``outcome`` is ``"retried"`` and whose ``retry.cause`` is
    ``unknown_tool`` or ``unavailable_tool``; it is logged as ``pydantic_ai_tool_rejected``,
    and also as ``pydantic_ai_tool_rejected_final`` when the model had no retry left. Parts
    are read by attribute, so no pydantic-ai import is needed.
    """
    return RejectionTracker().scan(messages)


@functools.cache
def _run_toolset_class(base: type) -> type:
    """A subclass of pydantic-ai's ``WrapperToolset`` that hands each call's run context to
    the deferral and logs rejected calls as each step starts."""

    @dataclass
    class AirlockRunToolset(base):  # type: ignore[misc]
        tracker: Any = None

        async def get_tools(self, ctx: Any) -> Any:
            if self.tracker is not None:
                self.tracker.scan(getattr(ctx, "messages", None) or ())
            return await super().get_tools(ctx)

        async def call_tool(self, name: str, tool_args: Any, ctx: Any, tool: Any) -> Any:
            token = _RUN_CONTEXT.set(ctx)
            try:
                return await super().call_tool(name, tool_args, ctx, tool)
            finally:
                _RUN_CONTEXT.reset(token)

    return AirlockRunToolset


def run_toolset(toolset: Any, *, tracker: RejectionTracker | None) -> Any:
    """``toolset`` behind the adapter's run toolset, or itself when pydantic-ai is missing."""
    try:
        from pydantic_ai.toolsets import WrapperToolset
    except ImportError:
        return toolset
    return _run_toolset_class(WrapperToolset)(wrapped=toolset, tracker=tracker)
