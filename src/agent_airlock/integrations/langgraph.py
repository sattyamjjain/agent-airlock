"""LangGraph: Airlock at the ToolNode, where the graph runs each tool call (V0.10.29).

The check belongs in the graph (langchain-ai/langgraph#8817, #8818): the model picks the
tool, and a guard on each ``@tool`` function sees only the tools it was put on. ToolNode's
``wrap_tool_call`` sees every call the node runs::

    from langgraph.prebuilt import ToolNode

    from agent_airlock.integrations.langgraph import (
        airlock_awrap_tool_call,
        airlock_wrap_tool_call,
    )

    node = ToolNode(
        tools,
        wrap_tool_call=airlock_wrap_tool_call(policy),
        awrap_tool_call=airlock_awrap_tool_call(policy),
    )

Each call runs through an ``Airlock`` built once per tool from its model-facing schema
(``tool.tool_call_schema``): the policy and every other gate, then ``execute`` with the
arguments Airlock admitted (ghost arguments stripped), then masking of the result's
content. A refusal is a ``ToolMessage`` with ``status="error"`` and the call's
``tool_call_id``, and ``execute`` never runs; so is a call of a tool the node does not have
(``request.tool is None``). :func:`airlock_middleware` is the same check as a
``create_agent`` middleware, and :func:`filter_tools` drops what the policy refuses before
``bind_tools``.

An escalation can be put to a human with LangGraph's ``interrupt()``
(:class:`InterruptApprovals`). The approval that resumes the graph is bound to the call that
asked: the thread, the checkpoint the task belongs to, the tool call and its arguments, by
an HMAC whose key the checkpoint store never holds, and it is spent once from a ledger kept
outside that store. So a forged checkpoint row, a replayed approval and a resume from an
older checkpoint (its head row deleted) admit nothing (langchain-ai/langgraph#8938: treat
the checkpoint as untrusted input on load and re-derive the decision).

``langgraph`` and ``langchain`` are imported only when used (``interrupt``, the
middleware's base class, ``ToolMessage``), so this module imports without them.
"""

from __future__ import annotations

import hashlib
import hmac
import inspect
import json
import secrets
import time
from collections.abc import Callable, Iterable, Mapping
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel

from .._log import structlog
from ..approvals import ApprovalLedger, args_digest
from ..config import AirlockConfig
from ..core import Airlock
from ..policy import PolicyEscalation, PolicyViolation, SecurityPolicy
from ..self_heal import is_refusal, refusal_text
from ._claude_sdk_tools import _ABSENT, _schema_fields
from ._tool_proxy import _adopt_identity

logger = structlog.get_logger("agent-airlock.integrations.langgraph")

__all__ = [
    "InterruptApprovals",
    "airlock_awrap_tool_call",
    "airlock_middleware",
    "airlock_wrap_tool_call",
    "filter_tools",
]


@dataclass
class _Call:
    """The tool call in flight: the node's request, its ``execute``, and what it returned."""

    request: Any
    execute: Callable[[Any], Any]
    message: Any = None


_CALL: ContextVar[_Call | None] = ContextVar("airlock_langgraph_call", default=None)


def _tool_name(request: Any) -> str:
    tool = getattr(request, "tool", None)
    call = getattr(request, "tool_call", None) or {}
    return str(getattr(tool, "name", None) or call.get("name") or "unknown_tool")


def _tool_message(request: Any, content: str) -> Any:
    """An error ``ToolMessage`` answering ``request``: its ``tool_call_id`` kept."""
    from langchain_core.messages import ToolMessage

    call = getattr(request, "tool_call", None) or {}
    return ToolMessage(
        content=content,
        tool_call_id=str(call.get("id") or ""),
        name=_tool_name(request),
        status="error",
    )


def _input_schema(tool: Any) -> Any:
    """The JSON schema of what the model fills in, the arguments LangGraph injects left out."""
    schema = getattr(tool, "tool_call_schema", None)
    if isinstance(schema, type) and issubclass(schema, BaseModel):
        return schema.model_json_schema()
    return schema if schema is not None else {"type": "object", "properties": {}}


def _executed(call: _Call, args: dict[str, Any]) -> Any:
    """Run the node's ``execute`` with ``args``; a message's content goes back to be masked."""
    result = call.execute(call.request.override(tool_call={**call.request.tool_call, "args": args}))
    return result


def _content_of(call: _Call, result: Any) -> Any:
    if hasattr(result, "content") and hasattr(result, "model_copy"):
        call.message = result
        return result.content
    return result  # a Command, returned as it is


def _spread(
    name: str, schema: Any, *, is_async: bool
) -> tuple[Callable[..., Any], frozenset[str] | None]:
    """A proxy named ``name`` with one keyword parameter per schema key, calling ``execute``.

    Returns the proxy and the keys it declares, or None for a schema that admits any key.
    """
    fields, open_ended = _schema_fields(schema, name=name)

    def plain(kwargs: dict[str, Any]) -> dict[str, Any]:
        return {key: value for key, value in kwargs.items() if value is not _ABSENT}

    def current() -> _Call:
        call = _CALL.get()
        if call is None:  # called outside a ToolNode wrapper: nothing to execute
            raise RuntimeError(f"{name} was called outside a ToolNode tool call")
        return call

    if is_async:

        async def proxy(**kwargs: Any) -> Any:
            call = current()
            result = _executed(call, plain(kwargs))
            return _content_of(call, await result if inspect.isawaitable(result) else result)

    else:

        def proxy(**kwargs: Any) -> Any:  # type: ignore[misc]
            call = current()
            return _content_of(call, _executed(call, plain(kwargs)))

    kw_only = inspect.Parameter.KEYWORD_ONLY
    parameters = [
        inspect.Parameter(
            key,
            kw_only,
            annotation=spec.annotation,
            default=inspect.Parameter.empty if spec.required else _ABSENT,
        )
        for key, spec in fields.items()
    ]
    if open_ended:
        parameters.append(inspect.Parameter("undeclared_keys", inspect.Parameter.VAR_KEYWORD))
    _adopt_identity(
        proxy,
        proxy,
        name=name,
        signature=inspect.Signature(parameters),
        annotations={param.name: param.annotation for param in parameters},
    )
    return proxy, None if open_ended else frozenset(fields)


def _escalation_for(
    policy: SecurityPolicy, name: str, arguments: Mapping[str, Any]
) -> PolicyEscalation | None:
    """The escalation step 2 would raise, read without spending a rate-limit token."""
    try:
        policy.check_tool_allowed(name)
        policy.check_time_restriction(name)
        policy.check_escalation(name)
    except PolicyEscalation as escalation:
        return None if policy.standing_grant_for(name, arguments) is not None else escalation
    except PolicyViolation:
        return None
    return None


class InterruptApprovals:
    """Approvals asked with LangGraph's ``interrupt()``, bound to the call that asked.

    The graph pauses with ``{"airlock_approval": {...}}`` as the interrupt's value: the tool,
    the rule, the reason, the call's arguments, the call's binding and a seal. Show it to a
    human; on a yes, resume with ``Command(resume=approvals.approve(value))``, and with
    anything else on a no. :meth:`approve` checks the seal, so a request altered in the
    checkpoint store is not signed, and records the approval in ``ledger``; the call is
    admitted only when the approval's token matches the binding the call derives again as
    it runs, and once.

    Args:
        key: The HMAC key, at least 16 bytes. Keep it outside the checkpoint store.
        ledger: Where each approval is recorded and spent once: an
            :class:`~agent_airlock.approvals.ApprovalLedger`, not the checkpoint store.
        ttl_seconds: How long an approval stays usable after it is given.

    Raises:
        ValueError: ``key`` is shorter than 16 bytes.
    """

    def __init__(self, key: bytes, ledger: ApprovalLedger, *, ttl_seconds: float = 3600.0) -> None:
        if not isinstance(key, bytes) or len(key) < 16:
            raise ValueError("InterruptApprovals needs a key of at least 16 bytes")
        self._key = key
        self._ledger = ledger
        self._ttl = ttl_seconds

    def _mac(self, *parts: str) -> str:
        return hmac.new(self._key, "\x1f".join(parts).encode("utf-8"), hashlib.sha256).hexdigest()

    @staticmethod
    def binding(request: Any, name: str, arguments: Mapping[str, Any]) -> str:
        """What an approval of this call is bound to: thread, checkpoint, call, arguments."""
        runtime = getattr(request, "runtime", None)
        config = getattr(runtime, "config", None) or {}
        configurable = config.get("configurable", {}) if isinstance(config, Mapping) else {}
        checkpoints = configurable.get("checkpoint_map") or {}
        fields = {
            "thread_id": str(configurable.get("thread_id")),
            "checkpoint_ns": str(configurable.get("checkpoint_ns")),
            "checkpoint_map": sorted((str(k), str(v)) for k, v in dict(checkpoints).items()),
            "tool_call_id": str((getattr(request, "tool_call", None) or {}).get("id")),
            "tool": name,
            "args_digest": args_digest(arguments),
        }
        return hashlib.sha256(json.dumps(fields, sort_keys=True).encode("utf-8")).hexdigest()

    def ask(
        self, binding: str, name: str, escalation: PolicyEscalation, arguments: Mapping[str, Any]
    ) -> dict[str, Any]:
        """The interrupt's value: what a human is asked, sealed by this key."""
        return {
            "airlock_approval": {
                "tool": name,
                "rule": escalation.rule,
                "reason": escalation.reason,
                "arguments": dict(arguments),
                "binding": binding,
                "seal": self._mac("ask", binding, name),
            }
        }

    def approve(self, value: Any) -> dict[str, Any]:
        """The resume value for a human's yes to the interrupt ``value``.

        Raises:
            ValueError: ``value`` is not a request this key sealed (altered in the store, or
                made up).
        """
        request = value.get("airlock_approval") if isinstance(value, Mapping) else None
        binding = request.get("binding") if isinstance(request, Mapping) else None
        name = request.get("tool") if isinstance(request, Mapping) else None
        seal = request.get("seal") if isinstance(request, Mapping) else None
        if not (isinstance(binding, str) and isinstance(name, str) and isinstance(seal, str)) or (
            not hmac.compare_digest(seal, self._mac("ask", binding, name))
        ):
            raise ValueError("not an approval request this key sealed")
        nonce = secrets.token_hex(16)
        self._ledger.grant(name, self._spent_key(nonce), expires_at=time.time() + self._ttl)
        return {
            "airlock_approval": {
                "binding": binding,
                "nonce": nonce,
                "token": self._mac("grant", binding, nonce),
            }
        }

    @staticmethod
    def _spent_key(nonce: str) -> str:
        return hashlib.sha256(f"airlock-langgraph-approval:{nonce}".encode()).hexdigest()

    def admit(self, binding: str, name: str, answer: Any) -> bool:
        """Whether ``answer`` approves the call bound to ``binding``; spends the approval."""
        grant = answer.get("airlock_approval") if isinstance(answer, Mapping) else None
        if not isinstance(grant, Mapping):
            return False
        nonce, token = grant.get("nonce"), grant.get("token")
        if (
            not (isinstance(nonce, str) and isinstance(token, str))
            or grant.get("binding") != binding
        ):
            return False
        if not hmac.compare_digest(token, self._mac("grant", binding, nonce)):
            return False
        return self._ledger.claim(name, self._spent_key(nonce), secrets.token_hex(8))


@dataclass
class _Gate:
    """One ``Airlock`` per tool and kind (sync or async), built on its first call."""

    policy: SecurityPolicy | None
    config: AirlockConfig | None
    approvals: InterruptApprovals | None
    grant_ttl_seconds: float = 60.0
    _built: dict[tuple[int, bool], tuple[Any, Callable[..., Any], frozenset[str] | None]] = field(
        default_factory=dict, repr=False
    )

    def __post_init__(self) -> None:
        if self.approvals is not None and (
            self.policy is None or self.policy.approval_ledger is None
        ):
            raise ValueError(
                "approvals need a SecurityPolicy with an approval_ledger: an approved call is "
                "admitted by claiming the approval recorded there"
            )

    def _guarded(
        self, tool: Any, name: str, *, is_async: bool
    ) -> tuple[Callable[..., Any], frozenset[str] | None]:
        key = (id(tool), is_async)
        built = self._built.get(key)
        if built is None or built[0] is not tool:
            proxy, declared = _spread(name, _input_schema(tool), is_async=is_async)
            airlock = Airlock(policy=self.policy, config=self.config)
            built = (tool, airlock(proxy), declared)
            self._built[key] = built
        return built[1], built[2]

    def _refused(self, request: Any, result: Any) -> Any:
        return _tool_message(request, refusal_text(result))

    def _asked(self, request: Any, name: str, arguments: dict[str, Any]) -> Any:
        """None to go on; an error message when the call escalates and is not approved."""
        if self.approvals is None or self.policy is None:
            return None
        escalation = _escalation_for(self.policy, name, arguments)
        if escalation is None:
            return None
        from langgraph.types import interrupt

        binding = self.approvals.binding(request, name, arguments)
        answer = interrupt(self.approvals.ask(binding, name, escalation, arguments))
        if not self.approvals.admit(binding, name, answer):
            logger.warning("langgraph_approval_refused", tool=name, rule=escalation.rule)
            return _tool_message(
                request,
                f"AIRLOCK_BLOCK: '{name}' was not approved (rule {escalation.rule!r}): the "
                "approval did not verify for this call, or was used already",
            )
        ledger = self.policy.approval_ledger
        if ledger is not None:
            ledger.grant(
                name, args_digest(arguments), expires_at=time.time() + self.grant_ttl_seconds
            )
        return None

    def _prepare(self, request: Any) -> tuple[str, dict[str, Any], Any]:
        name = _tool_name(request)
        if getattr(request, "tool", None) is None:
            logger.warning("langgraph_unknown_tool", tool=name)
            return (
                name,
                {},
                _tool_message(
                    request, f"AIRLOCK_BLOCK: '{name}' is not a tool this node has; it was not run"
                ),
            )
        arguments = dict((getattr(request, "tool_call", None) or {}).get("args") or {})
        return name, arguments, self._asked(request, name, arguments)

    def _finish(self, request: Any, call: _Call, result: Any) -> Any:
        if is_refusal(result):
            return self._refused(request, result)
        if call.message is not None:
            return call.message.model_copy(update={"content": result})
        return result

    def run(self, request: Any, execute: Callable[[Any], Any]) -> Any:
        name, arguments, refusal = self._prepare(request)
        if refusal is not None:
            return refusal
        guarded, _ = self._guarded(request.tool, name, is_async=False)
        call = _Call(request, execute)
        token = _CALL.set(call)
        try:
            result = guarded(**arguments)
        finally:
            _CALL.reset(token)
        return self._finish(request, call, result)

    async def arun(self, request: Any, execute: Callable[[Any], Any]) -> Any:
        name, arguments, refusal = self._prepare(request)
        if refusal is not None:
            return refusal
        guarded, _ = self._guarded(request.tool, name, is_async=True)
        call = _Call(request, execute)
        token = _CALL.set(call)
        try:
            result = await guarded(**arguments)
        finally:
            _CALL.reset(token)
        return self._finish(request, call, result)


def airlock_wrap_tool_call(
    policy: SecurityPolicy | None = None,
    *,
    config: AirlockConfig | None = None,
    approvals: InterruptApprovals | None = None,
) -> Callable[[Any, Callable[[Any], Any]], Any]:
    """A ``ToolNode(wrap_tool_call=...)`` that runs every call through Airlock.

    Args:
        policy: The policy each call is checked against.
        config: The ``AirlockConfig`` of each tool's ``Airlock``.
        approvals: Put escalations to a human through ``interrupt()``; needs a policy with
            an ``approval_ledger``.

    Raises:
        ValueError: ``approvals`` with a policy that has no ``approval_ledger``.
    """
    gate = _Gate(policy, config, approvals)

    def wrap_tool_call(request: Any, execute: Callable[[Any], Any]) -> Any:
        return gate.run(request, execute)

    return wrap_tool_call


def airlock_awrap_tool_call(
    policy: SecurityPolicy | None = None,
    *,
    config: AirlockConfig | None = None,
    approvals: InterruptApprovals | None = None,
) -> Callable[[Any, Callable[[Any], Any]], Any]:
    """The async twin of :func:`airlock_wrap_tool_call`, for ``ToolNode(awrap_tool_call=...)``."""
    gate = _Gate(policy, config, approvals)

    async def awrap_tool_call(request: Any, execute: Callable[[Any], Any]) -> Any:
        return await gate.arun(request, execute)

    return awrap_tool_call


def airlock_middleware(
    policy: SecurityPolicy | None = None,
    *,
    config: AirlockConfig | None = None,
    approvals: InterruptApprovals | None = None,
) -> Any:
    """An ``AgentMiddleware`` for ``create_agent(middleware=[...])`` that checks each tool call.

    Raises:
        ImportError: ``langchain`` (the ``create_agent`` package) is not installed.
    """
    from langchain.agents.middleware import AgentMiddleware

    gate = _Gate(policy, config, approvals)

    class AirlockMiddleware(AgentMiddleware):  # type: ignore[misc,unused-ignore]  # Any without langchain
        def wrap_tool_call(self, request: Any, handler: Callable[[Any], Any]) -> Any:
            return gate.run(request, handler)

        async def awrap_tool_call(self, request: Any, handler: Callable[[Any], Any]) -> Any:
            return await gate.arun(request, handler)

    return AirlockMiddleware()


def filter_tools(tools: Iterable[Any], policy: SecurityPolicy) -> list[Any]:
    """The tools ``policy`` admits by name, for ``model.bind_tools``.

    A tool the policy refuses outright (denied, or outside its allowlist) is dropped, so the
    model is never offered it; one it escalates is kept, since a human can approve it. Read
    without spending anything: no rate-limit token, no time window.
    """
    kept = []
    for tool in tools:
        name = getattr(tool, "name", None) or getattr(tool, "__name__", None)
        try:
            policy.check_tool_allowed(str(name))
        except PolicyViolation:
            continue
        kept.append(tool)
    return kept
