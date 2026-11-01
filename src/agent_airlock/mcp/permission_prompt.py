"""A permission-prompt tool for ``claude -p --permission-prompt-tool`` (V0.10.29).

In non-interactive mode Claude Code can hand each permission prompt to an MCP tool
(anthropics/claude-code#99813). :func:`permission_prompt_server` is a FastMCP server with
one such tool, ``permission_prompt``, that answers from a :class:`SecurityPolicy`::

    claude -p --mcp-config airlock.json \\
        --permission-prompt-tool mcp__airlock__permission_prompt "..."

The contract was read off Claude Code 2.1.316 by running it against a probe server: the
tool is called with ``{"tool_name", "input", "tool_use_id"}`` and answers with one text
block holding JSON, ``{"behavior": "allow", "updatedInput": {...}}`` or
``{"behavior": "deny", "message": "..."}``, where ``"interrupt": true`` ends the run. An
answer that also carries ``structuredContent`` is refused as invalid, so the tool has no
output schema.

The decision, in order:

* the fleet kill switch: while it is engaged every request is denied with
  ``interrupt``, which ends the run;
* a request that is not a tool name and an input object is denied;
* the policy's identity, allow and deny lists, time windows and rate limits refuse as
  they do for ``@Airlock``. A request from Claude Code names no agent, so an identity the
  policy requires is the server's own (``agent=``);
* a tool the policy escalates goes to its ``approver``. The request is bound to the input
  as ``@Airlock``'s are: it carries the input's ``args_digest``, a masked
  ``args_preview`` of it (never the raw input) and the ``tool_use_id``. Only a ``GRANT``
  that echoes the request's ``request_id`` within ``escalation_timeout_seconds``, and
  names this ``args_digest`` or none, allows; no approver, a denial, a timeout, an
  approver that raises or answers anything else, denies. Standing grants and the
  approval ledger are not consulted: every escalation goes to the approver;
* anything else is allowed with its input unchanged.

A request denied after the policy took its rate token gives the token back, since Claude
Code does not run a denied tool.

The input itself is not screened: Claude Code's own tools (Bash, Write) are not
Airlock-guarded functions, and the policy decides by tool name. Guard your own tools with
``@Airlock`` as well.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from .._log import structlog
from ..approvals import args_digest
from ..audit import AuditLogger
from ..kill_switch.registry import get as _kill_switch_get
from ..kill_switch.registry import is_frozen as _kill_switch_frozen
from ..oversight import OversightRequest, OversightResponse, OversightVerdict
from ..policy import AgentIdentity, PolicyEscalation, PolicyViolation, SecurityPolicy
from ..self_heal import handle_escalation, handle_policy_violation, refusal_text

logger = structlog.get_logger("agent-airlock.mcp.permission_prompt")

__all__ = ["TOOL_NAME", "decide", "permission_prompt_server"]

#: The tool's name: Claude Code calls it as ``mcp__<server name>__permission_prompt``.
TOOL_NAME = "permission_prompt"

_Outcome = Literal["no_approver", "denied", "timeout", "indeterminate"]


def _allow(tool_input: dict[str, Any]) -> dict[str, Any]:
    return {"behavior": "allow", "updatedInput": tool_input}


def _deny(message: str, *, interrupt: bool = False) -> dict[str, Any]:
    answer: dict[str, Any] = {"behavior": "deny", "message": message}
    if interrupt:
        answer["interrupt"] = True
    return answer


def _decided(answer: dict[str, Any], tool: str, tool_use_id: Any, why: str) -> dict[str, Any]:
    logger.info(
        "permission_prompt_decision",
        tool=tool,
        tool_use_id=tool_use_id if isinstance(tool_use_id, str) else None,
        behavior=answer["behavior"],
        why=why,
    )
    return answer


def _frozen(tool: str) -> dict[str, Any]:
    listener = _kill_switch_get()
    reason = listener.last_reason if listener else ""
    message = f"AIRLOCK_BLOCK: kill switch engaged; '{tool}' refused." + (
        f" Operator reason: {reason}" if reason else ""
    )
    return _deny(message, interrupt=True)


async def decide(
    policy: SecurityPolicy,
    tool_name: Any,
    tool_input: Any,
    tool_use_id: Any = None,
    *,
    agent: AgentIdentity | None = None,
) -> dict[str, Any]:
    """Answer one of Claude Code's permission requests from ``policy``.

    Args:
        policy: The policy that decides.
        tool_name: The ``tool_name`` of the request (``"Bash"``, ``"mcp__github__..."``).
        tool_input: Its ``input``, the arguments the tool would run with.
        tool_use_id: Its ``tool_use_id``, passed on to the approver.
        agent: The identity the policy checks: the server's own.

    Returns:
        The result object, ``{"behavior": "allow", "updatedInput": ...}`` or
        ``{"behavior": "deny", "message": ..., ["interrupt": True]}``.
    """
    label = tool_name if isinstance(tool_name, str) else ""
    if _kill_switch_frozen():
        return _decided(_frozen(label or "tool"), label, tool_use_id, "kill_switch")
    if (
        not label
        or not isinstance(tool_input, dict)
        or not (tool_use_id is None or isinstance(tool_use_id, str))
    ):
        message = (
            "AIRLOCK_BLOCK: malformed permission request: it needs a tool_name string, "
            "an input object and, if any, a tool_use_id string"
        )
        return _decided(_deny(message), label, tool_use_id, "malformed")
    try:
        policy.check(label, agent=agent)
    except PolicyEscalation as escalation:
        answer, why = await _escalate(policy, label, tool_input, tool_use_id, escalation, agent)
        if answer["behavior"] != "allow" and escalation.rate_charge is not None:
            # Claude Code does not run a denied tool, so it spends no rate token.
            escalation.rate_charge.refund()
        return _decided(answer, label, tool_use_id, why)
    except PolicyViolation as violation:
        refusal = handle_policy_violation(
            label, "SecurityPolicy", violation.message, violation_type=violation.violation_type
        )
        return _decided(_deny(refusal_text(refusal.to_dict())), label, tool_use_id, "policy")
    return _decided(_allow(tool_input), label, tool_use_id, "policy")


async def _ask(approver: Any, request: OversightRequest) -> Any:
    """The approver's answer within the request's deadline; a sync approver runs in a
    thread, and an awaitable it returns is awaited in what is left of the deadline.

    Raises:
        asyncio.TimeoutError: The deadline passed first.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + request.timeout_seconds
    answer = await asyncio.wait_for(asyncio.to_thread(approver, request), request.timeout_seconds)
    if inspect.isawaitable(answer):
        answer = await asyncio.wait_for(answer, max(0.0, deadline - loop.time()))
    return answer


async def _escalate(
    policy: SecurityPolicy,
    tool: str,
    tool_input: dict[str, Any],
    tool_use_id: str | None,
    escalation: PolicyEscalation,
    agent: AgentIdentity | None,
) -> tuple[dict[str, Any], str]:
    """Put an escalated request, bound to ``tool_input``'s digest, to the policy's
    approver; only a ``GRANT`` of that digest (or naming none) allows."""

    def refused(outcome: _Outcome, detail: str = "", by: str | None = None) -> dict[str, Any]:
        response = handle_escalation(
            tool,
            reason=escalation.reason,
            rule=escalation.rule,
            outcome=outcome,
            detail=detail,
            approver=by,
        )
        return _deny(refusal_text(response.to_dict()))

    if policy.approver is None:
        return refused("no_approver"), "escalation_no_approver"
    try:
        digest = args_digest(tool_input)
    except ValueError:
        detail = "the input nests too deep or contains itself, so no approval can be bound to it"
        return refused("indeterminate", detail), "escalation_unbindable"
    now = datetime.now(timezone.utc)
    timeout = float(policy.escalation_timeout_seconds)
    request = OversightRequest(
        request_id=str(uuid.uuid4()),
        tool_name=tool,
        args={
            "escalation_reason": escalation.reason,
            "escalation_rule": escalation.rule,
            "tool_use_id": tool_use_id,
        },
        channel=policy.escalation_channel,
        timeout_seconds=timeout,
        requested_at=now.isoformat(),
        args_digest=digest,
        args_preview=AuditLogger._redact_args(tool_input),
        agent_id=agent.agent_id if agent is not None else None,
        policy_digest=policy._compute_policy_digest(),
        expires_at=(now + timedelta(seconds=timeout)).isoformat(),
    )
    try:
        answer = await _ask(policy.approver, request)
    except asyncio.TimeoutError:
        detail = f"no answer within {request.timeout_seconds:g} seconds"
        return refused("timeout", detail), "escalation_timeout"
    except Exception as exc:  # noqa: BLE001 - an approver that raised did not approve
        return refused("denied", f"approver raised {type(exc).__name__}"), "escalation_error"
    if not isinstance(answer, OversightResponse) or answer.request_id != request.request_id:
        return refused(
            "denied", "the approver's answer is not for this request"
        ), "escalation_unread"
    if answer.verdict is OversightVerdict.GRANT:
        if answer.args_digest is not None and answer.args_digest != digest:
            detail = "the approval names other arguments"
            return refused("indeterminate", detail, answer.approver), "escalation_unread"
        return _allow(tool_input), "escalation_granted"
    outcome: _Outcome = "timeout" if answer.verdict is OversightVerdict.TIMEOUT else "denied"
    return refused(outcome, answer.detail, answer.approver), f"escalation_{outcome}"


def permission_prompt_server(
    policy: SecurityPolicy, *, name: str = "airlock", agent: AgentIdentity | None = None
) -> Any:
    """A FastMCP server with the one ``permission_prompt`` tool, answering from ``policy``.

    Run it over stdio (``server.run()``) and point Claude Code at it with
    ``--permission-prompt-tool mcp__<name>__permission_prompt``.

    Args:
        policy: The policy that decides each request.
        name: The server's name, the middle of the tool's full name.
        agent: The identity the policy checks; a request from Claude Code names none.

    Raises:
        ImportError: FastMCP is not installed (``pip install "agent-airlock[mcp]"``).
    """
    try:
        from fastmcp import FastMCP
    except ImportError as exc:
        raise ImportError('FastMCP is required: pip install "agent-airlock[mcp]"') from exc

    server = FastMCP(name)

    async def permission_prompt(
        tool_name: Any = None, input: Any = None, tool_use_id: Any = None
    ) -> str:
        """Answer a Claude Code permission prompt from the Airlock policy."""
        answer = await decide(policy, tool_name, input, tool_use_id, agent=agent)
        return json.dumps(answer)

    # No output schema: Claude Code refuses an answer that carries structuredContent.
    try:
        server.tool(permission_prompt, name=TOOL_NAME, output_schema=None)
    except TypeError:  # FastMCP before 2.10 has no output_schema, and no structured output
        server.tool(name=TOOL_NAME)(permission_prompt)
    return server
