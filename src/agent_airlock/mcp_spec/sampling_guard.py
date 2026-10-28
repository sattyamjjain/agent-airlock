"""MCP sampling-layer attack-vector guard (v0.5.5+).

Motivation
----------
Unit 42 (Palo Alto Networks) published an attack-vector catalog for the
Model Context Protocol sampling feature on 2026-04-24. The MCP spec lets
an MCP server ask the hosting client for LLM completions ("sampling")
so the server can reason with the client's model. Unit 42 showed three
concrete abuse patterns:

1. **Quota-exhaustion.** A malicious or compromised server issues an
   unbounded stream of sampling requests, burning the client's token
   budget and API quota. The protocol has no built-in cap.
2. **Persistent instruction injection.** The server includes
   system-style instructions in every sampling request so behavior
   compounds across calls — effectively forging a long-lived system
   prompt the end user never approved.
3. **Consent-bypass.** The MCP spec calls for human-in-the-loop
   approval of every sampling request, but several reference clients
   (per Unit 42) treated the approval as session-sticky, letting a
   server issue *further* sampling requests silently after a single
   "yes." One approved sampling call ≠ approval for every subsequent
   one.

This module provides ``audit_sampling_request`` as the caller's
defense. It is deliberately opt-in (v0.5.5 policy philosophy) — no
behavior change unless a preset pulls it in.

Usage::

    from agent_airlock.mcp_spec.sampling_guard import (
        SamplingGuardConfig,
        SamplingSessionState,
        audit_sampling_request,
    )
    from agent_airlock.policy_presets import unit42_mcp_sampling_defaults

    cfg = unit42_mcp_sampling_defaults()
    state = SamplingSessionState(session_id="s-42")
    audit_sampling_request(
        request={"messages": [...], "maxTokens": 2048},
        session_state=state,
        cfg=cfg,
        user_consented=True,
    )

Primary source
--------------
- Unit 42: <https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/>
"""

from __future__ import annotations

import math
import numbers
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .._log import structlog
from ..exceptions import AirlockError

logger = structlog.get_logger("agent-airlock.mcp_spec.sampling_guard")


@dataclass
class SamplingGuardConfig:
    """Policy applied by :func:`audit_sampling_request`.

    Attributes:
        max_sampling_requests_per_session: Hard cap on how many sampling
            requests a single MCP session may issue. Default 50 —
            ordinary assistive workflows stay well under this.
        max_tokens_per_sampling_request: Refuse requests whose declared
            ``maxTokens`` exceeds this. Default 4096 — quota-exhaustion
            tell is usually a very large single request.
        forbid_persistent_instructions: If True, any message role of
            ``"system"`` inside a sampling request is rejected. Unit 42
            recommends treating only ``"user"`` / ``"assistant"`` /
            ``"tool"`` as legitimate sampling content.
        require_user_consent_per_request: If True, the caller must pass
            ``user_consented=True`` on *every* request — not once per
            session. This is the Unit 42 fix for MCP clients that
            latched approval session-wide.
    """

    max_sampling_requests_per_session: int = 50
    max_tokens_per_sampling_request: int = 4096
    forbid_persistent_instructions: bool = True
    require_user_consent_per_request: bool = True


@dataclass
class SamplingSessionState:
    """Per-session counters consumed by :func:`audit_sampling_request`.

    Attributes:
        session_id: Opaque session identifier — for log correlation.
        requests_made: Number of sampling requests processed so far
            during this session. Incremented on every successful audit.
    """

    session_id: str
    requests_made: int = field(default=0)


class SamplingQuotaExceeded(AirlockError):
    """Raised when an MCP session's sampling-request count exceeds the cap."""

    def __init__(self, *, session_id: str, count: int, cap: int) -> None:
        self.session_id = session_id
        self.count = count
        self.cap = cap
        super().__init__(
            f"MCP session {session_id!r} has issued {count} sampling requests, "
            f"exceeding the per-session cap of {cap}"
        )


class SamplingInstructionPersistenceError(AirlockError):
    """Raised when a sampling request carries a ``system``-role message.

    Unit 42 showed that servers abuse system-role messages inside
    sampling requests to forge a persistent instruction channel the
    end user never approved. Legitimate sampling should carry only
    user / assistant / tool messages.
    """

    def __init__(self, *, session_id: str, offending_role: str) -> None:
        self.session_id = session_id
        self.offending_role = offending_role
        super().__init__(
            f"MCP sampling request for session {session_id!r} contains a "
            f"{offending_role!r}-role message — persistent-instruction "
            "injection refused (Unit 42 attack pattern #2)"
        )


class SamplingConsentMissingError(AirlockError):
    """Raised when a sampling request lands without per-request user consent.

    The MCP spec requires human-in-the-loop approval of every sampling
    request. Some reference clients latched approval session-wide;
    Unit 42 demonstrated the resulting silent-sampling attack.
    """

    def __init__(self, *, session_id: str) -> None:
        self.session_id = session_id
        super().__init__(
            f"MCP sampling request for session {session_id!r} arrived without "
            "per-request user consent — refusing (Unit 42 attack pattern #3)"
        )


_LEGITIMATE_ROLES: frozenset[str] = frozenset({"user", "assistant", "tool"})


def _request_bodies(request: Any, session_id: str) -> list[Mapping[str, Any]]:
    """The mappings a sampling request's fields live in: the request and its ``params``.

    A ``sampling/createMessage`` JSON-RPC envelope carries ``messages`` /
    ``systemPrompt`` / ``maxTokens`` under ``params``; the bare body carries them at the
    top level. Both are read, so neither can hide the other.

    Raises:
        ValueError: ``request``, or a ``params`` it carries, is not a mapping.
    """
    if not isinstance(request, Mapping):
        raise ValueError(
            f"MCP sampling request for session {session_id!r} is a "
            f"{type(request).__name__}, not a mapping; refusing rather than skipping it"
        )
    bodies: list[Mapping[str, Any]] = [request]
    params = request.get("params")
    if isinstance(params, Mapping):
        bodies.append(params)
    elif params is not None:
        raise ValueError(
            f"MCP sampling request for session {session_id!r} carries params of type "
            f"{type(params).__name__}, not a mapping; refusing rather than skipping it"
        )
    return bodies


def _check_max_tokens(value: Any, session_id: str, cap: int) -> None:
    """Refuse a ``maxTokens`` over ``cap``, below 1, or of no readable numeric shape.

    An ``int``, a finite ``float`` and a numeric string are compared with the cap (the
    cap applied only to an ``int`` until 0.10.28, so ``1e7`` or ``"10000000"`` passed).
    A count below 1 is refused too: some model runtimes read ``-1`` as "no limit".

    Raises:
        ValueError: The value is unreadable, not positive, or exceeds ``cap``.
    """
    number: float | None = None
    try:
        if isinstance(value, numbers.Real) and not isinstance(value, bool):
            number = float(value)
        elif isinstance(value, str):
            number = float(value.strip())
    except OverflowError:
        number = math.inf  # an int too large for a float is over any cap
    except ValueError:
        number = None
    if number is None or math.isnan(number):
        raise ValueError(
            f"MCP sampling request for session {session_id!r} carries maxTokens={value!r}, "
            "which is not a token count; refusing rather than skipping the cap"
        )
    if number < 1:
        raise ValueError(
            f"MCP sampling request for session {session_id!r} asked for "
            f"maxTokens={value}, below 1 (a runtime may read it as no limit)"
        )
    if number > cap:
        raise ValueError(
            f"MCP sampling request for session "
            f"{session_id!r} asked for "
            f"maxTokens={value}, exceeds cap "
            f"{cap}"
        )


def _check_persistent_instructions(body: Mapping[str, Any], session_id: str) -> None:
    """Refuse a ``systemPrompt``, a non-user/assistant/tool role, or messages it cannot read.

    ``systemPrompt`` is the protocol's own persistent-instruction channel, so it is read
    like a ``system``-role message; an empty one carries no instruction and passes.

    Raises:
        SamplingInstructionPersistenceError: On any of the above.
    """
    prompt = body.get("systemPrompt")
    if prompt is not None and not (isinstance(prompt, str) and not prompt.strip()):
        raise SamplingInstructionPersistenceError(
            session_id=session_id, offending_role="systemPrompt"
        )
    messages = body.get("messages")
    if messages is None:
        return
    if not isinstance(messages, (list, tuple)):
        raise SamplingInstructionPersistenceError(
            session_id=session_id,
            offending_role=f"<unreadable messages: {type(messages).__name__}>",
        )
    for msg in messages:
        if not isinstance(msg, Mapping):
            offending = f"<unreadable message: {type(msg).__name__}>"
        else:
            role = msg.get("role")
            if isinstance(role, str) and role in _LEGITIMATE_ROLES:
                continue
            # A missing or non-string role was skipped until 0.10.28.
            offending = role if isinstance(role, str) else f"<unreadable role: {role!r}>"
        raise SamplingInstructionPersistenceError(session_id=session_id, offending_role=offending)


def audit_sampling_request(
    request: Mapping[str, Any],
    session_state: SamplingSessionState,
    cfg: SamplingGuardConfig,
    *,
    user_consented: bool = False,
) -> None:
    """Audit an MCP sampling request against the three Unit 42 vectors.

    On success, ``session_state.requests_made`` is incremented by one.

    Args:
        request: The MCP sampling request body (``messages``,
            ``maxTokens``, ``systemPrompt``, etc.), or the whole
            ``sampling/createMessage`` JSON-RPC message, whose ``params`` is read
            too. Shape per MCP spec 2025-11-25.
        session_state: Mutable per-session counter — callers are
            responsible for scoping this to a single MCP session.
        cfg: Active :class:`SamplingGuardConfig`. Typically from
            :func:`agent_airlock.policy_presets.unit42_mcp_sampling_defaults`.
        user_consented: Whether the end user has explicitly approved
            *this specific* sampling request. Must be True when
            ``cfg.require_user_consent_per_request`` is True.

    Raises:
        SamplingQuotaExceeded: Session has hit
            ``cfg.max_sampling_requests_per_session``.
        SamplingInstructionPersistenceError: Request carries a non-empty
            ``systemPrompt``, a message whose role is not user / assistant /
            tool (a missing role included), or messages of a shape the guard
            cannot read, and ``cfg.forbid_persistent_instructions`` is True.
        SamplingConsentMissingError: Per-request consent missing.
        ValueError: ``request`` (or its ``params``) is not a mapping, or
            ``maxTokens`` exceeds ``cfg.max_tokens_per_sampling_request``, is
            below 1, or is not a number. (ValueError, not AirlockError, because
            the client sending an out-of-spec budget is a caller mistake, not an
            attack signal.)
    """
    # 1. Consent — checked first so failure isn't muddled by quota math.
    if cfg.require_user_consent_per_request and not user_consented:
        raise SamplingConsentMissingError(session_id=session_state.session_id)

    # 2. Quota cap. Evaluated *before* increment so the Nth request
    #    (where N == cap) is blocked, not the (N+1)th.
    if session_state.requests_made >= cfg.max_sampling_requests_per_session:
        raise SamplingQuotaExceeded(
            session_id=session_state.session_id,
            count=session_state.requests_made,
            cap=cfg.max_sampling_requests_per_session,
        )

    bodies = _request_bodies(request, session_state.session_id)

    # 3. Per-request max-tokens sanity — callers that ask for 1M tokens
    #    in a single sampling call are almost certainly the
    #    quota-exhaustion tell Unit 42 calls out. ValueError, not
    #    AirlockError, because this is a misshapen request, not a
    #    security event. Absent maxTokens is not checked (the client's
    #    own default applies); any value present is read or refused.
    for body in bodies:
        if body.get("maxTokens") is not None:
            _check_max_tokens(
                body["maxTokens"],
                session_state.session_id,
                cfg.max_tokens_per_sampling_request,
            )

    # 4. Persistent-instruction injection — refuse systemPrompt and
    #    system-role (or unreadable) messages.
    if cfg.forbid_persistent_instructions:
        for body in bodies:
            _check_persistent_instructions(body, session_state.session_id)

    session_state.requests_made += 1
    logger.debug(
        "sampling_request_audited",
        session_id=session_state.session_id,
        requests_made=session_state.requests_made,
    )


__all__ = [
    "SamplingConsentMissingError",
    "SamplingGuardConfig",
    "SamplingInstructionPersistenceError",
    "SamplingQuotaExceeded",
    "SamplingSessionState",
    "audit_sampling_request",
]
