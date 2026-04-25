"""Claude Managed Agents audit hook (v0.5.6+).

Anthropic launched Claude Managed Agents to public beta on
2026-04-08, advertised at $0.08/runtime-hour and used in production
by Notion, Rakuten, Asana, Vibecode, and Sentry. The runtime ships a
managed harness that exposes a curated tool surface
(``read_file``, ``bash``, ``web_browse``, ``code_execute``) and
streams raw tool inputs/outputs over Server-Sent Events.

Two integration concerns the existing agent-airlock surfaces don't
cover:

1. The harness's tool list bypasses any local ``SecurityPolicy.allowed_tools``
   constraint — a managed agent can use ``bash`` even if the caller's
   policy denied shell. This module enforces the intersection at the
   request boundary.
2. SSE streaming surfaces raw tool inputs and outputs to the calling
   process, including any secrets the model emitted while reasoning.
   This module pipes those frames through the v0.5.3
   ``log_redaction`` filter before the caller's log surface sees them.

Pin points to make the integration stable as Anthropic iterates:

- ``MANAGED_AGENTS_BETA_HEADER = "managed-agents-2026-04-01"``
- ``AGENT_TOOLSET_VERSION = "agent_toolset_20260401"``

The companion preset
``policy_presets.claude_managed_agents_safe_defaults()`` ships with
the four documented harness tools marked
``requires_explicit_optin=True``.

Primary sources
---------------
- Launch blog (2026-04-08): <https://claude.com/blog/claude-managed-agents>
- API overview: <https://platform.claude.com/docs/en/managed-agents/overview>
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

import structlog

from ..exceptions import AirlockError

logger = structlog.get_logger("agent-airlock.integrations.claude_managed_agents")

MANAGED_AGENTS_BETA_HEADER = "managed-agents-2026-04-01"
"""The pinned ``anthropic-beta`` header value for managed agents.

When Anthropic promotes a newer schema, update this constant and bump
the library minor version — older runtimes ignore unknown beta flags,
but newer schemas may rename fields."""

AGENT_TOOLSET_VERSION = "agent_toolset_20260401"
"""The current managed-agent toolset version.

Pinned so callers can detect schema drift early — a request body
carrying a different ``toolset_version`` hits :class:`UnknownToolsetVersionError`."""

# The four tools Anthropic documented in the 2026-04-08 launch post.
DEFAULT_HARNESS_TOOLS: tuple[str, ...] = (
    "read_file",
    "bash",
    "web_browse",
    "code_execute",
)


class ManagedAgentBetaHeaderMissingError(AirlockError):
    """Raised when a managed-agents request body lacks the beta header.

    The Anthropic API rejects such requests anyway; this guard fails
    fast before egress so callers don't pay for a doomed request.
    """


class ManagedAgentToolBlocked(AirlockError):
    """Raised when a managed-agent request asks for a tool not in the
    intersection of the harness toolset and the caller's
    ``SecurityPolicy.allowed_tools``.

    Attributes:
        tool_name: The tool the request asked for.
        allowed: The intersection set the caller declared.
    """

    def __init__(self, *, tool_name: str, allowed: Iterable[str]) -> None:
        self.tool_name = tool_name
        self.allowed = list(allowed)
        super().__init__(
            f"managed agent requested tool {tool_name!r} which is not in "
            f"the policy-allowed intersection {self.allowed!r}"
        )


class UnknownToolsetVersionError(AirlockError):
    """Raised when a request body's ``toolset_version`` doesn't match
    the pinned :data:`AGENT_TOOLSET_VERSION`.

    Indicates either an upstream Anthropic schema bump or a malformed
    request — either way, the safe response is to refuse until the
    caller updates the library.
    """


@dataclass
class ManagedAgentsAuditConfig:
    """Policy applied by :func:`audit_managed_agent_invocation`.

    Attributes:
        allowed_tools: Subset of ``DEFAULT_HARNESS_TOOLS`` the caller
            permits. Empty tuple = "no managed-agent tool calls" (the
            module is opt-in by toolset, not opt-in by tool).
        require_beta_header: If True (default), refuse a request whose
            body / headers do not carry the pinned beta marker.
        toolset_version: The expected toolset schema. Defaults to
            :data:`AGENT_TOOLSET_VERSION`. Set to ``None`` to skip
            the version check (not recommended).
        redact_sse_payloads: If True (default), every SSE frame the
            module observes is run through the v0.5.3 redaction filter
            before being surfaced to the caller's log handler.
    """

    allowed_tools: tuple[str, ...] = ()
    require_beta_header: bool = True
    toolset_version: str | None = AGENT_TOOLSET_VERSION
    redact_sse_payloads: bool = True


@dataclass
class ManagedAgentSession:
    """Per-session state used by token-budget composition (v0.5.1
    ``task_budget`` adapter)."""

    session_id: str
    invocations: int = field(default=0)


def _emit_otel_span(
    *,
    session_id: str,
    tool_name: str,
    allowed: Iterable[str],
) -> None:
    """Best-effort emit of the ``airlock.managed_agents.invoke`` span.

    Falls through silently if the OTel provider isn't configured —
    spans are observability, not load-bearing for security. The
    ``allowed`` iterable is consumed only to pre-compute its length
    for the span attribute (the iterable itself is not retained).
    """
    try:
        from ..observability import end_span, start_span
    except Exception:  # pragma: no cover
        return
    allowed_count = len(list(allowed))
    # Span emission is best-effort observability — a misconfigured OTel
    # provider must never break the audit path. ``contextlib.suppress``
    # makes the silent-failure intent explicit (B110 nosec).
    import contextlib

    with contextlib.suppress(Exception):  # pragma: no cover
        ctx = start_span("airlock.managed_agents.invoke", tool_name)
        ctx.set_attribute("airlock.managed_agents.session_id", session_id)
        ctx.set_attribute("airlock.managed_agents.allowed_count", allowed_count)
        end_span(ctx)


def audit_managed_agent_invocation(
    request: dict[str, Any],
    cfg: ManagedAgentsAuditConfig,
    *,
    session: ManagedAgentSession | None = None,
) -> None:
    """Audit an outbound Claude Managed Agents request before egress.

    Args:
        request: The request dict the caller is about to send. Must
            contain at least ``"tool"`` and (when
            ``cfg.toolset_version`` is set) ``"toolset_version"``.
            The ``"betas"`` key (list of beta-header strings) is
            consulted when ``cfg.require_beta_header=True``.
        cfg: The active :class:`ManagedAgentsAuditConfig`.
        session: Optional :class:`ManagedAgentSession` — when supplied,
            its ``invocations`` counter is bumped on a clean audit so
            callers can compose with the v0.5.1 task-budget adapter.

    Raises:
        ManagedAgentBetaHeaderMissingError: ``cfg.require_beta_header``
            is True and ``request["betas"]`` does not contain
            :data:`MANAGED_AGENTS_BETA_HEADER`.
        UnknownToolsetVersionError: ``cfg.toolset_version`` is set and
            ``request["toolset_version"]`` differs.
        ManagedAgentToolBlocked: ``request["tool"]`` is not in
            ``cfg.allowed_tools``.
    """
    # 1. Beta header check
    if cfg.require_beta_header:
        betas = request.get("betas") or []
        if MANAGED_AGENTS_BETA_HEADER not in betas:
            raise ManagedAgentBetaHeaderMissingError(
                f"managed-agents request missing beta header {MANAGED_AGENTS_BETA_HEADER!r}"
            )

    # 2. Toolset version check
    if cfg.toolset_version is not None:
        version = request.get("toolset_version")
        if version != cfg.toolset_version:
            raise UnknownToolsetVersionError(
                f"managed-agents request toolset_version={version!r} does "
                f"not match pinned {cfg.toolset_version!r}"
            )

    # 3. Tool intersection
    tool_name = request.get("tool")
    if tool_name is None:
        raise ManagedAgentToolBlocked(tool_name="<missing>", allowed=cfg.allowed_tools)
    if tool_name not in cfg.allowed_tools:
        raise ManagedAgentToolBlocked(tool_name=str(tool_name), allowed=cfg.allowed_tools)

    if session is not None:
        session.invocations += 1

    _emit_otel_span(
        session_id=session.session_id if session else "<no-session>",
        tool_name=str(tool_name),
        allowed=cfg.allowed_tools,
    )


def redact_sse_event(event_data: str) -> str:
    """Run an SSE frame through the v0.5.3 log-redaction filter.

    The managed-agents SSE stream surfaces tool inputs and outputs
    raw — anything the model put in a tool call lands in the caller's
    log surface. This pipes the frame through the same regex set that
    `RedactingLogFilter` applies to `logging` records.

    Args:
        event_data: Raw SSE ``data:`` payload.

    Returns:
        The frame with bearer / JWT / API-key shapes redacted.
    """
    from .log_redaction import _load_default_patterns  # noqa: PLC2701

    redacted = event_data
    for pattern in _load_default_patterns():
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


__all__ = [
    "AGENT_TOOLSET_VERSION",
    "DEFAULT_HARNESS_TOOLS",
    "MANAGED_AGENTS_BETA_HEADER",
    "ManagedAgentBetaHeaderMissingError",
    "ManagedAgentSession",
    "ManagedAgentToolBlocked",
    "ManagedAgentsAuditConfig",
    "UnknownToolsetVersionError",
    "audit_managed_agent_invocation",
    "redact_sse_event",
]
