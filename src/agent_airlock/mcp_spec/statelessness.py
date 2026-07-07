"""MCP 2026-07-28 statelessness conformance (SEP-2567 / SEP-2575).

The MCP 2026-07-28 specification removed the server-side **session lifecycle**: there
is no ``initialize`` → session handshake and no ``Mcp-Session-Id`` header any more
(SEP-2575). State that used to live implicitly in a server session is now passed
**explicitly, as an ordinary typed tool argument** (SEP-2567).

This module provides the two contract checks the stateless model needs, built **only**
on airlock's existing signature / ghost-argument primitives — it adds no new detection
engine:

* :func:`validate_stateless_request` — reject a call that still carries a
  ``Mcp-Session-Id`` header or that invokes a removed session-lifecycle method.
* :func:`validate_state_handle_declared` — a state handle passed as a tool argument
  must be an **explicit declared parameter** of the tool contract, not something
  absorbed by ``**kwargs`` or smuggled as a ghost argument. Reuses
  :func:`agent_airlock.validator.get_valid_parameters` and raises the shipped
  :class:`agent_airlock.validator.GhostArgumentError`.

References:
    - MCP 2026-07-28 specification (final).
    - SEP-2567 — explicit state handles as ordinary tool arguments.
    - SEP-2575 — removal of the session lifecycle / ``Mcp-Session-Id``.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from ..validator import GhostArgumentError, get_valid_parameters

__all__ = [
    "SESSION_HEADER",
    "SESSION_LIFECYCLE_METHODS",
    "DEFAULT_STATE_PARAMS",
    "StatefulSessionError",
    "validate_stateless_request",
    "validate_state_handle_declared",
]

#: The transport header the removed session lifecycle used.
SESSION_HEADER = "Mcp-Session-Id"

#: JSON-RPC methods that only exist under the removed session lifecycle.
SESSION_LIFECYCLE_METHODS = frozenset({"initialize", "notifications/initialized"})

#: Argument names conventionally used to carry an explicit state handle.
DEFAULT_STATE_PARAMS: tuple[str, ...] = (
    "state",
    "state_handle",
    "cursor",
    "resume_token",
    "session_state",
)


class StatefulSessionError(ValueError):
    """Raised when a call still depends on the removed MCP session lifecycle."""


def _candidate_headers(request: Mapping[str, Any]) -> list[tuple[Any, Any]]:
    """Every (key, value) pair a session header could hide in."""
    pairs: list[tuple[Any, Any]] = list(request.items())
    for nested in ("headers", "meta", "_meta", "transport"):
        sub = request.get(nested)
        if isinstance(sub, Mapping):
            pairs.extend(sub.items())
    return pairs


def validate_stateless_request(
    request: Mapping[str, Any],
    *,
    method: str | None = None,
    session_header: str = SESSION_HEADER,
) -> None:
    """Reject a request that assumes the removed MCP session lifecycle.

    Args:
        request: The request/tool-call mapping. The session header is looked for at
            the top level and inside ``headers`` / ``meta`` / ``_meta`` / ``transport``.
        method: The JSON-RPC method, if not carried on ``request['method']``.
        session_header: Header name to reject (default ``Mcp-Session-Id``).

    Raises:
        StatefulSessionError: If the request carries a non-empty session header or
            invokes a session-lifecycle method.
    """
    resolved_method = method if method is not None else request.get("method")
    if isinstance(resolved_method, str) and resolved_method in SESSION_LIFECYCLE_METHODS:
        raise StatefulSessionError(
            f"method {resolved_method!r} assumes the removed initialize→session "
            "handshake; MCP 2026-07-28 is stateless (SEP-2575)"
        )
    wanted = session_header.lower()
    for key, value in _candidate_headers(request):
        if isinstance(key, str) and key.lower() == wanted and value not in (None, ""):
            raise StatefulSessionError(
                f"request carries {session_header!r}; the MCP session lifecycle was "
                "removed in 2026-07-28 (SEP-2575). Pass state explicitly as a tool arg."
            )


def validate_state_handle_declared(
    tool: Callable[..., Any],
    kwargs: Mapping[str, Any],
    *,
    state_params: Sequence[str] = DEFAULT_STATE_PARAMS,
) -> None:
    """Require every state-handle argument to be an explicit declared parameter.

    SEP-2567 makes state an *ordinary, typed contract parameter*. A state handle that
    is absorbed by ``**kwargs`` (not explicitly declared) or passed as a ghost
    argument is exactly the implicit-state anti-pattern the stateless model removes.

    This reuses airlock's shipped signature primitive
    (:func:`~agent_airlock.validator.get_valid_parameters`) — no new engine. Strict
    *typing* of the declared parameter is then enforced by airlock's existing
    Pydantic strict validator at call time.

    Args:
        tool: The tool callable whose declared contract is inspected.
        kwargs: The arguments the tool was called with.
        state_params: Argument names treated as state handles.

    Raises:
        GhostArgumentError: If a state handle is not an explicit declared parameter.
    """
    valid_params, _accepts_kwargs = get_valid_parameters(tool)
    handles = set(state_params)
    offenders = {name for name in kwargs if name in handles and name not in valid_params}
    if offenders:
        raise GhostArgumentError(getattr(tool, "__name__", "tool"), offenders)
