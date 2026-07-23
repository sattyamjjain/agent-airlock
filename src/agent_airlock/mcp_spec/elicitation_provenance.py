"""MCP 2026-07-28 elicitation provenance guard (SEP-2260).

SEP-2260 makes **any unsolicited server→client request invalid**: a server may only
issue a server-initiated request (an *elicitation* / sampling prompt) **within an active
client-initiated request window**. A server that pushes an elicitation with no client
request in flight is acting unsolicited — a clean injection vector, because the host
renders the prompt as if the user's own system asked for it.

This guard is the **provenance** (the *when*) axis, complementary to the shipped
:class:`~agent_airlock.mcp_spec.elicitation_guard.ElicitationGuard`, which classifies the
elicitation's *content* (credential / policy-override / destructive / benign). Use both:
this one refuses the elicitation outright when it is unsolicited; the content guard then
classifies the payloads that survive.

It tracks the client-initiated requests currently in flight (a *window* is open while any
is active) and refuses an elicitation raised outside one. It reuses the shipped
observability hook (:func:`agent_airlock.observability.track_event`) — no new engine, no
new dependency — and integrates with the ``@observe`` / call seam via the
:func:`client_request_window` context manager the operator wraps a client request in.

Deny-by-default; stdlib only, Pydantic-only core, in-process (not a proxy).

References:
    - SEP-2260 — server→client requests must be solicited (MCP 2026-07-28).
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

import structlog

from ..observability import track_event

logger = structlog.get_logger("agent-airlock.mcp_spec.elicitation_provenance")

__all__ = [
    "ElicitationProvenanceError",
    "RequestWindow",
    "begin_client_request",
    "check_elicitation_solicited",
    "client_request_window",
    "end_client_request",
    "new_request_window",
]

_DECISION_EVENT = "mcp.elicitation_provenance.decision"


@dataclass
class RequestWindow:
    """The client-initiated requests currently in flight (one per server / session).

    A provenance *window* is open while any client request is active; a server-initiated
    elicitation is only solicited while the window is open.
    """

    active: set[str] = field(default_factory=set)

    @property
    def is_open(self) -> bool:
        """True while at least one client-initiated request is in flight."""
        return bool(self.active)


class ElicitationProvenanceError(ValueError):
    """Raised when a server-initiated elicitation is unsolicited (fail-closed; SEP-2260).

    Carries a structured, machine-readable :attr:`audit_event` in the same shape
    :class:`~agent_airlock.mcp_spec.header_integrity.HeaderBodyMismatchError` uses.
    """

    def __init__(self, message: str, audit_event: Mapping[str, Any]) -> None:
        super().__init__(message)
        #: Structured, machine-readable description of the refusal.
        self.audit_event: dict[str, Any] = dict(audit_event)


def new_request_window() -> RequestWindow:
    """Return a fresh per-server / per-session request window."""
    return RequestWindow()


def begin_client_request(window: RequestWindow, request_id: str) -> None:
    """Open the window for a client-initiated request (call at request start)."""
    window.active.add(str(request_id))


def end_client_request(window: RequestWindow, request_id: str) -> None:
    """Close a client-initiated request (call at request end)."""
    window.active.discard(str(request_id))


@contextmanager
def client_request_window(window: RequestWindow, request_id: str) -> Iterator[None]:
    """Context manager marking an active client-initiated request window.

    Wrap the handling of a client request in this (alongside ``@observe``); server
    elicitations raised inside the ``with`` are solicited, those raised outside are not.
    """
    begin_client_request(window, request_id)
    try:
        yield
    finally:
        end_client_request(window, request_id)


def _refuse(
    reason: str, message: str, *, server_origin: str, request_id: str | None
) -> ElicitationProvenanceError:
    audit: dict[str, Any] = {
        "event": "mcp.elicitation_provenance.refuse",
        "reason": reason,
        "server_origin": server_origin,
        "request_id": request_id,
    }
    track_event(_DECISION_EVENT, dict(audit))
    logger.warning(
        "elicitation_provenance_blocked",
        reason=reason,
        server_origin=server_origin,
        request_id=request_id,
    )
    return ElicitationProvenanceError(message, audit)


def check_elicitation_solicited(
    window: RequestWindow,
    *,
    request_id: str | None = None,
    server_origin: str = "",
) -> None:
    """Refuse a server-initiated elicitation that is not within an active client request.

    Args:
        window: The per-server request window.
        request_id: If given, the client request the elicitation claims to belong to —
            it must be one currently in flight.
        server_origin: A short id of the originating server, for the audit record.

    Raises:
        ElicitationProvenanceError: if no client request is in flight (unsolicited), or
            the referenced ``request_id`` is not an active window (foreign). The error
            carries a structured ``audit_event``.
    """
    if not window.is_open:
        raise _refuse(
            "unsolicited_elicitation",
            "server-initiated elicitation raised with no active client request — "
            "unsolicited server→client requests are invalid (SEP-2260)",
            server_origin=server_origin,
            request_id=request_id,
        )
    if request_id is not None and str(request_id) not in window.active:
        raise _refuse(
            "foreign_request_window",
            f"server-initiated elicitation references request {request_id!r} that is not "
            "in flight — refusing (SEP-2260)",
            server_origin=server_origin,
            request_id=request_id,
        )
