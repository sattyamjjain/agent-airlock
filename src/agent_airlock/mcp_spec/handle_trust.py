"""MCP 2026-07-28 stateless handle-channel trust (SEP-2567 + SEP-2243).

The 2026-07-28 revision removed the protocol-level session (SEP-2575) and moved two things
onto the tool-argument channel that used to live in trusted transport state:

* **Cross-call state** is now a *server-minted handle passed as an ordinary tool argument*
  (SEP-2567) — so a value that grants continuity now arrives in the same place as
  attacker-influenced tool inputs.
* **Custom headers** can be sourced *from tool parameters* via ``x-mcp-header`` (SEP-2243),
  rendered as ``Mcp-Param-{name}`` — so header values can now originate in the argument
  channel too.

Consequence: state and headers now share the injection-controlled channel. This module is
the deny-by-default contract check for that boundary, built only on stdlib traversal plus
airlock's shipped signature primitive (no new engine):

1. :func:`~agent_airlock.mcp_spec.statelessness.validate_state_handle_declared` — a handle
   argument must be an **explicit declared parameter** of the tool contract (a distinct
   trust class from caller data), not absorbed by ``**kwargs`` or smuggled as a ghost arg.
2. :func:`validate_no_reserved_header_override` — an ``x-mcp-header``-sourced header that
   would **set or override** a header airlock makes its own decisions on is rejected. The
   decision set is enumerated **explicitly** (:data:`RESERVED_DECISION_HEADERS`), not
   matched by prefix, so the trust boundary is auditable.
3. :func:`validate_handle_minted` — a presented handle that was **not minted within the
   current policy scope** is denied by default.

Honest limit: this is a contract layer. It can require a handle to be declared and to have
been minted in scope, but it cannot verify that a handle the server minted is one the server
*should* have minted (see ``docs/mcp/stateless-trust-boundary.md``).

References:
    - MCP 2026-07-28 specification (final).
    - SEP-2567 — explicit, server-minted state handles as ordinary tool arguments.
    - SEP-2243 — standard request headers + ``x-mcp-header`` custom headers from parameters.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

__all__ = [
    "RESERVED_DECISION_HEADERS",
    "HandleTrustError",
    "validate_handle_minted",
    "validate_no_reserved_header_override",
]

#: Headers airlock's own guards read to make security decisions. An ``x-mcp-header``-sourced
#: header (``Mcp-Param-{name}``) that resolves to one of these would let the tool-argument
#: channel set or override a value the policy trusts, so it is rejected. Enumerated
#: explicitly (lower-cased for case-insensitive comparison per RFC 9110) rather than matched
#: by a ``Mcp-*`` prefix, so the boundary is auditable and cannot silently widen.
RESERVED_DECISION_HEADERS: frozenset[str] = frozenset(
    {
        "mcp-protocol-version",  # transport.py — revision negotiation
        "mcp-method",  # header_integrity.py — SEP-2243 routing / body integrity
        "mcp-name",  # header_integrity.py — SEP-2243 routing / body integrity
        "authorization",  # oauth.py — bearer token
        "mcp-session-id",  # statelessness.py — removed session lifecycle
        "origin",  # mcp_origin_host_guard.py — DNS-rebinding
        "host",  # mcp_origin_host_guard.py / bind_address_guard.py
    }
)


class HandleTrustError(ValueError):
    """Raised when the stateless handle/header channel violates the trust boundary.

    The structured event describing the violation is attached as :attr:`audit_event` so the
    ``@Airlock`` seam can log a machine-readable record of the rejected request.
    """

    def __init__(self, message: str, audit_event: Mapping[str, Any]) -> None:
        super().__init__(message)
        #: Structured, machine-readable description of the rejection.
        self.audit_event: dict[str, Any] = dict(audit_event)


def _reject(reason: str, message: str, **fields: Any) -> HandleTrustError:
    return HandleTrustError(
        message,
        {
            "event": "mcp.handle_trust.reject",
            "spec": "SEP-2567/SEP-2243",
            "reason": reason,
            **fields,
        },
    )


def _reserved_names(reserved: Iterable[str]) -> frozenset[str]:
    """The reserved decision-header set, lower-cased.

    Raises:
        TypeError: ``reserved`` is a bare ``str`` / ``bytes`` (it would be read as its
            characters, so no real header would ever match) or holds a non-string.
    """
    if isinstance(reserved, (str, bytes, bytearray)):
        raise TypeError(f"reserved must be a collection of header names, not {reserved!r}")
    names = list(reserved)
    if not all(isinstance(name, str) for name in names):
        raise TypeError(f"reserved must hold header-name strings: {names!r}")
    return frozenset(name.strip().lower() for name in names)


def validate_no_reserved_header_override(
    candidate_headers: Iterable[str],
    *,
    reserved: Iterable[str] = RESERVED_DECISION_HEADERS,
) -> None:
    """Reject a tool-parameter-sourced header that targets a policy-decision header.

    A conformant ``x-mcp-header`` renders to ``Mcp-Param-{name}`` and never collides with a
    decision header; a definition (or misconfiguration) whose produced header name *is* one
    of the reserved decision headers would let the argument channel set or override a value
    the policy trusts, and is a confused-deputy vector.

    Every candidate is read: a bare string is refused rather than walked as its characters,
    and a candidate that is not a string (``bytes``, a nested list) is refused rather than
    skipped, as it was until 0.10.28. Surrounding whitespace is ignored when comparing.

    Args:
        candidate_headers: the header names the tool's ``x-mcp-header`` annotations would
            set (as they appear on the wire, e.g. ``Mcp-Param-Region``), or the raw
            ``x-mcp-header`` name values.
        reserved: the decision-header set (default :data:`RESERVED_DECISION_HEADERS`).

    Raises:
        HandleTrustError: if any candidate resolves (case-insensitively) to a reserved header,
            or the candidates (or one of them) are not header-name strings.
        TypeError: ``reserved`` is a bare string or holds a non-string.
    """
    reserved_set = _reserved_names(reserved)
    if isinstance(candidate_headers, (str, bytes, bytearray)) or not isinstance(
        candidate_headers, Iterable
    ):
        raise _reject(
            "unreadable_candidate_headers",
            f"candidate headers must be a collection of header names, got "
            f"{type(candidate_headers).__name__} {candidate_headers!r}; refusing rather "
            "than reading it as something else (SEP-2243)",
            header=repr(candidate_headers),
        )
    for name in candidate_headers:
        if not isinstance(name, str):
            raise _reject(
                "unreadable_candidate_header",
                f"candidate header {name!r} is a {type(name).__name__}, not a header-name "
                "string; refusing rather than skipping it (SEP-2243)",
                header=repr(name),
            )
        if name.strip().lower() in reserved_set:
            raise _reject(
                "reserved_header_override",
                f"x-mcp-header would set/override the policy-decision header {name!r}; "
                "tool-parameter headers must render to Mcp-Param-* and never to a header "
                "airlock makes decisions on (SEP-2243)",
                header=name,
            )


def _minted_pool(minted: Any, handle: Any) -> Iterable[Any]:
    """The handles a scope minted, as a container ``handle`` can be looked up in.

    ``None`` is a scope that minted nothing. A ``str`` / ``bytes`` is one token, never its
    characters (until 0.10.28 ``minted="h1x"`` admitted ``"h"``). Any other iterable is
    its items; anything else is refused.

    Raises:
        HandleTrustError: ``minted`` is not iterable.
    """
    if minted is None:
        return ()
    if isinstance(minted, (str, bytes, bytearray)):
        return (minted,)
    if isinstance(minted, (set, frozenset)):
        return minted
    if not isinstance(minted, Iterable):
        raise _reject(
            "unreadable_minted_scope",
            f"the minted scope is a {type(minted).__name__}, not a collection of handles; "
            "refusing every handle against it (SEP-2567)",
            handle=handle,
        )
    return tuple(minted)


def validate_handle_minted(handle: Any, *, minted: Iterable[Any]) -> None:
    """Deny a server-minted handle that was not minted within the current policy scope.

    Deny-by-default: if the scope has minted nothing, or the presented handle is not among
    the minted values, the call is rejected. ``minted`` is whatever the policy scope tracks
    as the handles it issued (a set/frozenset, or any container/iterable of values); a
    ``str`` scope is one token, and ``None`` is a scope that minted nothing.

    Raises:
        HandleTrustError: if ``handle`` was not minted within the scope, cannot be looked
            up in it (an unhashable handle against a set), or the scope is not iterable.
    """
    pool = _minted_pool(minted, handle)
    try:
        found = handle in pool
    except (TypeError, ValueError):  # unhashable, or an uncomparable value
        found = False
    if not found:
        raise _reject(
            "unminted_handle",
            f"handle {handle!r} was not minted within the current policy scope; a "
            "server-minted handle (SEP-2567) is denied by default unless it was issued here",
            handle=handle,
        )
