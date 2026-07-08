"""MCP 2026-07-28 request header-integrity conformance (SEP-2243).

The MCP 2026-07-28 Streamable HTTP transport **requires** two routing headers on
every request — ``Mcp-Method`` and ``Mcp-Name`` — so operational infrastructure
can route on the operation without inspecting the body (SEP-2243). Because those
headers now drive routing/rate-limiting/authorization at the edge while the
server executes the body, a request whose headers disagree with its body is a
confused-deputy vector: one operation is routed past the gateway while a
different one runs. The spec closes this with a server-side integrity rule.
Verbatim from the 2026-07-28 release candidate
(https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/):

    "The Streamable HTTP transport now requires ``Mcp-Method`` and ``Mcp-Name``
    headers (SEP-2243) so load balancers, gateways, and rate-limiters can route
    on the operation without inspecting the body."

    "Servers reject requests where the headers and body disagree."

This module provides that single contract check, built **only** on stdlib
mapping traversal — it adds no new detection engine:

* :func:`validate_header_body_integrity` — fail closed (deny) when a required
  routing header is absent, or when ``Mcp-Method`` / ``Mcp-Name`` disagree with
  the request body's method / operation name. On any violation it raises
  :class:`HeaderBodyMismatchError`, which carries a structured ``audit_event``
  mapping for the audit log.

References:
    - MCP 2026-07-28 specification (final).
    - SEP-2243 — ``Mcp-Method`` / ``Mcp-Name`` routing headers + header/body
      integrity ("Servers reject requests where the headers and body disagree").
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

__all__ = [
    "METHOD_HEADER",
    "NAME_HEADER",
    "HeaderBodyMismatchError",
    "validate_header_body_integrity",
]

#: Routing header carrying the JSON-RPC method (SEP-2243).
METHOD_HEADER = "Mcp-Method"

#: Routing header carrying the operation / tool name (SEP-2243).
NAME_HEADER = "Mcp-Name"


class HeaderBodyMismatchError(ValueError):
    """Raised when SEP-2243 routing headers are missing or disagree with the body.

    The structured event describing the violation is attached as
    :attr:`audit_event` so the ``@Airlock`` seam can log a machine-readable
    record of the rejected request.
    """

    def __init__(self, message: str, audit_event: Mapping[str, Any]) -> None:
        super().__init__(message)
        #: Structured, machine-readable description of the rejection.
        self.audit_event: dict[str, Any] = dict(audit_event)


def _header_value(request: Mapping[str, Any], name: str) -> Any:
    """Look a header up case-insensitively at the top level or under ``headers``.

    SEP-2243 headers ride the Streamable HTTP transport, so they live under a
    ``headers`` mapping; a flattened top-level form is accepted too. Mirrors the
    lookup surface of :mod:`agent_airlock.mcp_spec.statelessness`.
    """
    wanted = name.lower()
    containers: list[Mapping[str, Any]] = [request]
    sub = request.get("headers")
    if isinstance(sub, Mapping):
        containers.append(sub)
    for container in containers:
        for key, value in container.items():
            if isinstance(key, str) and key.lower() == wanted:
                return value
    return None


def _body_method(request: Mapping[str, Any]) -> Any:
    """The JSON-RPC method the body actually invokes."""
    return request.get("method")


def _body_name(request: Mapping[str, Any]) -> Any:
    """The operation/tool name the body actually targets.

    MCP carries the tool/prompt name under ``params.name`` (e.g. ``tools/call``);
    a flattened top-level ``name`` is accepted too.
    """
    params = request.get("params")
    if isinstance(params, Mapping) and "name" in params:
        return params["name"]
    return request.get("name")


def _reject(
    reason: str,
    message: str,
    *,
    header_method: Any,
    body_method: Any,
    header_name: Any,
    body_name: Any,
) -> HeaderBodyMismatchError:
    """Build the structured-audit-carrying rejection error."""
    audit_event = {
        "event": "mcp.header_integrity.reject",
        "spec": "SEP-2243",
        "reason": reason,
        "header_method": header_method,
        "body_method": body_method,
        "header_name": header_name,
        "body_name": body_name,
    }
    return HeaderBodyMismatchError(message, audit_event)


def validate_header_body_integrity(
    request: Mapping[str, Any],
    *,
    method_header: str = METHOD_HEADER,
    name_header: str = NAME_HEADER,
) -> None:
    """Reject a request whose SEP-2243 routing headers are missing or disagree with the body.

    Args:
        request: The request / tool-call mapping. Headers are read from a
            ``headers`` sub-mapping (or, flattened, the top level); the body
            method is ``request['method']`` and the body operation name is
            ``request['params']['name']`` (or a top-level ``name``).
        method_header: Header carrying the JSON-RPC method (default ``Mcp-Method``).
        name_header: Header carrying the operation name (default ``Mcp-Name``).

    Raises:
        HeaderBodyMismatchError: If a required routing header is absent/empty, or
            if a header disagrees with the corresponding body field. The raised
            error carries a structured ``audit_event`` mapping.
    """
    header_method = _header_value(request, method_header)
    header_name = _header_value(request, name_header)
    body_method = _body_method(request)
    body_name = _body_name(request)

    # (a) Both routing headers are REQUIRED by SEP-2243. Deny-by-default: an
    #     absent (or empty) header is a rejected request, not an exempt one.
    if header_method in (None, ""):
        raise _reject(
            "missing_method_header",
            f"required {method_header!r} routing header is absent (SEP-2243)",
            header_method=header_method,
            body_method=body_method,
            header_name=header_name,
            body_name=body_name,
        )
    if header_name in (None, ""):
        raise _reject(
            "missing_name_header",
            f"required {name_header!r} routing header is absent (SEP-2243)",
            header_method=header_method,
            body_method=body_method,
            header_name=header_name,
            body_name=body_name,
        )

    # (b) "Servers reject requests where the headers and body disagree" (SEP-2243).
    #     Compared whenever the body declares the corresponding field.
    if body_method is not None and header_method != body_method:
        raise _reject(
            "method_mismatch",
            f"{method_header!r}={header_method!r} disagrees with body method "
            f"{body_method!r} (SEP-2243)",
            header_method=header_method,
            body_method=body_method,
            header_name=header_name,
            body_name=body_name,
        )
    if body_name is not None and header_name != body_name:
        raise _reject(
            "name_mismatch",
            f"{name_header!r}={header_name!r} disagrees with body name {body_name!r} (SEP-2243)",
            header_method=header_method,
            body_method=body_method,
            header_name=header_name,
            body_name=body_name,
        )
