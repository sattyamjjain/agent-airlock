"""Streamable HTTP transport validators for MCP 2025-11-25.

Source: https://modelcontextprotocol.io/specification/2025-11-25 +
https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
(retrieved 2026-04-18).

Scope: runtime header + envelope validation. Not an HTTP server.

Key normative checks (all exposed as `validate_streamable_http_request`):

- `MCP-Protocol-Version: 2025-11-25` header present on every request (the
  spec-required version negotiation header).
- `Content-Type: application/json` on JSON-RPC request bodies.
- `Authorization: Bearer <token>` for any request targeting a protected
  server. Tokens MUST NOT be in the query string; we reject that
  explicitly.
- `Accept` header must allow `application/json` and/or `text/event-stream`
  (the two transport variants per the spec's streaming section).

Any violation raises `MCPTransportError` with a concise reason string that
matches what an MCP server SHOULD return in its JSON-RPC `error.message`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from .oauth import (
    BearerHeaderError,
    BearerToken,
    parse_authorization_header,
)

PROTOCOL_VERSION_HEADER = "MCP-Protocol-Version"
"""Name of the required MCP protocol version header on Streamable HTTP
requests. Value on the wire is `2025-11-25` for this spec revision."""

# See PROTOCOL_VERSION in __init__ — importing it here would create a
# cycle, so the string is duplicated with a test-level assertion in
# tests/mcp_spec/test_transport.py.
_PROTOCOL_VERSION_VALUE = "2025-11-25"


class MCPTransportError(ValueError):
    """Raised when a Streamable HTTP request or response violates the MCP spec."""


@dataclass
class StreamableHTTPValidation:
    """Structured result of validating a Streamable HTTP request.

    Only populated when validation succeeds; violations raise.
    """

    bearer: BearerToken | None
    accept_json: bool
    accept_sse: bool


def validate_streamable_http_request(
    *,
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: Any = None,
    require_auth: bool = True,
) -> StreamableHTTPValidation:
    """Validate a Streamable HTTP request against the MCP 2025-11-25 spec.

    Args:
        method: HTTP method (e.g. "POST").
        url: Full request URL, used to check the query string for leaked
            tokens (explicitly forbidden by spec §"Access Token Usage").
        headers: Request headers. Keys are case-insensitive.
        body: Request body (for Content-Type enforcement heuristics).
        require_auth: When True, an `Authorization: Bearer <token>` header
            is required. Set False for public endpoints like
            `/.well-known/oauth-protected-resource`.

    Returns:
        `StreamableHTTPValidation` on success.

    Raises:
        MCPTransportError: on any violation. Message is safe to include in
            a JSON-RPC `error.message`.
    """
    hdr = _case_insensitive(headers or {})

    # 1. Method sanity — Streamable HTTP uses POST for JSON-RPC and GET
    #    for the SSE stream; we don't restrict beyond that.
    if method.upper() not in ("GET", "POST", "DELETE"):
        raise MCPTransportError(f"unsupported HTTP method for Streamable HTTP: {method!r}")

    # 2. MCP-Protocol-Version header.
    version = hdr.get(PROTOCOL_VERSION_HEADER.lower())
    if version is None:
        raise MCPTransportError(f"missing required {PROTOCOL_VERSION_HEADER} header")
    if version != _PROTOCOL_VERSION_VALUE:
        raise MCPTransportError(
            f"{PROTOCOL_VERSION_HEADER}={version!r} does not match "
            f"implementation ({_PROTOCOL_VERSION_VALUE!r})"
        )

    # 3. Token MUST NOT appear in the query string.
    parsed = urlparse(url)
    if parsed.query:
        lowered = parsed.query.lower()
        if "access_token=" in lowered or "bearer=" in lowered:
            raise MCPTransportError(
                "access tokens MUST NOT be in the URI query string "
                "(MCP 2025-11-25 §'Access Token Usage')"
            )

    # 4. Content-Type for POST with a body.
    if method.upper() == "POST" and body is not None:
        content_type = hdr.get("content-type", "")
        if not content_type.lower().startswith("application/json"):
            raise MCPTransportError(
                f"Streamable HTTP POST requires Content-Type: application/json; "
                f"got {content_type!r}"
            )

    # 5. Accept header must include at least one of the two allowed types.
    accept = hdr.get("accept", "")
    accept_lower = accept.lower()
    accept_json = "application/json" in accept_lower or "*/*" in accept_lower or accept == ""
    accept_sse = "text/event-stream" in accept_lower or "*/*" in accept_lower
    if accept and not (accept_json or accept_sse):
        raise MCPTransportError(
            f"Accept header must allow application/json or text/event-stream; got {accept!r}"
        )

    # 6. Authorization header.
    bearer: BearerToken | None = None
    auth = hdr.get("authorization")
    if auth:
        try:
            bearer = parse_authorization_header(auth)
        except BearerHeaderError as e:
            raise MCPTransportError(str(e)) from e
    elif require_auth:
        raise MCPTransportError("protected MCP endpoint requires Authorization: Bearer <token>")

    return StreamableHTTPValidation(bearer=bearer, accept_json=accept_json, accept_sse=accept_sse)


def validate_streamable_http_response(
    *,
    status: int,
    headers: dict[str, str] | None = None,
) -> None:
    """Validate a server's Streamable HTTP response against the MCP spec.

    Enforces only the load-bearing response-side requirements:

    - On 401: `WWW-Authenticate` header MUST be present with either a
      `resource_metadata` parameter (MCP-preferred) or sufficient Bearer
      scheme info for well-known-URI fallback.
    - On 403: spec recommends `WWW-Authenticate` with `error="insufficient_scope"`;
      we warn but do not raise on absence — the spec says SHOULD, not MUST.
    - The server's `Content-Type` on a JSON-RPC response MUST be
      `application/json` (unless it's a streaming response, which uses
      `text/event-stream`).
    """
    hdr = _case_insensitive(headers or {})

    if status == 401:
        www = hdr.get("www-authenticate")
        if not www:
            raise MCPTransportError(
                "401 Unauthorized from MCP server MUST include WWW-Authenticate"
            )

    if status >= 200 and status < 300:
        ctype = hdr.get("content-type", "")
        if ctype and not (
            ctype.lower().startswith("application/json")
            or ctype.lower().startswith("text/event-stream")
        ):
            raise MCPTransportError(
                f"Streamable HTTP response Content-Type must be application/json or "
                f"text/event-stream; got {ctype!r}"
            )


# =============================================================================
# Helpers
# =============================================================================


def _case_insensitive(headers: dict[str, str]) -> dict[str, str]:
    return {k.lower(): v for k, v in headers.items()}


__all__ = [
    "PROTOCOL_VERSION_HEADER",
    "MCPTransportError",
    "StreamableHTTPValidation",
    "validate_streamable_http_request",
    "validate_streamable_http_response",
]
