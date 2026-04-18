"""MCP 2025-11-25 spec compliance helpers (Phase 1.2).

The Model Context Protocol 2025-11-25 release added:

- **Tasks primitive** (SEP-1686) — a `call-now, fetch-later` pattern where
  any JSON-RPC request can return a task handle that the client polls for
  status and results.
- **Streamable HTTP transport** — remote MCP servers carry JSON-RPC over
  HTTP with standard headers instead of a bespoke stdio protocol.
- **OAuth 2.1 with PKCE S256 mandatory** and **RFC 8707 `resource`
  parameter mandatory** for remote servers.

This submodule is intentionally scoped to **validators and schema helpers**
that runtime middleware can call:

- `oauth` — PKCE challenge/verifier generators, resource-parameter
  canonicalisation, Protected Resource Metadata parser, Authorization
  Server Metadata parser, Bearer-token audience validator.
- `tasks` — Pydantic V2 strict models for the task-state machine.
- `transport` — Streamable HTTP header & envelope validation.

It is NOT:

- An OAuth authorization server
- An MCP server framework (that's FastMCP; we already integrate with it)
- A DPoP implementation (still SEP-draft per the spec page we verified;
  flagged UNVERIFIED and deferred)

Every requirement implemented here is traceable to either
https://modelcontextprotocol.io/specification/2025-11-25 or
https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
(retrieved 2026-04-18, see `docs/research-log.md#2026-04-18-mcp-2025-11-25-compliance`).

MCP protocol version string (for the `MCP-Protocol-Version` header) is
a single public constant, `PROTOCOL_VERSION`, so every module agrees.
"""

from __future__ import annotations

from .oauth import (
    AuthorizationServerMetadata,
    ProtectedResourceMetadata,
    canonicalize_resource_uri,
    generate_pkce_challenge,
    generate_pkce_verifier,
    parse_authorization_header,
    parse_www_authenticate_header,
    validate_access_token_audience,
    validate_pkce_pair,
    validate_redirect_uri,
)
from .tasks import (
    Task,
    TaskCancelRequest,
    TaskGetRequest,
    TaskState,
    TaskStatus,
)
from .transport import (
    PROTOCOL_VERSION_HEADER,
    MCPTransportError,
    validate_streamable_http_request,
    validate_streamable_http_response,
)

PROTOCOL_VERSION = "2025-11-25"
"""MCP spec version this module implements, as it appears in the
`MCP-Protocol-Version` HTTP header on Streamable HTTP requests."""


__all__ = [
    "PROTOCOL_VERSION",
    # oauth
    "AuthorizationServerMetadata",
    "ProtectedResourceMetadata",
    "canonicalize_resource_uri",
    "generate_pkce_challenge",
    "generate_pkce_verifier",
    "parse_authorization_header",
    "parse_www_authenticate_header",
    "validate_access_token_audience",
    "validate_pkce_pair",
    "validate_redirect_uri",
    # tasks
    "Task",
    "TaskCancelRequest",
    "TaskGetRequest",
    "TaskState",
    "TaskStatus",
    # transport
    "PROTOCOL_VERSION_HEADER",
    "MCPTransportError",
    "validate_streamable_http_request",
    "validate_streamable_http_response",
]
