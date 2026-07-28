"""MCP spec compliance helpers.

Two Model Context Protocol revisions matter here, and this package is careful to
say which is which — see :data:`SPEC_REVISIONS`.

**Ratified — MCP 2025-11-25.** This is the current ratified revision
(``modelcontextprotocol.io/specification/latest`` redirects to
``/specification/2025-11-25``, verified 2026-07-28) and the value of
:data:`PROTOCOL_VERSION` / the ``MCP-Protocol-Version`` header. Implemented
against it: the **OAuth 2.1 + PKCE S256 + RFC 8707** validators (``oauth``) and
the **Streamable HTTP** header/envelope checks (``transport``); the ``tasks``
submodule holds the Pydantic V2 strict task-state models. Requirements trace to
https://modelcontextprotocol.io/specification/2025-11-25 and its
``/basic/authorization`` page.

**Release candidate — MCP 2026-07-28.** The ``2026-07-28-RC`` release is a
**pre-release** (``prerelease: true``, published 2026-05-29, verified 2026-07-28
at github.com/modelcontextprotocol/modelcontextprotocol/releases). The
2026-07-28-tagged guards in this package — schema-ref (SEP-2106), ``_meta`` trust,
step-up scope (SEP-2350 / 2352 / 2468), Tasks lifecycle (SEP-1686), Tasks
admission (SEP-2663), elicitation provenance (SEP-2260), header integrity
(SEP-2243), statelessness (SEP-2567 / 2575), and ``mcp_spec_2026_07_defaults`` —
are **forward-compatible hardening against a release candidate, not a conformance
claim**. The negotiated protocol version stays 2025-11-25 until the revision is
ratified.

This submodule is scoped to **validators and schema helpers** that runtime
middleware can call. It is NOT an OAuth authorization server, an MCP server
framework (that's FastMCP; we already integrate with it), or a DPoP
implementation (still SEP-draft; deferred).

:data:`PROTOCOL_VERSION` is the single public constant for the
``MCP-Protocol-Version`` header, so every module agrees.
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
`MCP-Protocol-Version` HTTP header on Streamable HTTP requests. This is the
ratified revision and MUST NOT be advanced to a release candidate."""

SPEC_REVISIONS: dict[str, str] = {
    "2025-11-25": "ratified",
    "2026-07-28": "release-candidate",
}
"""Status of each MCP revision this package references. ``2025-11-25`` is the
ratified revision — the negotiated :data:`PROTOCOL_VERSION`. ``2026-07-28`` is a
release candidate (release tag ``2026-07-28-RC``, ``prerelease: true``, verified
2026-07-28); its guards are forward-compatible hardening, not a conformance
claim."""


__all__ = [
    "PROTOCOL_VERSION",
    "SPEC_REVISIONS",
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
