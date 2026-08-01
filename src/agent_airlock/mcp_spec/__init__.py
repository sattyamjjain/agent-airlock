"""MCP spec compliance helpers.

Two Model Context Protocol revisions matter here, and this package is careful to
say which is which — see :data:`SPEC_REVISIONS` and
:data:`SUPPORTED_PROTOCOL_VERSIONS`.

**Current — MCP 2026-07-28.** This is the current ratified revision:
``modelcontextprotocol.io/specification/latest`` 307-redirects to
``/specification/2026-07-28`` and the versioning page states "The current
protocol version is 2026-07-28" (verified 2026-08-01); the release is
``prerelease: false``, published 2026-07-28T16:47:49Z. It is the value of
:data:`PROTOCOL_VERSION` / the ``MCP-Protocol-Version`` header and the newest
entry in :data:`SUPPORTED_PROTOCOL_VERSIONS`. The 2026-07-28-tagged guards in
this package — schema-ref (SEP-2106), ``_meta`` trust, step-up scope
(SEP-2350 / 2352 / 2468), Tasks lifecycle (SEP-1686), Tasks admission (SEP-2663),
elicitation provenance (SEP-2260), header integrity (SEP-2243), statelessness
(SEP-2567 / 2575), and ``mcp_spec_2026_07_defaults`` — target it. **airlock still
makes NO conformance claim: no MCP conformance suite has been run against this
package.** These are validators and forward-compatible hardening, not a
certification — correcting the false "release candidate" premise does not upgrade
the claim.

**Legacy — MCP 2025-11-25.** The prior revision (the spec labels ``<= 2025-11-25``
"Legacy"). airlock still accepts it on the wire for interop — the second entry in
:data:`SUPPORTED_PROTOCOL_VERSIONS`. The **OAuth 2.1 + PKCE S256 + RFC 8707**
validators (``oauth``), the **Streamable HTTP** header/envelope checks
(``transport``), and the ``tasks`` Pydantic V2 strict task-state models trace to
https://modelcontextprotocol.io/specification/2025-11-25 and its
``/basic/authorization`` page.

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

PROTOCOL_VERSION = "2026-07-28"
"""MCP spec version this module implements, as it appears in the
`MCP-Protocol-Version` HTTP header on Streamable HTTP requests. This is the
current ratified revision: ``/specification/latest`` 307-redirects to
``/specification/2026-07-28`` (verified 2026-08-01) and the release has been
``prerelease: false`` since 2026-07-28T16:47:49Z."""

SPEC_REVISIONS: dict[str, str] = {
    "2025-11-25": "legacy",
    "2026-07-28": "current",
}
"""Status of each MCP revision this package references, in the spec's own
terminology (``/specification/2026-07-28/basic/versioning`` — ``>= 2026-07-28``
is "Modern"/current, ``<= 2025-11-25`` is "Legacy"). ``2026-07-28`` is the
current ratified revision — the negotiated :data:`PROTOCOL_VERSION`.
``2025-11-25`` is legacy, still accepted on the wire for interop. This records
provenance only; airlock makes no conformance claim for either."""

SUPPORTED_PROTOCOL_VERSIONS: tuple[str, ...] = ("2026-07-28", "2025-11-25")
"""``MCP-Protocol-Version`` header values this package accepts on the wire,
newest first: the current ratified ``2026-07-28`` and the legacy ``2025-11-25``
(kept for interop). A request naming any other version is rejected with an
``UnsupportedProtocolVersionError``-shaped message; see
:func:`~agent_airlock.mcp_spec.transport.validate_streamable_http_request`."""


__all__ = [
    "PROTOCOL_VERSION",
    "SPEC_REVISIONS",
    "SUPPORTED_PROTOCOL_VERSIONS",
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
