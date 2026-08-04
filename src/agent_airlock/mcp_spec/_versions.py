"""Single source of truth for the MCP protocol-version values on the wire path.

Dependency-free leaf module (imports nothing from ``agent_airlock``), so both
``transport.py`` — whose :func:`~agent_airlock.mcp_spec.transport.validate_streamable_http_request`
enforces these on the wire — and the package ``__init__`` can import from here
without an import cycle. The enforced set and the public
``SUPPORTED_PROTOCOL_VERSIONS`` constant are therefore the **same object** and
cannot drift.
"""

from __future__ import annotations

PROTOCOL_VERSION = "2026-07-28"
"""The current ratified MCP revision; the negotiated ``MCP-Protocol-Version``
header value. ``/specification/latest`` 307-redirects to
``/specification/2026-07-28`` (verified 2026-08-01); the release has been
``prerelease: false`` since 2026-07-28T16:47:49Z."""

SUPPORTED_PROTOCOL_VERSIONS: tuple[str, ...] = (PROTOCOL_VERSION, "2025-11-25")
"""``MCP-Protocol-Version`` header values accepted on the wire, newest first: the
current ratified ``2026-07-28`` and the legacy ``2025-11-25`` (kept for interop).
``validate_streamable_http_request`` rejects any other value with an
``UnsupportedProtocolVersionError``-shaped message naming this set."""
