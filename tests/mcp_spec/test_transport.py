"""Tests for Streamable HTTP transport validation (MCP 2025-11-25)."""

from __future__ import annotations

import pytest

from agent_airlock.mcp_spec import PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS
from agent_airlock.mcp_spec.transport import (
    _PROTOCOL_VERSION_VALUE,
    _SUPPORTED_PROTOCOL_VERSIONS,
    PROTOCOL_VERSION_HEADER,
    MCPTransportError,
    validate_streamable_http_request,
    validate_streamable_http_response,
)


def _base_headers(**overrides: str) -> dict[str, str]:
    """Build a minimal valid Streamable HTTP header set."""
    headers = {
        PROTOCOL_VERSION_HEADER: PROTOCOL_VERSION,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": "Bearer abc123",
    }
    headers.update(overrides)
    return headers


class TestProtocolVersionHeader:
    def test_missing_header_rejected(self) -> None:
        headers = _base_headers()
        headers.pop(PROTOCOL_VERSION_HEADER)
        with pytest.raises(MCPTransportError, match="MCP-Protocol-Version"):
            validate_streamable_http_request(
                method="POST",
                url="https://mcp/",
                headers=headers,
                body={"jsonrpc": "2.0"},
            )

    def test_wrong_version_rejected(self) -> None:
        headers = _base_headers()
        headers[PROTOCOL_VERSION_HEADER] = "2024-01-01"
        with pytest.raises(MCPTransportError, match="unsupported"):
            validate_streamable_http_request(
                method="POST",
                url="https://mcp/",
                headers=headers,
                body={"jsonrpc": "2.0"},
            )

    def test_correct_version_accepted(self) -> None:
        result = validate_streamable_http_request(
            method="POST",
            url="https://mcp/",
            headers=_base_headers(),
            body={"jsonrpc": "2.0"},
        )
        assert result.bearer is not None
        assert result.bearer.token == "abc123"

    def test_legacy_2025_version_accepted(self) -> None:
        # 2025-11-25 (legacy) MUST still validate for interop, not raise.
        headers = _base_headers()
        headers[PROTOCOL_VERSION_HEADER] = "2025-11-25"
        result = validate_streamable_http_request(
            method="POST", url="https://mcp/", headers=headers, body={"jsonrpc": "2.0"}
        )
        assert result.bearer is not None

    def test_unknown_version_rejected_lists_both_supported(self) -> None:
        # An unsupported version is rejected with a message naming the supported
        # set (mirrors UnsupportedProtocolVersionError.data.supported).
        headers = _base_headers()
        headers[PROTOCOL_VERSION_HEADER] = "1900-01-01"
        with pytest.raises(MCPTransportError) as exc:
            validate_streamable_http_request(
                method="POST", url="https://mcp/", headers=headers, body={"jsonrpc": "2.0"}
            )
        msg = str(exc.value)
        assert "2026-07-28" in msg and "2025-11-25" in msg


class TestTokenInQueryString:
    def test_access_token_in_query_rejected(self) -> None:
        """Spec §'Access Token Usage': 'Access tokens MUST NOT be included in the URI query string.'"""
        with pytest.raises(MCPTransportError, match="query string"):
            validate_streamable_http_request(
                method="POST",
                url="https://mcp/?access_token=leaked",
                headers=_base_headers(),
                body={"jsonrpc": "2.0"},
            )

    def test_bearer_in_query_rejected(self) -> None:
        with pytest.raises(MCPTransportError, match="query string"):
            validate_streamable_http_request(
                method="POST",
                url="https://mcp/?bearer=leaked",
                headers=_base_headers(),
                body={"jsonrpc": "2.0"},
            )

    def test_benign_query_string_allowed(self) -> None:
        validate_streamable_http_request(
            method="GET",
            url="https://mcp/?cursor=abc",
            headers=_base_headers(),
        )


class TestContentType:
    def test_post_body_requires_json_content_type(self) -> None:
        headers = _base_headers(**{"Content-Type": "text/plain"})
        with pytest.raises(MCPTransportError, match="application/json"):
            validate_streamable_http_request(
                method="POST",
                url="https://mcp/",
                headers=headers,
                body={"jsonrpc": "2.0"},
            )

    def test_get_without_body_no_ctype_required(self) -> None:
        headers = _base_headers()
        headers.pop("Content-Type")
        validate_streamable_http_request(method="GET", url="https://mcp/", headers=headers)


class TestAcceptHeader:
    def test_accept_json_ok(self) -> None:
        r = validate_streamable_http_request(
            method="POST",
            url="https://mcp/",
            headers=_base_headers(Accept="application/json"),
            body={"jsonrpc": "2.0"},
        )
        assert r.accept_json

    def test_accept_sse_ok(self) -> None:
        r = validate_streamable_http_request(
            method="GET",
            url="https://mcp/",
            headers=_base_headers(Accept="text/event-stream"),
        )
        assert r.accept_sse

    def test_accept_wildcard_ok(self) -> None:
        r = validate_streamable_http_request(
            method="POST",
            url="https://mcp/",
            headers=_base_headers(Accept="*/*"),
            body={"jsonrpc": "2.0"},
        )
        assert r.accept_json

    def test_bad_accept_rejected(self) -> None:
        with pytest.raises(MCPTransportError, match="Accept"):
            validate_streamable_http_request(
                method="POST",
                url="https://mcp/",
                headers=_base_headers(Accept="text/html"),
                body={"jsonrpc": "2.0"},
            )


class TestAuthorizationHeader:
    def test_missing_auth_required(self) -> None:
        headers = _base_headers()
        headers.pop("Authorization")
        with pytest.raises(MCPTransportError, match="Authorization"):
            validate_streamable_http_request(
                method="POST",
                url="https://mcp/",
                headers=headers,
                body={"jsonrpc": "2.0"},
            )

    def test_missing_auth_allowed_on_public_endpoint(self) -> None:
        headers = _base_headers()
        headers.pop("Authorization")
        r = validate_streamable_http_request(
            method="GET",
            url="https://mcp/.well-known/oauth-protected-resource",
            headers=headers,
            require_auth=False,
        )
        assert r.bearer is None

    def test_non_bearer_rejected(self) -> None:
        headers = _base_headers(Authorization="Basic Zm9vOmJhcg==")
        with pytest.raises(MCPTransportError):
            validate_streamable_http_request(
                method="POST",
                url="https://mcp/",
                headers=headers,
                body={"jsonrpc": "2.0"},
            )


class TestResponse:
    def test_401_without_www_authenticate_rejected(self) -> None:
        with pytest.raises(MCPTransportError, match="WWW-Authenticate"):
            validate_streamable_http_response(status=401, headers={})

    def test_401_with_www_authenticate_accepted(self) -> None:
        validate_streamable_http_response(
            status=401,
            headers={
                "WWW-Authenticate": (
                    'Bearer resource_metadata="https://mcp/.well-known/oauth-protected-resource"'
                )
            },
        )

    def test_200_with_json_accepted(self) -> None:
        validate_streamable_http_response(status=200, headers={"Content-Type": "application/json"})

    def test_200_with_sse_accepted(self) -> None:
        validate_streamable_http_response(status=200, headers={"Content-Type": "text/event-stream"})

    def test_200_with_html_rejected(self) -> None:
        with pytest.raises(MCPTransportError):
            validate_streamable_http_response(status=200, headers={"Content-Type": "text/html"})


class TestConstantsConsistent:
    def test_package_version_matches_transport_header_value(self) -> None:
        """PROTOCOL_VERSION exported from the package matches the inline string in transport.py."""
        # Build a request with the package-level constant; must validate.
        validate_streamable_http_request(
            method="POST",
            url="https://mcp/",
            headers={
                PROTOCOL_VERSION_HEADER: PROTOCOL_VERSION,
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Authorization": "Bearer t",
            },
            body={"jsonrpc": "2.0"},
        )

    def test_private_transport_constants_track_the_package(self) -> None:
        # transport.py duplicates the version strings to avoid an import cycle;
        # this is the cross-check that they stay in lockstep with the package.
        assert _PROTOCOL_VERSION_VALUE == PROTOCOL_VERSION
        assert _SUPPORTED_PROTOCOL_VERSIONS == SUPPORTED_PROTOCOL_VERSIONS
        assert PROTOCOL_VERSION in _SUPPORTED_PROTOCOL_VERSIONS
