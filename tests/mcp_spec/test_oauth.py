"""OAuth 2.1 + PKCE + RFC 8707 conformance tests for MCP 2025-11-25."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agent_airlock.mcp_spec.oauth import (
    PKCE_VERIFIER_MAX_LEN,
    PKCE_VERIFIER_MIN_LEN,
    AuthorizationServerMetadata,
    BearerHeaderError,
    PKCEError,
    ProtectedResourceMetadata,
    RedirectURIError,
    ResourceURIError,
    TokenAudienceError,
    canonicalize_resource_uri,
    generate_pkce_challenge,
    generate_pkce_verifier,
    parse_authorization_header,
    parse_www_authenticate_header,
    validate_access_token_audience,
    validate_pkce_pair,
    validate_redirect_uri,
)

# =============================================================================
# PKCE (S256)
# =============================================================================


class TestPKCE:
    def test_verifier_default_length_in_range(self) -> None:
        v = generate_pkce_verifier()
        assert PKCE_VERIFIER_MIN_LEN <= len(v) <= PKCE_VERIFIER_MAX_LEN

    def test_verifier_rejects_short(self) -> None:
        with pytest.raises(PKCEError):
            generate_pkce_verifier(length=PKCE_VERIFIER_MIN_LEN - 1)

    def test_verifier_rejects_long(self) -> None:
        with pytest.raises(PKCEError):
            generate_pkce_verifier(length=PKCE_VERIFIER_MAX_LEN + 1)

    def test_round_trip_validates(self) -> None:
        v = generate_pkce_verifier()
        c = generate_pkce_challenge(v)
        assert validate_pkce_pair(v, c) is True

    def test_mismatched_pair_rejected(self) -> None:
        v1 = generate_pkce_verifier()
        v2 = generate_pkce_verifier()
        assert validate_pkce_pair(v1, generate_pkce_challenge(v2)) is False

    def test_challenge_rejects_invalid_chars(self) -> None:
        with pytest.raises(PKCEError):
            generate_pkce_challenge("abc def")  # space is outside the allowed set

    def test_rfc7636_known_vector(self) -> None:
        """RFC 7636 Appendix B example — the verifier/challenge pair is a spec fixture."""
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        assert generate_pkce_challenge(verifier) == expected_challenge


# =============================================================================
# Redirect URI allow-list
# =============================================================================


class TestRedirectURI:
    def test_allows_https(self) -> None:
        validate_redirect_uri("https://app.example.com/callback")

    def test_allows_localhost_http(self) -> None:
        validate_redirect_uri("http://localhost:3000/callback")

    def test_allows_127_0_0_1(self) -> None:
        validate_redirect_uri("http://127.0.0.1:3000/callback")

    def test_allows_ipv6_loopback(self) -> None:
        validate_redirect_uri("http://[::1]:3000/callback")

    def test_rejects_http_on_public_host(self) -> None:
        with pytest.raises(RedirectURIError):
            validate_redirect_uri("http://evil.example.com/callback")

    def test_rejects_non_http_scheme(self) -> None:
        with pytest.raises(RedirectURIError):
            validate_redirect_uri("javascript:alert(1)")

    def test_rejects_empty(self) -> None:
        with pytest.raises(RedirectURIError):
            validate_redirect_uri("")


# =============================================================================
# Authorization header parsing
# =============================================================================


class TestAuthorizationHeader:
    def test_valid_bearer(self) -> None:
        bt = parse_authorization_header("Bearer abc123")
        assert bt.token == "abc123"

    def test_case_insensitive_scheme(self) -> None:
        assert parse_authorization_header("bEaReR xyz").token == "xyz"

    def test_rejects_basic(self) -> None:
        with pytest.raises(BearerHeaderError):
            parse_authorization_header("Basic Zm9vOmJhcg==")

    def test_rejects_empty(self) -> None:
        with pytest.raises(BearerHeaderError):
            parse_authorization_header("")

    def test_rejects_whitespace_token(self) -> None:
        with pytest.raises(BearerHeaderError):
            parse_authorization_header("Bearer ")

    def test_rejects_multi_word_token(self) -> None:
        with pytest.raises(BearerHeaderError):
            parse_authorization_header("Bearer two words")


class TestWWWAuthenticateHeader:
    def test_simple_bearer(self) -> None:
        c = parse_www_authenticate_header('Bearer resource_metadata="https://mcp/.well-known"')
        assert c.scheme == "Bearer"
        assert c.resource_metadata == "https://mcp/.well-known"

    def test_mcp_spec_example(self) -> None:
        """The exact 401 example from the MCP spec, §'Authorization Server Location'."""
        header = (
            'Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource", '
            'scope="files:read"'
        )
        c = parse_www_authenticate_header(header)
        assert c.resource_metadata == "https://mcp.example.com/.well-known/oauth-protected-resource"
        assert c.scope == "files:read"

    def test_403_insufficient_scope_example(self) -> None:
        """403 shape from §'Scope Challenge Handling'."""
        header = (
            'Bearer error="insufficient_scope", scope="files:read files:write", '
            'resource_metadata="https://mcp/.well-known"'
        )
        c = parse_www_authenticate_header(header)
        assert c.error == "insufficient_scope"
        assert c.scope == "files:read files:write"

    def test_tolerates_no_params(self) -> None:
        c = parse_www_authenticate_header("Bearer")
        assert c.scheme == "Bearer"
        assert c.params == {}


# =============================================================================
# RFC 8707 canonicalisation
# =============================================================================


class TestResourceURI:
    def test_rejects_missing_scheme(self) -> None:
        with pytest.raises(ResourceURIError):
            canonicalize_resource_uri("mcp.example.com")

    def test_rejects_fragment(self) -> None:
        with pytest.raises(ResourceURIError):
            canonicalize_resource_uri("https://mcp.example.com#fragment")

    def test_lowercases_scheme_and_host(self) -> None:
        assert (
            canonicalize_resource_uri("HTTPS://MCP.Example.COM/API")
            == "https://mcp.example.com/API"
        )

    def test_strips_trailing_slash(self) -> None:
        assert (
            canonicalize_resource_uri("https://mcp.example.com/mcp/")
            == "https://mcp.example.com/mcp"
        )

    def test_keeps_root_slash(self) -> None:
        """A bare `/` path is allowed to remain."""
        assert canonicalize_resource_uri("https://mcp.example.com/") == "https://mcp.example.com/"

    def test_preserves_port(self) -> None:
        assert (
            canonicalize_resource_uri("https://mcp.example.com:8443/mcp")
            == "https://mcp.example.com:8443/mcp"
        )


# =============================================================================
# OAuth 2.0 metadata documents
# =============================================================================


class TestAuthorizationServerMetadata:
    def test_valid(self) -> None:
        md = AuthorizationServerMetadata(
            issuer="https://auth.example.com",
            authorization_endpoint="https://auth.example.com/authorize",
            token_endpoint="https://auth.example.com/token",
            code_challenge_methods_supported=["S256"],
        )
        assert md.code_challenge_methods_supported == ["S256"]

    def test_requires_s256(self) -> None:
        with pytest.raises(ValidationError):
            AuthorizationServerMetadata(
                issuer="https://auth.example.com",
                authorization_endpoint="https://auth.example.com/authorize",
                token_endpoint="https://auth.example.com/token",
                code_challenge_methods_supported=["plain"],
            )

    def test_empty_pkce_methods_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AuthorizationServerMetadata(
                issuer="https://auth.example.com",
                authorization_endpoint="https://auth.example.com/authorize",
                token_endpoint="https://auth.example.com/token",
                code_challenge_methods_supported=[],
            )

    def test_extra_field_allowed(self) -> None:
        """AS metadata is extensible; extras must not reject."""
        md = AuthorizationServerMetadata.model_validate(
            {
                "issuer": "https://auth.example.com",
                "authorization_endpoint": "https://auth.example.com/a",
                "token_endpoint": "https://auth.example.com/t",
                "code_challenge_methods_supported": ["S256", "plain"],
                "scopes_supported": ["files:read"],
                "response_types_supported": ["code"],
            }
        )
        assert md.issuer == "https://auth.example.com"


class TestProtectedResourceMetadata:
    def test_valid(self) -> None:
        md = ProtectedResourceMetadata(
            resource="https://mcp.example.com/mcp",
            authorization_servers=["https://auth.example.com"],
        )
        assert md.authorization_servers == ["https://auth.example.com"]

    def test_requires_at_least_one_as(self) -> None:
        with pytest.raises(ValidationError):
            ProtectedResourceMetadata(
                resource="https://mcp.example.com/mcp",
                authorization_servers=[],
            )


# =============================================================================
# Token audience validation
# =============================================================================


class TestTokenAudience:
    SERVER = "https://mcp.example.com/mcp"

    def test_string_aud_match(self) -> None:
        validate_access_token_audience({"aud": self.SERVER}, expected_audience=self.SERVER)

    def test_string_aud_canonicalised_match(self) -> None:
        """`HTTPS://...trailing/` vs `https://.../no-slash` — still same resource."""
        validate_access_token_audience(
            {"aud": "HTTPS://mcp.example.com/mcp/"},
            expected_audience=self.SERVER,
        )

    def test_list_aud_contains_match(self) -> None:
        validate_access_token_audience(
            {"aud": ["https://other", self.SERVER]},
            expected_audience=self.SERVER,
        )

    def test_aud_missing_rejected(self) -> None:
        with pytest.raises(TokenAudienceError):
            validate_access_token_audience({}, expected_audience=self.SERVER)

    def test_aud_empty_rejected(self) -> None:
        with pytest.raises(TokenAudienceError):
            validate_access_token_audience({"aud": ""}, expected_audience=self.SERVER)

    def test_aud_mismatch_rejected(self) -> None:
        with pytest.raises(TokenAudienceError):
            validate_access_token_audience(
                {"aud": "https://other.example.com/mcp"},
                expected_audience=self.SERVER,
            )

    def test_list_aud_no_match_rejected(self) -> None:
        with pytest.raises(TokenAudienceError):
            validate_access_token_audience(
                {"aud": ["https://a", "https://b"]},
                expected_audience=self.SERVER,
            )

    def test_aud_wrong_type_rejected(self) -> None:
        with pytest.raises(TokenAudienceError):
            validate_access_token_audience({"aud": 42}, expected_audience=self.SERVER)
