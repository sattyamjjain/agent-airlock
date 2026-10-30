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


class TestMetadataUrlScreen:
    """CVE-2026-119025: a discovery URL with ``$(...)`` ran PowerShell on the client.

    ``open`` 7.2.0 before 11.0.0 handed a URL unescaped to ``powershell -EncodedCommand`` on
    Windows and WSL, and a malicious MCP server controls the ``authorization_endpoint`` its
    discovery metadata names. The URLs a client follows are refused at parse time when they
    hold a character no URL needs unencoded, or are not https (plain http on loopback only).

    Primary source: https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-119025
    """

    VALID: dict[str, object] = {
        "issuer": "https://auth.example.com",
        "authorization_endpoint": "https://auth.example.com/authorize",
        "token_endpoint": "https://auth.example.com/token",
        "code_challenge_methods_supported": ["S256"],
    }

    def _refusal(self, **fields: object) -> str:
        with pytest.raises(ValidationError) as caught:
            AuthorizationServerMetadata.model_validate({**self.VALID, **fields})
        return str(caught.value)

    def test_shell_substitution_in_the_authorization_endpoint_is_refused(self) -> None:
        url = "https://as.example/authorize/$(calc)"

        text = self._refusal(authorization_endpoint=url)

        assert "authorization_endpoint holds a shell command substitution" in text
        assert url not in text  # never the whole URL
        assert "$(calc)" not in text
        assert "as.example" not in text

    @pytest.mark.parametrize(
        ("char", "named"),
        [
            ("`", "a backtick"),
            (" ", "a space"),
            ('"', "a double quote"),
            ("\r", "a control character"),
            ("\n", "a control character"),
            ("|", "a pipe"),
            ("^", "a caret"),
            ("<", "an angle bracket"),
            ("\\", "a backslash"),
            ("{", "a curly brace"),
        ],
    )
    def test_a_character_a_url_must_percent_encode_is_refused_by_its_class(
        self, char: str, named: str
    ) -> None:
        url = f"https://as.example/authorize{char}calc"

        text = self._refusal(authorization_endpoint=url)

        assert f"authorization_endpoint holds {named}, which a URL must percent-encode" in text
        assert url not in text

    @pytest.mark.parametrize(
        "field", ["issuer", "authorization_endpoint", "token_endpoint", "registration_endpoint"]
    )
    def test_every_url_a_client_follows_is_screened(self, field: str) -> None:
        text = self._refusal(**{field: "https://as.example/x`calc`"})
        assert f"{field} holds a backtick" in text

    @pytest.mark.parametrize(
        "url",
        [
            "http://localhost:3000/authorize",
            "http://LOCALHOST/authorize",
            "http://127.0.0.1:8080/authorize",
            "http://127.8.0.1/authorize",
            "http://[::1]:8080/authorize",
            "http://[::ffff:127.0.0.1]/authorize",
        ],
    )
    def test_plain_http_on_a_loopback_host_is_accepted(self, url: str) -> None:
        metadata = AuthorizationServerMetadata.model_validate(
            {**self.VALID, "authorization_endpoint": url}
        )
        assert metadata.authorization_endpoint == url

    @pytest.mark.parametrize(
        "url",
        [
            "http://as.example/authorize",
            "http://localhost.as.example/authorize",
            "http://localhost@as.example/authorize",
            "http://10.0.0.1/authorize",
        ],
    )
    def test_plain_http_on_any_other_host_is_refused(self, url: str) -> None:
        text = self._refusal(authorization_endpoint=url)
        assert "plain http on a host that is not loopback" in text

    @pytest.mark.parametrize(
        ("url", "reason"),
        [
            ("ftp://as.example/authorize", "must be an https URL"),
            ("javascript:alert(1)", "must be an https URL"),
            ("/authorize", "must be an https URL"),
            ("https:///authorize", "has no host"),
            ("https://[::1/authorize", "is not a valid URL"),
        ],
    )
    def test_anything_but_an_absolute_http_url_with_a_host_is_refused(
        self, url: str, reason: str
    ) -> None:
        assert f"authorization_endpoint {reason}" in self._refusal(authorization_endpoint=url)

    def test_an_unset_registration_endpoint_is_not_screened(self) -> None:
        metadata = AuthorizationServerMetadata.model_validate(
            {**self.VALID, "registration_endpoint": None}
        )
        assert metadata.registration_endpoint is None

    def test_metadata_parsed_from_a_discovery_response_is_screened(self) -> None:
        body = (
            '{"issuer": "https://as.example", '
            '"authorization_endpoint": "https://as.example/authorize?x=$(calc)", '
            '"token_endpoint": "https://as.example/token", '
            '"code_challenge_methods_supported": ["S256"]}'
        )
        with pytest.raises(ValidationError, match="shell command substitution"):
            AuthorizationServerMetadata.model_validate_json(body)

    def test_an_authorization_servers_list_with_one_bad_item_is_refused(self) -> None:
        bad = "https://as.example/$(calc)"
        with pytest.raises(ValidationError) as caught:
            ProtectedResourceMetadata(
                resource="https://mcp.example.com/mcp",
                authorization_servers=["https://auth.example.com", bad],
            )
        text = str(caught.value)
        assert "authorization_servers[1] holds a shell command substitution" in text
        assert bad not in text

    def test_plain_http_authorization_server_is_refused_off_loopback(self) -> None:
        with pytest.raises(ValidationError, match=r"authorization_servers\[0\] uses plain http"):
            ProtectedResourceMetadata(
                resource="https://mcp.example.com/mcp",
                authorization_servers=["http://auth.example.com"],
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

    # 0.10.27: three shapes the check now answers rather than skips or raises past.

    def test_a_list_holding_a_non_string_is_rejected_whole(self) -> None:
        """Until 0.10.27 the non-string was skipped and the matching item admitted it."""
        for item in (42, None, {"aud": self.SERVER}, [self.SERVER]):
            with pytest.raises(TokenAudienceError, match="not a string"):
                validate_access_token_audience(
                    {"aud": [item, self.SERVER]}, expected_audience=self.SERVER
                )

    def test_a_string_aud_that_is_not_a_uri_is_a_token_audience_error(self) -> None:
        """Until 0.10.27 this escaped as a ResourceURIError a caller catching the
        documented TokenAudienceError never saw."""
        with pytest.raises(TokenAudienceError, match="not a resource URI"):
            validate_access_token_audience(
                {"aud": "placeholder-client-id"}, expected_audience=self.SERVER
            )

    def test_a_non_uri_audience_beside_this_server_in_a_list_is_accepted(self) -> None:
        """Another audience may be a client id; it is not this server, and not an error."""
        validate_access_token_audience(
            {"aud": ["placeholder-client-id", self.SERVER]}, expected_audience=self.SERVER
        )

    def test_a_root_slash_is_the_same_resource_both_ways(self) -> None:
        """RFC 3986 §6.2.3. Until 0.10.27 a token for `https://host/` was refused by a
        server expecting `https://host`, and the other way round."""
        validate_access_token_audience(
            {"aud": ["https://mcp.example.com/"]}, expected_audience="https://mcp.example.com"
        )
        validate_access_token_audience(
            {"aud": "https://mcp.example.com"}, expected_audience="https://mcp.example.com/"
        )

    def test_a_root_slash_does_not_widen_a_path(self) -> None:
        with pytest.raises(TokenAudienceError):
            validate_access_token_audience(
                {"aud": "https://mcp.example.com/"}, expected_audience=self.SERVER
            )
