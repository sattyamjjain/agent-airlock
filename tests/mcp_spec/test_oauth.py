"""OAuth 2.1 + PKCE + RFC 8707 conformance tests for MCP 2025-11-25."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from agent_airlock import mcp_spec
from agent_airlock.mcp_spec.oauth import (
    PKCE_VERIFIER_MAX_LEN,
    PKCE_VERIFIER_MIN_LEN,
    AuthorizationServerMetadata,
    BearerHeaderError,
    IssuerMismatchError,
    PKCEError,
    ProtectedResourceMetadata,
    RedirectURIError,
    ResourceMismatchError,
    ResourceURIError,
    TokenAudienceError,
    canonicalize_resource_uri,
    generate_pkce_challenge,
    generate_pkce_verifier,
    issuer_from_discovery_url,
    parse_authorization_header,
    parse_www_authenticate_header,
    validate_access_token_audience,
    validate_authorization_response_iss,
    validate_metadata_issuer,
    validate_pkce_pair,
    validate_protected_resource,
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

    @pytest.mark.parametrize(
        "uri",
        [
            "https://app.example/cb#frag",
            "http://localhost:8080/cb#frag",
            "http://127.0.0.1:8080/#/cb",
            "http://[::1]:8080/cb#frag",
            "https://app.example/cb?state=1#frag",
            "https://app.example#frag",
            # urlparse reports no fragment for these two: a parsed.fragment test passes them.
            "https://app.example/cb#",
            "https://app.example/cb?state=1#",
        ],
    )
    def test_rejects_a_fragment_rfc_6749_3_1_2(self, uri: str) -> None:
        """ "The endpoint URI MUST NOT include a fragment component." See
        modelcontextprotocol/typescript-sdk#3142 for the same gap in a registration handler."""
        with pytest.raises(RedirectURIError, match=r"RFC 6749 section 3\.1\.2"):
            validate_redirect_uri(uri)

    def test_the_refusal_does_not_echo_the_fragment(self) -> None:
        with pytest.raises(RedirectURIError) as exc:
            validate_redirect_uri("https://app.example/cb#access_token=abc123")
        assert "abc123" not in str(exc.value)

    @pytest.mark.parametrize(
        "uri",
        [
            "https://app.example/cb",
            "http://127.0.0.1:8080/cb",
            "https://app.example/cb?state=1",
            # An escaped '#' is a path character, not a fragment delimiter (RFC 3986 section 2.2).
            "https://app.example/cb%23frag",
        ],
    )
    def test_a_uri_with_no_fragment_still_passes(self, uri: str) -> None:
        validate_redirect_uri(uri)


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
# RFC 8414 section 3.3: a metadata issuer is bound to its discovery URL
# =============================================================================

_OAUTH_PATH = "/.well-known/oauth-authorization-server"
_OPENID_PATH = "/.well-known/openid-configuration"
_AS = "https://as.example"
_DECOY = "https://decoy.example.net"


def _document(issuer: str) -> dict[str, Any]:
    """A metadata document naming ``issuer``, complete enough to parse."""
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{_AS}/authorize",
        "token_endpoint": f"{_AS}/token",
        "code_challenge_methods_supported": ["S256"],
    }


class TestIssuerFromDiscoveryUrl:
    """Each well-known form on MCP 2026-07-28's discovery page, inverted."""

    @pytest.mark.parametrize(
        ("url", "issuer"),
        [
            (f"{_AS}{_OAUTH_PATH}", _AS),
            (f"{_AS}{_OAUTH_PATH}/tenant1", f"{_AS}/tenant1"),
            (f"{_AS}{_OAUTH_PATH}/a/b", f"{_AS}/a/b"),
            (f"{_AS}{_OPENID_PATH}", _AS),
            (f"{_AS}{_OPENID_PATH}/tenant1", f"{_AS}/tenant1"),
            (f"{_AS}/tenant1{_OPENID_PATH}", f"{_AS}/tenant1"),
            (f"{_AS}/a/b{_OPENID_PATH}", f"{_AS}/a/b"),
            (f"https://as.example:8443{_OAUTH_PATH}", "https://as.example:8443"),
            (f"http://localhost:3000{_OAUTH_PATH}", "http://localhost:3000"),
            (f"http://[::1]:3000{_OAUTH_PATH}/t", "http://[::1]:3000/t"),
        ],
    )
    def test_each_form_inverts(self, url: str, issuer: str) -> None:
        assert issuer_from_discovery_url(url) == issuer

    @pytest.mark.parametrize(
        ("url", "issuer"),
        [
            (f"https://AS.example{_OAUTH_PATH}", "https://AS.example"),
            (f"https://as.example:443{_OAUTH_PATH}", "https://as.example:443"),
        ],
    )
    def test_the_origin_comes_back_as_written(self, url: str, issuer: str) -> None:
        """RFC 8414 compares issuers as strings: no case folding, no default port dropped."""
        assert issuer_from_discovery_url(url) == issuer

    @pytest.mark.parametrize(
        ("url", "issuer"),
        [
            (f"{_AS}{_OAUTH_PATH}/", _AS),
            (f"{_AS}{_OAUTH_PATH}/tenant1/", f"{_AS}/tenant1"),
            (f"{_AS}/tenant1{_OPENID_PATH}/", f"{_AS}/tenant1"),
        ],
    )
    def test_a_terminating_slash_is_read_as_absent(self, url: str, issuer: str) -> None:
        assert issuer_from_discovery_url(url) == issuer

    @pytest.mark.parametrize(
        "url",
        [
            # No well-known segment.
            _AS,
            f"{_AS}/",
            f"{_AS}/tenant1",
            f"{_AS}/authorize",
            f"{_AS}/.WELL-KNOWN/oauth-authorization-server",
            f"{_AS}/%2ewell-known/oauth-authorization-server",
            # A well-known segment in no form MCP discovery uses.
            f"{_AS}/.well-known",
            f"{_AS}/.well-known/",
            f"{_AS}/.well-known/oauth-protected-resource",
            f"{_AS}/tenant1{_OAUTH_PATH}",
            f"{_AS}/a{_OPENID_PATH}/b",
            # More than one issuer could have built these.
            f"{_AS}{_OAUTH_PATH}{_OPENID_PATH}",
            f"{_AS}{_OPENID_PATH}{_OPENID_PATH}",
            # RFC 8414 section 2: an issuer has no query, fragment or userinfo.
            f"{_AS}{_OAUTH_PATH}?x=1",
            f"{_AS}{_OAUTH_PATH}?",
            f"{_AS}{_OAUTH_PATH}#x",
            f"{_AS}{_OAUTH_PATH}#",
            f"{_DECOY}/?u={_OAUTH_PATH}",
            f"{_DECOY}/#{_OAUTH_PATH}",
            f"https://as.example@decoy.example.net{_OAUTH_PATH}",
            # A port that is not one.
            f"https://as.example:notaport{_OAUTH_PATH}",
            f"https://as.example:99999{_OAUTH_PATH}",
            # The server resolves these before it answers.
            f"{_AS}{_OAUTH_PATH}/../x",
            f"{_AS}/a/..{_OPENID_PATH}",
            f"{_AS}/.{_OPENID_PATH}",
            f"{_AS}{_OAUTH_PATH}/%2e%2e/x",
            f"{_AS}{_OAUTH_PATH}/%2E%2E/x",
            f"{_AS}/a/..;{_OPENID_PATH}",
            f"{_AS}{_OAUTH_PATH}/a;x=1",
            # Empty segments.
            f"{_AS}/{_OPENID_PATH}",
            f"{_AS}{_OAUTH_PATH}//x",
            f"{_AS}{_OAUTH_PATH}/x//",
            # The metadata URL screen, and whitespace it does not stop.
            f"http://as.example{_OAUTH_PATH}",
            f"ftp://as.example{_OAUTH_PATH}",
            f"{_AS}{_OAUTH_PATH}/$(id)",
            f"{_AS}{_OAUTH_PATH}/a b",
            f"{_AS}{_OAUTH_PATH} ",
        ],
    )
    def test_anything_else_is_refused_without_repeating_the_url(self, url: str) -> None:
        with pytest.raises(IssuerMismatchError) as exc:
            issuer_from_discovery_url(url)
        assert "discovery_url" in str(exc.value)
        assert "as.example" not in str(exc.value)
        assert "decoy" not in str(exc.value)
        assert exc.value.__suppress_context__ or exc.value.__context__ is None

    @pytest.mark.parametrize("url", [None, 7, f"{_AS}{_OAUTH_PATH}".encode(), [f"{_AS}"]])
    def test_a_url_that_is_not_a_string_is_refused(self, url: Any) -> None:
        with pytest.raises(IssuerMismatchError, match="not a string"):
            issuer_from_discovery_url(url)


class TestFromDiscovery:
    def test_a_decoy_issuer_at_the_real_servers_url_is_refused(self) -> None:
        with pytest.raises(IssuerMismatchError, match="RFC 8414 section 3.3"):
            AuthorizationServerMetadata.from_discovery(
                _document(_DECOY), discovery_url=f"{_AS}{_OAUTH_PATH}"
            )

    def test_the_mcp_pages_own_example_is_refused(self) -> None:
        """A document at attacker.example naming honest.example, the page's MUST-reject case."""
        with pytest.raises(IssuerMismatchError):
            AuthorizationServerMetadata.from_discovery(
                _document("https://honest.example"),
                discovery_url=f"https://attacker.example{_OAUTH_PATH}",
            )

    @pytest.mark.parametrize(
        ("issuer", "url"),
        [
            (_AS, f"{_AS}{_OAUTH_PATH}"),
            (_AS, f"{_AS}{_OPENID_PATH}"),
            (f"{_AS}/tenant1", f"{_AS}{_OAUTH_PATH}/tenant1"),
            (f"{_AS}/tenant1", f"{_AS}{_OPENID_PATH}/tenant1"),
            (f"{_AS}/tenant1", f"{_AS}/tenant1{_OPENID_PATH}"),
        ],
    )
    def test_the_matching_issuer_passes(self, issuer: str, url: str) -> None:
        metadata = AuthorizationServerMetadata.from_discovery(_document(issuer), discovery_url=url)
        assert isinstance(metadata, AuthorizationServerMetadata)
        assert metadata.issuer == issuer

    @pytest.mark.parametrize(
        ("issuer", "url"),
        [
            (f"{_AS}/", f"{_AS}{_OAUTH_PATH}"),
            (_AS, f"{_AS}{_OAUTH_PATH}/"),
            (f"{_AS}/tenant1/", f"{_AS}{_OAUTH_PATH}/tenant1"),
            (f"{_AS}/tenant1", f"{_AS}{_OAUTH_PATH}/tenant1/"),
            (f"{_AS}/tenant1/", f"{_AS}/tenant1{_OPENID_PATH}"),
        ],
    )
    def test_a_trailing_slash_on_one_side_passes(self, issuer: str, url: str) -> None:
        AuthorizationServerMetadata.from_discovery(_document(issuer), discovery_url=url)

    @pytest.mark.parametrize(
        ("issuer", "url"),
        [
            (f"{_AS}/tenant2", f"{_AS}{_OAUTH_PATH}/tenant1"),
            (f"{_AS}/tenant1", f"{_AS}{_OAUTH_PATH}"),
            (_AS, f"{_AS}{_OAUTH_PATH}/tenant1"),
            (_AS, f"{_AS}/tenant1{_OPENID_PATH}"),
            (f"{_AS}/tenant1/x", f"{_AS}{_OAUTH_PATH}/tenant1"),
            ("https://as.example:8443", f"{_AS}{_OAUTH_PATH}"),
            (_AS, f"https://as.example:443{_OAUTH_PATH}"),
            ("https://AS.example", f"{_AS}{_OAUTH_PATH}"),
            ("http://localhost", f"https://localhost{_OAUTH_PATH}"),
            ("https://as.example.decoy.example.net", f"{_AS}{_OAUTH_PATH}"),
            ("https://as.example?x=1", f"{_AS}{_OAUTH_PATH}"),
            ("https://as.example#x", f"{_AS}{_OAUTH_PATH}"),
            ("https://user@as.example", f"{_AS}{_OAUTH_PATH}"),
        ],
    )
    def test_any_other_difference_is_refused(self, issuer: str, url: str) -> None:
        """A tenant, a port, case: only trailing slashes are forgiven."""
        with pytest.raises(IssuerMismatchError):
            AuthorizationServerMetadata.from_discovery(_document(issuer), discovery_url=url)

    @pytest.mark.parametrize("space", [" ", "　", " "])
    def test_whitespace_the_screen_does_not_stop_is_not_forgiven(self, space: str) -> None:
        """`_normalize_issuer` strips it, so the document parses and only this refuses it."""
        with pytest.raises(IssuerMismatchError, match="whitespace"):
            AuthorizationServerMetadata.from_discovery(
                _document(f"{_AS}{space}"), discovery_url=f"{_AS}{_OAUTH_PATH}"
            )

    def test_the_error_text_holds_neither_url(self) -> None:
        with pytest.raises(IssuerMismatchError) as exc:
            AuthorizationServerMetadata.from_discovery(
                _document(_DECOY), discovery_url=f"{_AS}{_OAUTH_PATH}"
            )
        for text in (str(exc.value), repr(exc.value)):
            assert "as.example" not in text
            assert "decoy" not in text
        assert "issuer" in str(exc.value)

    def test_a_url_with_no_well_known_segment_is_refused(self) -> None:
        with pytest.raises(IssuerMismatchError, match="no /.well-known/ path segment"):
            AuthorizationServerMetadata.from_discovery(_document(_AS), discovery_url=_AS)

    def test_a_document_that_does_not_parse_stays_a_validation_error(self) -> None:
        with pytest.raises(ValidationError):
            AuthorizationServerMetadata.from_discovery(
                {"issuer": _AS}, discovery_url=f"{_AS}{_OAUTH_PATH}"
            )
        with pytest.raises(ValidationError):
            AuthorizationServerMetadata.from_discovery(
                _document(f"{_AS}/$(id)"), discovery_url=f"{_AS}{_OAUTH_PATH}"
            )

    @pytest.mark.parametrize("document", [None, "{}", [], 7])
    def test_a_document_that_is_not_an_object_is_refused(self, document: Any) -> None:
        with pytest.raises(ValidationError):
            AuthorizationServerMetadata.from_discovery(
                document, discovery_url=f"{_AS}{_OAUTH_PATH}"
            )

    def test_the_rest_of_the_document_is_kept(self) -> None:
        document = {**_document(_AS), "scopes_supported": ["files:read"]}
        metadata = AuthorizationServerMetadata.from_discovery(
            document, discovery_url=f"{_AS}{_OAUTH_PATH}"
        )
        assert metadata.token_endpoint == f"{_AS}/token"
        assert metadata.model_extra == {"scopes_supported": ["files:read"]}

    def test_the_plain_constructor_stays_as_it_was(self) -> None:
        """No URL, no check: a current caller keeps working, and the docs say which to use."""
        assert AuthorizationServerMetadata(**_document(_DECOY)).issuer == _DECOY


class TestValidateMetadataIssuer:
    def test_it_takes_parsed_metadata(self) -> None:
        metadata = AuthorizationServerMetadata(**_document(_AS))
        assert validate_metadata_issuer(metadata, discovery_url=f"{_AS}{_OAUTH_PATH}") is None
        with pytest.raises(IssuerMismatchError):
            validate_metadata_issuer(metadata, discovery_url=f"{_DECOY}{_OAUTH_PATH}")

    @pytest.mark.parametrize("issuer", [f" {_AS}", f"{_AS}\n", f"{_AS}$(id)", "", None, 7])
    def test_an_issuer_changed_after_parsing_is_screened_again(self, issuer: Any) -> None:
        """A model is not frozen, and `_normalize_issuer` would strip the first two."""
        metadata = AuthorizationServerMetadata(**_document(_AS))
        metadata.issuer = issuer
        with pytest.raises(IssuerMismatchError):
            validate_metadata_issuer(metadata, discovery_url=f"{_AS}{_OAUTH_PATH}")

    @pytest.mark.parametrize("metadata", [None, _document(_AS), _AS, object()])
    def test_something_with_no_issuer_attribute_is_refused(self, metadata: Any) -> None:
        with pytest.raises(IssuerMismatchError, match="issuer is a"):
            validate_metadata_issuer(metadata, discovery_url=f"{_AS}{_OAUTH_PATH}")


class TestTheMixUpEndToEnd:
    """RFC 9207's check compares with an expected issuer. These pin where that value comes from."""

    @staticmethod
    def _flow(document: dict[str, Any], *, url: str, iss: str, reached: list[str]) -> None:
        metadata = AuthorizationServerMetadata.from_discovery(document, discovery_url=url)
        reached.append(metadata.issuer)
        validate_authorization_response_iss({"iss": iss}, expected_issuer=metadata.issuer)

    def test_the_iss_check_alone_cannot_catch_it(self) -> None:
        """The gap: a raw `metadata.issuer` as the expected value passes the decoy's own `iss`."""
        metadata = AuthorizationServerMetadata(**_document(_DECOY))
        validate_authorization_response_iss({"iss": _DECOY}, expected_issuer=metadata.issuer)

    def test_a_refused_document_never_reaches_the_iss_check(self) -> None:
        reached: list[str] = []
        with pytest.raises(IssuerMismatchError, match="RFC 8414 section 3.3"):
            self._flow(_document(_DECOY), url=f"{_AS}{_OAUTH_PATH}", iss=_DECOY, reached=reached)
        assert reached == []

    def test_an_accepted_issuer_still_refuses_another_servers_response(self) -> None:
        reached: list[str] = []
        with pytest.raises(IssuerMismatchError, match="mix-up"):
            self._flow(_document(_AS), url=f"{_AS}{_OAUTH_PATH}", iss=_DECOY, reached=reached)
        assert reached == [_AS]

    def test_the_whole_flow_passes_for_the_real_server(self) -> None:
        reached: list[str] = []
        self._flow(_document(_AS), url=f"{_AS}{_OAUTH_PATH}", iss=_AS, reached=reached)
        assert reached == [_AS]

    @pytest.mark.parametrize(
        ("issuer", "iss"), [(f"{_AS}/", _AS), (_AS, f"{_AS}/"), (f"{_AS}/", f"{_AS}/")]
    )
    def test_the_two_checks_agree_about_a_trailing_slash(self, issuer: str, iss: str) -> None:
        self._flow(_document(issuer), url=f"{_AS}{_OAUTH_PATH}", iss=iss, reached=[])


class TestIssuerExports:
    @pytest.mark.parametrize(
        ("name", "value"),
        [
            ("IssuerMismatchError", IssuerMismatchError),
            ("issuer_from_discovery_url", issuer_from_discovery_url),
            ("validate_metadata_issuer", validate_metadata_issuer),
        ],
    )
    def test_the_protocol_surface_names_them(self, name: str, value: Any) -> None:
        assert name in mcp_spec.__all__
        assert getattr(mcp_spec, name) is value


# =============================================================================
# RFC 9728 section 3.3: protected resource metadata names the server asked for
# =============================================================================

_MCP = "https://mcp.example.com"
_MCP_A = "https://mcp-a.example.com/mcp"
_MCP_B = "https://mcp-b.example.com/mcp"


def _prm(resource: Any) -> dict[str, Any]:
    """A protected resource metadata document naming ``resource``, complete enough to parse."""
    return {"resource": resource, "authorization_servers": ["https://auth.example.com"]}


def _refusal_text(exc: BaseException) -> str:
    return f"{exc} {exc!r}"


class TestProtectedResourceFromDiscovery:
    def test_another_server_on_the_same_authorization_server_is_refused(self) -> None:
        """CVE-2026-123272 / CVE-2026-123271: the document names a server the client never asked for."""
        with pytest.raises(ResourceMismatchError, match="RFC 9728 section 3.3") as exc:
            ProtectedResourceMetadata.from_discovery(_prm(_MCP_B), resource_url=_MCP_A)
        assert "mcp-a" not in _refusal_text(exc.value)
        assert "mcp-b" not in _refusal_text(exc.value)

    @pytest.mark.parametrize(
        ("resource_url", "resource"),
        [
            pytest.param(f"{_MCP}/mcp", f"{_MCP}/admin/mcp", id="same-host-other-path"),
            pytest.param(f"{_MCP}/mcp", _MCP, id="the-origin-for-a-server-with-a-path"),
            pytest.param(_MCP, f"{_MCP}/mcp", id="a-path-for-a-server-at-the-root"),
            pytest.param(f"{_MCP}/mcp", f"{_MCP}/mcpx", id="a-longer-segment"),
            pytest.param(_MCP, "https://mcp.example.com:8443", id="other-port"),
            pytest.param("https://mcp.example.com:8443", _MCP, id="port-dropped"),
            pytest.param(_MCP, "https://mcp.example.com.evil.example", id="suffix-host"),
            pytest.param(f"{_MCP}/m?tenant=a", f"{_MCP}/m?tenant=b", id="other-query"),
            pytest.param(f"{_MCP}/m", f"{_MCP}/m?tenant=a", id="query-added"),
            pytest.param(
                "http://localhost:3000/mcp", "http://127.0.0.1:3000/mcp", id="another-loopback-name"
            ),
        ],
    )
    def test_any_other_server_is_refused(self, resource_url: str, resource: str) -> None:
        with pytest.raises(ResourceMismatchError, match="RFC 9728 section 3.3"):
            ProtectedResourceMetadata.from_discovery(_prm(resource), resource_url=resource_url)

    @pytest.mark.parametrize(
        "resource",
        [
            pytest.param("http://mcp.example.com", id="plain-http"),
            pytest.param("ftp://mcp.example.com", id="another-scheme"),
        ],
    )
    def test_another_scheme_is_refused(self, resource: str) -> None:
        with pytest.raises(ResourceMismatchError) as exc:
            ProtectedResourceMetadata.from_discovery(_prm(resource), resource_url=_MCP)
        assert "mcp.example.com" not in _refusal_text(exc.value)

    @pytest.mark.parametrize(
        ("resource_url", "resource"),
        [
            pytest.param(_MCP, f"{_MCP}/", id="root-slash"),
            pytest.param(f"{_MCP}/", _MCP, id="root-slash-on-the-url"),
            pytest.param(_MCP, "https://mcp.example.com:443", id="default-port"),
            pytest.param("https://mcp.example.com:443/", _MCP, id="default-port-on-the-url"),
            pytest.param(_MCP, "HTTPS://MCP.Example.com", id="scheme-and-host-case"),
            pytest.param(f"{_MCP}/mcp", f"{_MCP}/mcp/", id="trailing-slash-on-a-path"),
            pytest.param(
                "http://localhost:3000/mcp", "http://localhost:3000/mcp", id="loopback-http"
            ),
        ],
    )
    def test_what_the_token_audience_check_forgives_passes(
        self, resource_url: str, resource: str
    ) -> None:
        metadata = ProtectedResourceMetadata.from_discovery(
            _prm(resource), resource_url=resource_url
        )
        assert metadata.resource == resource

    @pytest.mark.parametrize(
        "resource",
        [
            pytest.param(f"{_MCP}#fragment", id="fragment"),
            pytest.param("", id="empty"),
            pytest.param(f" {_MCP}", id="leading-space"),
            pytest.param(f"{_MCP}\n", id="trailing-newline"),
            pytest.param(f"{_MCP} ", id="trailing-no-break-space"),
            pytest.param("mcp.example.com", id="no-scheme"),
            pytest.param("https://", id="no-host"),
            pytest.param("https://mcp.example.com:notaport", id="bad-port"),
            pytest.param("https://user@mcp.example.com", id="userinfo"),
            pytest.param("https://mcp.example.com/$(id)", id="shell-substitution"),
            pytest.param("https://mcp.example.com/a b", id="unencoded-space"),
        ],
    )
    def test_a_resource_that_is_not_a_server_uri_is_refused(self, resource: str) -> None:
        with pytest.raises(ResourceMismatchError) as exc:
            ProtectedResourceMetadata.from_discovery(_prm(resource), resource_url=_MCP)
        assert "mcp.example.com" not in _refusal_text(exc.value)
        assert "resource" in str(exc.value)
        assert exc.value.__suppress_context__ or exc.value.__context__ is None

    @pytest.mark.parametrize("resource", [7, None, [_MCP], {"url": _MCP}])
    def test_a_resource_that_is_not_a_string_is_refused_at_parse(self, resource: Any) -> None:
        with pytest.raises(ValidationError) as exc:
            ProtectedResourceMetadata.from_discovery(_prm(resource), resource_url=_MCP)
        assert "mcp.example.com" not in str(exc.value)

    @pytest.mark.parametrize(
        "resource_url",
        [
            pytest.param("", id="empty"),
            pytest.param(f" {_MCP}", id="leading-space"),
            pytest.param("mcp.example.com", id="no-scheme"),
            pytest.param(f"{_MCP}#fragment", id="fragment"),
            pytest.param("https://user@mcp.example.com", id="userinfo"),
            pytest.param(None, id="none"),
            pytest.param(b"https://mcp.example.com", id="bytes"),
        ],
    )
    def test_a_resource_url_that_is_not_a_server_uri_is_refused(self, resource_url: Any) -> None:
        with pytest.raises(ResourceMismatchError, match="resource_url") as exc:
            ProtectedResourceMetadata.from_discovery(_prm(_MCP), resource_url=resource_url)
        assert "mcp.example.com" not in _refusal_text(exc.value)

    def test_a_document_that_does_not_parse_stays_a_validation_error(self) -> None:
        with pytest.raises(ValidationError):
            ProtectedResourceMetadata.from_discovery({"resource": _MCP}, resource_url=_MCP)
        with pytest.raises(ValidationError):
            ProtectedResourceMetadata.from_discovery(
                {"resource": _MCP, "authorization_servers": ["http://auth.example.com"]},
                resource_url=_MCP,
            )

    @pytest.mark.parametrize("document", [None, "{}", [], 7])
    def test_a_document_that_is_not_an_object_is_refused(self, document: Any) -> None:
        with pytest.raises(ValidationError):
            ProtectedResourceMetadata.from_discovery(document, resource_url=_MCP)

    def test_a_matching_document_returns_the_parsed_model(self) -> None:
        document = {**_prm(_MCP_A), "scopes_supported": ["files:read"], "jwks_uri": f"{_MCP}/j"}
        metadata = ProtectedResourceMetadata.from_discovery(document, resource_url=_MCP_A)
        assert isinstance(metadata, ProtectedResourceMetadata)
        assert metadata.resource == _MCP_A
        assert metadata.authorization_servers == ["https://auth.example.com"]
        assert metadata.scopes_supported == ["files:read"]
        assert metadata.model_extra == {"jwks_uri": f"{_MCP}/j"}

    def test_the_plain_constructor_stays_as_it_was(self) -> None:
        """No URL, no check: a current caller keeps working, and the docs say which to use."""
        assert ProtectedResourceMetadata(**_prm(_MCP_B)).resource == _MCP_B


class TestValidateProtectedResource:
    def test_it_takes_parsed_metadata(self) -> None:
        metadata = ProtectedResourceMetadata(**_prm(_MCP_A))
        assert validate_protected_resource(metadata, resource_url=_MCP_A) is None
        with pytest.raises(ResourceMismatchError):
            validate_protected_resource(metadata, resource_url=_MCP_B)

    @pytest.mark.parametrize("resource", [7, None, "", f" {_MCP_A}", f"{_MCP_A}#x", _MCP_B])
    def test_a_resource_changed_after_parsing_is_checked_again(self, resource: Any) -> None:
        """A model is not frozen."""
        metadata = ProtectedResourceMetadata(**_prm(_MCP_A))
        metadata.resource = resource
        with pytest.raises(ResourceMismatchError):
            validate_protected_resource(metadata, resource_url=_MCP_A)

    @pytest.mark.parametrize("metadata", [None, _prm(_MCP_A), _MCP_A, object()])
    def test_something_with_no_resource_attribute_is_refused(self, metadata: Any) -> None:
        with pytest.raises(ResourceMismatchError, match="resource is a"):
            validate_protected_resource(metadata, resource_url=_MCP_A)

    def test_the_root_well_known_fallback_compares_with_the_origin(self) -> None:
        """RFC 9728 section 3.3: the identifier the metadata URL was built from, here the origin."""
        at_root = ProtectedResourceMetadata(**_prm(_MCP))
        validate_protected_resource(at_root, resource_url=_MCP)
        with pytest.raises(ResourceMismatchError):
            validate_protected_resource(at_root, resource_url=f"{_MCP}/mcp")


class TestTheResourceAndAudienceChecksAgree:
    """The comparison uses the token audience check's key, so a token minted for a resource
    this accepts is one the MCP server it names would accept, and the other way round."""

    @pytest.mark.parametrize(
        ("resource_url", "resource"),
        [
            (_MCP_A, _MCP_B),
            (f"{_MCP}/mcp", f"{_MCP}/admin/mcp"),
            (_MCP, "https://mcp.example.com:8443"),
            (_MCP, f"{_MCP}/"),
            (_MCP, "https://mcp.example.com:443"),
            (_MCP, "HTTPS://MCP.Example.com"),
            (f"{_MCP}/mcp", f"{_MCP}/mcp/"),
            (f"{_MCP}/m?tenant=a", f"{_MCP}/m?tenant=b"),
        ],
    )
    def test_both_reach_the_same_verdict(self, resource_url: str, resource: str) -> None:
        try:
            validate_protected_resource(
                ProtectedResourceMetadata(**_prm(resource)), resource_url=resource_url
            )
            resource_ok = True
        except ResourceMismatchError:
            resource_ok = False
        try:
            validate_access_token_audience({"aud": resource}, expected_audience=resource_url)
            audience_ok = True
        except TokenAudienceError:
            audience_ok = False
        assert resource_ok is audience_ok

    def test_a_token_minted_for_the_named_resource_is_refused_by_the_server_asked_for(
        self,
    ) -> None:
        """Why the binding matters: the token the CVE's flow mints fails the real server's
        audience check, so the only place it works is the server the document named."""
        with pytest.raises(TokenAudienceError):
            validate_access_token_audience({"aud": _MCP_B}, expected_audience=_MCP_A)
        validate_access_token_audience({"aud": _MCP_B}, expected_audience=_MCP_B)


class TestResourceExports:
    @pytest.mark.parametrize(
        ("name", "value"),
        [
            ("ResourceMismatchError", ResourceMismatchError),
            ("validate_protected_resource", validate_protected_resource),
            ("ProtectedResourceMetadata", ProtectedResourceMetadata),
        ],
    )
    def test_the_protocol_surface_names_them(self, name: str, value: Any) -> None:
        assert name in mcp_spec.__all__
        assert getattr(mcp_spec, name) is value

    def test_the_error_is_a_value_error_like_the_rest_of_the_module(self) -> None:
        assert issubclass(ResourceMismatchError, ValueError)


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
