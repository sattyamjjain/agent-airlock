"""OAuth 2.1 + PKCE S256 + RFC 8707 helpers for MCP 2025-11-25.

Source-of-truth: https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization
(retrieved 2026-04-18).

Scope: runtime validators. No authorization server, no token issuance, no
refresh flow — just the primitives an MCP server or client needs to check
that the other side is conforming to the spec.

Key normative requirements enforced:

- **PKCE S256 MUST be used when technically capable** (spec §"Authorization
  Code Protection"). We implement only S256; there is no `plain` fallback.
- **`code_challenge_methods_supported` MUST be present in AS metadata** or
  the client MUST refuse to proceed. `AuthorizationServerMetadata` enforces
  this at parse time.
- **Redirect URIs MUST be either `localhost`/`127.0.0.1` or HTTPS** (spec
  §"Communication Security"). `validate_redirect_uri` rejects anything else.
- **Access tokens MUST be Authorization: Bearer** — no query-string tokens,
  no other schemes (spec §"Access Token Usage"). `parse_authorization_header`
  rejects non-Bearer and `parse_www_authenticate_header` parses the
  response side.
- **RFC 8707 `resource` parameter MUST identify the MCP server**
  canonically. `canonicalize_resource_uri` applies the spec's canonical
  form (lowercase scheme+host, no fragment, no trailing slash unless
  semantically required).
- **Token audience MUST be validated** by the MCP server. `validate_access_token_audience`
  checks the decoded `aud` claim.
- **A discovery URL a client follows is screened at parse time.** The issuer, endpoint and
  authorization-server URLs in `AuthorizationServerMetadata` and
  `ProtectedResourceMetadata` must be https (plain http only on a loopback host) and may not
  hold a character a URL must percent-encode or `$(`: CVE-2026-119025's `open` ran such an
  `authorization_endpoint` through PowerShell.

DPoP is **intentionally not implemented**: per the spec page retrieved
2026-04-18 it is listed only as a SEP draft and not a normative
requirement (UNVERIFIED pending a normative spec citation).
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Any
from urllib.parse import parse_qs, urlparse, urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator

from .._log import structlog
from ..safe_types import _SHELL_SUBSTITUTION, _URL_MUST_BE_ENCODED

logger = structlog.get_logger("agent-airlock.mcp_spec.oauth")


# =============================================================================
# PKCE (S256 only)
# =============================================================================


PKCE_VERIFIER_MIN_LEN = 43
PKCE_VERIFIER_MAX_LEN = 128

# RFC 7636 section 4.1: unreserved characters from RFC 3986
_PKCE_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"


class PKCEError(ValueError):
    """Raised when a PKCE verifier or challenge is invalid."""


def generate_pkce_verifier(length: int = 64) -> str:
    """Generate a fresh PKCE code_verifier per RFC 7636 §4.1.

    Length must be between 43 and 128 inclusive (RFC 7636). Uses
    `secrets.choice` — cryptographically secure.
    """
    if not (PKCE_VERIFIER_MIN_LEN <= length <= PKCE_VERIFIER_MAX_LEN):
        raise PKCEError(
            f"PKCE verifier length must be in [{PKCE_VERIFIER_MIN_LEN}, "
            f"{PKCE_VERIFIER_MAX_LEN}], got {length}"
        )
    return "".join(secrets.choice(_PKCE_ALPHABET) for _ in range(length))


def generate_pkce_challenge(verifier: str) -> str:
    """Derive the S256 code_challenge from a verifier per RFC 7636 §4.2.

    `code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))` with
    the `=` padding stripped, which matches the exact normative transform.
    """
    if not isinstance(verifier, str):
        raise PKCEError(f"PKCE verifier must be a str, got {type(verifier).__name__}")
    if not verifier:
        raise PKCEError("PKCE verifier must be non-empty")
    if not all(c in _PKCE_ALPHABET for c in verifier):
        raise PKCEError("PKCE verifier contains characters outside the unreserved set")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def validate_pkce_pair(verifier: str, challenge: str) -> bool:
    """Return True iff the challenge is a valid S256 transform of the verifier.

    Constant-time comparison via `secrets.compare_digest` to avoid timing
    side-channels during token redemption. A challenge that is not an ASCII string
    is not a valid one: False, not the ``TypeError`` ``compare_digest`` raises.
    """
    if not isinstance(challenge, str) or not challenge.isascii():
        return False
    try:
        expected = generate_pkce_challenge(verifier)
    except PKCEError:
        return False
    return secrets.compare_digest(expected, challenge)


# =============================================================================
# Redirect URI validation (spec §"Communication Security")
# =============================================================================


class RedirectURIError(ValueError):
    """Raised when a redirect URI fails the MCP 2025-11-25 allow-list."""


def validate_redirect_uri(uri: str) -> None:
    """Reject any redirect URI that is not https:// or a localhost loopback.

    Per spec: "All redirect URIs MUST be either `localhost` or use HTTPS."
    We accept 127.0.0.1 and [::1] as equivalents; we reject `http://` for
    any other host.
    """
    if not isinstance(uri, str):
        raise RedirectURIError(f"redirect_uri must be a str, got {type(uri).__name__}")
    if not uri:
        raise RedirectURIError("redirect_uri must be non-empty")

    try:
        parsed = urlparse(uri)
    except ValueError as e:
        raise RedirectURIError(f"redirect_uri is not a valid URI: {e}") from e

    if parsed.scheme not in ("http", "https"):
        raise RedirectURIError(f"redirect_uri must use http or https scheme, got {parsed.scheme!r}")

    host = (parsed.hostname or "").lower()
    is_loopback = host in ("localhost", "127.0.0.1", "::1")

    if parsed.scheme == "http" and not is_loopback:
        raise RedirectURIError(
            f"HTTP redirect URIs are only allowed on loopback; got host {host!r}"
        )
    # https:// is always accepted regardless of host


# =============================================================================
# Authorization & WWW-Authenticate header parsing
# =============================================================================


@dataclass
class BearerToken:
    """Parsed Authorization: Bearer <token>."""

    token: str


class BearerHeaderError(ValueError):
    """Raised when an Authorization header is not a well-formed Bearer token."""


def parse_authorization_header(value: str) -> BearerToken:
    """Parse `Authorization: Bearer <token>`.

    Rejects every other scheme per spec §"Access Token Usage": "MCP client
    MUST use the Authorization request header field... Bearer <access-token>".
    """
    if not isinstance(value, str):
        raise BearerHeaderError(f"Authorization header must be a str, got {type(value).__name__}")
    if not value:
        raise BearerHeaderError("Authorization header is empty")

    parts = value.split(None, 1)
    if len(parts) != 2:
        raise BearerHeaderError("Authorization header must be '<scheme> <token>'")

    scheme, token = parts
    if scheme.lower() != "bearer":
        raise BearerHeaderError(f"MCP 2025-11-25 requires Bearer tokens; got scheme {scheme!r}")
    if not token or any(c in token for c in (" ", "\t")):
        raise BearerHeaderError("Bearer token must be a single non-empty opaque string")
    return BearerToken(token=token)


@dataclass
class WWWAuthenticateChallenge:
    """Parsed WWW-Authenticate header on a 401/403 response."""

    scheme: str
    params: dict[str, str] = field(default_factory=dict)

    @property
    def resource_metadata(self) -> str | None:
        """The `resource_metadata` URI a client uses to fetch RS metadata."""
        return self.params.get("resource_metadata")

    @property
    def scope(self) -> str | None:
        return self.params.get("scope")

    @property
    def error(self) -> str | None:
        return self.params.get("error")


def parse_www_authenticate_header(value: str) -> WWWAuthenticateChallenge:
    """Parse a WWW-Authenticate response header.

    Tolerant of the common RFC 6750 shape:
        Bearer resource_metadata="https://...", scope="files:read", error="insufficient_scope"

    Values may or may not be quoted; commas separate params. We do NOT try
    to handle every exotic case from RFC 7235 — the set used in RFC 6750
    and MCP 2025-11-25 is enough.
    """
    if not isinstance(value, str):
        raise BearerHeaderError(
            f"WWW-Authenticate header must be a str, got {type(value).__name__}"
        )
    if not value:
        raise BearerHeaderError("WWW-Authenticate header is empty")

    parts = value.split(None, 1)
    scheme = parts[0]
    params: dict[str, str] = {}

    if len(parts) == 2 and parts[1].strip():
        # Naive but correct for the canonical form used in the spec's examples.
        for raw in _split_top_level_commas(parts[1]):
            raw = raw.strip()
            if "=" not in raw:
                continue
            k, _, v = raw.partition("=")
            k = k.strip().lower()
            v = v.strip()
            if v.startswith('"') and v.endswith('"'):
                v = v[1:-1]
            params[k] = v

    return WWWAuthenticateChallenge(scheme=scheme, params=params)


def _split_top_level_commas(s: str) -> list[str]:
    """Split on commas not inside double-quoted strings."""
    out: list[str] = []
    depth = 0
    start = 0
    for i, ch in enumerate(s):
        if ch == '"':
            depth = 1 - depth
        elif ch == "," and depth == 0:
            out.append(s[start:i])
            start = i + 1
    out.append(s[start:])
    return out


# =============================================================================
# RFC 8707 resource parameter canonicalisation
# =============================================================================


class ResourceURIError(ValueError):
    """Raised when a resource URI can't be canonicalised."""


#: Each scheme's default port (RFC 3986 §6.2.3: an explicit default port names the same
#: resource as none). Read only by the audience comparison key, never the canonical form.
_DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443}


@dataclass(frozen=True)
class _ResourceParts:
    """A resource URI split into the parts its canonical form is built from."""

    scheme: str
    host: str  # an IPv6 literal keeps its brackets
    port: int | None
    path: str
    query: str

    def render(self, *, port: int | None) -> str:
        port_part = f":{port}" if port is not None else ""
        query = f"?{self.query}" if self.query else ""
        return f"{self.scheme}://{self.host}{port_part}{self.path}{query}"


def _resource_parts(uri: str) -> _ResourceParts:
    """Split ``uri`` for canonicalisation, refusing what cannot be read.

    Raises:
        ResourceURIError: ``uri`` is not a non-empty string, cannot be parsed (an unclosed
            IPv6 bracket, a port that is not a number or is out of range), or has no
            scheme, has a fragment, or has no host.
    """
    if not isinstance(uri, str):
        raise ResourceURIError(f"resource URI must be a str, got {type(uri).__name__}")
    if not uri:
        raise ResourceURIError("resource URI must be non-empty")
    try:
        parsed = urlparse(uri)
        port = parsed.port
    except ValueError as exc:
        # urllib raises a bare ValueError for these; until 0.10.28 it escaped the
        # documented error, and @Airlock step 0.6, in warn and deny mode alike.
        raise ResourceURIError(f"resource URI is malformed: {uri!r}: {exc}") from exc
    if not parsed.scheme:
        raise ResourceURIError(f"resource URI missing scheme: {uri!r}")
    if parsed.fragment:
        raise ResourceURIError(f"resource URI must not contain a fragment: {uri!r}")

    host = (parsed.hostname or "").lower()
    if not host:
        raise ResourceURIError(f"resource URI missing host: {uri!r}")
    if "[" in parsed.netloc.rpartition("@")[2]:
        # urllib strips an IPv6 literal's brackets; without them [::1]:80 and [::1:80]
        # (no port) both read "::1:80". Until 0.10.28 the two shared one canonical form.
        host = f"[{host}]"

    path = parsed.path or ""
    if path.endswith("/") and path != "/":
        path = path.rstrip("/")
    return _ResourceParts(parsed.scheme.lower(), host, port, path, parsed.query)


def canonicalize_resource_uri(uri: str) -> str:
    """Canonicalise an MCP server resource URI per spec §"Canonical Server URI".

    - scheme and host are lowercased; an IPv6 literal keeps its brackets
    - an explicit port is kept, ``:0`` and the scheme's default port included
    - fragment is rejected
    - trailing slash stripped unless the path is purely "/"
    - scheme must be present (rejects bare hostnames)

    Raises:
        ResourceURIError: ``uri`` is not a string, is empty or malformed (an unclosed
            IPv6 bracket, a port out of range or not a number), or has no scheme, a
            fragment, or no host.
    """
    parts = _resource_parts(uri)
    return parts.render(port=parts.port)


# =============================================================================
# OAuth 2.0 metadata documents (RFC 8414 + RFC 9728)
# =============================================================================

# What a character a URL must percent-encode is called in a refusal, so the message names
# its class and never repeats the URL.
_URL_CHARACTER_CLASSES: dict[str, str] = {
    " ": "a space",
    '"': "a double quote",
    "`": "a backtick",
    "<": "an angle bracket",
    ">": "an angle bracket",
    "\\": "a backslash",
    "^": "a caret",
    "{": "a curly brace",
    "}": "a curly brace",
    "|": "a pipe",
}


def _url_character_class(char: str) -> str:
    if ord(char) < 0x20 or char == "\x7f":
        return "a control character"
    return _URL_CHARACTER_CLASSES.get(char, "a character a URL must percent-encode")


def _is_loopback_host(host: str) -> bool:
    """``localhost``, or an address :mod:`ipaddress` reports as loopback. No DNS lookup."""
    if host == "localhost":
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        # Read an IPv4-mapped address as the IPv4 address it carries, whichever Python
        # patch release runs: how IPv6Address reports one has changed across releases.
        return address.ipv4_mapped.is_loopback
    return address.is_loopback


def _screen_metadata_url(field_name: str, value: str) -> str:
    """Refuse a discovery-metadata URL a client cannot safely follow (CVE-2026-119025).

    ``open`` 7.2.0 before 11.0.0 passed a URL unescaped to ``powershell -EncodedCommand`` on
    Windows and WSL, so a malicious MCP server whose discovery metadata put ``$(...)`` in its
    ``authorization_endpoint`` ran PowerShell on the client that opened it: the MCP
    Inspector 2.0.0 through 2.11.0 did (GHSA-q978-78c7-phqw). No URL needs these characters
    unencoded (``safe_types._URL_MUST_BE_ENCODED``, the RFC 3986 set, and
    ``safe_types._SHELL_SUBSTITUTION``), so the value is refused as it is parsed, before any
    client follows it. The scheme must be https, or plain http on a loopback host, which
    local MCP development uses. The message names the field and what it holds, never the
    URL.

    Raises:
        ValueError: The value holds one of those characters, is not an absolute http(s) URL
            with a host, or is plain http on a host that is not loopback.
    """
    if _SHELL_SUBSTITUTION in value:
        raise ValueError(
            f"{field_name} holds a shell command substitution, '$(', which no URL needs unencoded"
        )
    for char in value:
        if char in _URL_MUST_BE_ENCODED:
            raise ValueError(
                f"{field_name} holds {_url_character_class(char)}, which a URL must percent-encode"
            )
    try:
        parts = urlsplit(value)
    except ValueError:
        raise ValueError(f"{field_name} is not a valid URL") from None
    if parts.scheme not in ("https", "http"):
        raise ValueError(f"{field_name} must be an https URL")
    host = parts.hostname
    if not host:
        raise ValueError(f"{field_name} has no host")
    if parts.scheme == "http" and not _is_loopback_host(host):
        raise ValueError(
            f"{field_name} uses plain http on a host that is not loopback; it must be https"
        )
    return value


class AuthorizationServerMetadata(BaseModel):
    """Subset of RFC 8414 Authorization Server Metadata that MCP cares about.

    The spec REQUIRES `code_challenge_methods_supported` to be present
    and include `S256`. We enforce both with a `field_validator`.

    The URLs a client follows, `issuer`, `authorization_endpoint`, `token_endpoint` and
    `registration_endpoint` when set, are screened as they are parsed
    (`_screen_metadata_url`, CVE-2026-119025). A validation error's text never repeats the
    input (`hide_input_in_errors`); `ValidationError.errors()` still carries it unless
    called with `include_input=False`. Extra fields are kept as given and not screened.
    """

    model_config = ConfigDict(strict=True, extra="allow", hide_input_in_errors=True)

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    code_challenge_methods_supported: list[str] = Field(..., min_length=1)
    registration_endpoint: str | None = None
    client_id_metadata_document_supported: bool | None = None

    @field_validator("issuer", "authorization_endpoint", "token_endpoint", "registration_endpoint")
    @classmethod
    def _screen_urls(cls, value: str | None, info: ValidationInfo) -> str | None:
        if value is None:
            return None
        return _screen_metadata_url(str(info.field_name), value)

    @field_validator("code_challenge_methods_supported")
    @classmethod
    def _must_include_s256(cls, v: list[str]) -> list[str]:
        if "S256" not in v:
            raise ValueError(
                "MCP 2025-11-25 requires the authorization server to support "
                f"PKCE S256; code_challenge_methods_supported={v!r}"
            )
        return v


class ProtectedResourceMetadata(BaseModel):
    """Subset of RFC 9728 Protected Resource Metadata used for AS discovery.

    MCP servers MUST return at least one authorization server in
    `authorization_servers`. Each one is screened as it is parsed, as the
    `AuthorizationServerMetadata` URLs are (CVE-2026-119025), and a validation error's text
    never repeats the input.
    """

    model_config = ConfigDict(strict=True, extra="allow", hide_input_in_errors=True)

    resource: str
    authorization_servers: list[str] = Field(..., min_length=1)
    scopes_supported: list[str] | None = None
    bearer_methods_supported: list[str] | None = None

    @field_validator("authorization_servers")
    @classmethod
    def _screen_authorization_servers(cls, value: list[str]) -> list[str]:
        for index, url in enumerate(value):
            _screen_metadata_url(f"authorization_servers[{index}]", url)
        return value


# =============================================================================
# Access token audience validation
# =============================================================================


class TokenAudienceError(ValueError):
    """Raised when an access token is not valid for this MCP server."""


def _audience_key(uri: str) -> str:
    """``canonicalize_resource_uri(uri)`` with a root path and a default port dropped.

    RFC 3986 §6.2.3: for http(s) an empty path and ``/`` name the same resource, and so do
    no port and the scheme's default port, and the spec's canonical server URI has no
    trailing slash, so a token for ``https://mcp.example.com:443/`` is a token for
    ``https://mcp.example.com``. Until 0.10.27 a root slash, and until 0.10.28 a default
    port, was compared as written and refused. The canonical form itself keeps both
    (``canonicalize_resource_uri``); only the comparison ignores them. ``:0`` is not a
    default port and stays.

    Raises:
        ResourceURIError: ``uri`` cannot be canonicalised.
    """
    parts = _resource_parts(uri)
    if parts.path == "/":
        parts = replace(parts, path="")
    port = None if parts.port == _DEFAULT_PORTS.get(parts.scheme) else parts.port
    return parts.render(port=port)


def validate_access_token_audience(
    token_claims: Mapping[str, Any],
    *,
    expected_audience: str,
) -> None:
    """Validate an access token's `aud` claim per spec §"Token Handling".

    Accepts tokens where `aud` is either the expected audience string or a
    list that contains it. Canonicalises both sides via
    `canonicalize_resource_uri`, and reads a root path as no path, so
    superficial form differences (trailing slash, uppercase scheme) do not
    reject legitimate tokens.

    Args:
        token_claims: The decoded JWT claims dict (signature verification
            is the caller's responsibility; this is strictly an audience
            check).
        expected_audience: The canonical URI of THIS MCP server, as used
            when minting the Protected Resource Metadata.

    Raises:
        TokenAudienceError: If `aud` is missing, empty, or does not
            contain the expected audience (after canonicalisation). A string
            `aud` that is not a URI, and a list `aud` holding anything but
            strings, are refused with it too: until 0.10.27 the first escaped as
            a `ResourceURIError` and the second's other items were skipped. So
            are a malformed `aud` (an unclosed IPv6 bracket, a port out of range;
            until 0.10.28 a bare `ValueError`) and claims that are not a mapping.
        ResourceURIError: ``expected_audience`` itself is not a resource URI.
    """
    if not isinstance(token_claims, Mapping):
        raise TokenAudienceError(
            f"access token claims are a {type(token_claims).__name__}, not a mapping"
        )
    aud = token_claims.get("aud")
    if aud is None or aud == "":
        raise TokenAudienceError("access token has no 'aud' claim")

    expected = _audience_key(expected_audience)

    if isinstance(aud, str):
        try:
            canonical = _audience_key(aud)
        except ResourceURIError as exc:
            raise TokenAudienceError(
                f"access token 'aud'={aud!r} is not a resource URI, so not MCP server "
                f"{expected!r}: {exc}"
            ) from exc
        if canonical != expected:
            raise TokenAudienceError(
                f"access token 'aud'={aud!r} does not match MCP server {expected!r}"
            )
        return

    if isinstance(aud, list):
        # RFC 7519 §4.1.3: each audience is a string. A token whose list holds anything
        # else is malformed, and is refused whole rather than read past.
        if not all(isinstance(a, str) for a in aud):
            raise TokenAudienceError(
                f"access token 'aud'={aud!r} holds a value that is not a string"
            )
        for a in aud:
            # A string that is not a URI names some other audience (a client id, say).
            try:
                if _audience_key(a) == expected:
                    return
            except ResourceURIError:
                continue
        raise TokenAudienceError(
            f"access token 'aud'={aud!r} does not contain MCP server {expected!r}"
        )

    raise TokenAudienceError(f"access token 'aud' has unsupported type: {type(aud).__name__}")


# =============================================================================
# Authorization-response issuer (`iss`) validation — RFC 9207 / SEP-2468
# =============================================================================


class IssuerMismatchError(ValueError):
    """Raised when an OAuth authorization response fails `iss` validation.

    RFC 9207 defines the `iss` authorization-response parameter so a client can
    detect an authorization-server **mix-up attack** — an attacker replaying an
    authorization response from a different (malicious) server. MCP's SEP-2468
    (final 2026-07-28 spec) requires MCP clients to validate `iss` against the
    authorization server they initiated the flow with. This guard is
    deny-by-default: a missing (when required) or mismatched `iss` is refused.
    """


def _normalize_issuer(value: str) -> str:
    # RFC 8414 issuer identifiers carry no trailing slash; normalize it away so
    # a superficial difference does not falsely reject a legitimate response.
    return value.strip().rstrip("/")


def _unreadable_params(params: Any) -> IssuerMismatchError:
    return IssuerMismatchError(
        f"authorization response parameters are a {type(params).__name__} the issuer check "
        "cannot read; refusing rather than skipping the mix-up defence"
    )


#: The multi-value accessor a framework's query-params multi-dict reads every value of a
#: name through: Starlette, Werkzeug, Django and Bottle spell it ``getlist``, httpx
#: ``get_list``, multidict (aiohttp, yarl) and WebOb ``getall``.
_MULTI_VALUE_ACCESSORS: tuple[str, ...] = ("getlist", "get_list", "getall")


def _iss_values(params: Any) -> list[Any]:
    """Every ``iss`` value an authorization response carries, repeats included.

    Reads a query string (``str`` / ``bytes``), a mapping whose value may be a list (or a
    framework multi-dict, through its multi-value accessor), and a list of
    ``(key, value)`` pairs (``parse_qsl`` output). The accessor is called with the name
    alone, and a ``KeyError`` from it means no value (multidict's ``getall`` raises one).
    Until 0.10.28 httpx's ``get_list`` was not among them, and a ``getall`` that takes no
    default (WebOb's) or any accessor that could not be called fell back to ``get``, so
    each read one value and a second ``iss`` passed.

    Raises:
        IssuerMismatchError: ``params`` is of no readable shape, or is a multi-dict whose
            multi-value accessor cannot be called with a name alone.
    """
    if isinstance(params, (bytes, bytearray)):
        try:
            params = bytes(params).decode("utf-8")
        except UnicodeDecodeError:
            raise _unreadable_params(params) from None
    if isinstance(params, str):
        return list(parse_qs(params, keep_blank_values=True).get("iss", []))
    if isinstance(params, Mapping):
        for accessor in _MULTI_VALUE_ACCESSORS:
            getter = getattr(params, accessor, None)
            if not callable(getter):
                continue
            try:
                return list(getter("iss"))
            except KeyError:
                return []
            except TypeError:
                raise _unreadable_params(params) from None
        raw = params.get("iss")
        if isinstance(raw, (list, tuple)):
            return list(raw)
        return [] if raw is None else [raw]
    if isinstance(params, (list, tuple)):
        values: list[Any] = []
        for item in params:
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                raise _unreadable_params(params)
            if item[0] == "iss":
                values.append(item[1])
        return values
    raise _unreadable_params(params)


def validate_authorization_response_iss(
    params: Mapping[str, Any] | str | bytes | Sequence[tuple[str, Any]],
    *,
    expected_issuer: str,
    require_iss: bool = True,
) -> None:
    """Validate the `iss` parameter on an OAuth authorization response (RFC 9207).

    Implements the client-side check MCP SEP-2468 mandates: the authorization
    response returned to the redirect URI must carry an `iss` equal to the
    issuer identifier of the authorization server the client started the flow
    with. Comparison is exact after trailing-slash normalization (RFC 8414
    issuer identifiers are compared as strings, not resolved).

    Args:
        params: The authorization-response parameters — a mapping (e.g. parsed query
            params, where a value may be a ``str`` or a ``list[str]``; a framework
            multi-dict is read through its ``getlist`` / ``get_list`` / ``getall``), a
            list of ``(key, value)`` pairs, or a raw query string
            (``"code=…&state=…&iss=…"``, ``str`` or ``bytes``).
        expected_issuer: The issuer identifier of the authorization server the
            client initiated the flow with (e.g. from the discovered
            :class:`AuthorizationServerMetadata.issuer`).
        require_iss: When True (default, deny-by-default) a response with no
            `iss` is refused — the mix-up defence only holds if the parameter is
            actually present. Set False only for a documented legacy server that
            cannot emit `iss` yet.

    Raises:
        IssuerMismatchError: `iss` is missing (and required), any `iss` value does
            not match ``expected_issuer`` (a repeated `iss` is accepted only when
            every value matches; until 0.10.28 the first was read and the rest
            ignored), or ``params`` is of no readable shape.
        ValueError: ``expected_issuer`` is empty.
    """
    if not expected_issuer or not expected_issuer.strip():
        raise ValueError("expected_issuer must be a non-empty issuer identifier")

    values = _iss_values(params)
    if all(v is None or (isinstance(v, str) and v.strip() == "") for v in values):
        if require_iss:
            raise IssuerMismatchError(
                "authorization response has no 'iss' parameter; RFC 9207 / SEP-2468 "
                "require it to defend against authorization-server mix-up attacks"
            )
        return

    expected = _normalize_issuer(expected_issuer)
    for iss_raw in values:
        if not isinstance(iss_raw, str):
            raise IssuerMismatchError(
                f"authorization response 'iss' has unsupported type: {type(iss_raw).__name__}"
            )
        if _normalize_issuer(iss_raw) != expected:
            repeated = f" (one of {len(values)} 'iss' values)" if len(values) > 1 else ""
            raise IssuerMismatchError(
                f"authorization response 'iss'={iss_raw!r}{repeated} does not match the "
                f"expected authorization server {expected_issuer!r} (possible mix-up attack)"
            )


__all__ = [
    # PKCE
    "PKCE_VERIFIER_MIN_LEN",
    "PKCE_VERIFIER_MAX_LEN",
    "PKCEError",
    "generate_pkce_verifier",
    "generate_pkce_challenge",
    "validate_pkce_pair",
    # Redirect URI
    "RedirectURIError",
    "validate_redirect_uri",
    # Headers
    "BearerToken",
    "BearerHeaderError",
    "WWWAuthenticateChallenge",
    "parse_authorization_header",
    "parse_www_authenticate_header",
    # RFC 8707 resource
    "ResourceURIError",
    "canonicalize_resource_uri",
    # Metadata
    "AuthorizationServerMetadata",
    "ProtectedResourceMetadata",
    # Token audience
    "TokenAudienceError",
    "validate_access_token_audience",
    # RFC 9207 / SEP-2468 authorization-response issuer
    "IssuerMismatchError",
    "validate_authorization_response_iss",
]
