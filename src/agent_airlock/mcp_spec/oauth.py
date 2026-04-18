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

DPoP is **intentionally not implemented**: per the spec page retrieved
2026-04-18 it is listed only as a SEP draft and not a normative
requirement. Flagged UNVERIFIED in `docs/research-log.md`.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import structlog
from pydantic import BaseModel, ConfigDict, Field, field_validator

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
    if not verifier:
        raise PKCEError("PKCE verifier must be non-empty")
    if not all(c in _PKCE_ALPHABET for c in verifier):
        raise PKCEError("PKCE verifier contains characters outside the unreserved set")
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def validate_pkce_pair(verifier: str, challenge: str) -> bool:
    """Return True iff the challenge is a valid S256 transform of the verifier.

    Constant-time comparison via `secrets.compare_digest` to avoid timing
    side-channels during token redemption.
    """
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


def canonicalize_resource_uri(uri: str) -> str:
    """Canonicalise an MCP server resource URI per spec §"Canonical Server URI".

    - scheme and host are lowercased
    - fragment is rejected
    - trailing slash stripped unless the path is purely "/"
    - scheme must be present (rejects bare hostnames)
    """
    if not uri:
        raise ResourceURIError("resource URI must be non-empty")

    parsed = urlparse(uri)
    if not parsed.scheme:
        raise ResourceURIError(f"resource URI missing scheme: {uri!r}")
    if parsed.fragment:
        raise ResourceURIError(f"resource URI must not contain a fragment: {uri!r}")

    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    if not host:
        raise ResourceURIError(f"resource URI missing host: {uri!r}")

    port = f":{parsed.port}" if parsed.port else ""
    path = parsed.path or ""
    if path.endswith("/") and path != "/":
        path = path.rstrip("/")
    query = f"?{parsed.query}" if parsed.query else ""

    return f"{scheme}://{host}{port}{path}{query}"


# =============================================================================
# OAuth 2.0 metadata documents (RFC 8414 + RFC 9728)
# =============================================================================


class AuthorizationServerMetadata(BaseModel):
    """Subset of RFC 8414 Authorization Server Metadata that MCP cares about.

    The spec REQUIRES `code_challenge_methods_supported` to be present
    and include `S256`. We enforce both with a `field_validator`.
    """

    model_config = ConfigDict(strict=True, extra="allow")

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    code_challenge_methods_supported: list[str] = Field(..., min_length=1)
    registration_endpoint: str | None = None
    client_id_metadata_document_supported: bool | None = None

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
    `authorization_servers`.
    """

    model_config = ConfigDict(strict=True, extra="allow")

    resource: str
    authorization_servers: list[str] = Field(..., min_length=1)
    scopes_supported: list[str] | None = None
    bearer_methods_supported: list[str] | None = None


# =============================================================================
# Access token audience validation
# =============================================================================


class TokenAudienceError(ValueError):
    """Raised when an access token is not valid for this MCP server."""


def validate_access_token_audience(
    token_claims: dict[str, Any],
    *,
    expected_audience: str,
) -> None:
    """Validate an access token's `aud` claim per spec §"Token Handling".

    Accepts tokens where `aud` is either the expected audience string or a
    list that contains it. Canonicalises both sides via
    `canonicalize_resource_uri` so superficial form differences
    (trailing slash, uppercase scheme) do not reject legitimate tokens.

    Args:
        token_claims: The decoded JWT claims dict (signature verification
            is the caller's responsibility; this is strictly an audience
            check).
        expected_audience: The canonical URI of THIS MCP server, as used
            when minting the Protected Resource Metadata.

    Raises:
        TokenAudienceError: If `aud` is missing, empty, or does not
            contain the expected audience (after canonicalisation).
    """
    aud = token_claims.get("aud")
    if aud is None or aud == "":
        raise TokenAudienceError("access token has no 'aud' claim")

    expected = canonicalize_resource_uri(expected_audience)

    if isinstance(aud, str):
        if canonicalize_resource_uri(aud) != expected:
            raise TokenAudienceError(
                f"access token 'aud'={aud!r} does not match MCP server {expected!r}"
            )
        return

    if isinstance(aud, list):
        for a in aud:
            if not isinstance(a, str):
                continue
            try:
                if canonicalize_resource_uri(a) == expected:
                    return
            except ResourceURIError:
                continue
        raise TokenAudienceError(
            f"access token 'aud'={aud!r} does not contain MCP server {expected!r}"
        )

    raise TokenAudienceError(f"access token 'aud' has unsupported type: {type(aud).__name__}")


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
]
