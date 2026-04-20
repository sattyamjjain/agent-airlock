"""OAuth app audit guard (v0.5.2+).

Motivation
----------
On 2026-04-19 Vercel confirmed a breach that started with a compromised
third-party Google Workspace OAuth app (Context.ai, client_id
``110671459871-30f1spbu0hptbs60cb4vsmv79i7bbvqj.apps.googleusercontent.com``).
ShinyHunters claimed exfiltration of 580 employee records, API keys,
GitHub/NPM tokens, source code, and database access — all through a
legitimate-looking OAuth consent. v0.5.1 already shipped PKCE S256 and
audience-validation helpers. What was missing was a policy layer that
asks, *before* caching a freshly-exchanged token:

    "Is this OAuth app allowed to talk to us at all?"

This module is that layer.

Usage::

    from agent_airlock.mcp_spec.oauth_audit import (
        OAuthAppAuditConfig,
        audit_oauth_exchange,
    )
    from agent_airlock.policy_presets import oauth_audit_vercel_2026_defaults

    cfg = oauth_audit_vercel_2026_defaults()
    report = audit_oauth_exchange(
        token_response={"access_token": "...", "expires_in": 3600, ...},
        client_id="my-app.apps.googleusercontent.com",
        cfg=cfg,
    )
    # Raises OAuthAppBlocked / OAuthPolicyViolation on any rule failure.

References
----------
- Vercel bulletin (2026-04-19):
  https://vercel.com/kb/bulletin/vercel-april-2026-security-incident
- CyberInsider coverage (2026-04-19):
  https://cyberinsider.com/vercel-confirms-security-incident-as-hackers-claim-to-sell-internal-access/
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

from ..exceptions import AirlockError

logger = structlog.get_logger("agent-airlock.mcp_spec.oauth_audit")

# Known-compromised OAuth client IDs (public, from vendor disclosures).
# These are NOT secrets — they are the same IDs an attacker's phishing
# page would present to trick a user into granting consent.
KNOWN_COMPROMISED_CLIENT_IDS: frozenset[str] = frozenset(
    {
        # Context.ai — Vercel April 2026 breach vector.
        "110671459871-30f1spbu0hptbs60cb4vsmv79i7bbvqj.apps.googleusercontent.com",
    }
)


@dataclass
class OAuthAppAuditConfig:
    """Policy for auditing a fresh OAuth token exchange.

    Attributes:
        allowed_client_ids: If non-empty, the client_id MUST be in this
            set. Empty means "no allow-list, fall through to
            blocked_client_ids only."
        blocked_client_ids: Explicit deny-list. Takes precedence over
            the allow-list. Seed with
            ``KNOWN_COMPROMISED_CLIENT_IDS`` at minimum.
        max_token_age_seconds: Reject tokens whose ``expires_in``
            declares a lifetime longer than this. Default 3600 (1h)
            matches the Anthropic/Google defaults.
        require_pkce: Require the token-response dict to carry evidence
            of a PKCE exchange (either a ``code_challenge_method`` echo
            or an explicit ``pkce_used=true`` attestation from the
            auth server).
        require_refresh_rotation: If a ``refresh_token`` is present,
            require ``refresh_token_rotated=true`` in the response to
            prevent refresh-token reuse.
        deny_list_feed_path: Optional local JSON file path. When set,
            :func:`load_deny_list` reads a list of client IDs from it
            and merges them into ``blocked_client_ids``. No network
            fetches by default — air-gap-safe.
    """

    allowed_client_ids: frozenset[str] = field(default_factory=frozenset)
    blocked_client_ids: frozenset[str] = field(default_factory=lambda: KNOWN_COMPROMISED_CLIENT_IDS)
    max_token_age_seconds: int = 3600
    require_pkce: bool = True
    require_refresh_rotation: bool = True
    deny_list_feed_path: Path | None = None


@dataclass
class OAuthAuditReport:
    """Outcome of a successful audit — all rules passed."""

    client_id: str
    token_lifetime_seconds: int
    pkce_verified: bool
    refresh_rotated: bool
    audited_at: float


class OAuthAppBlocked(AirlockError):
    """Raised when ``client_id`` is on the deny-list."""

    def __init__(self, *, client_id: str, reason: str) -> None:
        self.client_id = client_id
        self.reason = reason
        super().__init__(f"OAuth app blocked: {client_id!r} — {reason}")


class OAuthPolicyViolation(AirlockError):
    """Raised when an OAuth exchange violates the audit policy
    (missing PKCE, refresh-reuse, oversize lifetime)."""

    def __init__(self, *, rule: str, detail: str) -> None:
        self.rule = rule
        self.detail = detail
        super().__init__(f"OAuth policy violation [{rule}]: {detail}")


def load_deny_list(path: Path) -> frozenset[str]:
    """Load a JSON file of additional blocked client IDs.

    The file must be a JSON array of strings. Unknown keys are ignored.
    Returns an empty set if the file is missing (deliberate — a
    deployment can ship without a feed and opt in later).
    """
    if not path.exists():
        return frozenset()
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise OAuthPolicyViolation(
            rule="deny_list_parse",
            detail=f"could not parse {path}: {exc}",
        ) from exc
    if not isinstance(data, list) or not all(isinstance(s, str) for s in data):
        raise OAuthPolicyViolation(
            rule="deny_list_shape",
            detail=f"{path} must be a JSON array of strings",
        )
    return frozenset(data)


def audit_oauth_exchange(
    token_response: dict[str, Any],
    client_id: str,
    cfg: OAuthAppAuditConfig,
) -> OAuthAuditReport:
    """Audit a fresh OAuth token exchange against the policy.

    Args:
        token_response: The JSON body of the token endpoint response.
            Must contain ``expires_in`` (int, seconds). May contain
            ``refresh_token``, ``refresh_token_rotated`` (bool),
            ``code_challenge_method`` (echo), ``pkce_used`` (bool).
        client_id: The OAuth client_id that initiated the exchange.
        cfg: ``OAuthAppAuditConfig`` with deny/allow lists and rules.

    Returns:
        ``OAuthAuditReport`` when every rule passes.

    Raises:
        OAuthAppBlocked: The client_id is denied.
        OAuthPolicyViolation: A rule failed (missing PKCE, stale
            refresh, oversize lifetime, malformed response).
    """
    # 1. Build the effective deny-list (config deny + optional feed).
    effective_deny = set(cfg.blocked_client_ids)
    if cfg.deny_list_feed_path is not None:
        effective_deny |= load_deny_list(cfg.deny_list_feed_path)
    if client_id in effective_deny:
        logger.warning(
            "oauth_app_blocked",
            client_id=client_id,
            source="deny_list",
        )
        raise OAuthAppBlocked(
            client_id=client_id,
            reason="client_id is on the compromised-app deny-list",
        )

    # 2. Allow-list (only applied when non-empty).
    if cfg.allowed_client_ids and client_id not in cfg.allowed_client_ids:
        raise OAuthAppBlocked(
            client_id=client_id,
            reason="client_id is not on the audit allow-list",
        )

    # 3. Token shape.
    if "expires_in" not in token_response:
        raise OAuthPolicyViolation(
            rule="token_shape",
            detail="token_response is missing 'expires_in'",
        )
    expires_in = token_response["expires_in"]
    if not isinstance(expires_in, int) or expires_in <= 0:
        raise OAuthPolicyViolation(
            rule="token_shape",
            detail=f"expires_in must be a positive int, got {expires_in!r}",
        )
    if expires_in > cfg.max_token_age_seconds:
        raise OAuthPolicyViolation(
            rule="token_lifetime",
            detail=(f"token lifetime {expires_in}s exceeds cap {cfg.max_token_age_seconds}s"),
        )

    # 4. PKCE evidence.
    pkce_verified = bool(
        token_response.get("pkce_used") or token_response.get("code_challenge_method") == "S256"
    )
    if cfg.require_pkce and not pkce_verified:
        raise OAuthPolicyViolation(
            rule="missing_pkce",
            detail=(
                "token_response did not attest PKCE usage "
                "(need pkce_used=true or code_challenge_method='S256')"
            ),
        )

    # 5. Refresh-token rotation.
    has_refresh = "refresh_token" in token_response
    rotated = bool(token_response.get("refresh_token_rotated"))
    if cfg.require_refresh_rotation and has_refresh and not rotated:
        raise OAuthPolicyViolation(
            rule="refresh_reuse",
            detail=(
                "refresh_token present but refresh_token_rotated!=True "
                "— reuse of a long-lived refresh token is forbidden"
            ),
        )

    logger.debug(
        "oauth_exchange_audited",
        client_id=client_id,
        lifetime=expires_in,
        pkce=pkce_verified,
        refresh_rotated=rotated,
    )
    return OAuthAuditReport(
        client_id=client_id,
        token_lifetime_seconds=expires_in,
        pkce_verified=pkce_verified,
        refresh_rotated=rotated,
        audited_at=time.time(),
    )


__all__ = [
    "KNOWN_COMPROMISED_CLIENT_IDS",
    "OAuthAppAuditConfig",
    "OAuthAppBlocked",
    "OAuthAuditReport",
    "OAuthPolicyViolation",
    "audit_oauth_exchange",
    "load_deny_list",
]
