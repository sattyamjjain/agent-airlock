"""OAuth audit regression for the 2026-04-19 Vercel / Context.ai breach.

Vercel confirmed a security incident caused by a compromised third-party
Google Workspace OAuth app (Context.ai). The attacker used the app's
legitimate consent flow to exfiltrate an employee's tokens and, from
there, 580 employee records, API keys, and source code. The client_id
``110671459871-30f1spbu0hptbs60cb4vsmv79i7bbvqj.apps.googleusercontent.com``
is public from Vercel's bulletin and used verbatim in this fixture.

Primary sources
---------------
- Vercel bulletin (2026-04-19):
  https://vercel.com/kb/bulletin/vercel-april-2026-security-incident
- CyberInsider (2026-04-19):
  https://cyberinsider.com/vercel-confirms-security-incident-as-hackers-claim-to-sell-internal-access/
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_airlock.exceptions import AirlockError
from agent_airlock.mcp_spec.oauth_audit import (
    KNOWN_COMPROMISED_CLIENT_IDS,
    OAuthAppAuditConfig,
    OAuthAppBlocked,
    OAuthPolicyViolation,
    audit_oauth_exchange,
)
from agent_airlock.policy_presets import oauth_audit_vercel_2026_defaults

CONTEXT_AI_CLIENT_ID = "110671459871-30f1spbu0hptbs60cb4vsmv79i7bbvqj.apps.googleusercontent.com"


def _good_response() -> dict:
    return {
        "access_token": "test-access-token",
        "expires_in": 3600,
        "refresh_token": "test-refresh",
        "refresh_token_rotated": True,
        "code_challenge_method": "S256",
    }


class TestVercel2026OAuthAudit:
    def test_01_clean_exchange_passes(self) -> None:
        """Baseline: a policy-compliant exchange must not raise."""
        cfg = oauth_audit_vercel_2026_defaults()
        report = audit_oauth_exchange(
            _good_response(),
            client_id="legit-app.apps.googleusercontent.com",
            cfg=cfg,
        )
        assert report.pkce_verified is True
        assert report.refresh_rotated is True
        assert report.token_lifetime_seconds == 3600

    def test_02_contextai_client_id_blocked(self) -> None:
        """The Vercel-disclosed Context.ai client_id must be refused."""
        cfg = oauth_audit_vercel_2026_defaults()
        assert CONTEXT_AI_CLIENT_ID in KNOWN_COMPROMISED_CLIENT_IDS
        with pytest.raises(OAuthAppBlocked) as exc:
            audit_oauth_exchange(
                _good_response(),
                client_id=CONTEXT_AI_CLIENT_ID,
                cfg=cfg,
            )
        assert "deny-list" in exc.value.reason.lower()

    def test_03_missing_pkce_raises(self) -> None:
        cfg = oauth_audit_vercel_2026_defaults()
        resp = _good_response()
        del resp["code_challenge_method"]
        with pytest.raises(OAuthPolicyViolation) as exc:
            audit_oauth_exchange(resp, client_id="legit.example", cfg=cfg)
        assert exc.value.rule == "missing_pkce"

    def test_04_oversize_token_lifetime_raises(self) -> None:
        cfg = oauth_audit_vercel_2026_defaults()
        resp = _good_response()
        resp["expires_in"] = 3600 * 24 * 7  # 1 week
        with pytest.raises(OAuthPolicyViolation) as exc:
            audit_oauth_exchange(resp, client_id="legit.example", cfg=cfg)
        assert exc.value.rule == "token_lifetime"

    def test_05_refresh_token_reuse_raises(self) -> None:
        cfg = oauth_audit_vercel_2026_defaults()
        resp = _good_response()
        resp["refresh_token_rotated"] = False
        with pytest.raises(OAuthPolicyViolation) as exc:
            audit_oauth_exchange(resp, client_id="legit.example", cfg=cfg)
        assert exc.value.rule == "refresh_reuse"

    def test_06_deny_list_feed_round_trip(self, tmp_path: Path) -> None:
        """Extra client_ids loaded from a JSON feed must also be denied."""
        feed = tmp_path / "extra-deny.json"
        feed.write_text(json.dumps(["another-compromised-app.example"]))
        cfg = OAuthAppAuditConfig(
            deny_list_feed_path=feed,
            require_pkce=False,
            require_refresh_rotation=False,
        )
        with pytest.raises(OAuthAppBlocked):
            audit_oauth_exchange(
                _good_response(),
                client_id="another-compromised-app.example",
                cfg=cfg,
            )


class TestOAuthAuditErrorHierarchy:
    """Both error classes must subclass ``AirlockError`` so callers can
    `except AirlockError:` and catch every audit failure in one clause."""

    def test_blocked_is_airlock_error(self) -> None:
        with pytest.raises(AirlockError):
            audit_oauth_exchange(
                _good_response(),
                client_id=CONTEXT_AI_CLIENT_ID,
                cfg=oauth_audit_vercel_2026_defaults(),
            )

    def test_policy_violation_is_airlock_error(self) -> None:
        cfg = oauth_audit_vercel_2026_defaults()
        resp = _good_response()
        resp["expires_in"] = 999_999
        with pytest.raises(AirlockError):
            audit_oauth_exchange(resp, client_id="legit.example", cfg=cfg)
