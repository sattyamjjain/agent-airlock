"""Regression tests for CVE-2026-35394 (Mobile MCP intent-URL RCE).

Source: https://www.sentinelone.com/vulnerability-database/cve-2026-35394/
"""

from __future__ import annotations

from typing import Any

import pytest

from agent_airlock import (
    MOBILE_MCP_INTENT_GUARD_2026_05_DEFAULTS,
    Airlock,
    MobileMcpIntentBlocked,
    SafeURLValidationError,
    mobile_mcp_intent_guard_2026_05,
)
from agent_airlock.unknown_args import UnknownArgsMode

# ---------------------------------------------------------------------------
# Fixtures: malicious vs benign URL classes from the CVE-2026-35394 corpus
# ---------------------------------------------------------------------------

# URLs the CVE proves are weaponizable when forwarded to Android's intent
# system. Each one must be blocked at the validator boundary.
MALICIOUS_INTENT_URLS = (
    "intent://launch/?action=run",
    "intent:#Intent;action=android.intent.action.CALL;data=tel:1234;end",
    "intent://contacts.read?package=com.bank",
)
MALICIOUS_CONTENT_URLS = (
    "content://contacts/people/1",
    "content://sms/inbox",
)
MALICIOUS_FILE_URLS = (
    "file:///etc/passwd",
    "file:///data/data/com.bank/databases/main.db",
)
MALICIOUS_APP_URLS = (
    "app://launch",
    "app://com.bank/open",
)
MALICIOUS_EMBEDDED_PAYLOAD_URLS = (
    "data:text/html,<script>alert(1)</script>",
    "javascript:alert('xss')",
    "vbscript:msgbox('xss')",
)
# All malicious schemes the preset must deny (allowlist of http+https
# implicitly rejects everything else, but we exercise the named ones
# from the CVE corpus to lock the behavior).
MALICIOUS_URLS = (
    MALICIOUS_INTENT_URLS
    + MALICIOUS_CONTENT_URLS
    + MALICIOUS_FILE_URLS
    + MALICIOUS_APP_URLS
    + MALICIOUS_EMBEDDED_PAYLOAD_URLS
)

# SSRF-class URLs that have an http(s) scheme but should still be blocked
# (defense in depth — private IPs and cloud metadata).
SSRF_URLS = (
    "http://127.0.0.1/admin",
    "http://localhost:8080/internal",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://10.0.0.5/internal",
)

# URLs the preset must permit — real web traffic.
BENIGN_URLS = (
    "https://api.example.com/data",
    "https://example.com/path/to/resource?query=1",
    "http://example.com/page",
    "https://docs.python.org/3/",
)


# ---------------------------------------------------------------------------
# Preset shape
# ---------------------------------------------------------------------------


class TestPresetShape:
    """The preset's return contract."""

    def test_returns_expected_keys(self) -> None:
        guard = mobile_mcp_intent_guard_2026_05()
        assert set(guard) == {
            "validator",
            "check_url",
            "airlock_config",
            "tool_names",
            "blocked_schemes",
            "source",
        }

    def test_source_points_to_sentinelone(self) -> None:
        guard = mobile_mcp_intent_guard_2026_05()
        assert guard["source"].startswith("https://www.sentinelone.com/")
        assert "cve-2026-35394" in guard["source"].lower()

    def test_tool_names_include_canonical_mobile_open_url(self) -> None:
        guard = mobile_mcp_intent_guard_2026_05()
        assert "mobile_open_url" in guard["tool_names"]

    def test_blocked_schemes_cover_intent_content_file_app(self) -> None:
        """The four scheme families called out by the CVE disclosure must
        appear in the documented blocked_schemes tuple."""
        guard = mobile_mcp_intent_guard_2026_05()
        for required in ("intent", "content", "file", "app"):
            assert required in guard["blocked_schemes"]

    def test_airlock_config_uses_unknown_args_block(self) -> None:
        """An attacker should not be able to smuggle a hallucinated kwarg
        past the validator; UnknownArgsMode.BLOCK closes that path."""
        guard = mobile_mcp_intent_guard_2026_05()
        assert guard["airlock_config"].unknown_args == UnknownArgsMode.BLOCK

    def test_eager_defaults_match_factory(self) -> None:
        """The module-level constant is the same shape as a fresh call."""
        fresh = mobile_mcp_intent_guard_2026_05()
        assert MOBILE_MCP_INTENT_GUARD_2026_05_DEFAULTS["tool_names"] == fresh["tool_names"]
        assert (
            MOBILE_MCP_INTENT_GUARD_2026_05_DEFAULTS["blocked_schemes"] == fresh["blocked_schemes"]
        )


# ---------------------------------------------------------------------------
# Validator (the actual security gate)
# ---------------------------------------------------------------------------


class TestMaliciousURLsBlocked:
    """Every URL the CVE-2026-35394 corpus identifies must raise."""

    @pytest.mark.parametrize("url", MALICIOUS_URLS)
    def test_malicious_url_blocked(self, url: str) -> None:
        guard = mobile_mcp_intent_guard_2026_05()
        with pytest.raises(SafeURLValidationError):
            guard["check_url"](url)

    @pytest.mark.parametrize("url", MALICIOUS_INTENT_URLS)
    def test_intent_scheme_reason_is_invalid_scheme(self, url: str) -> None:
        """Intent URLs should fail at the scheme allowlist (not later)."""
        guard = mobile_mcp_intent_guard_2026_05()
        with pytest.raises(SafeURLValidationError) as exc_info:
            guard["check_url"](url)
        assert exc_info.value.reason == "invalid_scheme"


class TestSSRFDefenseInDepth:
    """http(s)-scheme URLs that target private/metadata hosts must still block."""

    @pytest.mark.parametrize("url", SSRF_URLS)
    def test_ssrf_url_blocked(self, url: str) -> None:
        guard = mobile_mcp_intent_guard_2026_05()
        with pytest.raises(SafeURLValidationError):
            guard["check_url"](url)


class TestBenignURLsAllowed:
    """Real web URLs must pass — preset must not over-block."""

    @pytest.mark.parametrize("url", BENIGN_URLS)
    def test_benign_url_allowed(self, url: str) -> None:
        guard = mobile_mcp_intent_guard_2026_05()
        # Should not raise; check_url returns the (validated) URL.
        result = guard["check_url"](url)
        assert result == url


# ---------------------------------------------------------------------------
# End-to-end @Airlock integration
# ---------------------------------------------------------------------------


class TestAirlockIntegration:
    """Wraps a tool with the preset's AirlockConfig and exercises both
    the validator and the UnknownArgsMode.BLOCK seam."""

    def test_intent_url_blocked_inside_tool(self) -> None:
        guard = mobile_mcp_intent_guard_2026_05()

        @Airlock(config=guard["airlock_config"], return_dict=True)
        def mobile_open_url(url: str) -> dict[str, Any]:
            guard["check_url"](url)
            return {"opened": url}

        result = mobile_open_url(url="intent://launch/?action=run")
        assert isinstance(result, dict)
        # SafeURLValidationError → AIRLOCK_BLOCK with an "Unexpected error"
        # generic envelope (the validator raises ValueError-subclass mid-tool;
        # the @Airlock seam catches and converts to a block response).
        assert result["success"] is False

    def test_https_url_allowed_inside_tool(self) -> None:
        guard = mobile_mcp_intent_guard_2026_05()

        @Airlock(config=guard["airlock_config"], return_dict=True)
        def mobile_open_url(url: str) -> dict[str, Any]:
            guard["check_url"](url)
            return {"opened": url}

        result = mobile_open_url(url="https://api.example.com/data")
        assert isinstance(result, dict)
        assert result["success"] is True
        assert result["result"] == {"opened": "https://api.example.com/data"}

    def test_unknown_kwarg_blocked_by_airlock_config(self) -> None:
        """UnknownArgsMode.BLOCK rejects hallucinated kwargs BEFORE the
        tool runs — closes the kwarg-smuggling path the CVE doesn't
        cover directly but is part of the defensive bundle."""
        guard = mobile_mcp_intent_guard_2026_05()

        @Airlock(config=guard["airlock_config"], return_dict=True)
        def mobile_open_url(url: str) -> dict[str, Any]:
            guard["check_url"](url)
            return {"opened": url}

        result = mobile_open_url(
            url="https://api.example.com/data",
            extra_kwarg_smuggled="payload",  # type: ignore[call-arg]
        )
        assert isinstance(result, dict)
        assert result["success"] is False
        # block reason from ghost-arg validation
        assert result["block_reason"] in ("ghost_arguments", "validation_error")


# ---------------------------------------------------------------------------
# Exception class
# ---------------------------------------------------------------------------


class TestExceptionType:
    """MobileMcpIntentBlocked is the typed exception users can except on."""

    def test_subclasses_airlock_error(self) -> None:
        from agent_airlock.exceptions import AirlockError

        assert issubclass(MobileMcpIntentBlocked, AirlockError)

    def test_raise_and_catch(self) -> None:
        from agent_airlock.exceptions import AirlockError

        with pytest.raises(AirlockError):
            raise MobileMcpIntentBlocked("intent: scheme observed")
