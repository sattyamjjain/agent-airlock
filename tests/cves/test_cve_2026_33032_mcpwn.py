"""CVE-2026-33032 "MCPwn" — nginx-ui missing /mcp_message auth middleware.

Vulnerability: ``/mcp_message`` missed the ``AuthRequired()`` middleware,
letting unauthenticated clients invoke 12 destructive MCP tools.
CVSS 9.8, ~2,689 exposed instances, actively exploited in April 2026.

agent-airlock doesn't ship nginx-ui, but we're the canonical place for
the "would my MCPProxyGuard have caught a missing-auth on a destructive
tool?" question. This module proves the preset fires on the exact
nginx-ui tool inventory and on an IP-allowlist-only bypass attempt.

Primary sources
---------------
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-33032
- Rapid7 ETR (2026-04-15):
  https://www.rapid7.com/blog/post/etr-cve-2026-33032-nginx-ui-missing-mcp-authentication/
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_airlock.exceptions import AirlockError
from agent_airlock.policy_presets import (
    UnauthenticatedDestructiveToolError,
    is_destructive_tool,
    mcpwn_cve_2026_33032_check,
    mcpwn_cve_2026_33032_defaults,
)

FIXTURE = Path(__file__).parent / "fixtures" / "cve_2026_33032_mcpwn.json"


class TestMCPwnPreset:
    def test_01_clean_config_passes(self) -> None:
        """A destructive tool behind AuthRequired middleware is fine."""
        mcpwn_cve_2026_33032_check(
            [
                {"name": "reload_nginx", "middlewares": ["AuthRequired"]},
                {"name": "list_sites", "middlewares": []},  # non-destructive
            ]
        )

    def test_02_missing_auth_middleware_raises(self) -> None:
        """The MCPwn-class vuln — no middleware at all on a destructive tool."""
        with pytest.raises(UnauthenticatedDestructiveToolError) as exc:
            mcpwn_cve_2026_33032_check([{"name": "reload_nginx", "middlewares": []}])
        assert "reload_nginx" in str(exc.value)
        assert "CVE-2026-33032" in str(exc.value)

    def test_03_ip_allowlist_only_is_rejected(self) -> None:
        """nginx-ui's "IP allowlist" defaulted to 0.0.0.0/0 — not real auth."""
        with pytest.raises(UnauthenticatedDestructiveToolError):
            mcpwn_cve_2026_33032_check(
                [
                    {
                        "name": "run_shell_command",
                        "middlewares": ["IPAllowlist"],
                    }
                ]
            )


class TestMCPwnFixture:
    def test_all_twelve_nginx_ui_tools_classified_destructive(self) -> None:
        data = json.loads(FIXTURE.read_text())
        tools = data["destructive_tools"]
        assert len(tools) == 12
        for tool in tools:
            name = tool["name"]
            assert is_destructive_tool(name), (
                f"{name!r} should be classified destructive per CVE-2026-33032 tool inventory"
            )
            assert tool.get("source"), f"{name!r} fixture entry missing source attribution"

    def test_defaults_bundle_has_check_and_source(self) -> None:
        cfg = mcpwn_cve_2026_33032_defaults()
        assert callable(cfg["check"])
        assert callable(cfg["is_destructive"])
        assert "nvd.nist.gov/vuln/detail/CVE-2026-33032" in cfg["source"]


class TestErrorBaseClass:
    def test_is_airlock_error(self) -> None:
        with pytest.raises(AirlockError):
            mcpwn_cve_2026_33032_check([{"name": "delete_site", "middlewares": []}])
