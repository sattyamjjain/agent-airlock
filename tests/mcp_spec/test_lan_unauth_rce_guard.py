"""Tests for the v0.5.8 LAN-unauth-RCE guard.

Replays CVE-2026-27825 / -27826 fixtures + a synthetic
FastMCP-on-0.0.0.0 server with no auth.

Primary source:
- https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_airlock import LANUnauthMCPServerBlocked
from agent_airlock.exceptions import AirlockError
from agent_airlock.mcp_spec.lan_unauth_rce_guard import (
    LANUnauthRCEGuard,
    LANUnauthRCEPolicy,
)
from agent_airlock.policy_presets import (
    lan_unauth_mcp_guard,
    mcp_atlassian_cve_2026_27825,
)

FIXTURES = Path(__file__).parent.parent / "cves" / "fixtures"
F_27825 = FIXTURES / "cve_2026_27825_mcp_atlassian.json"
F_27826 = FIXTURES / "cve_2026_27826_mcp_atlassian.json"


class TestProdProfile:
    """Default prod profile: refuse LAN+no-auth, allow loopback or auth."""

    def test_zero_zero_no_auth_blocks(self) -> None:
        guard = LANUnauthRCEGuard()
        verdict = guard.inspect_server({"name": "x", "bind_address": "0.0.0.0", "auth_headers": {}})
        assert verdict.action == "block"

    def test_loopback_no_auth_allows(self) -> None:
        guard = LANUnauthRCEGuard()
        verdict = guard.inspect_server(
            {"name": "x", "bind_address": "127.0.0.1", "auth_headers": {}}
        )
        assert verdict.action == "allow"

    def test_lan_with_auth_allows(self) -> None:
        guard = LANUnauthRCEGuard()
        verdict = guard.inspect_server(
            {
                "name": "x",
                "bind_address": "10.0.0.5",
                "auth_headers": {"Authorization": "Bearer abc"},
            }
        )
        assert verdict.action == "allow"
        assert verdict.has_auth is True

    def test_rfc1918_no_auth_blocks(self) -> None:
        guard = LANUnauthRCEGuard()
        verdict = guard.inspect_server(
            {"name": "x", "bind_address": "192.168.1.42", "auth_headers": {}}
        )
        assert verdict.action == "block"

    def test_inspect_or_raise_raises(self) -> None:
        guard = LANUnauthRCEGuard()
        with pytest.raises(LANUnauthMCPServerBlocked):
            guard.inspect_or_raise({"name": "evil", "bind_address": "0.0.0.0", "auth_headers": {}})


class TestDevProfile:
    """Dev profile: warn instead of block."""

    def test_lan_no_auth_warns(self) -> None:
        guard = LANUnauthRCEGuard(LANUnauthRCEPolicy(profile="dev"))
        verdict = guard.inspect_server({"name": "x", "bind_address": "0.0.0.0", "auth_headers": {}})
        assert verdict.action == "warn"


class TestStrictProfile:
    """Strict profile: every server requires auth, including loopback."""

    def test_loopback_no_auth_blocks_strict(self) -> None:
        guard = LANUnauthRCEGuard(LANUnauthRCEPolicy(profile="strict"))
        verdict = guard.inspect_server(
            {"name": "x", "bind_address": "127.0.0.1", "auth_headers": {}}
        )
        assert verdict.action == "block"

    def test_loopback_with_auth_allows_strict(self) -> None:
        guard = LANUnauthRCEGuard(LANUnauthRCEPolicy(profile="strict"))
        verdict = guard.inspect_server(
            {
                "name": "x",
                "bind_address": "127.0.0.1",
                "auth_headers": {"X-API-Key": "abc"},
            }
        )
        assert verdict.action == "allow"


class TestIPv6:
    def test_unspecified_v6_blocks(self) -> None:
        guard = LANUnauthRCEGuard()
        verdict = guard.inspect_server({"name": "x", "bind_address": "::", "auth_headers": {}})
        assert verdict.action == "block"

    def test_link_local_v6_blocks(self) -> None:
        guard = LANUnauthRCEGuard()
        verdict = guard.inspect_server({"name": "x", "bind_address": "fe80::1", "auth_headers": {}})
        assert verdict.action == "block"


class TestPresets:
    def test_atlassian_preset_blocks_zero_zero(self) -> None:
        cfg = mcp_atlassian_cve_2026_27825()
        with pytest.raises(LANUnauthMCPServerBlocked):
            cfg["guard"].inspect_or_raise(
                {"name": "mcp-atlassian", "bind_address": "0.0.0.0", "auth_headers": {}}
            )

    def test_generic_preset_blocks(self) -> None:
        cfg = lan_unauth_mcp_guard()
        with pytest.raises(LANUnauthMCPServerBlocked):
            cfg["guard"].inspect_or_raise(
                {"name": "any-mcp", "bind_address": "0.0.0.0", "auth_headers": {}}
            )

    def test_atlassian_preset_dev_profile_warns(self) -> None:
        cfg = mcp_atlassian_cve_2026_27825(profile="dev")
        verdict = cfg["guard"].inspect_server(
            {"name": "mcp-atlassian", "bind_address": "0.0.0.0", "auth_headers": {}}
        )
        assert verdict.action == "warn"


class TestFixtures:
    def test_27825_fixture(self) -> None:
        data = json.loads(F_27825.read_text(encoding="utf-8"))
        guard = LANUnauthRCEGuard()
        for payload in data["payloads"]:
            verdict = guard.inspect_server(payload["spec"])
            assert verdict.action == payload["expected"], (
                f"{payload['name']!r}: expected {payload['expected']!r}, got {verdict.action!r}"
            )

    def test_27826_fixture(self) -> None:
        data = json.loads(F_27826.read_text(encoding="utf-8"))
        guard = LANUnauthRCEGuard()
        for payload in data["payloads"]:
            verdict = guard.inspect_server(payload["spec"])
            assert verdict.action == payload["expected"]


class TestErrorHierarchy:
    def test_subclasses_airlock_error(self) -> None:
        assert issubclass(LANUnauthMCPServerBlocked, AirlockError)


class TestNoFalsePositives:
    """Common shapes that must NOT be blocked in prod profile."""

    def test_localhost_hostname_allows(self) -> None:
        guard = LANUnauthRCEGuard()
        verdict = guard.inspect_server(
            {"name": "x", "bind_address": "localhost", "auth_headers": {}}
        )
        assert verdict.action == "allow"

    def test_x_api_key_recognised(self) -> None:
        guard = LANUnauthRCEGuard()
        verdict = guard.inspect_server(
            {
                "name": "x",
                "bind_address": "10.0.0.1",
                "auth_headers": {"X-API-Key": "k"},
            }
        )
        assert verdict.action == "allow"
