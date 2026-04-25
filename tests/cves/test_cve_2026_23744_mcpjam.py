"""Tests for CVE-2026-23744 MCPJam Inspector unauthenticated public bind (v0.5.6+).

Primary source (cited per v0.5.1+ convention):
- GHSA-232v-j27c-5pp6 / CVE-2026-23744 (CVSS 9.8, fixed 1.4.3):
  <https://github.com/advisories/GHSA-232v-j27c-5pp6>
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_airlock import (
    BindAddressPublicError,
    UnauthenticatedPublicBindError,
)
from agent_airlock.exceptions import AirlockError
from agent_airlock.mcp_spec.bind_address_guard import (
    BindAddressGuardConfig,
    validate_bind_address,
)
from agent_airlock.policy_presets import mcpjam_cve_2026_23744_defaults

FIXTURE = Path(__file__).parent / "fixtures" / "cve_2026_23744_mcpjam.json"


class TestBindAddressGuard:
    """The :func:`validate_bind_address` primitive on its own."""

    def test_loopback_passes(self) -> None:
        validate_bind_address("127.0.0.1", BindAddressGuardConfig())

    def test_ipv6_loopback_passes(self) -> None:
        validate_bind_address("::1", BindAddressGuardConfig())

    def test_zero_dot_zero_blocks(self) -> None:
        with pytest.raises(BindAddressPublicError):
            validate_bind_address("0.0.0.0", BindAddressGuardConfig())

    def test_ipv6_unspecified_blocks(self) -> None:
        with pytest.raises(BindAddressPublicError):
            validate_bind_address("::", BindAddressGuardConfig())

    def test_public_bind_with_auth_passes(self) -> None:
        validate_bind_address(
            "0.0.0.0",
            BindAddressGuardConfig(allow_public_bind=True, auth_required=True),
        )

    def test_public_bind_without_auth_blocks(self) -> None:
        """The exact CVE-2026-23744 shape."""
        with pytest.raises(UnauthenticatedPublicBindError):
            validate_bind_address(
                "0.0.0.0",
                BindAddressGuardConfig(allow_public_bind=True, auth_required=False),
            )


class TestPreset:
    """``mcpjam_cve_2026_23744_defaults`` factory + name-pattern scope."""

    def test_preset_blocks_default_mcpjam_bind(self) -> None:
        cfg = mcpjam_cve_2026_23744_defaults()
        with pytest.raises(BindAddressPublicError):
            cfg["check"]("mcpjam", "0.0.0.0", auth_required=False)

    def test_preset_allows_loopback_for_mcpjam(self) -> None:
        cfg = mcpjam_cve_2026_23744_defaults()
        cfg["check"]("mcpjam", "127.0.0.1", auth_required=False)

    def test_preset_unscoped_for_unrelated_tool(self) -> None:
        """A tool name outside the dev-server pattern is unaffected."""
        cfg = mcpjam_cve_2026_23744_defaults()
        # The preset is per-tool-name. Tools outside the pattern bind
        # however they like — unrelated to this CVE.
        cfg["check"]("readPod", "0.0.0.0", auth_required=False)


class TestErrorHierarchy:
    @pytest.mark.parametrize(
        "err",
        [BindAddressPublicError, UnauthenticatedPublicBindError],
    )
    def test_subclasses_airlock_error(self, err: type[Exception]) -> None:
        assert issubclass(err, AirlockError)


class TestFixture:
    def test_fixture_payloads_match_guard_outcomes(self) -> None:
        data = json.loads(FIXTURE.read_text(encoding="utf-8"))
        assert data["cve"] == "CVE-2026-23744"
        assert data["cvss_v3"] == 9.8
        cfg = mcpjam_cve_2026_23744_defaults()
        for payload in data["payloads"]:
            tool_name = payload["tool_name"]
            addr = payload["addr"]
            auth = payload["auth_required"]
            if payload["expected"] == "blocked":
                with pytest.raises(AirlockError):
                    cfg["check"](tool_name, addr, auth_required=auth)
            else:
                # allowed — must not raise
                cfg["check"](tool_name, addr, auth_required=auth)
