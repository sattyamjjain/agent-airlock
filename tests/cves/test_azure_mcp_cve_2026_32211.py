"""CVE-2026-32211 — Azure MCP Server SSE token-echo (v0.5.3+).

Microsoft disclosed 2026-04-20: the reference Azure MCP server echoed
the caller's ``Authorization`` header back in a ``WWW-Authenticate``
field on 401 responses, leaking short-lived AAD tokens. CVSS 8.6,
fixed in Azure MCP Server 1.4.2.

This regression codifies the echo-class so a proxy sitting in front
of an unpatched server refuses to forward the leaked token.

Primary sources
---------------
- MSRC: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32211
- NVD:  https://nvd.nist.gov/vuln/detail/CVE-2026-32211
"""

from __future__ import annotations

import pytest

from agent_airlock import SnapshotIntegrityError  # noqa: F401  top-level reexport smoke
from agent_airlock.exceptions import AirlockError
from agent_airlock.mcp_proxy_guard import MCPProxyConfig, MCPProxyGuard, MCPSecurityError
from agent_airlock.mcp_spec.header_audit import (
    ResponseHeaderAuditConfig,
    ResponseHeaderLeakError,
    audit_response_headers,
)
from agent_airlock.policy_presets import azure_mcp_cve_2026_32211_defaults


class TestAzureMCPCVE2026_32211:
    """The 6 spec cases."""

    def test_01_clean_200_passes(self) -> None:
        """A normal 200 response with innocuous headers must not raise."""
        cfg = azure_mcp_cve_2026_32211_defaults()
        audit_response_headers(
            status=200,
            headers={"Content-Type": "application/json", "X-Request-Id": "abc"},
            cfg=cfg,
        )

    def test_02_401_with_bearer_in_www_authenticate_raises(self) -> None:
        """The Azure CVE-2026-32211 payload shape — bearer echoed in WWW-Authenticate."""
        cfg = azure_mcp_cve_2026_32211_defaults()
        with pytest.raises(ResponseHeaderLeakError) as exc:
            audit_response_headers(
                status=401,
                headers={
                    "WWW-Authenticate": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmMifQ.sig",
                    "Content-Type": "application/json",
                },
                cfg=cfg,
            )
        assert exc.value.header_name == "www-authenticate"
        assert exc.value.status == 401

    def test_03_200_with_jwt_shape_anywhere_raises(self) -> None:
        """Even on 200, a JWT-shaped value in any header leaks through."""
        cfg = azure_mcp_cve_2026_32211_defaults()
        with pytest.raises(ResponseHeaderLeakError) as exc:
            audit_response_headers(
                status=200,
                headers={
                    "X-Debug-Token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.abc",
                },
                cfg=cfg,
            )
        assert "debug-token" in exc.value.header_name

    def test_04_401_with_safe_basic_realm_passes(self) -> None:
        """``Basic realm="x"`` is the correct 401 response — must pass."""
        cfg = azure_mcp_cve_2026_32211_defaults()
        audit_response_headers(
            status=401,
            headers={"WWW-Authenticate": 'Basic realm="example"'},
            cfg=cfg,
        )

    def test_05_oversize_header_value_raises(self) -> None:
        """DoS guard: a header value over max_header_value_bytes is refused."""
        cfg = ResponseHeaderAuditConfig(max_header_value_bytes=100)
        with pytest.raises(ResponseHeaderLeakError) as exc:
            audit_response_headers(
                status=200,
                headers={"X-Huge": "A" * 500},
                cfg=cfg,
            )
        assert "exceeds cap" in exc.value.reason

    def test_06_preset_bundle_round_trip(self) -> None:
        """``azure_mcp_cve_2026_32211_defaults()`` returns a usable config
        and is exported from ``policy_presets``."""
        cfg = azure_mcp_cve_2026_32211_defaults()
        assert cfg.max_header_value_bytes == 8192
        assert 401 in cfg.forbidden_header_names_by_status


class TestErrorHierarchy:
    def test_is_airlock_error(self) -> None:
        cfg = azure_mcp_cve_2026_32211_defaults()
        with pytest.raises(AirlockError):
            audit_response_headers(
                status=401,
                headers={"WWW-Authenticate": "Bearer eyJsecretToken.abc.def"},
                cfg=cfg,
            )


class TestMCPProxyGuardIntegration:
    def test_guard_method_delegates_to_audit(self) -> None:
        guard = MCPProxyGuard(
            MCPProxyConfig(
                response_header_audit=azure_mcp_cve_2026_32211_defaults(),
                bind_to_session=False,
            )
        )
        with pytest.raises(ResponseHeaderLeakError):
            guard.audit_response_headers(
                status=401,
                headers={"WWW-Authenticate": "Bearer eyJfoobar.xx.yy"},
            )

    def test_guard_without_config_raises_mcp_security(self) -> None:
        guard = MCPProxyGuard(MCPProxyConfig(bind_to_session=False))
        with pytest.raises(MCPSecurityError):
            guard.audit_response_headers(status=200, headers={})
