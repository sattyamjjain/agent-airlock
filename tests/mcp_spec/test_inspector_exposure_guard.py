"""Tests for the v0.8.0 MCP Inspector exposure guard (CVE-2026-23744 runtime extension).

CVE-2026-23744: MCPJam Inspector ≤1.4.2 binds to 0.0.0.0 by default
with no auth, enabling remote install + execution of malicious MCP
servers. v0.5.x already ships ``bind_address_guard.py`` for the
config-time check; this module adds a **runtime listener-scan**
that inspects the process's actual listening sockets via the
stdlib (``/proc/net/tcp`` on Linux, no psutil dep). Useful when the
config-time hook didn't fire (e.g. operator injected a binary that
binds to 0.0.0.0 outside the airlock-wrapped path).

Primary source
--------------
https://github.com/boroeurnprach/CVE-2026-23744-PoC
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_airlock.mcp_spec.inspector_exposure_guard import (
    DEFAULT_INSPECTOR_PORTS,
    InspectorExposureDecision,
    InspectorExposureGuard,
    InspectorExposureVerdict,
)

# A small captured /proc/net/tcp snapshot. The local_address field is
# "<hex_ip>:<hex_port>". 0.0.0.0:6274 = "00000000:1882".
_PROC_NET_TCP_EXPOSED = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1882 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0
"""

_PROC_NET_TCP_LOOPBACK = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1882 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0
"""

_PROC_NET_TCP_NOT_INSPECTOR_PORT = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0
"""


class TestCVE_2026_23744_RuntimeListenerScan:
    """The CVE class — MCPJam inspector LISTEN on 0.0.0.0:6274 detected at runtime."""

    def test_zero_zero_zero_zero_bind_on_inspector_port_denied(self, tmp_path: Path) -> None:
        proc_net_tcp = tmp_path / "tcp"
        proc_net_tcp.write_text(_PROC_NET_TCP_EXPOSED, encoding="utf-8")
        guard = InspectorExposureGuard()
        decision = guard.scan_listeners(proc_net_tcp_path=proc_net_tcp)
        assert isinstance(decision, InspectorExposureDecision)
        assert decision.allowed is False
        assert decision.verdict == InspectorExposureVerdict.DENY_UNAUTH_PUBLIC_BIND
        assert decision.matched_port == 6274
        assert decision.matched_address.startswith("0.0.0.0")

    def test_loopback_bind_allowed(self, tmp_path: Path) -> None:
        """A 127.0.0.1 bind on the same port is NOT an exposure."""
        proc_net_tcp = tmp_path / "tcp"
        proc_net_tcp.write_text(_PROC_NET_TCP_LOOPBACK, encoding="utf-8")
        guard = InspectorExposureGuard()
        decision = guard.scan_listeners(proc_net_tcp_path=proc_net_tcp)
        assert decision.allowed is True

    def test_non_inspector_port_allowed(self, tmp_path: Path) -> None:
        """A 0.0.0.0 bind on a port outside the inspector range is allowed by default."""
        proc_net_tcp = tmp_path / "tcp"
        proc_net_tcp.write_text(_PROC_NET_TCP_NOT_INSPECTOR_PORT, encoding="utf-8")
        guard = InspectorExposureGuard()
        decision = guard.scan_listeners(proc_net_tcp_path=proc_net_tcp)
        assert decision.allowed is True


class TestRequireAuthEnvBypass:
    """``MCP_INSPECTOR_REQUIRE_AUTH=1`` opts out of the deny."""

    def test_auth_env_bypasses_deny(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MCP_INSPECTOR_REQUIRE_AUTH", "1")
        proc_net_tcp = tmp_path / "tcp"
        proc_net_tcp.write_text(_PROC_NET_TCP_EXPOSED, encoding="utf-8")
        guard = InspectorExposureGuard()
        decision = guard.scan_listeners(proc_net_tcp_path=proc_net_tcp)
        assert decision.allowed is True
        assert decision.verdict == InspectorExposureVerdict.ALLOW_AUTH_REQUIRED_DECLARED

    def test_auth_env_zero_does_not_bypass(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("MCP_INSPECTOR_REQUIRE_AUTH", "0")
        proc_net_tcp = tmp_path / "tcp"
        proc_net_tcp.write_text(_PROC_NET_TCP_EXPOSED, encoding="utf-8")
        guard = InspectorExposureGuard()
        decision = guard.scan_listeners(proc_net_tcp_path=proc_net_tcp)
        assert decision.allowed is False


class TestCustomPortRange:
    """Operators can extend the inspector-port set."""

    def test_custom_inspector_port_caught(self, tmp_path: Path) -> None:
        # 8080 = 0x1F90 — same as _PROC_NET_TCP_NOT_INSPECTOR_PORT but
        # in the operator's custom inspector set.
        proc_net_tcp = tmp_path / "tcp"
        proc_net_tcp.write_text(_PROC_NET_TCP_NOT_INSPECTOR_PORT, encoding="utf-8")
        guard = InspectorExposureGuard(inspector_ports=frozenset({8080}))
        decision = guard.scan_listeners(proc_net_tcp_path=proc_net_tcp)
        assert decision.allowed is False
        assert decision.matched_port == 8080


class TestMissingProcNetTcp:
    """Non-Linux environments / missing /proc/net/tcp → fail-open with a clear reason."""

    def test_missing_file_returns_unknown(self, tmp_path: Path) -> None:
        proc_net_tcp = tmp_path / "does-not-exist"
        guard = InspectorExposureGuard()
        decision = guard.scan_listeners(proc_net_tcp_path=proc_net_tcp)
        # Fail-open: we don't know, and we don't want to block macOS / Windows
        # CI on a Linux-only stdlib path.
        assert decision.allowed is True
        assert decision.verdict == InspectorExposureVerdict.UNKNOWN_PLATFORM_UNSUPPORTED


class TestDefaultExports:
    def test_default_inspector_ports_includes_6274(self) -> None:
        assert 6274 in DEFAULT_INSPECTOR_PORTS
        # Full range from the spec: 6274-6277.
        assert {6274, 6275, 6276, 6277}.issubset(DEFAULT_INSPECTOR_PORTS)


class TestFactoryShape:
    """`policy_presets.mcp_inspector_exposure_guard_defaults` factory."""

    def test_factory_returns_expected_config_shape(self) -> None:
        from agent_airlock.policy_presets import (
            mcp_inspector_exposure_guard_defaults,
        )

        config = mcp_inspector_exposure_guard_defaults()
        assert config["preset_id"] == "mcp_inspector_exposure_guard_2026_23744"
        assert config["severity"] == "high"
        assert config["default_action"] == "deny"
        assert "CVE-2026-23744" in config["cves"]
        assert isinstance(config["inspector_ports"], frozenset)
        assert 6274 in config["inspector_ports"]


class TestBadConstruction:
    def test_non_frozenset_inspector_ports_rejected(self) -> None:
        with pytest.raises(TypeError, match="frozenset"):
            InspectorExposureGuard(inspector_ports=[6274])  # type: ignore[arg-type]

    def test_non_int_port_rejected(self) -> None:
        with pytest.raises(TypeError, match="int"):
            InspectorExposureGuard(inspector_ports=frozenset({"6274"}))  # type: ignore[arg-type]
