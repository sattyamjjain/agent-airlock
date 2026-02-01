"""Tests for the network security module (V0.3.0)."""

from __future__ import annotations

import socket
import threading

import pytest

import agent_airlock.network as network_module

from agent_airlock.network import (
    HTTPS_ONLY_POLICY,
    INTERNAL_ONLY_POLICY,
    NO_NETWORK_POLICY,
    NetworkBlockedError,
    NetworkPolicy,
    _extract_host_port,
    _get_current_policy,
    _is_host_allowed,
    _is_port_allowed,
    _reset_interceptors,
    network_airgap,
)


class TestNetworkPolicy:
    """Tests for NetworkPolicy dataclass."""

    def test_default_policy(self) -> None:
        """Test default policy allows all egress."""
        policy = NetworkPolicy()
        assert policy.allow_egress is True
        assert policy.allowed_hosts == []
        assert policy.allowed_ports == []
        assert policy.block_dns is False

    def test_no_egress_policy(self) -> None:
        """Test policy that blocks all egress."""
        policy = NetworkPolicy(allow_egress=False)
        assert policy.allow_egress is False

    def test_allowed_hosts_policy(self) -> None:
        """Test policy with specific allowed hosts."""
        policy = NetworkPolicy(
            allowed_hosts=["api.example.com", "internal.service"],
        )
        assert len(policy.allowed_hosts) == 2

    def test_allowed_ports_policy(self) -> None:
        """Test policy with specific allowed ports."""
        policy = NetworkPolicy(
            allowed_ports=[443, 80, 8080],
        )
        assert 443 in policy.allowed_ports
        assert 22 not in policy.allowed_ports

    def test_predefined_no_network_policy(self) -> None:
        """Test the predefined NO_NETWORK_POLICY."""
        policy = NO_NETWORK_POLICY
        assert policy.allow_egress is False
        assert policy.block_dns is True

    def test_predefined_internal_only_policy(self) -> None:
        """Test the predefined INTERNAL_ONLY_POLICY."""
        policy = INTERNAL_ONLY_POLICY
        assert policy.allow_egress is True
        assert "localhost" in policy.allowed_hosts
        assert "127.0.0.1" in policy.allowed_hosts

    def test_predefined_https_only_policy(self) -> None:
        """Test the predefined HTTPS_ONLY_POLICY."""
        policy = HTTPS_ONLY_POLICY
        assert policy.allow_egress is True
        assert 443 in policy.allowed_ports
        assert 80 not in policy.allowed_ports


class TestHostAndPortValidation:
    """Tests for host and port validation helpers."""

    def test_is_host_allowed_no_restriction(self) -> None:
        """Test host allowed when no restrictions."""
        policy = NetworkPolicy(allowed_hosts=[])
        assert _is_host_allowed("any.host.com", policy) is True

    def test_is_host_allowed_exact_match(self) -> None:
        """Test exact host matching."""
        policy = NetworkPolicy(allowed_hosts=["api.example.com"])
        assert _is_host_allowed("api.example.com", policy) is True
        assert _is_host_allowed("other.example.com", policy) is False

    def test_is_host_allowed_wildcard(self) -> None:
        """Test wildcard subdomain matching."""
        policy = NetworkPolicy(allowed_hosts=["*.example.com"])
        assert _is_host_allowed("api.example.com", policy) is True
        assert _is_host_allowed("internal.example.com", policy) is True
        assert _is_host_allowed("example.com", policy) is False
        assert _is_host_allowed("other.com", policy) is False

    def test_is_port_allowed_no_restriction(self) -> None:
        """Test port allowed when no restrictions."""
        policy = NetworkPolicy(allowed_ports=[])
        assert _is_port_allowed(443, policy) is True
        assert _is_port_allowed(12345, policy) is True

    def test_is_port_allowed_specific_ports(self) -> None:
        """Test specific port restrictions."""
        policy = NetworkPolicy(allowed_ports=[80, 443])
        assert _is_port_allowed(443, policy) is True
        assert _is_port_allowed(80, policy) is True
        assert _is_port_allowed(22, policy) is False


class TestExtractHostPort:
    """Tests for address parsing."""

    def test_extract_ipv4_address(self) -> None:
        """Test extracting from IPv4 address tuple."""
        host, port = _extract_host_port(("192.168.1.1", 8080))
        assert host == "192.168.1.1"
        assert port == 8080

    def test_extract_hostname(self) -> None:
        """Test extracting from hostname tuple."""
        host, port = _extract_host_port(("example.com", 443))
        assert host == "example.com"
        assert port == 443

    def test_extract_invalid_address(self) -> None:
        """Test handling invalid address format."""
        host, port = _extract_host_port("invalid")
        assert host is None
        assert port is None

    def test_extract_empty_tuple(self) -> None:
        """Test handling empty tuple."""
        host, port = _extract_host_port(())
        assert host is None
        assert port is None


class TestNetworkAirgap:
    """Tests for the network_airgap context manager."""

    def test_airgap_blocks_connection(self) -> None:
        """Test that airgap blocks socket connections."""
        with network_airgap(NetworkPolicy(allow_egress=False)):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                with pytest.raises(NetworkBlockedError) as exc_info:
                    sock.connect(("example.com", 80))

                assert exc_info.value.operation == "connect"
                assert "egress" in exc_info.value.message.lower()
            finally:
                sock.close()

    def test_airgap_default_policy(self) -> None:
        """Test airgap with default (no egress) policy."""
        with network_airgap():  # Default is allow_egress=False
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                with pytest.raises(NetworkBlockedError):
                    sock.connect(("example.com", 80))
            finally:
                sock.close()

    def test_airgap_allows_permitted_host(self) -> None:
        """Test that airgap allows connections to permitted hosts."""
        policy = NetworkPolicy(
            allow_egress=True,
            allowed_hosts=["localhost", "127.0.0.1"],
        )

        # This test verifies policy checking, not actual connection
        with network_airgap(policy):
            # The policy check should pass for localhost
            # We don't actually connect because localhost might not have a service
            current_policy = _get_current_policy()
            assert current_policy is not None
            assert _is_host_allowed("localhost", current_policy)
            assert _is_host_allowed("127.0.0.1", current_policy)

    def test_airgap_blocks_disallowed_host(self) -> None:
        """Test that airgap blocks connections to disallowed hosts."""
        policy = NetworkPolicy(
            allow_egress=True,
            allowed_hosts=["allowed.com"],
        )

        with network_airgap(policy):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                with pytest.raises(NetworkBlockedError) as exc_info:
                    sock.connect(("blocked.com", 80))

                assert "not in allowed list" in exc_info.value.message
            finally:
                sock.close()

    def test_airgap_blocks_disallowed_port(self) -> None:
        """Test that airgap blocks connections to disallowed ports."""
        policy = NetworkPolicy(
            allow_egress=True,
            allowed_ports=[443],
        )

        with network_airgap(policy):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                with pytest.raises(NetworkBlockedError) as exc_info:
                    sock.connect(("example.com", 80))  # Port 80 not allowed

                assert "port" in exc_info.value.message.lower()
            finally:
                sock.close()

    def test_airgap_policy_restored_after_context(self) -> None:
        """Test that policy is restored after context exits."""
        # Verify no policy before
        assert _get_current_policy() is None

        with network_airgap(NetworkPolicy(allow_egress=False)):
            # Policy active inside
            assert _get_current_policy() is not None
            assert _get_current_policy().allow_egress is False

        # Policy should be restored (None) after
        assert _get_current_policy() is None

    def test_airgap_nested_contexts(self) -> None:
        """Test nested airgap contexts."""
        outer_policy = NetworkPolicy(allow_egress=True, allowed_hosts=["outer.com"])
        inner_policy = NetworkPolicy(allow_egress=False)

        with network_airgap(outer_policy):
            assert _get_current_policy().allow_egress is True

            with network_airgap(inner_policy):
                assert _get_current_policy().allow_egress is False

            # Outer policy restored
            assert _get_current_policy().allow_egress is True

        # No policy after
        assert _get_current_policy() is None


class TestThreadSafety:
    """Tests for thread-local policy isolation."""

    def test_thread_local_isolation(self) -> None:
        """Test that policies are isolated per thread."""
        results: dict[str, bool | None] = {}

        def thread_with_airgap() -> None:
            with network_airgap(NetworkPolicy(allow_egress=False)):
                policy = _get_current_policy()
                results["airgap_thread"] = policy is not None and not policy.allow_egress

        def thread_without_airgap() -> None:
            # Small delay to ensure other thread has started
            import time

            time.sleep(0.1)
            policy = _get_current_policy()
            results["no_airgap_thread"] = policy is None

        t1 = threading.Thread(target=thread_with_airgap)
        t2 = threading.Thread(target=thread_without_airgap)

        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert results["airgap_thread"] is True
        assert results["no_airgap_thread"] is True


class TestDNSBlocking:
    """Tests for DNS lookup blocking."""

    def test_dns_blocked_when_configured(self) -> None:
        """Test that DNS lookups are blocked when block_dns=True."""
        policy = NetworkPolicy(
            allow_egress=False,
            block_dns=True,
        )

        with network_airgap(policy):
            with pytest.raises(NetworkBlockedError) as exc_info:
                socket.getaddrinfo("example.com", 80)

            assert exc_info.value.operation == "dns_lookup"

    def test_dns_allowed_when_not_blocked(self) -> None:
        """Test that DNS lookups work when not blocked."""
        policy = NetworkPolicy(
            allow_egress=True,
            block_dns=False,
            allowed_hosts=["example.com"],
        )

        with network_airgap(policy):
            # This should not raise - DNS is allowed
            # The actual lookup might fail but NetworkBlockedError shouldn't be raised
            current_policy = _get_current_policy()
            assert current_policy is not None
            assert not current_policy.block_dns


class TestNetworkBlockedError:
    """Tests for NetworkBlockedError exception."""

    def test_error_attributes(self) -> None:
        """Test error has correct attributes."""
        error = NetworkBlockedError(
            message="Connection blocked",
            operation="connect",
            target="example.com:80",
            details={"reason": "host_not_allowed"},
        )

        assert error.message == "Connection blocked"
        assert error.operation == "connect"
        assert error.target == "example.com:80"
        assert error.details == {"reason": "host_not_allowed"}
        assert str(error) == "Connection blocked"

    def test_error_without_target(self) -> None:
        """Test error without target."""
        error = NetworkBlockedError(
            message="DNS blocked",
            operation="dns_lookup",
        )

        assert error.target is None
        assert error.details == {}


class TestConnectExMethod:
    """Tests for socket.connect_ex interception."""

    def test_connect_ex_blocked(self) -> None:
        """Test that connect_ex is also blocked."""
        with network_airgap(NetworkPolicy(allow_egress=False)):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                with pytest.raises(NetworkBlockedError):
                    sock.connect_ex(("example.com", 80))
            finally:
                sock.close()


class TestEdgeCases:
    """Tests for edge cases and unusual inputs."""

    def test_ipv6_address(self) -> None:
        """Test handling of IPv6 addresses."""
        host, port = _extract_host_port(("::1", 8080))
        assert host == "::1"
        assert port == 8080

    def test_policy_with_ip_ranges(self) -> None:
        """Test policy behavior with IP addresses."""
        policy = NetworkPolicy(
            allow_egress=True,
            allowed_hosts=["192.168.1.1", "10.0.0.1"],
        )

        assert _is_host_allowed("192.168.1.1", policy) is True
        assert _is_host_allowed("192.168.1.2", policy) is False

    def test_exception_during_airgap(self) -> None:
        """Test that policy is cleaned up on exception."""
        try:
            with network_airgap(NetworkPolicy(allow_egress=False)):
                raise ValueError("Test exception")
        except ValueError:
            pass

        # Policy should be cleaned up
        assert _get_current_policy() is None

    def test_multiple_allowed_hosts(self) -> None:
        """Test policy with many allowed hosts."""
        hosts = [f"host{i}.example.com" for i in range(100)]
        policy = NetworkPolicy(
            allow_egress=True,
            allowed_hosts=hosts,
        )

        assert _is_host_allowed("host50.example.com", policy) is True
        assert _is_host_allowed("other.com", policy) is False

    def test_localhost_variants(self) -> None:
        """Test different localhost representations."""
        policy = NetworkPolicy(
            allow_egress=True,
            allowed_hosts=["localhost", "127.0.0.1"],
        )

        assert _is_host_allowed("localhost", policy) is True
        assert _is_host_allowed("127.0.0.1", policy) is True
        # Note: 127.0.0.2 is NOT allowed unless explicitly listed
        assert _is_host_allowed("127.0.0.2", policy) is False


class TestInterceptorRefCounting:
    """Tests for socket interceptor reference counting (Issue #1 & #2 fix)."""

    def setup_method(self) -> None:
        """Reset interceptors before each test."""
        _reset_interceptors()

    def teardown_method(self) -> None:
        """Reset interceptors after each test."""
        _reset_interceptors()

    def test_interceptors_uninstalled_after_context(self) -> None:
        """Verify socket.connect is restored after context exits."""
        original = socket.socket.connect

        with network_airgap():
            # Interceptors should be installed
            assert network_module._socket_patched is True

        # After context, interceptors should be uninstalled
        assert network_module._socket_patched is False
        assert socket.socket.connect == original

    def test_nested_contexts_ref_counting(self) -> None:
        """Nested contexts should maintain interceptors until last exits."""
        with network_airgap():
            assert network_module._interceptor_ref_count == 1

            with network_airgap():
                assert network_module._interceptor_ref_count == 2

            # After inner context, still 1 reference
            assert network_module._interceptor_ref_count == 1
            assert network_module._socket_patched is True

        # After outer context, 0 references
        assert network_module._interceptor_ref_count == 0
        assert network_module._socket_patched is False

    def test_triple_nested_contexts(self) -> None:
        """Three levels of nesting should work correctly."""
        with network_airgap():
            with network_airgap():
                with network_airgap():
                    assert network_module._interceptor_ref_count == 3
                assert network_module._interceptor_ref_count == 2
            assert network_module._interceptor_ref_count == 1
        assert network_module._interceptor_ref_count == 0
        assert network_module._socket_patched is False

    def test_exception_cleans_up_ref_count(self) -> None:
        """Exceptions should still properly decrement ref count."""
        try:
            with network_airgap():
                assert network_module._interceptor_ref_count == 1
                raise ValueError("Test exception")
        except ValueError:
            pass

        # Ref count should be decremented even on exception
        assert network_module._interceptor_ref_count == 0
        assert network_module._socket_patched is False

    def test_reset_interceptors(self) -> None:
        """_reset_interceptors should fully clean up state."""
        # Create some nested contexts
        with network_airgap():
            with network_airgap():
                # Force reset while nested
                _reset_interceptors()

                # Should be fully reset
                assert network_module._interceptor_ref_count == 0
                assert network_module._socket_patched is False
                assert _get_current_policy() is None


class TestTestingUtilities:
    """Tests for the testing module."""

    def test_reset_all_does_not_error(self) -> None:
        """reset_all should not raise any errors."""
        from agent_airlock.testing import reset_all

        # Should not raise
        reset_all()

    def test_individual_reset_functions(self) -> None:
        """Individual reset functions should not raise errors."""
        from agent_airlock.testing import (
            reset_audit_logger,
            reset_circuit_breakers,
            reset_context,
            reset_conversation_tracker,
            reset_cost_tracker,
            reset_network_interceptors,
            reset_observability,
            reset_sandbox_pool,
        )

        # All should complete without error
        reset_audit_logger()
        reset_circuit_breakers()
        reset_context()
        reset_conversation_tracker()
        reset_cost_tracker()
        reset_network_interceptors()
        reset_observability()
        reset_sandbox_pool()
