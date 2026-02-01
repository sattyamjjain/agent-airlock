"""Tests for capabilities module (V0.4.0)."""

from __future__ import annotations

import pytest

from agent_airlock.capabilities import (
    NO_NETWORK_CAPABILITY_POLICY,
    PERMISSIVE_CAPABILITY_POLICY,
    READ_ONLY_CAPABILITY_POLICY,
    STRICT_CAPABILITY_POLICY,
    Capability,
    CapabilityDeniedError,
    CapabilityPolicy,
    capabilities_to_list,
    get_required_capabilities,
    requires,
)


class TestCapabilityFlag:
    """Test the Capability flag enum."""

    def test_basic_capabilities_defined(self) -> None:
        """Test that basic capabilities are defined."""
        assert Capability.FILESYSTEM_READ is not None
        assert Capability.FILESYSTEM_WRITE is not None
        assert Capability.FILESYSTEM_DELETE is not None
        assert Capability.NETWORK_HTTPS is not None
        assert Capability.NETWORK_HTTP is not None
        assert Capability.PROCESS_SHELL is not None

    def test_capability_combinations(self) -> None:
        """Test that capabilities can be combined."""
        read_write = Capability.FILESYSTEM_READ | Capability.FILESYSTEM_WRITE
        assert Capability.FILESYSTEM_READ in read_write
        assert Capability.FILESYSTEM_WRITE in read_write
        assert Capability.FILESYSTEM_DELETE not in read_write

    def test_dangerous_capability_group(self) -> None:
        """Test the DANGEROUS capability group."""
        dangerous = Capability.DANGEROUS
        assert Capability.PROCESS_SHELL in dangerous
        assert Capability.FILESYSTEM_DELETE in dangerous
        assert Capability.NETWORK_ARBITRARY in dangerous


class TestCapabilityPolicy:
    """Test the CapabilityPolicy class."""

    def test_default_policy(self) -> None:
        """Test default capability policy."""
        policy = CapabilityPolicy()
        assert policy.granted == Capability.NONE
        assert policy.denied == Capability.NONE

    def test_granted_capabilities(self) -> None:
        """Test policy with granted capabilities."""
        policy = CapabilityPolicy(granted=Capability.FILESYSTEM_READ | Capability.NETWORK_HTTPS)
        assert Capability.FILESYSTEM_READ in policy.granted
        assert Capability.NETWORK_HTTPS in policy.granted

    def test_denied_capabilities(self) -> None:
        """Test policy with denied capabilities."""
        policy = CapabilityPolicy(denied=Capability.PROCESS_SHELL)
        assert Capability.PROCESS_SHELL in policy.denied

    def test_check_granted_capability(self) -> None:
        """Test checking a granted capability."""
        policy = CapabilityPolicy(granted=Capability.FILESYSTEM_READ)
        # Should not raise
        policy.check(Capability.FILESYSTEM_READ, "read_file")

    def test_check_denied_capability_raises(self) -> None:
        """Test checking a denied capability raises error."""
        policy = CapabilityPolicy(denied=Capability.PROCESS_SHELL)
        with pytest.raises(CapabilityDeniedError, match="denied"):
            policy.check(Capability.PROCESS_SHELL, "run_shell")

    def test_check_ungranted_capability_raises(self) -> None:
        """Test checking an ungranted capability raises error."""
        policy = CapabilityPolicy(granted=Capability.FILESYSTEM_READ)
        with pytest.raises(CapabilityDeniedError, match="not granted"):
            policy.check(Capability.FILESYSTEM_WRITE, "write_file")

    def test_require_sandbox_for(self) -> None:
        """Test require_sandbox_for setting."""
        policy = CapabilityPolicy(
            granted=Capability.PROCESS_SHELL,
            require_sandbox_for=Capability.PROCESS_SHELL,
        )
        assert policy.requires_sandbox(Capability.PROCESS_SHELL)

    def test_is_allowed_method(self) -> None:
        """Test the is_allowed method."""
        policy = CapabilityPolicy(granted=Capability.FILESYSTEM_READ | Capability.NETWORK_HTTPS)
        assert policy.is_allowed(Capability.FILESYSTEM_READ)
        assert policy.is_allowed(Capability.NETWORK_HTTPS)
        assert not policy.is_allowed(Capability.PROCESS_SHELL)


class TestRequiresDecorator:
    """Test the @requires decorator."""

    def test_decorator_sets_capabilities(self) -> None:
        """Test that decorator sets __airlock_capabilities__."""

        @requires(Capability.FILESYSTEM_READ)
        def read_file(path: str) -> str:
            return f"Contents of {path}"

        assert hasattr(read_file, "__airlock_capabilities__")
        assert read_file.__airlock_capabilities__ == Capability.FILESYSTEM_READ

    def test_decorator_with_multiple_capabilities(self) -> None:
        """Test decorator with multiple capabilities."""

        @requires(Capability.FILESYSTEM_READ, Capability.FILESYSTEM_WRITE)
        def copy_file(src: str, dst: str) -> None:
            pass

        caps = copy_file.__airlock_capabilities__
        assert Capability.FILESYSTEM_READ in caps
        assert Capability.FILESYSTEM_WRITE in caps

    def test_decorator_preserves_function(self) -> None:
        """Test that decorator preserves the function."""

        @requires(Capability.NETWORK_HTTPS)
        def fetch_data(url: str) -> str:
            return f"Data from {url}"

        result = fetch_data("https://example.com")
        assert result == "Data from https://example.com"


class TestGetRequiredCapabilities:
    """Test the get_required_capabilities function."""

    def test_returns_none_for_unmarked_function(self) -> None:
        """Test that unmarked functions return NONE."""

        def plain_function() -> None:
            pass

        assert get_required_capabilities(plain_function) == Capability.NONE

    def test_returns_capabilities_for_marked_function(self) -> None:
        """Test that marked functions return their capabilities."""

        @requires(Capability.FILESYSTEM_READ)
        def read_file(path: str) -> str:
            return ""

        caps = get_required_capabilities(read_file)
        assert caps == Capability.FILESYSTEM_READ


class TestCapabilitiesToList:
    """Test the capabilities_to_list function."""

    def test_single_capability(self) -> None:
        """Test converting single capability to list."""
        result = capabilities_to_list(Capability.FILESYSTEM_READ)
        assert "FILESYSTEM_READ" in result

    def test_multiple_capabilities(self) -> None:
        """Test converting multiple capabilities to list."""
        caps = Capability.FILESYSTEM_READ | Capability.NETWORK_HTTPS
        result = capabilities_to_list(caps)
        assert "FILESYSTEM_READ" in result
        assert "NETWORK_HTTPS" in result

    def test_empty_capability(self) -> None:
        """Test converting empty capability to list."""
        result = capabilities_to_list(Capability.NONE)
        assert result == []


class TestPredefinedPolicies:
    """Test predefined capability policies."""

    def test_permissive_policy(self) -> None:
        """Test PERMISSIVE_CAPABILITY_POLICY."""
        policy = PERMISSIVE_CAPABILITY_POLICY
        # Should allow read operations
        assert policy.is_allowed(Capability.FILESYSTEM_READ)

    def test_strict_policy(self) -> None:
        """Test STRICT_CAPABILITY_POLICY."""
        policy = STRICT_CAPABILITY_POLICY
        # Should deny dangerous capabilities
        assert not policy.is_allowed(Capability.PROCESS_SHELL)

    def test_read_only_policy(self) -> None:
        """Test READ_ONLY_CAPABILITY_POLICY."""
        policy = READ_ONLY_CAPABILITY_POLICY
        # Should allow read, deny write
        assert policy.is_allowed(Capability.FILESYSTEM_READ)
        assert not policy.is_allowed(Capability.FILESYSTEM_WRITE)

    def test_no_network_policy(self) -> None:
        """Test NO_NETWORK_CAPABILITY_POLICY."""
        policy = NO_NETWORK_CAPABILITY_POLICY
        # Should deny all network
        assert not policy.is_allowed(Capability.NETWORK_HTTPS)


class TestCapabilityDeniedError:
    """Test the CapabilityDeniedError exception."""

    def test_error_message(self) -> None:
        """Test error message contains capability info."""
        error = CapabilityDeniedError(
            message="Tool requires denied capabilities",
            tool_name="run_shell",
            required=Capability.PROCESS_SHELL,
        )
        assert "requires" in str(error)

    def test_error_attributes(self) -> None:
        """Test error has correct attributes."""
        error = CapabilityDeniedError(
            message="Denied",
            tool_name="delete_file",
            required=Capability.FILESYSTEM_DELETE,
            denied=Capability.FILESYSTEM_DELETE,
        )
        assert error.tool_name == "delete_file"
        assert error.denied == Capability.FILESYSTEM_DELETE


class TestCapabilityIntegration:
    """Test capability integration scenarios."""

    def test_policy_with_sandbox_requirement(self) -> None:
        """Test policy requiring sandbox for dangerous operations."""
        policy = CapabilityPolicy(
            granted=Capability.PROCESS_SHELL,
            require_sandbox_for=Capability.PROCESS_SHELL,
        )
        # Should allow but require sandbox
        assert policy.is_allowed(Capability.PROCESS_SHELL)
        assert policy.requires_sandbox(Capability.PROCESS_SHELL)

    def test_combined_read_write_policy(self) -> None:
        """Test policy with both read and write."""
        policy = CapabilityPolicy(
            granted=Capability.FILESYSTEM_READ | Capability.FILESYSTEM_WRITE,
            denied=Capability.FILESYSTEM_DELETE,
        )
        assert policy.is_allowed(Capability.FILESYSTEM_READ)
        assert policy.is_allowed(Capability.FILESYSTEM_WRITE)
        assert not policy.is_allowed(Capability.FILESYSTEM_DELETE)
