"""Tests for per-tool endpoint policy (V0.4.1).

Tests EndpointPolicy, validate_endpoint(), TOML config parsing,
and integration with the @Airlock decorator.
"""

from __future__ import annotations

import pytest

from agent_airlock import Airlock, AirlockConfig, BlockReason
from agent_airlock.network import (
    EndpointPolicy,
    NetworkBlockedError,
    validate_endpoint,
)
from agent_airlock.self_heal import handle_endpoint_violation


class TestEndpointPolicy:
    """Tests for EndpointPolicy dataclass."""

    def test_default_policy(self) -> None:
        """Test default policy has empty lists and blocks private/metadata."""
        policy = EndpointPolicy()
        assert policy.allowed_endpoints == []
        assert policy.blocked_patterns == []
        assert policy.allow_private_ips is False
        assert policy.allow_metadata_urls is False


class TestValidateEndpoint:
    """Tests for validate_endpoint function."""

    def test_allowed_endpoint_passes(self) -> None:
        """Test that a URL matching allowed endpoints passes validation."""
        policy = EndpointPolicy(
            allowed_endpoints=["api.example.com", "management.azure.com"],
        )
        # Should not raise
        validate_endpoint("https://api.example.com/data", policy)
        validate_endpoint("https://management.azure.com/resource", policy)

    def test_blocked_endpoint_raises(self) -> None:
        """Test that a URL matching blocked patterns raises."""
        policy = EndpointPolicy(
            blocked_patterns=["evil.com", "bad.org"],
        )
        with pytest.raises(NetworkBlockedError) as exc_info:
            validate_endpoint("https://evil.com/steal", policy)
        assert exc_info.value.details["reason"] == "blocked_pattern"

    def test_wildcard_matching(self) -> None:
        """Test wildcard pattern matching (*.blob.core.windows.net)."""
        policy = EndpointPolicy(
            allowed_endpoints=["*.blob.core.windows.net"],
        )
        validate_endpoint("https://myaccount.blob.core.windows.net/data", policy)

        with pytest.raises(NetworkBlockedError):
            validate_endpoint("https://other.example.com/data", policy)

    def test_private_ip_blocking(self) -> None:
        """Test private IP addresses are blocked by default."""
        policy = EndpointPolicy()
        with pytest.raises(NetworkBlockedError) as exc_info:
            validate_endpoint("http://192.168.1.1/admin", policy)
        assert exc_info.value.details["reason"] == "private_ip"

    def test_private_ip_allowed(self) -> None:
        """Test private IPs pass when allow_private_ips=True."""
        policy = EndpointPolicy(allow_private_ips=True)
        validate_endpoint("http://192.168.1.1/admin", policy)

    def test_metadata_url_blocking(self) -> None:
        """Test cloud metadata URLs are blocked by default."""
        policy = EndpointPolicy()
        with pytest.raises(NetworkBlockedError) as exc_info:
            validate_endpoint("http://169.254.169.254/latest/meta-data/", policy)
        assert exc_info.value.details["reason"] == "metadata_url"

    def test_metadata_url_allowed(self) -> None:
        """Test metadata URLs pass when allow_metadata_urls=True."""
        policy = EndpointPolicy(allow_metadata_urls=True, allow_private_ips=True)
        validate_endpoint("http://169.254.169.254/latest/meta-data/", policy)

    def test_localhost_blocking(self) -> None:
        """Test localhost is blocked by default."""
        policy = EndpointPolicy()
        with pytest.raises(NetworkBlockedError):
            validate_endpoint("http://localhost:8080/api", policy)

    def test_no_hostname_raises(self) -> None:
        """Test URL without hostname raises error."""
        policy = EndpointPolicy()
        with pytest.raises(NetworkBlockedError):
            validate_endpoint("not-a-url", policy)

    def test_not_in_allowlist_raises(self) -> None:
        """Test URL not in allowlist is blocked."""
        policy = EndpointPolicy(
            allowed_endpoints=["api.example.com"],
        )
        with pytest.raises(NetworkBlockedError) as exc_info:
            validate_endpoint("https://other.com/data", policy)
        assert exc_info.value.details["reason"] == "not_in_allowlist"

    def test_empty_allowlist_allows_all_non_blocked(self) -> None:
        """Test empty allowlist allows all URLs (except blocked patterns)."""
        policy = EndpointPolicy(
            blocked_patterns=["evil.com"],
        )
        validate_endpoint("https://any-host.com/data", policy)

    def test_blocked_pattern_takes_precedence(self) -> None:
        """Test blocked patterns are checked before allowed endpoints."""
        policy = EndpointPolicy(
            allowed_endpoints=["evil.com"],
            blocked_patterns=["evil.com"],
        )
        with pytest.raises(NetworkBlockedError) as exc_info:
            validate_endpoint("https://evil.com/data", policy)
        assert exc_info.value.details["reason"] == "blocked_pattern"


class TestEndpointPolicyConfig:
    """Tests for TOML config parsing of endpoint policies."""

    def test_parse_endpoint_policies(self) -> None:
        """Test parsing endpoint policies from config dict."""
        from agent_airlock.config import _parse_endpoint_policies

        data = {
            "azure_resource_query": {
                "allowed_endpoints": ["management.azure.com", "graph.microsoft.com"],
                "blocked_patterns": ["169.254.169.254"],
                "allow_private_ips": False,
            },
        }
        policies = _parse_endpoint_policies(data)
        assert "azure_resource_query" in policies
        assert policies["azure_resource_query"].allowed_endpoints == [
            "management.azure.com",
            "graph.microsoft.com",
        ]
        assert policies["azure_resource_query"].blocked_patterns == ["169.254.169.254"]

    def test_config_has_endpoint_policies_field(self) -> None:
        """Test AirlockConfig has endpoint_policies field."""
        config = AirlockConfig()
        assert config.endpoint_policies == {}


class TestEndpointSelfHeal:
    """Tests for endpoint violation self-healing responses."""

    def test_handle_endpoint_violation_response(self) -> None:
        """Test self-healing response includes correct fix_hints."""
        response = handle_endpoint_violation(
            func_name="fetch_data",
            url="https://evil.com/steal",
            hostname="evil.com",
            reason="blocked_pattern",
            allowed_endpoints=["api.example.com"],
        )
        assert response.success is False
        assert response.block_reason == BlockReason.ENDPOINT_BLOCKED
        assert any("api.example.com" in hint for hint in response.fix_hints)


class TestEndpointIntegration:
    """Integration tests with @Airlock decorator."""

    def test_airlock_validates_url_params(self) -> None:
        """Test @Airlock validates URL parameters against endpoint policy."""
        config = AirlockConfig(
            endpoint_policies={
                "fetch_data": EndpointPolicy(
                    allowed_endpoints=["api.example.com"],
                ),
            },
            enable_audit_log=False,
        )

        @Airlock(config=config)
        def fetch_data(url: str) -> str:
            return f"fetched {url}"

        # Blocked URL
        result = fetch_data(url="https://evil.com/steal")
        assert isinstance(result, dict)
        assert result["success"] is False
        assert result["block_reason"] == "endpoint_blocked"

    def test_airlock_allows_matching_endpoint(self) -> None:
        """Test @Airlock allows URLs matching endpoint policy."""
        config = AirlockConfig(
            endpoint_policies={
                "fetch_data": EndpointPolicy(
                    allowed_endpoints=["api.example.com"],
                ),
            },
            enable_audit_log=False,
            sanitize_output=False,
        )

        @Airlock(config=config)
        def fetch_data(url: str) -> str:
            return f"fetched {url}"

        result = fetch_data(url="https://api.example.com/data")
        assert result == "fetched https://api.example.com/data"

    def test_airlock_skips_non_url_params(self) -> None:
        """Test @Airlock doesn't validate non-URL parameters."""
        config = AirlockConfig(
            endpoint_policies={
                "process_data": EndpointPolicy(
                    allowed_endpoints=["api.example.com"],
                ),
            },
            enable_audit_log=False,
            sanitize_output=False,
        )

        @Airlock(config=config)
        def process_data(name: str, count: int) -> str:
            return f"{name}: {count}"

        result = process_data(name="test", count=5)
        assert result == "test: 5"
