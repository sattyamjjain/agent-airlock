"""Tests for per-tool credential scope declarations (V0.4.1).

Tests CredentialScope, validate_tool_credentials(), get_tool_scope(),
and TOML config parsing.
"""

from __future__ import annotations

import time

import pytest

from agent_airlock.mcp_proxy_guard import (
    CredentialScope,
    MCPProxyConfig,
    MCPProxyGuard,
    MCPSecurityError,
)


class TestCredentialScope:
    """Tests for CredentialScope dataclass."""

    def test_default_scope(self) -> None:
        """Test default scope values."""
        scope = CredentialScope()
        assert scope.required_scopes == []
        assert scope.max_token_age_seconds == 3600
        assert scope.require_fresh_token is False
        assert scope.allowed_audiences == []


class TestScopeValidation:
    """Tests for validate_tool_credentials."""

    def _make_guard(self, scopes: dict[str, CredentialScope] | None = None) -> MCPProxyGuard:
        """Create a guard with tool scopes."""
        config = MCPProxyConfig(
            block_token_passthrough=False,
            bind_to_session=False,
            tool_scopes=scopes or {},
        )
        return MCPProxyGuard(config)

    def test_scope_validation_passes_with_correct_scopes(self) -> None:
        """Test validation passes when token has required scopes."""
        guard = self._make_guard(
            {
                "read_storage": CredentialScope(
                    required_scopes=["storage.read"],
                ),
            }
        )
        guard.validate_tool_credentials(
            "read_storage",
            token_claims={"scp": "storage.read storage.write"},
        )

    def test_scope_validation_fails_with_missing_scopes(self) -> None:
        """Test validation fails when token is missing required scopes."""
        guard = self._make_guard(
            {
                "read_storage": CredentialScope(
                    required_scopes=["storage.read", "keyvault.list"],
                ),
            }
        )
        with pytest.raises(MCPSecurityError) as exc_info:
            guard.validate_tool_credentials(
                "read_storage",
                token_claims={"scp": "storage.read"},
            )
        assert exc_info.value.violation_type == "insufficient_scopes"
        assert "keyvault.list" in exc_info.value.details["missing_scopes"]

    def test_token_age_check_expired(self) -> None:
        """Test token age check rejects expired tokens."""
        guard = self._make_guard(
            {
                "sensitive_tool": CredentialScope(
                    max_token_age_seconds=60,
                ),
            }
        )
        old_iat = time.time() - 120  # 2 minutes old
        with pytest.raises(MCPSecurityError) as exc_info:
            guard.validate_tool_credentials(
                "sensitive_tool",
                token_claims={"iat": old_iat},
            )
        assert exc_info.value.violation_type == "token_expired"

    def test_token_age_check_passes(self) -> None:
        """Test token age check passes for fresh tokens."""
        guard = self._make_guard(
            {
                "tool": CredentialScope(
                    max_token_age_seconds=300,
                ),
            }
        )
        guard.validate_tool_credentials(
            "tool",
            token_claims={"iat": time.time() - 10},
        )

    def test_require_fresh_token_enforcement(self) -> None:
        """Test require_fresh_token rejects tokens older than 60s."""
        guard = self._make_guard(
            {
                "critical_tool": CredentialScope(
                    require_fresh_token=True,
                ),
            }
        )
        with pytest.raises(MCPSecurityError) as exc_info:
            guard.validate_tool_credentials(
                "critical_tool",
                token_claims={"iat": time.time() - 90},
            )
        assert exc_info.value.violation_type == "token_not_fresh"

    def test_audience_validation_passes(self) -> None:
        """Test audience validation passes with matching aud."""
        guard = self._make_guard(
            {
                "azure_tool": CredentialScope(
                    allowed_audiences=["https://management.azure.com"],
                ),
            }
        )
        guard.validate_tool_credentials(
            "azure_tool",
            token_claims={"aud": "https://management.azure.com"},
        )

    def test_audience_validation_fails(self) -> None:
        """Test audience validation fails with mismatched aud."""
        guard = self._make_guard(
            {
                "azure_tool": CredentialScope(
                    allowed_audiences=["https://management.azure.com"],
                ),
            }
        )
        with pytest.raises(MCPSecurityError) as exc_info:
            guard.validate_tool_credentials(
                "azure_tool",
                token_claims={"aud": "https://wrong-audience.com"},
            )
        assert exc_info.value.violation_type == "audience_mismatch"

    def test_tool_without_scope_passes_freely(self) -> None:
        """Test tool without scope declaration passes without validation."""
        guard = self._make_guard(
            {
                "other_tool": CredentialScope(required_scopes=["admin"]),
            }
        )
        # This tool has no scope declared, should pass
        guard.validate_tool_credentials("unscoped_tool", token_claims={})

    def test_get_tool_scope_returns_correct_scope(self) -> None:
        """Test get_tool_scope returns the right scope."""
        scope = CredentialScope(required_scopes=["read"])
        guard = self._make_guard({"my_tool": scope})
        assert guard.get_tool_scope("my_tool") is scope
        assert guard.get_tool_scope("other") is None

    def test_no_token_with_required_scopes_raises(self) -> None:
        """Test missing token raises when scopes are required."""
        guard = self._make_guard(
            {
                "secure_tool": CredentialScope(required_scopes=["admin"]),
            }
        )
        with pytest.raises(MCPSecurityError) as exc_info:
            guard.validate_tool_credentials("secure_tool")
        assert exc_info.value.violation_type == "missing_credentials"

    def test_scope_claim_as_list(self) -> None:
        """Test scopes from 'scope' claim as list."""
        guard = self._make_guard(
            {
                "tool": CredentialScope(required_scopes=["read"]),
            }
        )
        guard.validate_tool_credentials(
            "tool",
            token_claims={"scope": ["read", "write"]},
        )

    def test_audience_as_list(self) -> None:
        """Test audience validation with aud as list."""
        guard = self._make_guard(
            {
                "tool": CredentialScope(
                    allowed_audiences=["https://api.example.com"],
                ),
            }
        )
        guard.validate_tool_credentials(
            "tool",
            token_claims={"aud": ["https://api.example.com", "https://other.com"]},
        )


class TestCredentialScopeConfig:
    """Tests for TOML config parsing."""

    def test_parse_credential_scopes(self) -> None:
        """Test parsing credential scopes from config dict."""
        from agent_airlock.config import _parse_credential_scopes

        data = {
            "azure_resource_query": {
                "required_scopes": ["https://management.azure.com/.default"],
                "max_token_age_seconds": 300,
                "require_fresh_token": False,
                "allowed_audiences": ["https://management.azure.com"],
            },
        }
        scopes = _parse_credential_scopes(data)
        assert "azure_resource_query" in scopes
        scope = scopes["azure_resource_query"]
        assert scope.required_scopes == ["https://management.azure.com/.default"]
        assert scope.max_token_age_seconds == 300
        assert scope.allowed_audiences == ["https://management.azure.com"]
