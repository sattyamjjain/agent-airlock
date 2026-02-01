"""Tests for mcp_proxy_guard module (V0.4.0)."""

from __future__ import annotations

import time

import pytest

from agent_airlock.mcp_proxy_guard import (
    DEFAULT_PROXY_CONFIG,
    PERMISSIVE_PROXY_CONFIG,
    STRICT_PROXY_CONFIG,
    MCPProxyConfig,
    MCPProxyGuard,
    MCPSecurityError,
    MCPSession,
)


class TestMCPProxyConfig:
    """Test the MCPProxyConfig dataclass."""

    def test_default_values(self) -> None:
        """Test default configuration values."""
        config = MCPProxyConfig()
        assert config.block_token_passthrough is True
        assert config.bind_to_session is True
        assert config.session_id_header == "X-MCP-Session-ID"

    def test_custom_values(self) -> None:
        """Test custom configuration."""
        config = MCPProxyConfig(
            block_token_passthrough=False,
            bind_to_session=False,
            session_id_header="X-Custom-Session",
        )
        assert config.block_token_passthrough is False
        assert config.bind_to_session is False
        assert config.session_id_header == "X-Custom-Session"

    def test_token_audience_configuration(self) -> None:
        """Test token audience configuration."""
        config = MCPProxyConfig(
            required_token_audience="my-mcp-server",
        )
        assert config.required_token_audience == "my-mcp-server"

    def test_require_consent_for_tools(self) -> None:
        """Test consent requirement configuration."""
        config = MCPProxyConfig(
            require_consent_for_tools=["delete_*", "write_*"],
        )
        assert "delete_*" in config.require_consent_for_tools


class TestMCPSession:
    """Test the MCPSession dataclass."""

    def test_basic_creation(self) -> None:
        """Test basic session creation."""
        session = MCPSession(
            session_id="sess-123",
            user_id="user-001",
        )
        assert session.session_id == "sess-123"
        assert session.user_id == "user-001"

    def test_with_created_at(self) -> None:
        """Test session with creation timestamp."""
        session = MCPSession(
            session_id="sess-123",
        )
        assert session.created_at is not None
        assert session.created_at <= time.time()

    def test_consented_tools(self) -> None:
        """Test session with consented tools."""
        session = MCPSession(
            session_id="sess-123",
            consented_tools={"read_file", "list_files"},
        )
        assert session.has_consent("read_file")
        assert not session.has_consent("delete_file")

    def test_add_consent(self) -> None:
        """Test adding consent."""
        session = MCPSession(session_id="sess-123")
        session.add_consent("new_tool")
        assert session.has_consent("new_tool")

    def test_touch_updates_activity(self) -> None:
        """Test touch updates last activity."""
        session = MCPSession(session_id="sess-123")
        old_activity = session.last_activity
        time.sleep(0.01)
        session.touch()
        assert session.last_activity >= old_activity

    def test_is_expired(self) -> None:
        """Test session expiry check."""
        session = MCPSession(session_id="sess-123")
        # Fresh session should not be expired
        assert not session.is_expired(max_age_seconds=3600)
        # Expired with 0 max age
        assert session.is_expired(max_age_seconds=0)


class TestMCPProxyGuard:
    """Test the MCPProxyGuard class."""

    def test_basic_creation(self) -> None:
        """Test basic guard creation."""
        guard = MCPProxyGuard()
        assert guard is not None

    def test_creation_with_config(self) -> None:
        """Test guard creation with custom config."""
        config = MCPProxyConfig(block_token_passthrough=False)
        guard = MCPProxyGuard(config=config)
        assert guard.config.block_token_passthrough is False

    def test_validate_request_with_session(self) -> None:
        """Test validating a request with session ID."""
        guard = MCPProxyGuard()
        request = {
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {"path": "/app/data.txt"},
            },
            "headers": {
                "X-MCP-Session-ID": "sess-123",
            },
        }
        # Should not raise
        guard.validate_request(request)

    def test_validate_request_missing_session_raises(self) -> None:
        """Test that missing session ID raises error."""
        guard = MCPProxyGuard()
        request = {
            "method": "tools/call",
            "params": {"name": "read_file"},
            "headers": {},
        }
        with pytest.raises(MCPSecurityError, match="session"):
            guard.validate_request(request)

    def test_validate_request_without_session_binding(self) -> None:
        """Test request validation without session binding."""
        config = MCPProxyConfig(bind_to_session=False)
        guard = MCPProxyGuard(config=config)
        request = {
            "method": "tools/call",
            "params": {"name": "read_file"},
            "headers": {},
        }
        # Should not raise when binding disabled
        guard.validate_request(request)

    def test_validate_request_blocks_passthrough_header(self) -> None:
        """Test that passthrough headers are blocked."""
        config = MCPProxyConfig(bind_to_session=False)
        guard = MCPProxyGuard(config=config)
        request = {
            "method": "tools/call",
            "params": {"name": "fetch_data"},
            "headers": {
                "X-Original-Authorization": "Bearer stolen-token",
            },
        }
        with pytest.raises(MCPSecurityError, match="passthrough"):
            guard.validate_request(request)

    def test_validate_request_allows_safe_headers(self) -> None:
        """Test that safe headers are allowed."""
        config = MCPProxyConfig(bind_to_session=False)
        guard = MCPProxyGuard(config=config)
        request = {
            "method": "tools/call",
            "params": {"name": "read_file"},
            "headers": {
                "Content-Type": "application/json",
                "User-Agent": "MCP-Client/1.0",
            },
        }
        # Should not raise
        guard.validate_request(request)

    def test_get_or_create_session(self) -> None:
        """Test getting or creating a session."""
        guard = MCPProxyGuard()
        request = {"headers": {"X-MCP-Session-ID": "sess-123"}}

        session = guard.get_or_create_session(request, user_id="user-001")
        assert session is not None
        assert session.user_id == "user-001"

    def test_check_tool_consent_not_required(self) -> None:
        """Test tool consent when not required."""
        guard = MCPProxyGuard()
        session = MCPSession(session_id="sess-123")

        # No consent patterns configured, should pass
        result = guard.check_tool_consent(session, "any_tool")
        assert result is True

    def test_check_tool_consent_required_and_given(self) -> None:
        """Test tool consent when required and given."""
        config = MCPProxyConfig(require_consent_for_tools=["delete_*"])
        guard = MCPProxyGuard(config=config)
        session = MCPSession(
            session_id="sess-123",
            consented_tools={"delete_file"},
        )

        result = guard.check_tool_consent(session, "delete_file")
        assert result is True

    def test_check_tool_consent_required_not_given(self) -> None:
        """Test tool consent when required but not given."""
        config = MCPProxyConfig(require_consent_for_tools=["delete_*"])
        guard = MCPProxyGuard(config=config)
        session = MCPSession(session_id="sess-123")

        with pytest.raises(MCPSecurityError, match="consent"):
            guard.check_tool_consent(session, "delete_file")

    def test_grant_consent(self) -> None:
        """Test granting consent for a tool."""
        guard = MCPProxyGuard()
        session = MCPSession(session_id="sess-123")

        guard.grant_consent(session, "dangerous_tool")
        assert session.has_consent("dangerous_tool")

    def test_cleanup_expired_sessions(self) -> None:
        """Test cleaning up expired sessions."""
        config = MCPProxyConfig(max_session_age_seconds=0)
        guard = MCPProxyGuard(config=config)

        # Create a session
        request = {"headers": {"X-MCP-Session-ID": "sess-123"}}
        guard.get_or_create_session(request)

        # Clean up (should remove expired)
        removed = guard.cleanup_expired_sessions()
        assert removed >= 1

    def test_get_session_count(self) -> None:
        """Test getting session count."""
        guard = MCPProxyGuard()
        initial_count = guard.get_session_count()

        request = {"headers": {"X-MCP-Session-ID": "new-sess"}}
        guard.get_or_create_session(request)

        assert guard.get_session_count() == initial_count + 1


class TestMCPSecurityError:
    """Test the MCPSecurityError exception."""

    def test_error_message(self) -> None:
        """Test error message."""
        error = MCPSecurityError("Token passthrough detected")
        assert "passthrough" in str(error)

    def test_error_with_violation_type(self) -> None:
        """Test error with violation type."""
        error = MCPSecurityError(
            message="Header blocked",
            violation_type="token_passthrough",
        )
        assert error.violation_type == "token_passthrough"

    def test_error_with_details(self) -> None:
        """Test error with details dict."""
        error = MCPSecurityError(
            message="Consent required",
            violation_type="consent_required",
            details={"tool": "delete_file"},
        )
        assert error.details["tool"] == "delete_file"


class TestPredefinedConfigs:
    """Test predefined proxy configurations."""

    def test_default_config(self) -> None:
        """Test DEFAULT_PROXY_CONFIG."""
        config = DEFAULT_PROXY_CONFIG
        assert config.block_token_passthrough is True
        assert config.bind_to_session is True

    def test_strict_config(self) -> None:
        """Test STRICT_PROXY_CONFIG."""
        config = STRICT_PROXY_CONFIG
        assert config.block_token_passthrough is True
        assert config.rotate_session_on_auth is True
        assert len(config.require_consent_for_tools) > 0

    def test_permissive_config(self) -> None:
        """Test PERMISSIVE_PROXY_CONFIG."""
        config = PERMISSIVE_PROXY_CONFIG
        assert config.block_token_passthrough is False
        assert config.bind_to_session is False


class TestConsentPatterns:
    """Test consent pattern matching."""

    def test_wildcard_pattern_match(self) -> None:
        """Test wildcard pattern matching."""
        config = MCPProxyConfig(require_consent_for_tools=["delete_*"])
        guard = MCPProxyGuard(config=config)
        session = MCPSession(session_id="sess-123")

        # delete_file should match delete_*
        with pytest.raises(MCPSecurityError, match="consent"):
            guard.check_tool_consent(session, "delete_file")

    def test_non_matching_pattern(self) -> None:
        """Test non-matching pattern."""
        config = MCPProxyConfig(require_consent_for_tools=["delete_*"])
        guard = MCPProxyGuard(config=config)
        session = MCPSession(session_id="sess-123")

        # read_file should not match delete_*
        result = guard.check_tool_consent(session, "read_file")
        assert result is True
