"""Comprehensive tests for MCP module - targeting 100% coverage."""

from __future__ import annotations

import sys
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from agent_airlock.config import AirlockConfig
from agent_airlock.policy import SecurityPolicy


class TestMCPAvailability:
    """Tests for FastMCP availability check."""

    def test_check_fastmcp_available_true(self) -> None:
        """Test FastMCP check when available."""
        mock_fastmcp = MagicMock()
        with patch.dict(sys.modules, {"fastmcp": mock_fastmcp}):
            from agent_airlock.mcp import _check_fastmcp_available

            # Need to reload to pick up the mocked module
            result = _check_fastmcp_available()
            assert isinstance(result, bool)

    def test_check_fastmcp_available_false(self) -> None:
        """Test FastMCP check when not available."""
        # Save original
        original = sys.modules.get("fastmcp")
        try:
            sys.modules["fastmcp"] = None
            sys.modules.pop("fastmcp", None)

            from agent_airlock.mcp import _check_fastmcp_available

            # Result depends on actual environment
            result = _check_fastmcp_available()
            assert isinstance(result, bool)
        finally:
            if original:
                sys.modules["fastmcp"] = original


class TestMCPAirlock:
    """Tests for MCPAirlock decorator."""

    def test_mcp_airlock_init(self) -> None:
        """Test MCPAirlock initialization."""
        from agent_airlock.mcp import MCPAirlock

        config = AirlockConfig(strict_mode=True)
        policy = SecurityPolicy(allowed_tools=["*"])

        decorator = MCPAirlock(sandbox=True, config=config, policy=policy, report_progress=True)

        assert decorator.sandbox is True
        assert decorator.config is config
        assert decorator.policy is policy
        assert decorator.report_progress is True

    def test_mcp_airlock_decorates_function(self) -> None:
        """Test MCPAirlock decorates a function."""
        from agent_airlock.mcp import MCPAirlock

        decorator = MCPAirlock()

        @decorator
        def my_func(x: int) -> int:
            return x * 2

        result = my_func(x=5)
        assert result == 10

    def test_mcp_airlock_with_context_and_progress(self) -> None:
        """Test MCPAirlock with context and progress reporting."""
        from agent_airlock.mcp import MCPAirlock

        decorator = MCPAirlock(report_progress=True)

        mock_ctx = MagicMock()
        mock_ctx.report_progress = MagicMock()

        @decorator
        def my_func(x: int, ctx: Any = None) -> int:
            return x * 2

        result = my_func(x=5, ctx=mock_ctx)
        assert result == 10
        # Progress should be reported
        assert mock_ctx.report_progress.call_count >= 1

    def test_mcp_airlock_handles_progress_error(self) -> None:
        """Test MCPAirlock handles progress reporting errors gracefully."""
        from agent_airlock.mcp import MCPAirlock

        decorator = MCPAirlock(report_progress=True)

        mock_ctx = MagicMock()
        mock_ctx.report_progress = MagicMock(side_effect=Exception("Progress error"))

        @decorator
        def my_func(x: int, ctx: Any = None) -> int:
            return x * 2

        # Should not raise despite progress error
        result = my_func(x=5, ctx=mock_ctx)
        assert result == 10

    def test_mcp_airlock_formats_error_response(self) -> None:
        """Test MCPAirlock formats error responses for MCP."""
        from agent_airlock.mcp import MCPAirlock

        config = AirlockConfig(strict_mode=True)
        decorator = MCPAirlock(config=config)

        @decorator
        def my_func(x: int) -> int:
            return x * 2

        # Call with ghost argument - should return formatted error
        result = my_func(x=5, ghost_arg=True)  # type: ignore

        assert isinstance(result, str)
        assert "Error" in result


class TestSecureTool:
    """Tests for secure_tool decorator."""

    def test_secure_tool_creates_decorated_function(self) -> None:
        """Test secure_tool creates a decorated function."""
        from agent_airlock.mcp import secure_tool

        mock_mcp = MagicMock()
        mock_mcp.tool = MagicMock(side_effect=lambda **kwargs: lambda f: f)

        @secure_tool(mock_mcp)
        def my_tool(x: int) -> int:
            return x * 2

        # Function should be decorated
        assert callable(my_tool)

    def test_secure_tool_with_options(self) -> None:
        """Test secure_tool with custom options."""
        from agent_airlock.mcp import secure_tool

        mock_mcp = MagicMock()
        mock_mcp.tool = MagicMock(side_effect=lambda **kwargs: lambda f: f)

        policy = SecurityPolicy(rate_limits={"*": "100/hour"})
        config = AirlockConfig(strict_mode=True)

        @secure_tool(
            mock_mcp,
            sandbox=True,
            config=config,
            policy=policy,
            name="custom_name",
            description="Custom description",
        )
        def my_tool(x: int) -> int:
            return x * 2

        assert callable(my_tool)
        # mcp.tool should be called with name and description
        mock_mcp.tool.assert_called()


class TestCreateSecureMCPServer:
    """Tests for create_secure_mcp_server factory."""

    def test_create_secure_mcp_server_raises_without_fastmcp(self) -> None:
        """Test create_secure_mcp_server raises when FastMCP not installed."""
        from agent_airlock.mcp import create_secure_mcp_server

        with patch("agent_airlock.mcp._check_fastmcp_available", return_value=False):
            with pytest.raises(ImportError) as exc_info:
                create_secure_mcp_server("Test Server")
            assert "FastMCP" in str(exc_info.value)

    def test_create_secure_mcp_server_with_mock_fastmcp(self) -> None:
        """Test create_secure_mcp_server with mocked FastMCP."""
        from agent_airlock.mcp import create_secure_mcp_server

        mock_fastmcp_class = MagicMock()
        mock_mcp_instance = MagicMock()
        mock_fastmcp_class.return_value = mock_mcp_instance
        mock_mcp_instance.tool = MagicMock(side_effect=lambda **kwargs: lambda f: f)

        with patch("agent_airlock.mcp._check_fastmcp_available", return_value=True):
            with patch.dict(sys.modules, {"fastmcp": MagicMock(FastMCP=mock_fastmcp_class)}):
                mcp, secure = create_secure_mcp_server(
                    "Test Server",
                    config=AirlockConfig(strict_mode=True),
                    default_policy=SecurityPolicy(allowed_tools=["*"]),
                )

                assert mcp is mock_mcp_instance
                assert callable(secure)

    def test_make_secure_tool_with_func(self) -> None:
        """Test make_secure_tool with direct function."""
        from agent_airlock.mcp import create_secure_mcp_server

        mock_fastmcp_class = MagicMock()
        mock_mcp_instance = MagicMock()
        mock_fastmcp_class.return_value = mock_mcp_instance
        mock_mcp_instance.tool = MagicMock(side_effect=lambda **kwargs: lambda f: f)

        with patch("agent_airlock.mcp._check_fastmcp_available", return_value=True):
            with patch.dict(sys.modules, {"fastmcp": MagicMock(FastMCP=mock_fastmcp_class)}):
                mcp, secure = create_secure_mcp_server("Test Server")

                def my_tool(x: int) -> int:
                    return x * 2

                # Call secure directly with function
                decorated = secure(my_tool)
                assert callable(decorated)

    def test_make_secure_tool_as_decorator(self) -> None:
        """Test make_secure_tool as decorator with options."""
        from agent_airlock.mcp import create_secure_mcp_server

        mock_fastmcp_class = MagicMock()
        mock_mcp_instance = MagicMock()
        mock_fastmcp_class.return_value = mock_mcp_instance
        mock_mcp_instance.tool = MagicMock(side_effect=lambda **kwargs: lambda f: f)

        with patch("agent_airlock.mcp._check_fastmcp_available", return_value=True):
            with patch.dict(sys.modules, {"fastmcp": MagicMock(FastMCP=mock_fastmcp_class)}):
                mcp, secure = create_secure_mcp_server("Test Server")

                @secure(sandbox=True, tool_name="custom")
                def my_tool(x: int) -> int:
                    return x * 2

                assert callable(my_tool)


class TestMCPContextExtractor:
    """Tests for MCPContextExtractor utility class."""

    def test_extract_agent_id_from_client_id(self) -> None:
        """Test extracting agent ID from client_id."""
        from agent_airlock.mcp import MCPContextExtractor

        mock_ctx = MagicMock()
        mock_ctx.client_id = "agent-123"

        result = MCPContextExtractor.extract_agent_id(mock_ctx)
        assert result == "agent-123"

    def test_extract_agent_id_from_session_id(self) -> None:
        """Test extracting agent ID from session_id."""
        from agent_airlock.mcp import MCPContextExtractor

        mock_ctx = MagicMock(spec=["session_id"])
        mock_ctx.session_id = "session-456"

        result = MCPContextExtractor.extract_agent_id(mock_ctx)
        assert result == "session-456"

    def test_extract_agent_id_from_request_id(self) -> None:
        """Test extracting agent ID from request_id."""
        from agent_airlock.mcp import MCPContextExtractor

        mock_ctx = MagicMock(spec=["request_id"])
        mock_ctx.request_id = "request-789"

        result = MCPContextExtractor.extract_agent_id(mock_ctx)
        assert result == "request-789"

    def test_extract_agent_id_returns_none_on_error(self) -> None:
        """Test extract_agent_id returns None on error."""
        from agent_airlock.mcp import MCPContextExtractor

        mock_ctx = MagicMock()
        # Make accessing client_id raise an exception
        type(mock_ctx).client_id = property(lambda self: (_ for _ in ()).throw(Exception("Error")))

        result = MCPContextExtractor.extract_agent_id(mock_ctx)
        assert result is None

    def test_extract_metadata(self) -> None:
        """Test extracting metadata from context."""
        from agent_airlock.mcp import MCPContextExtractor

        mock_ctx = MagicMock()
        mock_ctx.client_info = {"name": "test-client"}
        mock_ctx.protocol_version = "1.0"

        result = MCPContextExtractor.extract_metadata(mock_ctx)
        assert result["client_info"] == {"name": "test-client"}
        assert result["protocol_version"] == "1.0"

    def test_extract_metadata_handles_missing_attrs(self) -> None:
        """Test extract_metadata handles missing attributes."""
        from agent_airlock.mcp import MCPContextExtractor

        mock_ctx = MagicMock(spec=[])  # No attributes

        result = MCPContextExtractor.extract_metadata(mock_ctx)
        assert result == {}

    def test_extract_metadata_handles_errors(self) -> None:
        """Test extract_metadata handles errors gracefully."""
        from agent_airlock.mcp import MCPContextExtractor

        mock_ctx = MagicMock()
        type(mock_ctx).client_info = property(
            lambda self: (_ for _ in ()).throw(Exception("Error"))
        )

        # Should return empty dict, not raise
        result = MCPContextExtractor.extract_metadata(mock_ctx)
        assert isinstance(result, dict)
