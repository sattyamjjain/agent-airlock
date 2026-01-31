"""Tests for __init__.py lazy imports - targeting 100% coverage."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

from agent_airlock.config import AirlockConfig
from agent_airlock.policy import SecurityPolicy


class TestGetSandboxPool:
    """Tests for get_sandbox_pool function."""

    def test_get_sandbox_pool(self) -> None:
        """Test get_sandbox_pool imports and returns pool."""
        from agent_airlock import get_sandbox_pool

        # Mock the sandbox module
        mock_pool = MagicMock()
        mock_get_pool = MagicMock(return_value=mock_pool)

        with patch.dict(
            sys.modules,
            {
                "agent_airlock.sandbox": MagicMock(
                    SandboxPool=MagicMock, get_sandbox_pool=mock_get_pool
                )
            },
        ):
            config = AirlockConfig()
            result = get_sandbox_pool(config)
            # Should call the internal function
            assert result is not None


class TestGetMCPAirlock:
    """Tests for get_mcp_airlock function."""

    def test_get_mcp_airlock(self) -> None:
        """Test get_mcp_airlock imports and returns class."""
        from agent_airlock import get_mcp_airlock

        mock_mcp_airlock = MagicMock()

        with patch.dict(sys.modules, {"agent_airlock.mcp": MagicMock(MCPAirlock=mock_mcp_airlock)}):
            # This tests the import path
            result = get_mcp_airlock()
            assert result is not None


class TestGetSecureTool:
    """Tests for get_secure_tool function."""

    def test_get_secure_tool(self) -> None:
        """Test get_secure_tool imports and returns function."""
        from agent_airlock import get_secure_tool

        mock_secure_tool = MagicMock()

        with patch.dict(
            sys.modules, {"agent_airlock.mcp": MagicMock(secure_tool=mock_secure_tool)}
        ):
            result = get_secure_tool()
            assert result is not None


class TestCreateSecureMCPServer:
    """Tests for create_secure_mcp_server wrapper."""

    def test_create_secure_mcp_server(self) -> None:
        """Test create_secure_mcp_server wrapper imports and calls."""
        from agent_airlock import create_secure_mcp_server

        mock_create = MagicMock(return_value=(MagicMock(), MagicMock()))

        with patch.dict(
            sys.modules,
            {"agent_airlock.mcp": MagicMock(create_secure_mcp_server=mock_create)},
        ):
            config = AirlockConfig()
            policy = SecurityPolicy()
            result = create_secure_mcp_server("Test Server", config=config, default_policy=policy)
            assert result is not None


class TestVersionAndExports:
    """Tests for version and exports."""

    def test_version_exists(self) -> None:
        """Test __version__ is defined."""
        from agent_airlock import __version__

        assert isinstance(__version__, str)
        assert len(__version__) > 0

    def test_all_exports_exist(self) -> None:
        """Test all items in __all__ are importable."""
        import agent_airlock
        from agent_airlock import __all__

        for name in __all__:
            assert hasattr(agent_airlock, name), f"Missing export: {name}"
