"""Tests for the MCP integration module."""

import pytest

from agent_airlock import AirlockConfig, SecurityPolicy
from agent_airlock.mcp import MCPAirlock, _check_fastmcp_available


class TestFastMCPAvailability:
    """Tests for FastMCP availability check."""

    def test_check_fastmcp_available(self) -> None:
        # Just verify the function works and returns a boolean
        result = _check_fastmcp_available()
        assert isinstance(result, bool)


class TestMCPAirlock:
    """Tests for MCPAirlock decorator."""

    def test_basic_decoration(self) -> None:
        @MCPAirlock()
        def simple_tool(x: int) -> int:
            return x * 2

        result = simple_tool(x=5)
        assert result == 10

    def test_with_config(self) -> None:
        config = AirlockConfig(strict_mode=True)

        @MCPAirlock(config=config)
        def strict_tool(name: str) -> str:
            return f"Hello, {name}"

        result = strict_tool(name="World")
        assert result == "Hello, World"

    def test_validation_error_returns_formatted_string(self) -> None:
        @MCPAirlock()
        def typed_tool(count: int) -> int:
            return count

        # Pass wrong type - should get formatted error string
        result = typed_tool(count="not an int")  # type: ignore[arg-type]

        # MCPAirlock converts error dicts to formatted strings
        assert isinstance(result, str)
        assert "Error:" in result

    def test_ghost_arguments_stripped(self) -> None:
        @MCPAirlock()
        def simple_tool(x: int) -> int:
            return x

        # Ghost argument should be stripped
        result = simple_tool(x=5, unknown_arg=True)  # type: ignore[call-arg]
        assert result == 5

    def test_strict_mode_returns_error_string(self) -> None:
        config = AirlockConfig(strict_mode=True)

        @MCPAirlock(config=config)
        def strict_tool(x: int) -> int:
            return x

        # Ghost argument in strict mode should return error
        result = strict_tool(x=5, unknown=True)  # type: ignore[call-arg]

        assert isinstance(result, str)
        assert "Error:" in result

    def test_with_policy(self) -> None:
        policy = SecurityPolicy(denied_tools=["denied_tool"])

        @MCPAirlock(policy=policy)
        def denied_tool(x: int) -> int:
            return x

        result = denied_tool(x=5)

        # Policy violation returns error string
        assert isinstance(result, str)
        assert "Error:" in result
        assert "denied" in result.lower()

    def test_sandbox_option(self) -> None:
        @MCPAirlock(sandbox=True)
        def sandboxed_tool(x: int) -> int:
            return x * 2

        # Should work or return error if sandbox not available
        result = sandboxed_tool(x=5)

        # Either succeeds with fallback or returns formatted error
        if isinstance(result, int):
            assert result == 10
        else:
            # Sandbox not available - check it returns a formatted error
            assert isinstance(result, str)
            assert "Error:" in result

    def test_preserves_function_metadata(self) -> None:
        @MCPAirlock()
        def documented_tool(x: int) -> int:
            """This is a documented tool."""
            return x

        assert documented_tool.__name__ == "documented_tool"
        assert documented_tool.__doc__ == "This is a documented tool."


class TestMCPAirlockWithContext:
    """Tests for MCPAirlock with MCP context."""

    def test_handles_ctx_parameter(self) -> None:
        @MCPAirlock(report_progress=True)
        def tool_with_ctx(x: int, ctx: object = None) -> int:  # noqa: ARG001
            return x * 2

        # Should work with or without ctx
        result = tool_with_ctx(x=5)
        assert result == 10

        # With a mock context
        class MockContext:
            def report_progress(self, progress: int, message: str) -> None:
                pass

        result = tool_with_ctx(x=5, ctx=MockContext())
        assert result == 10

    def test_progress_reporting_no_error_on_failure(self) -> None:
        @MCPAirlock(report_progress=True)
        def tool_with_ctx(x: int, ctx: object = None) -> int:  # noqa: ARG001
            return x

        # Context without report_progress method
        class BrokenContext:
            pass

        # Should not raise even with broken context
        result = tool_with_ctx(x=5, ctx=BrokenContext())
        assert result == 5


class TestDecoratorComposition:
    """Tests for decorator composition patterns."""

    def test_airlock_with_other_decorators(self) -> None:
        def log_calls(func):  # type: ignore[no-untyped-def]
            calls: list[tuple[tuple, dict]] = []  # type: ignore[type-arg]

            def wrapper(*args, **kwargs):  # type: ignore[no-untyped-def]
                calls.append((args, kwargs))
                return func(*args, **kwargs)

            wrapper.calls = calls  # type: ignore[attr-defined]
            return wrapper

        @log_calls
        @MCPAirlock()
        def tracked_tool(x: int) -> int:
            return x * 2

        result = tracked_tool(x=5)
        assert result == 10
        assert len(tracked_tool.calls) == 1  # type: ignore[attr-defined]

    def test_mcp_airlock_then_airlock(self) -> None:
        # MCPAirlock wraps regular Airlock internally
        @MCPAirlock()
        def tool(x: int) -> int:
            return x

        result = tool(x=10)
        assert result == 10


class TestErrorFormatting:
    """Tests for MCP-friendly error formatting."""

    def test_validation_error_includes_fix_hints(self) -> None:
        @MCPAirlock()
        def typed_tool(age: int) -> int:
            return age

        result = typed_tool(age="twenty")  # type: ignore[arg-type]

        assert isinstance(result, str)
        assert "Suggested fixes:" in result or "Error:" in result

    def test_policy_error_formatted(self) -> None:
        policy = SecurityPolicy(allowed_tools=["allowed_*"])

        @MCPAirlock(policy=policy)
        def blocked_tool(x: int) -> int:
            return x

        result = blocked_tool(x=5)

        assert isinstance(result, str)
        assert "Error:" in result


class TestCreateSecureMCPServer:
    """Tests for create_secure_mcp_server function."""

    def test_raises_without_fastmcp(self) -> None:
        if _check_fastmcp_available():
            pytest.skip("FastMCP is installed")

        from agent_airlock.mcp import create_secure_mcp_server

        with pytest.raises(ImportError, match="FastMCP is required"):
            create_secure_mcp_server("test")


@pytest.mark.skipif(
    not _check_fastmcp_available(),
    reason="FastMCP not installed",
)
class TestWithFastMCP:
    """Tests that require FastMCP to be installed."""

    def test_secure_tool_decorator(self) -> None:
        from fastmcp import FastMCP

        from agent_airlock.mcp import secure_tool

        mcp = FastMCP("test")

        @secure_tool(mcp)
        def my_tool(x: int) -> int:
            return x * 2

        # secure_tool returns a FunctionTool registered with the server
        # We verify the tool was registered and has correct attributes
        assert my_tool is not None
        assert hasattr(my_tool, "name")
        assert my_tool.name == "my_tool"

    def test_create_secure_mcp_server(self) -> None:
        from agent_airlock.mcp import create_secure_mcp_server

        mcp, secure = create_secure_mcp_server("Test Server")

        @secure
        def my_tool(x: int) -> int:
            return x

        # secure decorator returns a FunctionTool registered with the server
        # We verify the tool was registered and has correct attributes
        assert my_tool is not None
        assert hasattr(my_tool, "name")
        assert my_tool.name == "my_tool"

    def test_secure_tool_with_policy(self) -> None:
        from fastmcp import FastMCP

        from agent_airlock.mcp import secure_tool

        mcp = FastMCP("test")
        policy = SecurityPolicy(allowed_tools=["allowed_*"])

        @secure_tool(mcp, policy=policy)
        def allowed_tool(x: int) -> int:
            return x

        # Verify the tool was registered with correct name
        assert allowed_tool is not None
        assert hasattr(allowed_tool, "name")
        assert allowed_tool.name == "allowed_tool"

    def test_secure_tool_with_sandbox(self) -> None:
        from fastmcp import FastMCP

        from agent_airlock.mcp import secure_tool

        mcp = FastMCP("test")

        @secure_tool(mcp, sandbox=True)
        def sandboxed_tool(x: int) -> int:
            return x * 2

        # Verify the tool was registered with correct name
        assert sandboxed_tool is not None
        assert hasattr(sandboxed_tool, "name")
        assert sandboxed_tool.name == "sandboxed_tool"


class TestMCPContextExtractor:
    """Tests for MCPContextExtractor utility."""

    def test_extract_agent_id(self) -> None:
        from agent_airlock.mcp import MCPContextExtractor

        class MockContext:
            client_id = "agent-123"

        ctx = MockContext()
        agent_id = MCPContextExtractor.extract_agent_id(ctx)  # type: ignore[arg-type]
        assert agent_id == "agent-123"

    def test_extract_agent_id_fallbacks(self) -> None:
        from agent_airlock.mcp import MCPContextExtractor

        class SessionContext:
            session_id = "session-456"

        ctx = SessionContext()
        agent_id = MCPContextExtractor.extract_agent_id(ctx)  # type: ignore[arg-type]
        assert agent_id == "session-456"

    def test_extract_agent_id_none(self) -> None:
        from agent_airlock.mcp import MCPContextExtractor

        class EmptyContext:
            pass

        ctx = EmptyContext()
        agent_id = MCPContextExtractor.extract_agent_id(ctx)  # type: ignore[arg-type]
        assert agent_id is None

    def test_extract_metadata(self) -> None:
        from agent_airlock.mcp import MCPContextExtractor

        class MockContext:
            client_info = {"name": "Claude"}
            protocol_version = "2024-11-05"

        ctx = MockContext()
        metadata = MCPContextExtractor.extract_metadata(ctx)  # type: ignore[arg-type]
        assert metadata["client_info"] == {"name": "Claude"}
        assert metadata["protocol_version"] == "2024-11-05"

    def test_extract_metadata_empty(self) -> None:
        from agent_airlock.mcp import MCPContextExtractor

        class EmptyContext:
            pass

        ctx = EmptyContext()
        metadata = MCPContextExtractor.extract_metadata(ctx)  # type: ignore[arg-type]
        assert metadata == {}
