"""FastMCP integration for Agent-Airlock.

Provides seamless integration with FastMCP servers, enabling:
- Decorator composition (@mcp.tool + @Airlock)
- MCP context awareness
- Progress reporting during execution
- MCP-formatted error responses
"""

from __future__ import annotations

import contextlib
import functools
import inspect
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, ParamSpec, TypeVar

import structlog

from .config import DEFAULT_CONFIG, AirlockConfig
from .policy import SecurityPolicy

if TYPE_CHECKING:
    from fastmcp import Context

logger = structlog.get_logger("agent-airlock.mcp")

P = ParamSpec("P")
R = TypeVar("R")


def _check_fastmcp_available() -> bool:
    """Check if FastMCP is installed."""
    try:
        import fastmcp  # noqa: F401

        return True
    except ImportError:
        return False


class MCPAirlock:
    """MCP-aware Airlock decorator for FastMCP tools.

    Provides the same security features as @Airlock but with MCP-specific
    enhancements:
    - Automatic MCP context extraction
    - Progress reporting for long operations
    - MCP-formatted error responses
    - Agent identity from MCP session

    Example:
        from fastmcp import FastMCP
        from agent_airlock.mcp import MCPAirlock, secure_tool

        mcp = FastMCP("My Server")

        @mcp.tool
        @MCPAirlock()
        def read_file(filename: str) -> str:
            with open(filename) as f:
                return f.read()

        # Or use the convenience decorator:
        @secure_tool(mcp)
        def write_file(filename: str, content: str) -> str:
            with open(filename, 'w') as f:
                f.write(content)
            return "Written"
    """

    def __init__(
        self,
        *,
        sandbox: bool = False,
        config: AirlockConfig | None = None,
        policy: SecurityPolicy | None = None,
        report_progress: bool = False,
    ) -> None:
        """Initialize the MCP Airlock decorator.

        Args:
            sandbox: If True, execute in E2B sandbox.
            config: Configuration options.
            policy: Security policy to enforce.
            report_progress: If True, report progress via MCP context.
        """
        self.sandbox = sandbox
        self.config = config or DEFAULT_CONFIG
        self.policy = policy
        self.report_progress = report_progress

    def __call__(self, func: Callable[P, R]) -> Callable[P, R]:
        """Apply the decorator to a function."""
        # Import here to avoid circular imports
        from .core import Airlock

        # Create base Airlock decorator
        airlock = Airlock(
            sandbox=self.sandbox,
            config=self.config,
            policy=self.policy,
            return_dict=False,  # MCP tools should return direct values
        )

        # Wrap with Airlock first
        airlocked_func = airlock(func)

        @functools.wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            # Extract MCP context if present
            ctx = kwargs.get("ctx")

            if ctx is not None and self.report_progress:
                try:
                    # Report start of execution
                    if hasattr(ctx, "report_progress"):
                        ctx.report_progress(0, f"Starting {func.__name__}...")
                except Exception as e:
                    logger.debug(
                        "progress_report_failed",
                        function=func.__name__,
                        stage="start",
                        error=str(e),
                    )

            # Execute the airlocked function
            result = airlocked_func(*args, **kwargs)

            # Check if result is an error dict
            if isinstance(result, dict) and result.get("success") is False:
                # Convert to MCP-friendly error format
                error_msg = result.get("error", "Unknown error")
                fix_hints = result.get("fix_hints", [])

                # Format as helpful message for LLM
                formatted_error = f"Error: {error_msg}"
                if fix_hints:
                    formatted_error += "\n\nSuggested fixes:\n"
                    formatted_error += "\n".join(f"- {hint}" for hint in fix_hints)

                # For MCP, we return the error as a string response
                # The LLM will see this and can retry
                return formatted_error  # type: ignore[return-value]

            if ctx is not None and self.report_progress:
                try:
                    if hasattr(ctx, "report_progress"):
                        ctx.report_progress(100, f"Completed {func.__name__}")
                except Exception as e:
                    logger.debug(
                        "progress_report_failed",
                        function=func.__name__,
                        stage="complete",
                        error=str(e),
                    )

            return result  # type: ignore[return-value]

        # Preserve function signature for MCP/LLM framework introspection
        # FastMCP and other frameworks use inspect.signature() to generate
        # JSON schemas for tool calls
        with contextlib.suppress(ValueError, TypeError):
            wrapper.__signature__ = inspect.signature(func)  # type: ignore[attr-defined]

        wrapper.__annotations__ = getattr(func, "__annotations__", {})

        return wrapper


def secure_tool(
    mcp: Any,
    *,
    sandbox: bool = False,
    config: AirlockConfig | None = None,
    policy: SecurityPolicy | None = None,
    name: str | None = None,
    description: str | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Convenience decorator that combines @mcp.tool and @MCPAirlock.

    This is the recommended way to create secure MCP tools.

    Example:
        from fastmcp import FastMCP
        from agent_airlock.mcp import secure_tool

        mcp = FastMCP("Secure Server")

        @secure_tool(mcp, sandbox=True)
        def run_code(code: str) -> str:
            '''Execute code safely in sandbox.'''
            exec(code)
            return "Executed"

        @secure_tool(mcp, policy=READ_ONLY_POLICY)
        def read_database(query: str) -> list:
            '''Query the database (read-only).'''
            return db.execute(query)

    Args:
        mcp: FastMCP instance.
        sandbox: If True, execute in E2B sandbox.
        config: Configuration options.
        policy: Security policy to enforce.
        name: Optional tool name (defaults to function name).
        description: Optional tool description (defaults to docstring).

    Returns:
        Decorator function.
    """

    def decorator(func: Callable[P, R]) -> Callable[P, R]:
        # Apply MCPAirlock first
        secured = MCPAirlock(
            sandbox=sandbox,
            config=config,
            policy=policy,
            report_progress=True,
        )(func)

        # Then register with MCP
        tool_kwargs: dict[str, Any] = {}
        if name:
            tool_kwargs["name"] = name
        if description:
            tool_kwargs["description"] = description

        return mcp.tool(**tool_kwargs)(secured)  # type: ignore[no-any-return]

    return decorator


def create_secure_mcp_server(
    name: str,
    *,
    config: AirlockConfig | None = None,
    default_policy: SecurityPolicy | None = None,
) -> tuple[Any, Callable[..., Any]]:
    """Create a FastMCP server with pre-configured Airlock security.

    Returns a tuple of (mcp_server, secure_tool_decorator).

    Example:
        from agent_airlock.mcp import create_secure_mcp_server

        mcp, secure = create_secure_mcp_server(
            "My Secure Server",
            default_policy=READ_ONLY_POLICY,
        )

        @secure
        def read_file(path: str) -> str:
            with open(path) as f:
                return f.read()

        @secure(sandbox=True)  # Override for dangerous operations
        def run_script(code: str) -> str:
            exec(code)
            return "Done"

    Args:
        name: Name of the MCP server.
        config: Default Airlock configuration.
        default_policy: Default security policy for all tools.

    Returns:
        Tuple of (FastMCP instance, secure_tool decorator).

    Raises:
        ImportError: If FastMCP is not installed.
    """
    if not _check_fastmcp_available():
        raise ImportError(
            "FastMCP is required for MCP integration. Install with: pip install agent-airlock[mcp]"
        )

    from fastmcp import FastMCP

    mcp = FastMCP(name)
    config = config or DEFAULT_CONFIG

    def make_secure_tool(
        func: Callable[P, R] | None = None,
        *,
        sandbox: bool = False,
        policy: SecurityPolicy | None = None,
        tool_name: str | None = None,
        tool_description: str | None = None,
    ) -> Callable[P, R] | Callable[[Callable[P, R]], Callable[P, R]]:
        """Create a secure tool with optional overrides."""
        effective_policy = policy or default_policy

        def decorator(fn: Callable[P, R]) -> Callable[P, R]:
            return secure_tool(
                mcp,
                sandbox=sandbox,
                config=config,
                policy=effective_policy,
                name=tool_name,
                description=tool_description,
            )(fn)

        if func is None:
            return decorator
        return decorator(func)

    return mcp, make_secure_tool


class MCPContextExtractor:
    """Utility class for extracting information from MCP context.

    Use this to build agent identity from MCP requests.
    """

    @staticmethod
    def extract_agent_id(ctx: Context) -> str | None:
        """Extract agent ID from MCP context."""
        try:
            # Try common locations for agent ID
            if hasattr(ctx, "client_id"):
                return str(ctx.client_id)
            if hasattr(ctx, "session_id"):
                return str(ctx.session_id)
            if hasattr(ctx, "request_id"):
                return str(ctx.request_id)
        except Exception as e:
            logger.debug(
                "context_extraction_failed",
                field="agent_id",
                error=str(e),
            )
        return None

    @staticmethod
    def extract_metadata(ctx: Context) -> dict[str, Any]:
        """Extract metadata from MCP context."""
        metadata: dict[str, Any] = {}

        try:
            if hasattr(ctx, "client_info"):
                metadata["client_info"] = ctx.client_info
            if hasattr(ctx, "protocol_version"):
                metadata["protocol_version"] = ctx.protocol_version
        except Exception as e:
            logger.debug(
                "metadata_extraction_failed",
                error=str(e),
            )

        return metadata


# Re-export for convenience
__all__ = [
    "MCPAirlock",
    "MCPContextExtractor",
    "create_secure_mcp_server",
    "secure_tool",
]
