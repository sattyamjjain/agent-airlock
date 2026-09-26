"""FastMCP integration for Agent-Airlock.

Provides integration with FastMCP servers:
- Decorator composition (@mcp.tool + @MCPAirlock, or @secure_tool(mcp))
- Refused calls raised as FastMCP's ``ToolError``, which the client receives as an error
  result carrying the refusal and its fix hints
- Progress notifications at the start and end of a call
- ``MCPContextExtractor`` for reading identifiers off a FastMCP ``Context``

FastMCP validates and coerces a call's arguments against the tool's schema before the
tool, and so Airlock, sees them.
"""

from __future__ import annotations

import contextlib
import functools
import inspect
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, ParamSpec, TypeVar

from .._log import structlog
from ..config import DEFAULT_CONFIG, AirlockConfig
from ..policy import SecurityPolicy

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


def _is_refusal(result: Any) -> bool:
    """Whether ``result`` is Airlock's own refusal (``AirlockResponse.to_dict()``).

    ``status == "blocked"`` is checked as well as ``success``: a tool may itself return a
    dict with ``"success": False``, and that is its result, not a refusal.
    """
    return (
        isinstance(result, dict)
        and result.get("success") is False
        and result.get("status") == "blocked"
    )


def _refusal_text(refusal: dict[str, Any]) -> str:
    """The refusal as the text the model reads: the error, then the fix hints."""
    text = f"Error: {refusal.get('error', 'Unknown error')}"
    hints = refusal.get("fix_hints") or []
    if hints:
        text += "\n\nSuggested fixes:\n" + "\n".join(f"- {hint}" for hint in hints)
    return text


def _refuse(refusal: dict[str, Any]) -> str:
    """Raise FastMCP's ToolError with the refusal text; without FastMCP, return the text.

    FastMCP sends a ToolError to the client as an error result with this text, whatever
    the tool's return type. Until 0.10.18 the text was returned as the tool's result,
    which fails FastMCP's output-schema check on a tool declared ``-> dict`` or
    ``-> int``, so the client got a schema error instead of the refusal.
    """
    text = _refusal_text(refusal)
    try:
        from fastmcp.exceptions import ToolError
    except ImportError:
        return text
    raise ToolError(text)


def _mcp_context(kwargs: dict[str, Any]) -> Any | None:
    """The FastMCP ``Context`` among a tool's arguments, whatever its parameter is named."""
    try:
        from fastmcp import Context
    except ImportError:
        return kwargs.get("ctx")
    for value in kwargs.values():
        if isinstance(value, Context):
            return value
    return kwargs.get("ctx")


async def _report_progress_async(ctx: Any, progress: float, message: str, function: str) -> None:
    """Send a progress notification from an async tool. Never fails the call."""
    try:
        outcome = ctx.report_progress(progress, 100, message)
        if inspect.isawaitable(outcome):
            await outcome
    except Exception as e:
        logger.debug("progress_report_failed", function=function, progress=progress, error=str(e))


def _report_progress_sync(ctx: Any, progress: float, message: str, function: str) -> None:
    """Send a progress notification from a sync tool. Never fails the call.

    ``Context.report_progress`` is a coroutine function. FastMCP 3.x and later run a sync
    tool in an AnyIO worker thread, from which it can be run on the server's event loop.
    FastMCP 2.x runs a sync tool on the event loop's own thread, where nothing can be
    awaited, so no notification is sent there.
    """
    try:
        from anyio.from_thread import run as run_on_event_loop

        run_on_event_loop(ctx.report_progress, progress, 100, message)
    except Exception as e:
        logger.debug("progress_report_failed", function=function, progress=progress, error=str(e))


class MCPAirlock:
    """MCP-aware Airlock decorator for FastMCP tools.

    Provides the same security features as @Airlock but with MCP-specific
    enhancements:
    - A refused call raises FastMCP's ``ToolError``, so the client receives an error
      result carrying the refusal and its fix hints, for sync and async tools alike
    - Optional progress notifications at the start and end of each call

    It does not derive an agent identity from the MCP session. ``MCPContextExtractor``
    reads identifiers off a ``Context``, but ``client_id`` is whatever the client sends,
    so it is not a basis for access checks.

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
            report_progress: If True, send a progress notification (0 of 100, then 100
                of 100) at the start and end of each call, through the tool's
                FastMCP ``Context``. A client receives them only when it asked for
                progress; from a sync tool they are sent on FastMCP 3.x and later.
        """
        self.sandbox = sandbox
        self.config = config or DEFAULT_CONFIG
        self.policy = policy
        self.report_progress = report_progress

    def __call__(self, func: Callable[P, R]) -> Callable[P, R]:
        """Apply the decorator to a function."""
        # Import here to avoid circular imports
        from ..core import Airlock

        # Create base Airlock decorator
        airlock = Airlock(
            sandbox=self.sandbox,
            config=self.config,
            policy=self.policy,
            return_dict=False,  # MCP tools should return direct values
        )

        # Wrap with Airlock first
        airlocked_func = airlock(func)
        name = func.__name__
        wrapper: Callable[..., Any]

        # Until 0.10.18 an async tool got the sync wrapper below: the refusal check saw a
        # coroutine, so a refused async call returned Airlock's raw response dict, and the
        # progress coroutines were never awaited (with the message passed as ``total``).
        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
                ctx = _mcp_context(kwargs) if self.report_progress else None
                if ctx is not None:
                    await _report_progress_async(ctx, 0, f"Starting {name}...", name)

                result = await airlocked_func(*args, **kwargs)  # type: ignore[misc]
                if _is_refusal(result):
                    return _refuse(result)

                if ctx is not None:
                    await _report_progress_async(ctx, 100, f"Completed {name}", name)
                return result

            wrapper = async_wrapper
        else:

            @functools.wraps(func)
            def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
                ctx = _mcp_context(kwargs) if self.report_progress else None
                if ctx is not None:
                    _report_progress_sync(ctx, 0, f"Starting {name}...", name)

                result = airlocked_func(*args, **kwargs)
                if _is_refusal(result):
                    return _refuse(result)  # type: ignore[arg-type]

                if ctx is not None:
                    _report_progress_sync(ctx, 100, f"Completed {name}", name)
                return result

            wrapper = sync_wrapper

        # Preserve function signature for MCP/LLM framework introspection
        # FastMCP and other frameworks use inspect.signature() to generate
        # JSON schemas for tool calls
        with contextlib.suppress(ValueError, TypeError):
            wrapper.__signature__ = inspect.signature(func)  # type: ignore[union-attr]

        wrapper.__annotations__ = getattr(func, "__annotations__", {})

        return wrapper  # type: ignore[return-value]


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
        """Extract an identifier from MCP context.

        Returns the first of ``client_id``, ``session_id`` and ``request_id`` that has a
        value, or None when none does or reading one raises. A FastMCP ``Context`` has all
        three and leaves ``client_id`` None unless the client sends one; until 0.10.18 that
        None came back as the string ``"None"``. ``client_id`` is whatever the client
        sends, so do not base access checks on it.
        """
        for field_name in ("client_id", "session_id", "request_id"):
            try:
                value = getattr(ctx, field_name, None)
            except Exception as e:
                logger.debug(
                    "context_extraction_failed",
                    field=field_name,
                    error=str(e),
                )
                return None
            if value is not None and value != "":
                return str(value)
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
