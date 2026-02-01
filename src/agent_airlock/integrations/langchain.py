"""LangChain integration for Agent-Airlock.

Provides LangChain-specific decorators, tool wrappers, and
callback handlers for seamless security integration.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, TypeVar

import structlog

from agent_airlock.config import AirlockConfig
from agent_airlock.core import Airlock
from agent_airlock.policy import SecurityPolicy

if TYPE_CHECKING:
    pass

logger = structlog.get_logger("agent-airlock.integrations.langchain")

T = TypeVar("T")


def secure_tool(
    config: AirlockConfig | None = None,
    policy: SecurityPolicy | None = None,
    sandbox: bool = False,
    **airlock_kwargs: Any,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Decorator factory for securing LangChain tools with Airlock.

    This decorator should be applied AFTER the @tool decorator:

        @tool
        @secure_tool(policy=STRICT_POLICY)
        def my_tool(arg: str) -> str:
            return f"Result: {arg}"

    Args:
        config: Airlock configuration.
        policy: Security policy to apply.
        sandbox: Whether to run in E2B sandbox.
        **airlock_kwargs: Additional Airlock arguments.

    Returns:
        Decorator function.
    """

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        # Airlock returns T | dict, but for integration purposes we preserve T signature
        return Airlock(
            config=config,
            policy=policy,
            sandbox=sandbox,
            **airlock_kwargs,
        )(func)  # type: ignore[return-value]

    return decorator


class AirlockCallbackHandler:
    """LangChain callback handler for Airlock monitoring.

    Tracks tool invocations and integrates with Airlock's audit logging.

    Usage:
        from langchain_core.callbacks import CallbackManager
        handler = AirlockCallbackHandler()
        callback_manager = CallbackManager([handler])
    """

    def __init__(
        self,
        config: AirlockConfig | None = None,
        log_inputs: bool = False,
        log_outputs: bool = False,
    ) -> None:
        """Initialize callback handler.

        Args:
            config: Airlock configuration.
            log_inputs: Whether to log tool inputs.
            log_outputs: Whether to log tool outputs.
        """
        self.config = config or AirlockConfig()
        self.log_inputs = log_inputs
        self.log_outputs = log_outputs

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        """Called when a tool starts executing."""
        tool_name = serialized.get("name", "unknown")
        logger.info(
            "langchain_tool_start",
            tool=tool_name,
            input_preview=input_str[:100] if self.log_inputs else "[redacted]",
        )

    def on_tool_end(
        self,
        output: str,
        **kwargs: Any,
    ) -> None:
        """Called when a tool finishes executing."""
        logger.info(
            "langchain_tool_end",
            output_preview=output[:100] if self.log_outputs else "[redacted]",
        )

    def on_tool_error(
        self,
        error: Exception | KeyboardInterrupt,
        **kwargs: Any,
    ) -> None:
        """Called when a tool errors."""
        logger.error(
            "langchain_tool_error",
            error=str(error),
            error_type=type(error).__name__,
        )


def wrap_langchain_tool(
    tool: Any,
    config: AirlockConfig | None = None,
    policy: SecurityPolicy | None = None,
    sandbox: bool = False,
) -> Any:
    """Wrap an existing LangChain tool with Airlock security.

    Args:
        tool: LangChain BaseTool instance.
        config: Airlock configuration.
        policy: Security policy.
        sandbox: Whether to use sandbox execution.

    Returns:
        Wrapped tool with Airlock security.
    """
    try:
        from langchain_core.tools import BaseTool
    except ImportError:
        logger.warning("langchain_not_installed")
        return tool

    if not isinstance(tool, BaseTool):
        raise TypeError(f"Expected BaseTool, got {type(tool)}")

    # Wrap the tool's function
    airlock = Airlock(config=config, policy=policy, sandbox=sandbox)

    if hasattr(tool, "func") and tool.func is not None:
        original_func = tool.func
        tool.func = airlock(original_func)
    elif hasattr(tool, "_run"):
        original_run = tool._run

        @functools.wraps(original_run)
        def secured_run(*args: Any, **kwargs: Any) -> Any:
            return airlock(original_run)(*args, **kwargs)

        tool._run = secured_run  # type: ignore[method-assign]

    return tool


def create_secure_tool(
    func: Callable[..., T],
    name: str | None = None,
    description: str | None = None,
    config: AirlockConfig | None = None,
    policy: SecurityPolicy | None = None,
    sandbox: bool = False,
) -> Any:
    """Create a LangChain tool with Airlock security built-in.

    Args:
        func: The function to convert to a tool.
        name: Tool name (defaults to function name).
        description: Tool description (defaults to docstring).
        config: Airlock configuration.
        policy: Security policy.
        sandbox: Whether to use sandbox execution.

    Returns:
        LangChain StructuredTool with Airlock security.
    """
    try:
        from langchain_core.tools import StructuredTool
    except ImportError as e:
        raise ImportError("langchain-core is required: pip install langchain-core") from e

    # Wrap with Airlock first
    secured_func = Airlock(config=config, policy=policy, sandbox=sandbox)(func)

    return StructuredTool.from_function(
        func=secured_func,
        name=name or func.__name__,
        description=description or func.__doc__ or "No description",
    )


class SecureToolkit:
    """A toolkit that wraps all tools with Airlock security.

    Usage:
        toolkit = SecureToolkit(policy=STRICT_POLICY)
        tools = toolkit.wrap_tools(my_toolkit.get_tools())
    """

    def __init__(
        self,
        config: AirlockConfig | None = None,
        policy: SecurityPolicy | None = None,
        sandbox: bool = False,
    ) -> None:
        self.config = config
        self.policy = policy
        self.sandbox = sandbox

    def wrap_tools(self, tools: list[Any]) -> list[Any]:
        """Wrap a list of tools with Airlock security.

        Args:
            tools: List of LangChain tools.

        Returns:
            List of secured tools.
        """
        return [
            wrap_langchain_tool(
                tool,
                config=self.config,
                policy=self.policy,
                sandbox=self.sandbox,
            )
            for tool in tools
        ]

    def create_tool(
        self,
        func: Callable[..., T],
        name: str | None = None,
        description: str | None = None,
    ) -> Any:
        """Create a new secured tool.

        Args:
            func: Function to convert to tool.
            name: Tool name.
            description: Tool description.

        Returns:
            Secured LangChain tool.
        """
        return create_secure_tool(
            func,
            name=name,
            description=description,
            config=self.config,
            policy=self.policy,
            sandbox=self.sandbox,
        )
