"""Anthropic SDK integration for Agent-Airlock.

Provides Anthropic-specific tool call handling and message processing
for the official Anthropic Python SDK.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any, TypeVar

import structlog

from agent_airlock.config import AirlockConfig
from agent_airlock.core import Airlock
from agent_airlock.policy import SecurityPolicy
from agent_airlock.sanitizer import sanitize_output

if TYPE_CHECKING:
    pass

logger = structlog.get_logger("agent-airlock.integrations.anthropic")

T = TypeVar("T")


def secure_tool(
    config: AirlockConfig | None = None,
    policy: SecurityPolicy | None = None,
    sandbox: bool = False,
    **airlock_kwargs: Any,
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Decorator for securing Anthropic tool functions.

    Usage:
        @secure_tool(policy=STRICT_POLICY)
        def get_weather(location: str) -> str:
            return f"Weather in {location}: Sunny"

    Args:
        config: Airlock configuration.
        policy: Security policy.
        sandbox: Whether to run in sandbox.
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


class ToolRegistry:
    """Registry for Anthropic tool functions with Airlock security.

    Usage:
        registry = ToolRegistry(policy=STRICT_POLICY)

        @registry.tool
        def get_weather(location: str) -> str:
            '''Get weather for a location.'''
            return f"Weather in {location}: Sunny"

        # Get tool definitions for API
        tools = registry.get_tool_definitions()

        # Execute a tool from API response
        result = registry.execute_tool("get_weather", {"location": "NYC"})
    """

    def __init__(
        self,
        config: AirlockConfig | None = None,
        policy: SecurityPolicy | None = None,
        sandbox: bool = False,
    ) -> None:
        self.config = config or AirlockConfig()
        self.policy = policy
        self.sandbox = sandbox
        self._tools: dict[str, Callable[..., Any]] = {}
        self._schemas: dict[str, dict[str, Any]] = {}

    def tool(
        self,
        name: str | None = None,
        description: str | None = None,
    ) -> Callable[[Callable[..., T]], Callable[..., T]]:
        """Decorator to register a tool function.

        Args:
            name: Tool name (defaults to function name).
            description: Tool description (defaults to docstring).

        Returns:
            Decorator function.
        """

        def decorator(func: Callable[..., T]) -> Callable[..., T]:
            tool_name = name or func.__name__
            tool_desc = description or func.__doc__ or "No description"

            # Wrap with Airlock
            secured = Airlock(
                config=self.config,
                policy=self.policy,
                sandbox=self.sandbox,
            )(func)

            # Register tool
            self._tools[tool_name] = secured
            self._schemas[tool_name] = self._generate_schema(func, tool_name, tool_desc)

            # Airlock returns T | dict, but for integration we preserve T signature
            return secured  # type: ignore[return-value]

        return decorator

    def _generate_schema(
        self,
        func: Callable[..., Any],
        name: str,
        description: str,
    ) -> dict[str, Any]:
        """Generate Anthropic tool schema from function signature."""
        import inspect

        sig = inspect.signature(func)
        hints = func.__annotations__

        properties: dict[str, Any] = {}
        required: list[str] = []

        for param_name, param in sig.parameters.items():
            if param_name in ("self", "cls"):
                continue

            param_type = hints.get(param_name, Any)
            json_type = self._python_type_to_json(param_type)

            properties[param_name] = {"type": json_type}

            if param.default is inspect.Parameter.empty:
                required.append(param_name)

        return {
            "name": name,
            "description": description,
            "input_schema": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
        }

    def _python_type_to_json(self, python_type: type) -> str:
        """Convert Python type to JSON schema type."""
        type_map = {
            str: "string",
            int: "integer",
            float: "number",
            bool: "boolean",
            list: "array",
            dict: "object",
        }

        # Handle generic types
        origin = getattr(python_type, "__origin__", None)
        if origin is not None:
            python_type = origin

        return type_map.get(python_type, "string")

    def get_tool_definitions(self) -> list[dict[str, Any]]:
        """Get tool definitions for Anthropic API.

        Returns:
            List of tool definitions for messages.create().
        """
        return list(self._schemas.values())

    def execute_tool(
        self,
        name: str,
        inputs: dict[str, Any],
    ) -> Any:
        """Execute a registered tool.

        Args:
            name: Tool name.
            inputs: Tool inputs.

        Returns:
            Tool result.

        Raises:
            KeyError: If tool not found.
        """
        if name not in self._tools:
            raise KeyError(f"Unknown tool: {name}")

        return self._tools[name](**inputs)

    def process_tool_use(
        self,
        tool_use: Any,
    ) -> dict[str, Any]:
        """Process a ToolUseBlock from API response.

        Args:
            tool_use: ToolUseBlock from Anthropic API.

        Returns:
            Tool result formatted for tool_result message.
        """
        try:
            result = self.execute_tool(tool_use.name, tool_use.input)
            return {
                "type": "tool_result",
                "tool_use_id": tool_use.id,
                "content": str(result),
            }
        except Exception as e:
            logger.error("tool_execution_error", tool=tool_use.name, error=str(e))
            return {
                "type": "tool_result",
                "tool_use_id": tool_use.id,
                "content": f"Error: {e}",
                "is_error": True,
            }


def process_message_tools(
    message: Any,
    registry: ToolRegistry,
    should_sanitize: bool = True,
) -> list[dict[str, Any]]:
    """Process all tool use blocks in a message.

    Args:
        message: Anthropic Message object.
        registry: Tool registry to use.
        should_sanitize: Whether to sanitize tool outputs.

    Returns:
        List of tool_result content blocks.
    """
    results = []

    for block in message.content:
        if block.type == "tool_use":
            result = registry.process_tool_use(block)

            if should_sanitize and "content" in result:
                sanitized = sanitize_output(result["content"])
                result["content"] = sanitized.content

            results.append(result)

    return results


class SecureAnthropicClient:
    """Wrapper around Anthropic client with automatic tool security.

    Usage:
        from anthropic import Anthropic
        client = SecureAnthropicClient(Anthropic(), registry)
        response = client.messages.create(...)
    """

    def __init__(
        self,
        client: Any,
        registry: ToolRegistry,
        auto_process_tools: bool = True,
    ) -> None:
        """Initialize secure client wrapper.

        Args:
            client: Anthropic client instance.
            registry: Tool registry.
            auto_process_tools: Auto-process tool calls in responses.
        """
        self._client = client
        self.registry = registry
        self.auto_process_tools = auto_process_tools

    @property
    def messages(self) -> SecureMessages:
        """Get messages interface."""
        return SecureMessages(self)


class SecureMessages:
    """Secure messages interface."""

    def __init__(self, secure_client: SecureAnthropicClient) -> None:
        self._secure_client = secure_client

    def create(self, **kwargs: Any) -> Any:
        """Create a message with automatic tool definitions.

        Automatically adds registered tools if not specified.
        """
        if "tools" not in kwargs and self._secure_client.registry._tools:
            kwargs["tools"] = self._secure_client.registry.get_tool_definitions()

        return self._secure_client._client.messages.create(**kwargs)
