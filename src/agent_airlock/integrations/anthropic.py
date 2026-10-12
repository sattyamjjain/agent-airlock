"""Anthropic Messages API integration for Agent-Airlock.

Registers tool functions for ``client.messages.create(tools=...)`` and turns the
``tool_use`` blocks of a response into the ``tool_result`` blocks of the next request,
with every call routed through ``@Airlock``.

Two things this module guarantees since 0.10.25:

* **The schema the model sees is the contract Airlock enforces.** Each tool's
  ``input_schema`` is generated from its resolved type hints by Pydantic: an ``int``
  parameter is ``"integer"``, a ``Literal`` an ``enum``, an ``Optional`` an ``anyOf``,
  ``Annotated[int, Field(ge=1)]`` carries its bounds, and a nested model lands in
  ``$defs``. Until 0.10.25 every parameter that was not one of six builtins was
  advertised as ``"string"``, so the model sent ``"5"`` and Airlock's strict validation
  refused it. An annotation that cannot be resolved or described raises
  :class:`~agent_airlock.exceptions.AirlockError` when the tool is registered.
* **A refusal reaches the model as an error.** ``process_tool_use`` returns an Airlock
  refusal as ``{"type": "tool_result", ..., "is_error": True}`` with its error and fix
  hints as text. Until 0.10.25 it was ``str(dict)`` with no ``is_error``, so the model
  read a refusal as a successful result.

The ``anthropic`` package is never imported: blocks are read by attribute or by key, so
SDK objects and plain dicts both work.
"""

from __future__ import annotations

import dataclasses
import datetime
import decimal
import enum
import functools
import inspect
import json
import re
import warnings
from collections.abc import Callable, Mapping
from pathlib import PurePath
from typing import Any, TypeVar, overload

from pydantic import BaseModel, ConfigDict, TypeAdapter
from typing_extensions import NotRequired, TypedDict, get_type_hints

from agent_airlock.config import AirlockConfig
from agent_airlock.core import Airlock
from agent_airlock.policy import SecurityPolicy
from agent_airlock.sanitizer import sanitize_output

from .._log import structlog
from ..exceptions import AirlockError
from ..self_heal import is_refusal, refusal_text

logger = structlog.get_logger("agent-airlock.integrations.anthropic")

T = TypeVar("T")

#: Content-block types a ``tool_result`` may carry as a list.
_CONTENT_BLOCK_TYPES = frozenset({"text", "image", "document", "search_result"})

_SKIPPED_PARAMETERS = ("self", "cls")

#: Typed Any so a TypedDict built at runtime is not read by mypy as a class definition.
#: ``typing_extensions``' class, because Pydantic refuses ``typing.TypedDict`` before 3.12.
_TYPED_DICT: Any = TypedDict


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

        response = client.messages.create(tools=registry.get_tool_definitions(), ...)
        results = process_message_tools(response, registry)
        # send `results` back as the content of the next user message
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

    @overload
    def tool(self, name: Callable[..., T], description: str | None = None) -> Callable[..., T]: ...

    @overload
    def tool(
        self,
        name: str | None = None,
        description: str | None = None,
    ) -> Callable[[Callable[..., T]], Callable[..., T]]: ...

    def tool(
        self,
        name: str | Callable[..., Any] | None = None,
        description: str | None = None,
    ) -> Any:
        """Register a tool function, as ``@registry.tool`` or ``@registry.tool(...)``.

        Args:
            name: Tool name (defaults to the function name). When the decorator is
                applied bare, this is the function itself.
            description: Tool description (defaults to the docstring).

        Returns:
            The Airlock-wrapped function, or a decorator that returns it.

        Raises:
            AirlockError: An annotation cannot be resolved or described by a JSON
                schema, or a parameter is positional-only, so the model could not be
                told the contract Airlock enforces.
        """
        if callable(name):
            return self._register(name, None, description)

        def decorator(func: Callable[..., T]) -> Callable[..., T]:
            return self._register(func, name, description)

        return decorator

    def _register(
        self,
        func: Callable[..., T],
        name: str | None,
        description: str | None,
    ) -> Callable[..., T]:
        tool_name = name or func.__name__
        tool_desc = description or inspect.getdoc(func) or "No description"
        definition = {
            "name": tool_name,
            "description": tool_desc,
            "input_schema": _input_schema(func, tool_name),
        }
        secured = Airlock(config=self.config, policy=self.policy, sandbox=self.sandbox)(func)
        self._tools[tool_name] = secured
        self._schemas[tool_name] = definition
        # Airlock returns T | dict, but for integration we preserve T signature
        return secured  # type: ignore[return-value]

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
        """Execute a registered tool and return what it returned, refusals included.

        Args:
            name: Tool name.
            inputs: Tool inputs.

        Returns:
            Tool result: an Airlock refusal is a dict (:func:`is_refusal`), and an async
            tool returns a coroutine.

        Raises:
            KeyError: If tool not found.
        """
        if name not in self._tools:
            raise KeyError(f"Unknown tool: {name}")

        return self._tools[name](**inputs)

    def process_tool_use(self, tool_use: Any) -> dict[str, Any]:
        """Run one ``tool_use`` block and return its ``tool_result`` block.

        Args:
            tool_use: A ``ToolUseBlock`` from the SDK, or a dict of the same shape.

        Returns:
            A ``tool_result`` block. A refusal, an unknown tool, unreadable input or an
            async tool (use :meth:`aprocess_tool_use`) comes back with
            ``"is_error": True``.

        Raises:
            AirlockError: The block has no string ``id``, so no result can address it.
        """
        tool_use_id, call = self._prepare(tool_use)
        if isinstance(call, dict):
            return call
        name, inputs = call
        result = self._call(tool_use_id, name, inputs)
        if isinstance(result, _Failed):
            return result.block
        if inspect.isawaitable(result):
            close = getattr(result, "close", None)
            if callable(close):
                close()  # never awaited, so nothing in the tool ran
            logger.warning("anthropic_async_tool_in_sync_path", tool=name, tool_use_id=tool_use_id)
            return _error_block(
                tool_use_id,
                f"AIRLOCK_BLOCK: tool {name!r} is async and was not run. The caller must use "
                "ToolRegistry.aprocess_tool_use (or aprocess_message_tools) for it.",
            )
        return _result_block(tool_use_id, result)

    async def aprocess_tool_use(self, tool_use: Any) -> dict[str, Any]:
        """Like :meth:`process_tool_use`, awaiting an async tool's result.

        Args:
            tool_use: A ``ToolUseBlock`` from the SDK, or a dict of the same shape.

        Returns:
            A ``tool_result`` block, as :meth:`process_tool_use` describes.

        Raises:
            AirlockError: The block has no string ``id``.
        """
        tool_use_id, call = self._prepare(tool_use)
        if isinstance(call, dict):
            return call
        name, inputs = call
        result = self._call(tool_use_id, name, inputs)
        if isinstance(result, _Failed):
            return result.block
        if inspect.isawaitable(result):
            try:
                result = await result
            except Exception as exc:  # noqa: BLE001 - reported to the model, never raised
                return _call_failed(tool_use_id, name, exc)
        return _result_block(tool_use_id, result)

    def _prepare(self, tool_use: Any) -> tuple[str, tuple[str, dict[str, Any]] | dict[str, Any]]:
        """``(tool_use_id, (name, inputs))``, or ``(tool_use_id, error_block)``."""
        tool_use_id = _field(tool_use, "id")
        if not isinstance(tool_use_id, str) or not tool_use_id:
            raise AirlockError("tool_use block has no string 'id'; no tool_result can address it")
        name = _field(tool_use, "name")
        if not isinstance(name, str):
            return tool_use_id, _error_block(tool_use_id, "AIRLOCK_BLOCK: tool_use has no name")
        inputs = _field(tool_use, "input")
        if inputs is None:
            inputs = {}
        if not isinstance(inputs, Mapping) or not all(isinstance(k, str) for k in inputs):
            return tool_use_id, _error_block(
                tool_use_id,
                f"AIRLOCK_BLOCK: the input to tool {name!r} must be an object with string keys",
            )
        if name not in self._tools:
            registered = ", ".join(sorted(self._tools)) or "none"
            logger.warning("anthropic_unknown_tool", tool=name, tool_use_id=tool_use_id)
            return tool_use_id, _error_block(
                tool_use_id,
                f"AIRLOCK_BLOCK: unknown tool {name!r}. Registered tools: {registered}",
            )
        return tool_use_id, (name, dict(inputs))

    def _call(self, tool_use_id: str, name: str, inputs: dict[str, Any]) -> Any:
        try:
            return self._tools[name](**inputs)
        except Exception as exc:  # noqa: BLE001 - reported to the model, never raised
            return _Failed(_call_failed(tool_use_id, name, exc))


@dataclasses.dataclass(frozen=True)
class _Failed:
    """A call that raised outside Airlock's own handling, already rendered."""

    block: dict[str, Any]


def _call_failed(tool_use_id: str, name: str, exc: Exception) -> dict[str, Any]:
    # The exception text stays in the log: it can carry what the model must not see.
    logger.error(
        "tool_execution_error", tool=name, tool_use_id=tool_use_id, error=type(exc).__name__
    )
    return _error_block(tool_use_id, f"AIRLOCK_BLOCK: tool {name!r} failed ({type(exc).__name__})")


def _field(block: Any, key: str) -> Any:
    """``block[key]`` for a mapping, ``block.key`` for an SDK object."""
    if isinstance(block, Mapping):
        return block.get(key)
    return getattr(block, key, None)


def _error_block(tool_use_id: str, text: str) -> dict[str, Any]:
    return {"type": "tool_result", "tool_use_id": tool_use_id, "content": text, "is_error": True}


def _result_block(tool_use_id: str, result: Any) -> dict[str, Any]:
    if is_refusal(result):
        return _error_block(tool_use_id, refusal_text(result))
    return {"type": "tool_result", "tool_use_id": tool_use_id, "content": _content(result)}


def _is_content_block(block: Any) -> bool:
    if not isinstance(block, Mapping) or block.get("type") not in _CONTENT_BLOCK_TYPES:
        return False
    return block.get("type") != "text" or isinstance(block.get("text"), str)


def _content(result: Any) -> str | list[Any]:
    """A tool's return value as ``tool_result`` content.

    A string is sent as it is; a non-empty list of content blocks (text, image,
    document, search result) passes through; anything else is JSON.
    """
    if isinstance(result, str):
        return result
    if isinstance(result, list | tuple) and result and all(map(_is_content_block, result)):
        return list(result)
    return json.dumps(result, default=_json_default, ensure_ascii=False)


def _json_default(value: Any) -> Any:
    """What ``json.dumps`` cannot encode on its own, as something it can."""
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return dataclasses.asdict(value)
    if isinstance(value, set | frozenset):
        return sorted(value, key=repr)
    if isinstance(value, datetime.date | datetime.time):
        return value.isoformat()
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, decimal.Decimal | PurePath):
        return str(value)
    if isinstance(value, bytes | bytearray):
        return bytes(value).decode("utf-8", errors="replace")
    return str(value)


def _input_schema(func: Callable[..., Any], name: str) -> dict[str, Any]:
    """The JSON schema of ``func``'s parameters, from its resolved type hints.

    Raises:
        AirlockError: An annotation cannot be resolved or described, or a parameter is
            positional-only (a keyword call cannot pass it).
    """
    hints = _resolved_hints(func, name)
    fields: dict[str, Any] = {}
    defaults: dict[str, Any] = {}
    open_ended = False
    for pname, param in inspect.signature(func).parameters.items():
        if pname in _SKIPPED_PARAMETERS or param.kind is param.VAR_POSITIONAL:
            continue
        if param.kind is param.VAR_KEYWORD:
            open_ended = True
            continue
        if param.kind is param.POSITIONAL_ONLY:
            raise AirlockError(
                f"tool {name!r}: parameter {pname!r} is positional-only, and a tool call "
                "passes every argument by name"
            )
        annotation = hints.get(pname, Any)
        if param.default is inspect.Parameter.empty:
            fields[pname] = annotation
        else:
            fields[pname] = NotRequired[annotation]
            defaults[pname] = param.default

    schema = _typed_dict_schema(name, fields, open_ended)
    schema.pop("title", None)
    properties = schema.setdefault("properties", {})
    for pname, default in defaults.items():
        if _json_encodable(default) and isinstance(properties.get(pname), dict):
            properties[pname]["default"] = default
    schema.setdefault("type", "object")
    return schema


def _resolved_hints(func: Callable[..., Any], name: str) -> dict[str, Any]:
    """``func``'s annotations, resolved against the module that defines it.

    A ``functools.partial`` is read through to the function it wraps, and a callable
    object through its class's ``__call__``.

    Raises:
        AirlockError: An annotation names something that cannot be found.
    """
    target: Any = func
    while isinstance(target, functools.partial):
        target = target.func
    if not (inspect.isfunction(target) or inspect.ismethod(target)) and callable(target):
        target = type(target).__call__
    try:
        return get_type_hints(target, include_extras=True)
    except Exception as exc:
        qualname = getattr(target, "__qualname__", repr(target))
        raise AirlockError(
            f"tool {name!r}: cannot resolve the annotations of {qualname} ({exc}). "
            "Define the types it names at module level, where they can be found."
        ) from exc


def _typed_dict_schema(name: str, fields: dict[str, Any], open_ended: bool) -> dict[str, Any]:
    """Pydantic's JSON schema of a TypedDict holding ``fields``."""
    typed = _TYPED_DICT(re.sub(r"\W", "_", name) + "_input", fields)
    if not open_ended:
        # Airlock strips or refuses an argument the signature does not declare, so the
        # schema says so instead of inviting it.
        typed.__pydantic_config__ = ConfigDict(extra="forbid")
    try:
        return dict(TypeAdapter(typed).json_schema())
    except Exception as exc:
        culprit = next((pname for pname, tp in fields.items() if not _describable(tp)), "<unknown>")
        raise AirlockError(
            f"tool {name!r}: parameter {culprit!r} has an annotation no JSON schema can "
            f"describe ({type(exc).__name__}: {exc})"
        ) from exc


def _describable(tp: Any) -> bool:
    try:
        TypeAdapter(tp).json_schema()
    except Exception:  # noqa: BLE001 - only locating the parameter to name
        return False
    return True


def _json_encodable(value: Any) -> bool:
    try:
        json.dumps(value)
    except (TypeError, ValueError):
        return False
    return True


def _sanitize_content(content: Any) -> Any:
    """Mask PII and secrets in a ``tool_result``'s text, whatever its shape."""
    if isinstance(content, str):
        return sanitize_output(content).content
    if isinstance(content, list):
        return [_sanitize_block(block) for block in content]
    return content


def _sanitize_block(block: Any) -> Any:
    if not isinstance(block, Mapping):
        return block
    if block.get("type") == "text" and isinstance(block.get("text"), str):
        return {**block, "text": sanitize_output(block["text"]).content}
    if block.get("type") == "search_result" and isinstance(block.get("content"), list):
        return {**block, "content": [_sanitize_block(inner) for inner in block["content"]]}
    return block


def _tool_use_blocks(message: Any) -> list[Any]:
    content = _field(message, "content") or []
    return [block for block in content if _field(block, "type") == "tool_use"]


def process_message_tools(
    message: Any,
    registry: ToolRegistry,
    should_sanitize: bool = True,
) -> list[dict[str, Any]]:
    """Process every ``tool_use`` block in a message.

    Args:
        message: An SDK ``Message``, or a dict with a ``content`` list.
        registry: Tool registry to use.
        should_sanitize: Whether to mask PII and secrets in each result's text.

    Returns:
        The ``tool_result`` blocks, in order, for the next user message.
    """
    results = []
    for block in _tool_use_blocks(message):
        result = registry.process_tool_use(block)
        if should_sanitize:
            result["content"] = _sanitize_content(result.get("content"))
        results.append(result)
    return results


async def aprocess_message_tools(
    message: Any,
    registry: ToolRegistry,
    should_sanitize: bool = True,
) -> list[dict[str, Any]]:
    """Like :func:`process_message_tools`, awaiting async tools.

    Args:
        message: An SDK ``Message``, or a dict with a ``content`` list.
        registry: Tool registry to use.
        should_sanitize: Whether to mask PII and secrets in each result's text.

    Returns:
        The ``tool_result`` blocks, in order, for the next user message.
    """
    results = []
    for block in _tool_use_blocks(message):
        result = await registry.aprocess_tool_use(block)
        if should_sanitize:
            result["content"] = _sanitize_content(result.get("content"))
        results.append(result)
    return results


class SecureAnthropicClient:
    """Wrapper around Anthropic client that adds the registry's tool definitions.

    Usage:
        from anthropic import Anthropic
        client = SecureAnthropicClient(Anthropic(), registry)
        response = client.messages.create(...)
        results = process_message_tools(response, registry)

    Tool calls in a response are not run automatically: pass each response to
    :func:`process_message_tools` (or :func:`aprocess_message_tools`).
    """

    def __init__(
        self,
        client: Any,
        registry: ToolRegistry,
        auto_process_tools: bool | None = None,
    ) -> None:
        """Initialize secure client wrapper.

        Args:
            client: Anthropic client instance.
            registry: Tool registry.
            auto_process_tools: Deprecated, removal in v1.0.0. Nothing has ever applied
                it; passing it emits a ``FutureWarning``.
        """
        if auto_process_tools is not None:
            warnings.warn(
                "SecureAnthropicClient(auto_process_tools=...) is deprecated and will be "
                "removed in v1.0.0. Nothing has ever applied it: tool calls in a response "
                "are not run automatically; pass each response to process_message_tools "
                "(or aprocess_message_tools).",
                FutureWarning,
                stacklevel=2,
            )
        self._client = client
        self.registry = registry
        self.auto_process_tools = True if auto_process_tools is None else auto_process_tools

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
