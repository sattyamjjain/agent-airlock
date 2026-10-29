"""LangChain integration for Agent-Airlock.

Provides LangChain-specific decorators, tool wrappers, and
callback handlers for seamless security integration.

:func:`wrap_langchain_tool` guards every callable LangChain runs a tool through, with one
``Airlock`` built for the tool: ``func`` and ``coroutine`` on a ``StructuredTool`` /
``Tool``, whose ``_run`` / ``_arun`` hand off to them, and ``_run`` and an overridden
``_arun`` on a ``BaseTool`` subclass. Until 0.10.28 only the sync callable was guarded, so
``.ainvoke`` ran an ``async`` tool, a ``StructuredTool``'s ``coroutine`` and a subclass's
``_arun`` with no check at all (verified on langchain-core 1.7.1 under a deny-all policy).
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from typing import Any, TypeVar

from agent_airlock.config import AirlockConfig
from agent_airlock.core import Airlock
from agent_airlock.policy import SecurityPolicy

from .._log import structlog
from ..exceptions import AirlockError
from ._tool_proxy import already_guarded, mark_guarded, named_tool_proxy

logger = structlog.get_logger("agent-airlock.integrations.langchain")

T = TypeVar("T")

#: The parameters LangChain fills itself and removes from a tool's argument schema
#: (``langchain_core.tools.FILTERED_ARGS``). The model never supplies them; they carry
#: callback managers, which have no Pydantic schema, so they are not strictly validated.
#: LangChain finds them by name, so relaxing their annotation changes nothing it reads.
_LANGCHAIN_FILLED_PARAMS: tuple[str, ...] = ("run_manager", "callbacks")


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
    """Wrap an existing LangChain tool with Airlock security, in place.

    Every callable LangChain runs the tool through is replaced by a guarded one, all
    built from one ``Airlock``: ``func`` and ``coroutine`` on a ``StructuredTool`` or
    ``Tool``, ``_run`` and an overridden ``_arun`` on a ``BaseTool`` subclass. So
    ``.invoke``, ``.ainvoke``, ``.run`` and ``.arun`` are all checked. Policy lists match
    the tool's ``name`` (the name the model calls), not the callable's own name.

    Wrapping is idempotent per callable: one already guarded with the same ``config``,
    ``policy`` and ``sandbox`` is left alone, so wrapping a tool twice still costs one audit
    record and one rate-limit token per call. One guarded with other settings is wrapped
    again, with a warning, so both apply: until the 0.10.28 review only the policy was
    compared, and a second wrap asking for a sandbox or for masking was skipped silently.

    Args:
        tool: LangChain BaseTool instance.
        config: Airlock configuration.
        policy: Security policy.
        sandbox: Whether to use sandbox execution.

    Returns:
        The same tool, its callables guarded.

    Raises:
        TypeError: ``tool`` is not a LangChain ``BaseTool``.
        AirlockError: The tool exposes no callable LangChain could run it through.
    """
    try:
        from langchain_core.tools import BaseTool
    except ImportError:
        logger.warning("langchain_not_installed")
        return tool

    if not isinstance(tool, BaseTool):
        raise TypeError(f"Expected BaseTool, got {type(tool)}")

    name = str(getattr(tool, "name", "") or type(tool).__name__)
    entry_points = _entry_points(tool)
    if not entry_points:
        raise AirlockError(
            f"LangChain tool {name!r} has no func, coroutine or _run to guard; cannot wrap"
        )

    airlock = Airlock(config=config, policy=policy, sandbox=sandbox)
    settings = (policy, config, sandbox)
    guarded = 0
    for attr, forward in entry_points:
        if already_guarded(forward, *settings, tool=name):
            continue
        # setattr: the attribute is a pydantic field (func, coroutine) or a method shadowed
        # on the instance (_run, _arun), which static analysis would otherwise flag.
        setattr(tool, attr, _guard(forward, name=name, airlock=airlock, settings=settings))  # noqa: B010
        guarded += 1

    logger.debug(
        "langchain_tool_wrapped",
        tool=name,
        entry_points=[attr for attr, _ in entry_points],
        newly_guarded=guarded,
    )
    return tool


def _entry_points(tool: Any) -> list[tuple[str, Callable[..., Any]]]:
    """The attributes holding the callables LangChain runs ``tool`` through.

    ``BaseTool.run`` calls ``_run`` and ``BaseTool.arun`` calls ``_arun``. A
    ``StructuredTool`` / ``Tool`` implements those by calling ``func`` and ``coroutine``
    (``_arun`` falls back to ``_run`` when there is no ``coroutine``), so those two are
    guarded; on any other class ``_run`` and, when the class overrides it, ``_arun`` are.
    ``BaseTool._arun`` itself only hands ``_run`` to a thread, which is already guarded.
    """
    from langchain_core.tools import BaseTool

    dispatchers = _dispatching_classes()
    cls = type(tool)
    points: list[tuple[str, Callable[..., Any]]] = []

    if getattr(cls, "_run", None) in {getattr(each, "_run", None) for each in dispatchers}:
        func = getattr(tool, "func", None)
        if callable(func):
            points.append(("func", func))
    else:
        points.append(("_run", tool._run))

    class_arun = getattr(cls, "_arun", None)
    if class_arun in {getattr(each, "_arun", None) for each in dispatchers}:
        coroutine = getattr(tool, "coroutine", None)
        if callable(coroutine):
            points.append(("coroutine", coroutine))
    elif class_arun is not getattr(BaseTool, "_arun", None):
        points.append(("_arun", tool._arun))
    return points


def _dispatching_classes() -> tuple[type, ...]:
    """LangChain's tool classes whose ``_run`` / ``_arun`` call ``func`` / ``coroutine``."""
    import langchain_core.tools as lc_tools

    return tuple(
        cls
        for cls in (getattr(lc_tools, "StructuredTool", None), getattr(lc_tools, "Tool", None))
        if isinstance(cls, type)
    )


def _guard(
    forward: Callable[..., Any],
    *,
    name: str,
    airlock: Airlock,
    settings: tuple[object, ...],
) -> Callable[..., Any]:
    """``forward`` behind ``airlock``, re-tagged with the tool's name and contract.

    The proxy carries ``forward``'s signature, so ``Airlock`` validates the tool's own
    parameters, and is async exactly when ``forward`` is, so an ``async`` tool gets the
    async wrapper (awaited, then audited and sanitised). LangChain still finds what it
    injects by name (``run_manager``, ``callbacks``) or by type (a ``RunnableConfig``
    parameter keeps its annotation).
    """
    proxy = named_tool_proxy(forward, name=name, relaxed_params=_filled_params(forward))
    guarded: Callable[..., Any] = airlock(proxy)
    mark_guarded(guarded, *settings)
    return guarded


def _filled_params(forward: Callable[..., Any]) -> frozenset[str]:
    """``forward``'s parameters that LangChain fills itself (see ``FILTERED_ARGS``)."""
    try:
        from langchain_core.tools import FILTERED_ARGS

        filled = tuple(FILTERED_ARGS)
    except ImportError:  # an SDK without the constant: fall back to its 1.x value
        filled = _LANGCHAIN_FILLED_PARAMS
    try:
        parameters = inspect.signature(forward).parameters
    except (TypeError, ValueError):
        return frozenset()  # named_tool_proxy refuses a callable with no readable signature
    return frozenset(name for name in parameters if name in filled)


def create_secure_tool(
    func: Callable[..., T],
    name: str | None = None,
    description: str | None = None,
    config: AirlockConfig | None = None,
    policy: SecurityPolicy | None = None,
    sandbox: bool = False,
) -> Any:
    """Create a LangChain tool with Airlock security built-in.

    An ``async def`` function becomes the tool's ``coroutine``, so ``.ainvoke`` awaits the
    guarded call and returns its result; a plain function becomes its ``func``. Until
    0.10.28 an async function was passed as ``func``, and ``.ainvoke`` returned the
    un-awaited coroutine. Policy lists match the tool's name (``name``, else the
    function's name).

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

    tool_name = name or func.__name__
    airlock = Airlock(config=config, policy=policy, sandbox=sandbox)
    secured = _guard(func, name=tool_name, airlock=airlock, settings=(policy, config, sandbox))
    callable_kind = "coroutine" if inspect.iscoroutinefunction(secured) else "func"

    return StructuredTool.from_function(
        name=tool_name,
        description=description or func.__doc__ or "No description",
        **{callable_kind: secured},
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
