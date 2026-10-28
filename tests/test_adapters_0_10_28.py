"""Regressions for 0.10.28: framework adapters guard every entry point, exactly once.

- F-F1  LangChain: ``wrap_langchain_tool`` guarded only the sync callable, so ``.ainvoke``
  ran an ``async`` tool, a ``StructuredTool``'s ``coroutine`` and a ``BaseTool``
  subclass's ``_arun`` under a deny-all policy (verified on langchain-core 1.7.1), and
  ``create_secure_tool(async_fn).ainvoke`` returned an un-awaited coroutine.
- F-F2  PydanticAI: the walker skipped every toolset without its own ``tools`` (prefixed,
  filtered, renamed, combined, dynamic, run-time) in silence, and their tools ran under a
  deny-all policy (verified on pydantic-ai 2.63.0).
- F-F3  Walker idempotency: ``pydantic_ai``, ``google_adk`` and the Claude Agent SDK
  adapter stacked a second Airlock layer when wrapping twice (two audit records and two
  rate-limit tokens per call, so a ``1/hour`` tool was refused on its first call).
- F-F4  OpenAI Agents SDK: ``AirlockGuardrails.wrap_agent`` appended plain functions the
  SDK cannot run (every ``Runner.run`` crashed); ``PolicyGuardrail.check`` ignored rate
  limits and allowed a time window it could not parse.
- F-F5  CrewAI: tools CrewAI adds at run time (delegation, ``agent.mcps``, the skill
  loader...) ran outside Airlock, in a crew and in ``Agent.kickoff`` (verified on crewai
  1.15.22).
- F-F7 / D-F6  The PydanticAI pin in its module docstring, and the Model Armor install hint.

CI installs no agent SDK, so each adapter is driven by stubs that mirror the SDK's own
call path (``tests/integrations/CLAUDE.md`` "Tests"); every case was also run against the
real SDK for the release.
"""

from __future__ import annotations

import asyncio
import importlib.machinery
import inspect
import re
import sys
import types
import warnings
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from agent_airlock.policy import SecurityPolicy

_DENY_ALL = SecurityPolicy(denied_tools=["*"])


def _blocked(result: Any) -> bool:
    return isinstance(result, dict) and result.get("status") == "blocked"


def _one_per_hour() -> SecurityPolicy:
    """A fresh policy whose first call is allowed and second refused (one token)."""
    return SecurityPolicy(rate_limits={"*": "1/hour"})


# ---------------------------------------------------------------------------------------
# LangChain stubs: mirror langchain-core 1.7.1's BaseTool / StructuredTool dispatch.
# ---------------------------------------------------------------------------------------


class _RunManager:
    """Stands in for ``CallbackManagerForToolRun``: no Pydantic schema."""

    def get_child(self) -> str:
        return "child-callbacks"

    def get_sync(self) -> _RunManager:
        return self


def _params(fn: Callable[..., Any]) -> Any:
    return inspect.signature(fn).parameters  # langchain's _signature_parameters


class _LCBaseTool:
    """``BaseTool``: ``invoke`` -> ``run`` -> ``_run``; ``ainvoke`` -> ``arun`` -> ``_arun``."""

    name = "tool"

    def __init__(self, name: str | None = None) -> None:
        if name is not None:
            self.name = name

    def _run(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError

    async def _arun(self, *args: Any, **kwargs: Any) -> Any:
        # BaseTool._arun hands the sync path to a worker thread.
        if kwargs.get("run_manager") and "run_manager" in _params(self._run):
            kwargs["run_manager"] = kwargs["run_manager"].get_sync()
        return await asyncio.to_thread(self._run, *args, **kwargs)

    def invoke(self, tool_input: dict[str, Any]) -> Any:
        kwargs = dict(tool_input)
        if "run_manager" in _params(self._run):
            kwargs["run_manager"] = _RunManager()
        return self._run(**kwargs)

    async def ainvoke(self, tool_input: dict[str, Any]) -> Any:
        own_arun = type(self)._arun is not _LCBaseTool._arun
        func_to_check = self._arun if own_arun else self._run
        kwargs = dict(tool_input)
        if "run_manager" in _params(func_to_check):
            kwargs["run_manager"] = _RunManager()
        return await self._arun(**kwargs)


class _LCStructuredTool(_LCBaseTool):
    """``StructuredTool``: ``_run`` calls ``func``, ``_arun`` calls ``coroutine``."""

    def __init__(
        self,
        name: str,
        func: Callable[..., Any] | None = None,
        coroutine: Callable[..., Any] | None = None,
        description: str = "",
    ) -> None:
        super().__init__(name)
        self.func = func
        self.coroutine = coroutine
        self.description = description

    @classmethod
    def from_function(
        cls,
        func: Callable[..., Any] | None = None,
        coroutine: Callable[..., Any] | None = None,
        name: str | None = None,
        description: str | None = None,
    ) -> _LCStructuredTool:
        source = func or coroutine
        if source is None:
            raise ValueError("Function and/or coroutine must be provided")
        return cls(name or source.__name__, func, coroutine, description or "")

    async def ainvoke(self, tool_input: dict[str, Any]) -> Any:
        if not self.coroutine:  # no async version: run the sync path in a thread
            return await asyncio.to_thread(self.invoke, tool_input)
        return await super().ainvoke(tool_input)

    def _run(self, *args: Any, config: Any = None, run_manager: Any = None, **kwargs: Any) -> Any:
        if self.func:
            if run_manager and "callbacks" in _params(self.func):
                kwargs["callbacks"] = run_manager.get_child()
            return self.func(*args, **kwargs)
        raise NotImplementedError("StructuredTool does not support sync invocation.")

    async def _arun(
        self, *args: Any, config: Any = None, run_manager: Any = None, **kwargs: Any
    ) -> Any:
        if self.coroutine:
            if run_manager and "callbacks" in _params(self.coroutine):
                kwargs["callbacks"] = run_manager.get_child()
            return await self.coroutine(*args, **kwargs)
        return await super()._arun(*args, run_manager=run_manager, **kwargs)


def _lc_tool(fn: Callable[..., Any]) -> _LCStructuredTool:
    """``@tool``: an ``async def`` becomes the ``coroutine``, a ``def`` the ``func``."""
    if inspect.iscoroutinefunction(fn):
        return _LCStructuredTool.from_function(coroutine=fn, name=fn.__name__)
    return _LCStructuredTool.from_function(func=fn, name=fn.__name__)


@pytest.fixture
def langchain_core(monkeypatch: pytest.MonkeyPatch) -> types.ModuleType:
    """Install a ``langchain_core.tools`` whose classes mirror the real dispatch."""
    package = types.ModuleType("langchain_core")
    package.__path__ = []
    tools = types.ModuleType("langchain_core.tools")
    tools.BaseTool = _LCBaseTool  # type: ignore[attr-defined]
    tools.StructuredTool = _LCStructuredTool  # type: ignore[attr-defined]
    tools.Tool = _LCStructuredTool  # type: ignore[attr-defined]
    tools.FILTERED_ARGS = ("run_manager", "callbacks")  # type: ignore[attr-defined]
    package.tools = tools  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "langchain_core", package)
    monkeypatch.setitem(sys.modules, "langchain_core.tools", tools)
    return tools


class TestLangChainAsyncEntryPointsAreGuarded:
    """F-F1: every LangChain entry point runs through Airlock, sync and async."""

    def test_async_tool_ainvoke_is_refused(self, langchain_core: Any) -> None:
        from agent_airlock.integrations.langchain import wrap_langchain_tool

        ran: list[int] = []

        async def lookup(x: int) -> str:
            ran.append(x)
            return "async body"

        tool = wrap_langchain_tool(_lc_tool(lookup), policy=_DENY_ALL)

        assert _blocked(asyncio.run(tool.ainvoke({"x": 1})))
        assert ran == []

    def test_control_async_tool_runs_and_is_awaited(self, langchain_core: Any) -> None:
        from agent_airlock.integrations.langchain import wrap_langchain_tool

        async def lookup(x: int) -> str:
            return f"async body {x}"

        tool = wrap_langchain_tool(_lc_tool(lookup), policy=SecurityPolicy())

        assert asyncio.run(tool.ainvoke({"x": 1})) == "async body 1"

    def test_structured_tool_func_and_coroutine_are_both_refused(self, langchain_core: Any) -> None:
        from agent_airlock.integrations.langchain import wrap_langchain_tool

        ran: list[str] = []

        def sync_body(x: int) -> str:
            ran.append("func")
            return "func body"

        async def async_body(x: int) -> str:
            ran.append("coroutine")
            return "coroutine body"

        tool = wrap_langchain_tool(
            _LCStructuredTool.from_function(sync_body, async_body, name="both"),
            policy=_DENY_ALL,
        )

        assert _blocked(tool.invoke({"x": 1}))
        assert _blocked(asyncio.run(tool.ainvoke({"x": 1})))
        assert ran == []

    def test_control_structured_tool_runs_on_both_paths(self, langchain_core: Any) -> None:
        from agent_airlock.integrations.langchain import wrap_langchain_tool

        def sync_body(x: int) -> str:
            return "func body"

        async def async_body(x: int) -> str:
            return "coroutine body"

        tool = wrap_langchain_tool(
            _LCStructuredTool.from_function(sync_body, async_body, name="both"),
            policy=SecurityPolicy(),
        )

        assert tool.invoke({"x": 1}) == "func body"
        assert asyncio.run(tool.ainvoke({"x": 1})) == "coroutine body"

    def test_base_tool_subclass_arun_is_refused(self, langchain_core: Any) -> None:
        from agent_airlock.integrations.langchain import wrap_langchain_tool

        ran: list[str] = []

        class Lookup(_LCBaseTool):
            name = "lookup"

            def _run(self, x: int) -> str:
                ran.append("_run")
                return "run body"

            async def _arun(self, x: int) -> str:
                ran.append("_arun")
                return "arun body"

        tool = wrap_langchain_tool(Lookup(), policy=_DENY_ALL)

        assert _blocked(tool.invoke({"x": 1}))
        assert _blocked(asyncio.run(tool.ainvoke({"x": 1})))
        assert ran == []

    def test_control_base_tool_subclass_runs(self, langchain_core: Any) -> None:
        from agent_airlock.integrations.langchain import wrap_langchain_tool

        class Lookup(_LCBaseTool):
            name = "lookup"

            def _run(self, x: int) -> str:
                return "run body"

            async def _arun(self, x: int) -> str:
                return "arun body"

        tool = wrap_langchain_tool(Lookup(), policy=SecurityPolicy())

        assert tool.invoke({"x": 1}) == "run body"
        assert asyncio.run(tool.ainvoke({"x": 1})) == "arun body"

    def test_create_secure_tool_awaits_an_async_function(self, langchain_core: Any) -> None:
        from agent_airlock.integrations.langchain import create_secure_tool

        async def lookup(x: int) -> str:
            return f"looked up {x}"

        tool = create_secure_tool(lookup, policy=SecurityPolicy())

        assert asyncio.run(tool.ainvoke({"x": 2})) == "looked up 2"

    def test_create_secure_tool_async_is_refused_under_deny_all(self, langchain_core: Any) -> None:
        from agent_airlock.integrations.langchain import create_secure_tool

        ran: list[int] = []

        async def lookup(x: int) -> str:
            ran.append(x)
            return "body"

        tool = create_secure_tool(lookup, policy=_DENY_ALL)

        assert _blocked(asyncio.run(tool.ainvoke({"x": 2})))
        assert ran == []

    def test_policy_lists_match_the_tool_name_not_run(self, langchain_core: Any) -> None:
        # The guard used to be named `_run`, so a deny list naming the tool missed it.
        from agent_airlock.integrations.langchain import wrap_langchain_tool

        class Delete(_LCBaseTool):
            name = "delete_record"

            def _run(self, record_id: int) -> str:
                return "deleted"

        denied = wrap_langchain_tool(
            Delete(), policy=SecurityPolicy(denied_tools=["delete_record"])
        )
        assert _blocked(denied.invoke({"record_id": 1}))

        control = wrap_langchain_tool(Delete(), policy=SecurityPolicy(denied_tools=["other"]))
        assert control.invoke({"record_id": 1}) == "deleted"

    def test_run_manager_is_filled_by_langchain_not_validated(self, langchain_core: Any) -> None:
        # A `run_manager` parameter used to fail schema generation on every call.
        from agent_airlock.integrations.langchain import wrap_langchain_tool

        class Traced(_LCBaseTool):
            name = "traced"

            def _run(self, x: int, run_manager: _RunManager | None = None) -> str:
                return f"{x}:{type(run_manager).__name__}"

        tool = wrap_langchain_tool(Traced(), policy=SecurityPolicy())

        assert tool.invoke({"x": 3}) == "3:_RunManager"
        assert asyncio.run(tool.ainvoke({"x": 3})) == "3:_RunManager"
        assert _blocked(tool.invoke({"x": "3"})), "model-supplied args stay strict"

    def test_sync_and_async_share_one_policy_budget(self, langchain_core: Any) -> None:
        from agent_airlock.integrations.langchain import wrap_langchain_tool

        def sync_body(x: int) -> str:
            return "func body"

        async def async_body(x: int) -> str:
            return "coroutine body"

        tool = wrap_langchain_tool(
            _LCStructuredTool.from_function(sync_body, async_body, name="both"),
            policy=_one_per_hour(),
        )

        assert tool.invoke({"x": 1}) == "func body"
        assert _blocked(asyncio.run(tool.ainvoke({"x": 1})))

    def test_wrapping_twice_is_one_layer(self, langchain_core: Any) -> None:
        from agent_airlock.integrations.langchain import SecureToolkit, wrap_langchain_tool

        def lookup(x: int) -> str:
            return "sync body"

        policy = _one_per_hour()
        tool = wrap_langchain_tool(_lc_tool(lookup), policy=policy)
        SecureToolkit(policy=policy).wrap_tools([tool])

        assert tool.invoke({"x": 1}) == "sync body"
        assert _blocked(tool.invoke({"x": 1})), "control: the second call spends the token"

    def test_secure_toolkit_guards_async_tools(self, langchain_core: Any) -> None:
        from agent_airlock.integrations.langchain import SecureToolkit

        ran: list[int] = []

        async def lookup(x: int) -> str:
            ran.append(x)
            return "async body"

        (tool,) = SecureToolkit(policy=_DENY_ALL).wrap_tools([_lc_tool(lookup)])

        assert _blocked(asyncio.run(tool.ainvoke({"x": 1})))
        assert ran == []


# ---------------------------------------------------------------------------------------
# PydanticAI stubs: mirror pydantic-ai 2.63.0's toolsets and Agent._get_toolset.
# ---------------------------------------------------------------------------------------


class _PFunctionSchema:
    """``FunctionSchema.call``: calls ``self.function``, captured when the Tool was built."""

    def __init__(self, function: Callable[..., Any]) -> None:
        self.function = function
        self.is_async = inspect.iscoroutinefunction(function)

    async def call(self, args: dict[str, Any], ctx: Any) -> Any:
        result = self.function(**args)
        return await result if inspect.isawaitable(result) else result


class _PTool:
    def __init__(self, function: Callable[..., Any]) -> None:
        self.name = function.__name__
        self.function = function
        self.takes_ctx = False
        self.function_schema = _PFunctionSchema(function)


class _PFunctionToolset:
    """``FunctionToolset``: ``tools`` dict; ``call_tool`` -> ``function_schema.call``."""

    def __init__(self, functions: list[Callable[..., Any]]) -> None:
        self.tools = {tool.name: tool for tool in map(_PTool, functions)}

    async def for_run(self, ctx: Any) -> Any:
        return self

    def names(self) -> dict[str, tuple[Any, str]]:
        return {name: (self, name) for name in self.tools}

    async def call_tool(self, name: str, args: dict[str, Any], ctx: Any) -> Any:
        return await self.tools[name].function_schema.call(args, ctx)


class _PWrapperToolset:
    """``WrapperToolset`` (``prefixed`` / ``renamed`` / ``filtered``): ``.wrapped``."""

    def __init__(self, wrapped: Any, prefix: str = "") -> None:
        self.wrapped = wrapped
        self.prefix = prefix

    async def for_run(self, ctx: Any) -> Any:
        return _PWrapperToolset(await self.wrapped.for_run(ctx), self.prefix)

    def names(self) -> dict[str, tuple[Any, str]]:
        return {f"{self.prefix}{name}": hit for name, hit in self.wrapped.names().items()}


class _PCombinedToolset:
    """``CombinedToolset``: ``.toolsets``."""

    def __init__(self, toolsets: list[Any]) -> None:
        self.toolsets = toolsets

    async def for_run(self, ctx: Any) -> Any:
        return _PCombinedToolset([await each.for_run(ctx) for each in self.toolsets])

    def names(self) -> dict[str, tuple[Any, str]]:
        found: dict[str, tuple[Any, str]] = {}
        for each in self.toolsets:
            found.update(each.names())
        return found


class _PDynamicToolset:
    """``DynamicToolset``: ``toolset_func(ctx)`` builds the toolset for each run."""

    def __init__(self, toolset_func: Callable[[Any], Any]) -> None:
        self.toolset_func = toolset_func
        self._toolset: Any = None

    async def for_run(self, ctx: Any) -> Any:
        new = _PDynamicToolset(self.toolset_func)
        built = self.toolset_func(ctx)
        new._toolset = await built if inspect.isawaitable(built) else built
        return new

    def names(self) -> dict[str, tuple[Any, str]]:
        return self._toolset.names() if self._toolset is not None else {}


class _PRemoteToolset:
    """A leaf with no local callables, the shape of ``MCPToolset`` / ``ExternalToolset``."""

    label = "remote server"

    def __init__(self, ran: list[str]) -> None:
        self.ran = ran

    async def for_run(self, ctx: Any) -> Any:
        return self

    def names(self) -> dict[str, tuple[Any, str]]:
        return {}


class _PAgent:
    """``Agent``: ``toolsets`` property; every run builds its toolset in ``_get_toolset``."""

    def __init__(self, functions: tuple[Callable[..., Any], ...] = (), toolsets: Any = ()):
        self._function_toolset = _PFunctionToolset(list(functions))
        self._user_toolsets = list(toolsets)

    @property
    def toolsets(self) -> list[Any]:
        return [self._function_toolset, *self._user_toolsets]

    def _get_toolset(
        self, output_toolset: Any = None, additional_toolsets: Any = None, **_: Any
    ) -> Any:
        toolsets = list(self.toolsets)
        if additional_toolsets:
            toolsets = [*toolsets, *additional_toolsets]
        return _PCombinedToolset(toolsets)

    def run_tool(self, name: str, args: dict[str, Any], toolsets: Any = None) -> Any:
        """``agent.run(..., toolsets=...)`` up to the one tool call the model asks for."""
        toolset = self._get_toolset(additional_toolsets=toolsets)

        async def run() -> Any:
            for_run = await toolset.for_run(None)
            leaf, inner = for_run.names()[name]
            return await leaf.call_tool(inner, args, None)

        return asyncio.run(run())


def _recorder(ran: list[str], name: str) -> Callable[[int], str]:
    def tool(x: int) -> str:
        ran.append(name)
        return f"{name} ran"

    tool.__name__ = name
    return tool


def _pai_wrap(agent: Any, policy: SecurityPolicy | None) -> Any:
    from agent_airlock.integrations.pydantic_ai import PydanticAIAdapter

    return PydanticAIAdapter(attach_output_validate=False).wrap_agent(agent, policy=policy)


class TestPydanticAIEveryToolsetShapeIsWalked:
    """F-F2: wrapper, combined, dynamic and run-time toolsets are guarded too."""

    @pytest.mark.parametrize(
        ("label", "build", "call_name"),
        [
            ("prefixed", lambda f: _PWrapperToolset(_PFunctionToolset([f]), "p_"), "p_t"),
            ("combined", lambda f: _PCombinedToolset([_PFunctionToolset([f])]), "t"),
            ("dynamic", lambda f: _PDynamicToolset(lambda ctx: _PFunctionToolset([f])), "t"),
        ],
    )
    def test_agent_toolset_shapes_are_refused(
        self, label: str, build: Callable[[Any], Any], call_name: str
    ) -> None:
        ran: list[str] = []
        agent = _pai_wrap(_PAgent(toolsets=[build(_recorder(ran, "t"))]), _DENY_ALL)

        assert _blocked(agent.run_tool(call_name, {"x": 1})), label
        assert ran == [], label

    @pytest.mark.parametrize(
        ("build", "call_name"),
        [
            (lambda f: _PWrapperToolset(_PFunctionToolset([f]), "p_"), "p_t"),
            (lambda f: _PCombinedToolset([_PFunctionToolset([f])]), "t"),
            (lambda f: _PDynamicToolset(lambda ctx: _PFunctionToolset([f])), "t"),
        ],
    )
    def test_control_agent_toolset_shapes_run(
        self, build: Callable[[Any], Any], call_name: str
    ) -> None:
        ran: list[str] = []
        agent = _pai_wrap(_PAgent(toolsets=[build(_recorder(ran, "t"))]), SecurityPolicy())

        assert agent.run_tool(call_name, {"x": 1}) == "t ran"
        assert ran == ["t"]

    def test_toolsets_passed_at_run_time_are_refused(self) -> None:
        ran: list[str] = []
        agent = _pai_wrap(_PAgent(), _DENY_ALL)

        result = agent.run_tool("t", {"x": 1}, toolsets=[_PFunctionToolset([_recorder(ran, "t")])])

        assert _blocked(result)
        assert ran == []

    def test_control_toolsets_passed_at_run_time_run(self) -> None:
        ran: list[str] = []
        agent = _pai_wrap(_PAgent(), SecurityPolicy())

        result = agent.run_tool("t", {"x": 1}, toolsets=[_PFunctionToolset([_recorder(ran, "t")])])

        assert result == "t ran"

    def test_a_tool_registered_after_the_wrap_is_refused(self) -> None:
        ran: list[str] = []
        agent = _pai_wrap(_PAgent(), _DENY_ALL)
        agent._function_toolset.tools["late"] = _PTool(_recorder(ran, "late"))

        assert _blocked(agent.run_tool("late", {"x": 1}))
        assert ran == []

    def test_a_toolset_with_no_local_callable_is_reported(self) -> None:
        ran: list[str] = []
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _pai_wrap(_PAgent(toolsets=[_PWrapperToolset(_PRemoteToolset(ran))]), _DENY_ALL)

        messages = [str(w.message) for w in caught if issubclass(w.category, UserWarning)]
        assert any(
            "_PRemoteToolset (remote server)" in m and "NOT validated" in m for m in messages
        )

    def test_a_remote_toolset_passed_at_run_time_is_reported(self) -> None:
        agent = _pai_wrap(_PAgent(functions=(_recorder([], "t"),)), _DENY_ALL)

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            agent._get_toolset(additional_toolsets=[_PRemoteToolset([])])

        assert any("_PRemoteToolset" in str(w.message) for w in caught)

    def test_control_function_toolsets_alone_do_not_warn(self) -> None:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            agent = _pai_wrap(_PAgent(functions=(_recorder([], "t"),)), SecurityPolicy())
            agent.run_tool("t", {"x": 1})

        assert not [w for w in caught if "agent-airlock" in str(w.message)]

    def test_the_report_can_be_turned_off(self) -> None:
        from agent_airlock.integrations.pydantic_ai import PydanticAIAdapter

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            PydanticAIAdapter(attach_output_validate=False, warn_on_unwrappable=False).wrap_agent(
                _PAgent(toolsets=[_PRemoteToolset([])]), policy=_DENY_ALL
            )

        assert not [w for w in caught if "did not guard" in str(w.message)]

    def test_a_schema_holding_another_function_is_the_one_guarded(self) -> None:
        # The run path calls function_schema.function, whatever it holds.
        ran: list[str] = []
        tool = _PTool(_recorder(ran, "t"))
        tool.function_schema.function = _recorder(ran, "schema")
        toolset = _PFunctionToolset([])
        toolset.tools["t"] = tool

        _pai_wrap(_PAgent(toolsets=[toolset]), _DENY_ALL)

        assert _blocked(asyncio.run(tool.function_schema.call({"x": 1}, None)))
        assert ran == []


# ---------------------------------------------------------------------------------------
# Idempotency (F-F3): wrapping twice is one Airlock layer, so a 1/hour tool still runs once.
# ---------------------------------------------------------------------------------------


def _add(a: int, b: int) -> int:
    return a + b


class _ADKFunctionTool:
    """``google.adk`` ``FunctionTool``: the runtime calls ``.func``."""

    def __init__(self, func: Callable[..., Any]) -> None:
        self.name = func.__name__
        self.func = func


@dataclass
class _SdkMcpTool:
    """``claude_agent_sdk.SdkMcpTool``: the server calls ``handler(args)``."""

    name: str
    description: str
    input_schema: Any
    handler: Callable[[dict[str, Any]], Any]


async def _sdk_add(args: dict[str, Any]) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": str(args["a"] + args["b"])}]}


class TestWalkersAreIdempotent:
    """F-F3: one audit record and one rate-limit charge per call after two wraps."""

    def test_pydantic_ai(self) -> None:
        policy = _one_per_hour()
        agent = _PAgent(functions=(_add,))
        _pai_wrap(agent, policy)
        _pai_wrap(agent, policy)

        assert agent.run_tool("_add", {"a": 1, "b": 2}) == 3

    def test_google_adk(self) -> None:
        from agent_airlock.integrations.google_adk import GoogleADKAdapter

        policy = _one_per_hour()
        tool = _ADKFunctionTool(_add)
        agent = types.SimpleNamespace(tools=[tool, _add])
        GoogleADKAdapter().wrap_agent(agent, policy=policy)
        GoogleADKAdapter().wrap_agent(agent, policy=policy)

        assert tool.func(a=1, b=2) == 3
        assert _blocked(agent.tools[1](a=1, b=2)), "the bucket is shared: one token per call"

    def test_google_adk_bare_callable(self) -> None:
        from agent_airlock.integrations.google_adk import GoogleADKAdapter

        policy = _one_per_hour()
        agent = types.SimpleNamespace(tools=[_add])
        GoogleADKAdapter().wrap_agent(agent, policy=policy)
        GoogleADKAdapter().wrap_agent(agent, policy=policy)

        assert agent.tools[0](a=1, b=2) == 3

    def test_claude_sdk_wrap_agent(self) -> None:
        from agent_airlock.integrations.anthropic_claude_agent_sdk import (
            AnthropicClaudeAgentSDKAdapter,
        )

        policy = _one_per_hour()
        agent = types.SimpleNamespace(
            tools=[_SdkMcpTool("add", "d", {"a": int, "b": int}, _sdk_add)]
        )
        AnthropicClaudeAgentSDKAdapter().wrap_agent(agent, policy=policy)
        AnthropicClaudeAgentSDKAdapter().wrap_agent(agent, policy=policy)

        result = asyncio.run(agent.tools[0].handler({"a": 1, "b": 2}))
        assert result == {"content": [{"type": "text", "text": "3"}]}

    def test_claude_sdk_wrap_tools(self) -> None:
        from agent_airlock.integrations.anthropic_claude_agent_sdk import wrap_tools

        policy = _one_per_hour()
        tools = wrap_tools([_SdkMcpTool("add", "d", {"a": int, "b": int}, _sdk_add)], policy=policy)
        tools = wrap_tools(tools, policy=policy)

        result = asyncio.run(tools[0].handler({"a": 1, "b": 2}))
        assert result == {"content": [{"type": "text", "text": "3"}]}

    def test_claude_sdk_forward_and_callable_entries(self) -> None:
        from agent_airlock.integrations.anthropic_claude_agent_sdk import (
            AnthropicClaudeAgentSDKAdapter,
        )

        # wrap_agent names a bare callable entry by its index: tool_1.
        policy = SecurityPolicy(rate_limits={"forward_tool": "1/hour", "tool_1": "1/hour"})
        forward_tool = types.SimpleNamespace(name="forward_tool", forward=_add)
        agent = types.SimpleNamespace(tools=[forward_tool, _add])
        AnthropicClaudeAgentSDKAdapter().wrap_agent(agent, policy=policy)
        AnthropicClaudeAgentSDKAdapter().wrap_agent(agent, policy=policy)

        assert forward_tool.forward(a=1, b=2) == 3
        assert agent.tools[1](a=1, b=2) == 3

    def test_control_a_second_call_is_still_refused(self) -> None:
        """The idempotency checks above discriminate: the second call spends the token."""
        policy = _one_per_hour()
        agent = _PAgent(functions=(_add,))
        _pai_wrap(agent, policy)

        assert agent.run_tool("_add", {"a": 1, "b": 2}) == 3
        assert _blocked(agent.run_tool("_add", {"a": 1, "b": 2}))

    def test_rewrapping_with_another_policy_warns(self) -> None:
        agent = _PAgent(functions=(_add,))
        _pai_wrap(agent, SecurityPolicy())

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _pai_wrap(agent, _DENY_ALL)

        assert any("already guarded under another policy" in str(w.message) for w in caught)


# ---------------------------------------------------------------------------------------
# OpenAI Agents SDK stubs (F-F4): mirror openai-agents 0.13.2's guardrail classes.
# ---------------------------------------------------------------------------------------


@dataclass
class _GuardrailFunctionOutput:
    output_info: Any
    tripwire_triggered: bool


@dataclass
class _SDKInputGuardrail:
    """``agents.InputGuardrail``: ``run`` calls ``guardrail_function(context, agent, input)``."""

    guardrail_function: Callable[[Any, Any, Any], Any]
    name: str | None = None
    run_in_parallel: bool = True

    def get_name(self) -> str:
        return self.name or self.guardrail_function.__name__

    async def run(self, agent: Any, agent_input: Any, context: Any) -> Any:
        output = self.guardrail_function(context, agent, agent_input)
        if inspect.isawaitable(output):
            output = await output
        return types.SimpleNamespace(guardrail=self, output=output)


@dataclass
class _SDKOutputGuardrail:
    """``agents.OutputGuardrail``: ``run`` calls ``guardrail_function(context, agent, out)``."""

    guardrail_function: Callable[[Any, Any, Any], Any]
    name: str | None = None

    def get_name(self) -> str:
        return self.name or self.guardrail_function.__name__

    async def run(self, context: Any, agent: Any, agent_output: Any) -> Any:
        output = self.guardrail_function(context, agent, agent_output)
        if inspect.isawaitable(output):
            output = await output
        return types.SimpleNamespace(guardrail=self, output=output)


@pytest.fixture
def agents_sdk(monkeypatch: pytest.MonkeyPatch) -> types.ModuleType:
    module = types.ModuleType("agents")
    module.__spec__ = importlib.machinery.ModuleSpec("agents", None)
    module.InputGuardrail = _SDKInputGuardrail  # type: ignore[attr-defined]
    module.OutputGuardrail = _SDKOutputGuardrail  # type: ignore[attr-defined]
    module.GuardrailFunctionOutput = _GuardrailFunctionOutput  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "agents", module)
    return module


def _sdk_agent() -> Any:
    return types.SimpleNamespace(name="a", input_guardrails=[], output_guardrails=[])


def _guarded_agent(policy: SecurityPolicy) -> Any:
    from agent_airlock.integrations.openai_guardrails import AirlockGuardrails

    guardrails = AirlockGuardrails(policy=policy)

    @guardrails.secure_tool
    def lookup(q: str) -> str:
        return "x"

    return guardrails.wrap_agent(_sdk_agent())


class TestOpenAIGuardrailsAreSdkObjects:
    """F-F4: wrap_agent appends guardrails the Agents SDK can run."""

    def test_wrap_agent_appends_sdk_guardrail_objects(self, agents_sdk: Any) -> None:
        agent = _guarded_agent(SecurityPolicy())

        assert [type(g) for g in agent.input_guardrails] == [_SDKInputGuardrail]
        assert [type(g) for g in agent.output_guardrails] == [_SDKOutputGuardrail]
        assert agent.input_guardrails[0].get_name() == "airlock_policy:lookup"
        assert agent.input_guardrails[0].run_in_parallel is False

    def test_a_denied_tool_trips_the_input_guardrail(self, agents_sdk: Any) -> None:
        agent = _guarded_agent(_DENY_ALL)

        result = asyncio.run(agent.input_guardrails[0].run(agent, "hello", None))

        assert result.output.tripwire_triggered is True

    def test_control_an_allowed_tool_passes_the_input_guardrail(self, agents_sdk: Any) -> None:
        agent = _guarded_agent(SecurityPolicy())

        result = asyncio.run(agent.input_guardrails[0].run(agent, "hello", None))

        assert result.output.tripwire_triggered is False

    def test_pii_in_the_output_trips_the_output_guardrail(self, agents_sdk: Any) -> None:
        agent = _guarded_agent(SecurityPolicy())
        guardrail = agent.output_guardrails[0]

        assert asyncio.run(guardrail.run(None, agent, "mail a@b.co")).output.tripwire_triggered
        assert not asyncio.run(guardrail.run(None, agent, "all good")).output.tripwire_triggered

    def test_an_agent_without_guardrail_lists_is_refused(self, agents_sdk: Any) -> None:
        from agent_airlock.integrations.openai_guardrails import AirlockGuardrails

        guardrails = AirlockGuardrails(policy=SecurityPolicy())

        @guardrails.secure_tool
        def lookup(q: str) -> str:
            return "x"

        with pytest.raises(TypeError, match="input_guardrails"):
            guardrails.wrap_agent(types.SimpleNamespace(name="no lists"))


class TestPolicyGuardrailAppliesThePolicy:
    """F-F4: rate limits apply; an unreadable time window refuses; patterns are fnmatch."""

    def test_rate_limit_is_applied(self) -> None:
        from agent_airlock.integrations.openai_guardrails import PolicyGuardrail

        guardrail = PolicyGuardrail(SecurityPolicy(rate_limits={"lookup": "1/hour"}), "lookup")

        assert guardrail.check({}).passed is True
        second = guardrail.check({})
        assert second.passed is False
        assert "Rate limit" in (second.violations or [""])[0]

    def test_control_no_rate_limit_passes_repeatedly(self) -> None:
        from agent_airlock.integrations.openai_guardrails import PolicyGuardrail

        guardrail = PolicyGuardrail(SecurityPolicy(), "lookup")

        assert all(guardrail.check({}).passed for _ in range(3))

    def test_a_non_consuming_check_reads_the_tools_own_budget(self) -> None:
        from agent_airlock.core import Airlock
        from agent_airlock.integrations.openai_guardrails import PolicyGuardrail

        policy = SecurityPolicy(rate_limits={"lookup": "1/hour"})
        guardrail = PolicyGuardrail(policy, "lookup", consume_rate_limit=False)

        @Airlock(policy=policy)
        def lookup(q: str) -> str:
            return "x"

        assert guardrail.check({}).passed and guardrail.check({}).passed, "it spends nothing"
        assert lookup(q="a") == "x"
        assert guardrail.check({}).passed is False, "the tool spent the budget"

    def test_an_unreadable_time_window_is_refused(self) -> None:
        from agent_airlock.integrations.openai_guardrails import PolicyGuardrail

        policy = SecurityPolicy()
        policy.time_restrictions["lookup"] = "9am-5pm"  # set after the policy was built

        result = PolicyGuardrail(policy, "lookup").check({})

        assert result.passed is False
        assert "unreadable time window" in (result.violations or [""])[0]

    def test_control_an_all_day_window_passes(self) -> None:
        from agent_airlock.integrations.openai_guardrails import PolicyGuardrail

        policy = SecurityPolicy(time_restrictions={"lookup": "00:00-23:59"})

        assert PolicyGuardrail(policy, "lookup").check({}).passed is True

    def test_patterns_match_like_the_policy(self) -> None:
        from agent_airlock.integrations.openai_guardrails import PolicyGuardrail

        policy = SecurityPolicy(denied_tools=["*_file"])

        assert PolicyGuardrail(policy, "delete_file").check({}).passed is False
        assert PolicyGuardrail(policy, "lookup").check({}).passed is True

    def test_default_deny_with_no_allowlist_refuses(self) -> None:
        from agent_airlock.integrations.openai_guardrails import PolicyGuardrail

        policy = SecurityPolicy(default_deny=True)

        assert PolicyGuardrail(policy, "lookup").check({}).passed is False


# ---------------------------------------------------------------------------------------
# CrewAI stubs (F-F5): mirror crewai 1.15.22's run-time tool assembly.
# ---------------------------------------------------------------------------------------


class _CBaseTool:
    """``crewai.tools.BaseTool``: ``to_structured_tool`` captures ``self._run``."""

    name = "tool"

    def to_structured_tool(self) -> _CStructuredTool:
        return _CStructuredTool(self.name, self._run)

    def _run(self, **kwargs: Any) -> Any:
        raise NotImplementedError


class _CStructuredTool:
    """``CrewStructuredTool.invoke``: ``self.func(**args)``."""

    def __init__(self, name: str, func: Callable[..., Any]) -> None:
        self.name = name
        self.func = func

    def invoke(self, args: dict[str, Any]) -> Any:
        return self.func(**args)


class _DelegateWorkTool(_CBaseTool):
    name = "Delegate work to coworker"

    def __init__(self, ran: list[str]) -> None:
        self.ran = ran

    def _run(self, task: str, context: str, coworker: str | None = None) -> str:
        self.ran.append("delegation")
        return "delegated"


class _McpTool(_CBaseTool):
    name = "mcp_lookup"

    def __init__(self, ran: list[str]) -> None:
        self.ran = ran

    def _run(self, query: str) -> str:
        self.ran.append("mcp")
        return "mcp result"


class _SkillLoaderTool(_CBaseTool):
    name = "load_skill"

    def __init__(self, ran: list[str]) -> None:
        self.ran = ran

    def _run(self, skill: str) -> str:
        self.ran.append("skill")
        return "skill text"


class _CAgent:
    """``crewai.Agent``: ``_add_skill_loader_tool`` gets the final list, then ``parse_tools``."""

    def __init__(
        self,
        ran: list[str],
        *,
        role: str = "lead",
        tools: list[Any] | None = None,
        mcps: list[str] | None = None,
        skills: list[str] | None = None,
        allow_delegation: bool = False,
    ) -> None:
        self.ran = ran
        self.role = role
        self.tools = tools if tools is not None else []
        self.mcps = mcps
        self.skills = skills
        self.allow_delegation = allow_delegation
        self.executor_tools: dict[str, _CStructuredTool] = {}

    def get_delegation_tools(self, agents: list[Any]) -> list[Any]:
        return [_DelegateWorkTool(self.ran)]

    def get_mcp_tools(self, mcps: list[str]) -> list[Any]:
        return [_McpTool(self.ran)]

    def _add_skill_loader_tool(self, tools: list[Any], task: Any = None) -> list[Any]:
        return [*tools, _SkillLoaderTool(self.ran)] if self.skills else tools

    def create_agent_executor(self, tools: list[Any] | None = None, task: Any = None) -> None:
        configured = tools if tools is not None else self.tools or []
        raw = self._add_skill_loader_tool(list(configured), task=task)
        self.executor_tools = {t.name: t.to_structured_tool() for t in raw}  # parse_tools

    def kickoff(self, tool_name: str, args: dict[str, Any]) -> Any:
        """``Agent.kickoff`` -> ``_prepare_kickoff`` up to the one tool call."""
        if self.mcps:
            self.tools.extend(self.get_mcp_tools(self.mcps))
        raw = self._add_skill_loader_tool(list(self.tools or []))
        parsed = {t.name: t.to_structured_tool() for t in raw}
        return parsed[tool_name].invoke(args)


class _CTask:
    def __init__(self, agent: _CAgent) -> None:
        self.agent = agent
        self.tools = agent.tools  # Task(agent=a) shares the agent's own list


class _CCrew:
    """``crewai.Crew``: ``prepare_task_execution`` -> ``_prepare_tools`` -> the executor."""

    def __init__(self, agents: list[_CAgent], tasks: list[_CTask]) -> None:
        self.agents = agents
        self.tasks = tasks

    def _prepare_tools(self, agent: _CAgent, task: _CTask, tools: list[Any]) -> list[Any]:
        if agent.allow_delegation:
            others = [a for a in self.agents if a is not agent]
            tools = [*tools, *agent.get_delegation_tools(others)]
        if agent.mcps:
            tools = [*tools, *agent.get_mcp_tools(agent.mcps)]
        return tools

    def copy(self) -> _CCrew:
        agents = [_CAgent(a.ran, role=a.role, tools=a.tools, mcps=a.mcps) for a in self.agents]
        return _CCrew(agents, [_CTask(agent) for agent in agents])

    def run_task(self, task: _CTask, tool_name: str, args: dict[str, Any]) -> Any:
        tools = self._prepare_tools(task.agent, task, task.tools or task.agent.tools or [])
        task.agent.create_agent_executor(tools=tools, task=task)
        return task.agent.executor_tools[tool_name].invoke(args)


class _CStaticTool(_CBaseTool):
    name = "static_lookup"

    def __init__(self, ran: list[str]) -> None:
        self.ran = ran

    def _run(self, query: str) -> str:
        self.ran.append("static")
        return "static result"


def _crew(ran: list[str], **agent_kwargs: Any) -> _CCrew:
    lead = _CAgent(ran, **agent_kwargs)
    worker = _CAgent(ran, role="worker")
    return _CCrew([lead, worker], [_CTask(lead)])


class TestCrewAIRunTimeToolsAreGuarded:
    """F-F5: tools CrewAI adds while a task runs go through Airlock too."""

    @pytest.mark.parametrize(
        ("label", "agent_kwargs", "tool", "args"),
        [
            (
                "delegation",
                {"allow_delegation": True},
                "Delegate work to coworker",
                {"task": "t", "context": "c", "coworker": "worker"},
            ),
            ("agent.mcps", {"mcps": ["https://mcp.example"]}, "mcp_lookup", {"query": "q"}),
            ("skill loader", {"skills": ["s"]}, "load_skill", {"skill": "s"}),
        ],
    )
    def test_injected_tools_are_refused_in_a_crew(
        self, label: str, agent_kwargs: dict[str, Any], tool: str, args: dict[str, Any]
    ) -> None:
        from agent_airlock.integrations.crewai import CrewAIAdapter

        ran: list[str] = []
        crew = CrewAIAdapter().wrap_crew(_crew(ran, **agent_kwargs), policy=_DENY_ALL)

        assert _blocked(crew.run_task(crew.tasks[0], tool, args)), label
        assert ran == [], label

    def test_control_injected_tools_run_under_allow(self) -> None:
        from agent_airlock.integrations.crewai import CrewAIAdapter

        ran: list[str] = []
        crew = CrewAIAdapter().wrap_crew(_crew(ran, mcps=["m"]), policy=SecurityPolicy())

        assert crew.run_task(crew.tasks[0], "mcp_lookup", {"query": "q"}) == "mcp result"
        assert ran == ["mcp"]

    def test_mcp_tools_of_a_standalone_kickoff_are_refused(self) -> None:
        from agent_airlock.integrations.crewai import CrewAIAdapter

        ran: list[str] = []
        agent = CrewAIAdapter().wrap_agent(_CAgent(ran, mcps=["m"]), policy=_DENY_ALL)

        assert _blocked(agent.kickoff("mcp_lookup", {"query": "q"}))
        assert ran == []

    def test_control_standalone_kickoff_runs_under_allow(self) -> None:
        from agent_airlock.integrations.crewai import CrewAIAdapter

        ran: list[str] = []
        agent = CrewAIAdapter().wrap_agent(_CAgent(ran, mcps=["m"]), policy=SecurityPolicy())

        assert agent.kickoff("mcp_lookup", {"query": "q"}) == "mcp result"

    def test_a_copied_crew_is_guarded_too(self) -> None:
        from agent_airlock.integrations.crewai import CrewAIAdapter

        ran: list[str] = []
        crew = CrewAIAdapter().wrap_crew(_crew(ran, mcps=["m"]), policy=_DENY_ALL)
        clone = crew.copy()  # what kickoff_for_each runs

        assert _blocked(clone.run_task(clone.tasks[0], "mcp_lookup", {"query": "q"}))
        assert ran == []

    def test_a_static_tool_is_still_one_layer(self) -> None:
        # The run-time walk meets the agent's own tools again; it must not re-wrap them.
        from agent_airlock.integrations.crewai import CrewAIAdapter

        ran: list[str] = []
        crew = _crew(ran, tools=[_CStaticTool(ran)])
        crew = CrewAIAdapter().wrap_crew(crew, policy=_one_per_hour())

        assert crew.run_task(crew.tasks[0], "static_lookup", {"query": "q"}) == "static result"

    def test_unreachable_run_time_tools_are_reported(self) -> None:
        from agent_airlock.integrations.crewai import CrewAIAdapter

        agent = types.SimpleNamespace(role="solo", tools=[], mcps=["m"], allow_delegation=True)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            CrewAIAdapter().wrap_agent(agent, policy=_DENY_ALL)

        messages = [str(w.message) for w in caught]
        assert any("MCP server tools" in m and "delegation tools" in m for m in messages)

    def test_control_an_agent_without_run_time_tools_is_not_reported(self) -> None:
        from agent_airlock.integrations.crewai import CrewAIAdapter

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            CrewAIAdapter().wrap_agent(types.SimpleNamespace(tools=[]), policy=_DENY_ALL)

        assert not [w for w in caught if "agent-airlock" in str(w.message)]


# ---------------------------------------------------------------------------------------
# F-F7 and D-F6.
# ---------------------------------------------------------------------------------------


class TestDocumentedPinsAndHints:
    def test_pydantic_ai_docstring_states_the_pyproject_pin(self) -> None:
        import agent_airlock.integrations.pydantic_ai as module

        pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
        pin = re.search(r"pydantic-ai(>=[0-9.]+,<[0-9.]+)", pyproject.read_text("utf-8"))
        assert pin is not None
        assert f"pydantic-ai{pin.group(1)}" in (module.__doc__ or "")

    def test_model_armor_missing_package_names_the_extra(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from agent_airlock.integrations.model_armor import (
            ModelArmorNotInstalled,
            ModelArmorScanner,
        )

        google = types.ModuleType("google")
        google.__path__ = []
        cloud = types.ModuleType("google.cloud")
        cloud.__path__ = []
        monkeypatch.setitem(sys.modules, "google", google)
        monkeypatch.setitem(sys.modules, "google.cloud", cloud)
        monkeypatch.setitem(sys.modules, "google.cloud.modelarmor_v1", None)
        # A client was injected, so only the request-building import can fail.
        scanner = ModelArmorScanner(template="projects/p/locations/l/templates/t", client=object())

        with pytest.raises(ModelArmorNotInstalled, match=r"agent-airlock\[model-armor\]"):
            scanner.scan_user_prompt("anything")
