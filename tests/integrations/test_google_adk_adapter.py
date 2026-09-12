"""Tests for the v0.9.0 Google ADK canonical-leg adapter.

The adapter's stub-friendly contract: any object exposing a ``tools``
list (ADK 2.9.0's ``LlmAgent.tools`` public surface) is acceptable. Only
objects whose ``__module__`` starts with ``google.adk`` go through the
SDK import check, so this whole file runs with no ADK installed.

Every structural assumption pinned here was introspected against
``google-adk`` 2.9.0 (published 2026-09-10):

* ``LlmAgent.tools`` is ``list[Callable | BaseTool | BaseToolset]`` and
  ADK keeps bare callables bare;
* ``FunctionTool`` is not a Pydantic model and holds the user callable
  at ``.func``;
* ``FunctionTool._ignore_params == ['tool_context', 'input_stream']``;
* ``BaseToolset.get_tools`` is ``async`` and rebuilds its list per call.
"""

from __future__ import annotations

import asyncio
import inspect
import sys
import warnings
from pathlib import Path
from typing import Any

import pytest

from agent_airlock.exceptions import AirlockError
from agent_airlock.integrations.google_adk import (
    ADK_INJECTED_PARAMS,
    SUPPORTED_GOOGLE_ADK_VERSIONS,
    GoogleADKAdapter,
    GoogleADKMissingError,
    wrap_agent,
)
from agent_airlock.policy import SecurityPolicy


class _StubToolContext:
    """Stand-in for ``google.adk.tools.tool_context.ToolContext``.

    The real one is an alias of ``google.adk.agents.context.Context`` — an
    arbitrary class with no Pydantic core schema. A bare class reproduces
    that property without needing ADK installed.
    """


class _StubFunctionTool:
    """Stand-in for ADK's ``FunctionTool`` (holds the callable at ``.func``)."""

    def __init__(self, func: Any) -> None:
        # ADK computes name/description at construction from the original
        # function, so they must survive a later ``.func`` swap.
        self.func = func
        self.name = func.__name__
        self.description = func.__doc__


class _StubToolset:
    """Stand-in for ``BaseToolset`` — tools come from an async ``get_tools``."""

    async def get_tools(self, readonly_context: Any = None) -> list[Any]:
        return []


class _StubBuiltinTool:
    """Stand-in for a model-side built-in (``GoogleSearchTool``): no ``.func``."""

    name = "google_search"


class _StubAgent:
    """Stand-in for ``google.adk.agents.Agent`` (exposes ``tools``)."""

    def __init__(self, tools: list[Any]) -> None:
        self.tools = tools


def get_weather(city: str, units: str = "celsius") -> dict[str, Any]:
    """Get the current weather.

    Args:
        city: City name.
        units: celsius or fahrenheit.
    """
    return {"city": city, "units": units, "temp": 22}


def delete_records(table: str) -> dict[str, Any]:
    """Delete records from a table.

    Args:
        table: Table name.
    """
    return {"deleted": table}


def remember(fact: str, tool_context: _StubToolContext) -> dict[str, Any]:
    """Remember a fact.

    Args:
        fact: The fact to store.
    """
    return {"stored": fact, "ctx": tool_context}


class TestWrapsTheToolCollection:
    """``wrap_agent`` walks ``agent.tools`` and replaces each callable."""

    def test_bare_callable_is_replaced(self) -> None:
        agent = _StubAgent([get_weather])

        returned = wrap_agent(agent)

        assert returned is agent
        assert agent.tools[0] is not get_weather, "callable was not replaced"
        assert agent.tools[0](city="Bangalore") == {
            "city": "Bangalore",
            "units": "celsius",
            "temp": 22,
        }

    def test_function_tool_func_is_replaced_in_place(self) -> None:
        """A ``BaseTool`` carrying ``.func`` keeps its identity; only ``.func`` moves."""
        tool = _StubFunctionTool(get_weather)
        agent = _StubAgent([tool])

        wrap_agent(agent)

        assert agent.tools[0] is tool, "the tool object itself must survive"
        assert tool.func is not get_weather, "`.func` was not replaced"
        # ADK derived these at construction; the swap must not disturb them.
        assert tool.name == "get_weather"
        assert tool.description == get_weather.__doc__

    def test_allowed_tool_passes_through(self) -> None:
        agent = _StubAgent([get_weather])
        wrap_agent(agent, SecurityPolicy(allowed_tools=["get_weather"]))

        assert agent.tools[0](city="Pune") == {
            "city": "Pune",
            "units": "celsius",
            "temp": 22,
        }

    def test_denied_tool_is_blocked(self) -> None:
        """A denied tool returns the AirlockResponse blocked dict.

        ``@Airlock`` returns a structured response rather than raising —
        that is the repo-wide contract (see ``core._pre_execution``), so
        the assertion is on the dict, not on an exception.
        """
        agent = _StubAgent([delete_records])
        wrap_agent(agent, SecurityPolicy(denied_tools=["delete_*"]))

        result = agent.tools[0](table="users")

        assert isinstance(result, dict), "blocked call must return AirlockResponse dict"
        assert result.get("status") == "blocked"
        assert result.get("success") is False
        assert "delete_records" in str(result.get("error", ""))

    def test_ghost_argument_is_stripped(self) -> None:
        """An argument the model invented does not reach the tool."""
        agent = _StubAgent([get_weather])
        wrap_agent(agent)

        result = agent.tools[0](city="Delhi", force=True)

        assert result == {"city": "Delhi", "units": "celsius", "temp": 22}

    def test_strict_validation_still_fires(self) -> None:
        agent = _StubAgent([get_weather])
        wrap_agent(agent)

        result = agent.tools[0](city=123)

        assert isinstance(result, dict)
        assert result.get("status") == "blocked"
        assert result.get("block_reason") == "validation_error"


class TestToolContractSurvivesTheWrap:
    """Name, signature and docstring must be unchanged after wrapping."""

    def test_signature_survives(self) -> None:
        agent = _StubAgent([get_weather])
        before = inspect.signature(get_weather)

        wrap_agent(agent)

        assert inspect.signature(agent.tools[0]) == before

    def test_docstring_and_name_survive(self) -> None:
        agent = _StubAgent([get_weather])
        wrap_agent(agent)

        assert agent.tools[0].__doc__ == get_weather.__doc__
        assert agent.tools[0].__name__ == "get_weather"

    def test_async_tool_stays_a_coroutine_function(self) -> None:
        """ADK awaits tool callables; the wrap must not turn one sync."""

        async def fetch(url: str) -> dict[str, Any]:
            """Fetch a URL.

            Args:
                url: The URL.
            """
            return {"url": url}

        agent = _StubAgent([fetch])
        wrap_agent(agent)

        assert inspect.iscoroutinefunction(agent.tools[0])
        assert asyncio.run(agent.tools[0](url="https://example.com")) == {
            "url": "https://example.com"
        }


class TestRuntimeInjectedParameters:
    """The reason this is an adapter and not a docs page.

    ADK injects ``tool_context`` at call time; the model never supplies
    it. Its runtime type has no Pydantic schema, so a bare ``@Airlock()``
    fails at *decoration* time. The adapter relaxes exactly those
    parameters and leaves every model-supplied one strictly validated.
    """

    def test_bare_airlock_cannot_decorate_a_tool_context_tool(self) -> None:
        """Negative control: without the adapter's relaxation this fails.

        If this test ever starts passing, ``Airlock`` grew arbitrary-type
        tolerance and :func:`_relax_injected_params` may be redundant —
        which is worth knowing rather than silently carrying.
        """
        from agent_airlock.core import Airlock

        with pytest.raises(Exception) as excinfo:
            Airlock()(remember)

        assert "schema" in str(excinfo.value).lower()

    def test_adapter_wraps_a_tool_context_tool(self) -> None:
        agent = _StubAgent([remember])

        wrap_agent(agent)

        assert agent.tools[0] is not remember

    def test_injected_context_still_reaches_the_tool(self) -> None:
        agent = _StubAgent([remember])
        wrap_agent(agent)
        ctx = _StubToolContext()

        result = agent.tools[0](fact="sky is blue", tool_context=ctx)

        assert result == {"stored": "sky is blue", "ctx": ctx}

    def test_model_supplied_params_stay_strictly_validated(self) -> None:
        """Relaxing ``tool_context`` must not relax ``fact``."""
        agent = _StubAgent([remember])
        wrap_agent(agent)

        result = agent.tools[0](fact=12345, tool_context=_StubToolContext())

        assert isinstance(result, dict)
        assert result.get("status") == "blocked"
        assert result.get("block_reason") == "validation_error"

    def test_parameter_names_order_and_defaults_are_unchanged(self) -> None:
        """ADK reads the signature to decide what to inject.

        The annotation of an injected parameter is *deliberately* relaxed to
        ``Any`` — that is the fix. Everything ADK actually keys off (names,
        order, defaults) must be untouched, because ADK detects its context
        parameter by name and builds the model-facing declaration from the
        rest.
        """
        agent = _StubAgent([remember])
        before = inspect.signature(remember).parameters

        wrap_agent(agent)
        after = inspect.signature(agent.tools[0]).parameters

        assert list(after) == list(before), "parameter names/order changed"
        assert [p.default for p in after.values()] == [p.default for p in before.values()]
        assert [p.kind for p in after.values()] == [p.kind for p in before.values()]

    def test_only_the_injected_annotation_is_relaxed(self) -> None:
        agent = _StubAgent([remember])
        before = inspect.signature(remember).parameters

        wrap_agent(agent)
        after = inspect.signature(agent.tools[0]).parameters

        assert after["tool_context"].annotation is Any, "injected param not relaxed"
        assert after["fact"].annotation == before["fact"].annotation, (
            "a model-supplied parameter must keep its real annotation"
        )

    def test_injected_param_set_matches_adk(self) -> None:
        """Mirrors ``FunctionTool._ignore_params`` in ADK 2.9.0."""
        assert frozenset({"tool_context", "input_stream"}) == ADK_INJECTED_PARAMS

    def test_a_tool_without_injected_params_is_not_shimmed(self) -> None:
        """The common path costs no extra frame: no relaxation, no shim."""
        from agent_airlock.integrations.google_adk import _relax_injected_params

        assert _relax_injected_params(get_weather) is get_weather


class TestUnguardableEntriesAreReported:
    """Silence is the wrong default for a deny-by-default layer."""

    def test_toolset_is_not_silently_skipped(self) -> None:
        toolset = _StubToolset()
        agent = _StubAgent([toolset])

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            wrap_agent(agent)

        assert agent.tools[0] is toolset, "a toolset must be left alone, not mangled"
        assert any(
            issubclass(w.category, UserWarning) and "_StubToolset" in str(w.message) for w in caught
        ), f"expected a warning naming the toolset; got {[str(w.message) for w in caught]}"

    def test_builtin_tool_without_callable_is_reported(self) -> None:
        agent = _StubAgent([_StubBuiltinTool()])

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            wrap_agent(agent)

        assert any(
            issubclass(w.category, UserWarning) and "google_search" in str(w.message)
            for w in caught
        ), f"expected a warning naming the tool; got {[str(w.message) for w in caught]}"

    def test_reporting_can_be_turned_off(self) -> None:
        agent = _StubAgent([_StubToolset()])

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            wrap_agent(agent, warn_on_unwrappable=False)

        assert not [w for w in caught if issubclass(w.category, UserWarning)]

    def test_guardable_tools_are_still_wrapped_alongside(self) -> None:
        """One unguardable entry must not abort the rest of the walk."""
        agent = _StubAgent([_StubBuiltinTool(), get_weather])

        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            wrap_agent(agent)

        assert agent.tools[1] is not get_weather


class TestSdkGating:
    """No ADK import at module load; a clear error for real ADK objects."""

    def test_importing_agent_airlock_does_not_import_adk(self) -> None:
        import importlib

        importlib.import_module("agent_airlock")
        importlib.import_module("agent_airlock.integrations.google_adk")

        assert "google.adk" not in sys.modules, (
            "the adapter must not import google.adk at module load"
        )

    def test_real_adk_object_raises_when_extra_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class _FakeRealAgent:
            tools: list[Any] = []

        _FakeRealAgent.__module__ = "google.adk.agents.llm_agent"
        monkeypatch.setitem(sys.modules, "google.adk", None)

        with pytest.raises(GoogleADKMissingError) as excinfo:
            GoogleADKAdapter().wrap_agent(_FakeRealAgent())

        message = str(excinfo.value)
        assert "google-adk" in message
        assert 'pip install "agent-airlock[google-adk]"' in message, (
            "the error must carry the install hint"
        )

    def test_stub_agents_bypass_the_sdk_check(self) -> None:
        """A stub never triggers the import — that is the test seam."""
        agent = _StubAgent([get_weather])

        wrap_agent(agent)

        assert "google.adk" not in sys.modules

    def test_version_drift_emits_userwarning(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import types

        # Both keys, deliberately. The adapter runs ``import google.adk as _adk``,
        # which resolves the parent package first, so seeding only ``google.adk``
        # passes on a machine that happens to have some other google-namespace
        # package installed and fails on one that does not. That exact skew was
        # green locally (anaconda ships a ``google`` namespace) and red on CI.
        fake_google = types.ModuleType("google")
        fake_adk = types.ModuleType("google.adk")
        fake_adk.__version__ = "99.0.0"  # type: ignore[attr-defined]
        fake_google.adk = fake_adk  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "google", fake_google)
        monkeypatch.setitem(sys.modules, "google.adk", fake_adk)

        class _FakeRealAgent:
            __module__ = "google.adk.agents.llm_agent"
            tools: list[Any] = []

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            GoogleADKAdapter().wrap_agent(_FakeRealAgent())

        assert any(
            issubclass(w.category, UserWarning)
            and "99.0.0" in str(w.message)
            and "SUPPORTED_GOOGLE_ADK_VERSIONS" in str(w.message)
            for w in caught
        ), f"expected UserWarning about 99.0.0; got {[str(w.message) for w in caught]}"


class TestShapeRejection:
    """Deny-by-default: an unrecognised agent shape fails loudly."""

    def test_agent_without_tools_raises(self) -> None:
        class _NoTools:
            pass

        with pytest.raises(AirlockError, match="no `tools` attribute"):
            wrap_agent(_NoTools())

    def test_non_list_tools_raises(self) -> None:
        class _DictTools:
            tools = {"a": get_weather}

        with pytest.raises(AirlockError, match="unrecognised tools type"):
            wrap_agent(_DictTools())


class TestAgainstRealAdk:
    """Runs only where the ``[google-adk]`` extra is installed; skips otherwise.

    The stub tests above pin the adapter's own contract. These pin the claim
    that matters to a user — that the tool contract *the model sees* is
    byte-identical after wrapping — against the real ADK declaration builder,
    which no stub can stand in for.
    """

    def test_function_declaration_is_identical_after_wrap(self) -> None:
        pytest.importorskip("google.adk", reason="needs the [google-adk] extra")
        from google.adk.tools.function_tool import FunctionTool

        before = FunctionTool(func=get_weather)._get_declaration()
        agent = _StubAgent([get_weather])
        wrap_agent(agent)
        after = FunctionTool(func=agent.tools[0])._get_declaration()

        assert after == before, (
            f"the model-visible tool declaration changed: {before!r} -> {after!r}"
        )

    def test_adk_still_excludes_the_injected_param_from_the_schema(self) -> None:
        """ADK keys off the parameter *name*, so relaxing its type is safe.

        ``FunctionTool._ignore_params`` is a list of names, and ADK 2.9.0
        drops those from the declaration without ever building a schema for
        their type. That is the property the adapter's relaxation relies on,
        so it is asserted here rather than assumed.
        """
        pytest.importorskip("google.adk", reason="needs the [google-adk] extra")
        from google.adk.tools.function_tool import FunctionTool

        before = FunctionTool(func=remember)._get_declaration()
        agent = _StubAgent([remember])
        wrap_agent(agent)
        tool = FunctionTool(func=agent.tools[0])

        assert tool._get_declaration() == before
        assert tool._context_param_name == "tool_context", (
            "ADK must still recognise its injected context parameter"
        )
        assert set(tool._ignore_params) == set(ADK_INJECTED_PARAMS), (
            "ADK_INJECTED_PARAMS has drifted from FunctionTool._ignore_params"
        )
        properties = (tool._get_declaration().parameters_json_schema or {}).get("properties", {})
        assert "tool_context" not in properties


class TestDeclaredSupport:
    """The version claim and the extra pin are machine-checked."""

    def test_supported_versions_documented(self) -> None:
        assert "2.9.0" in SUPPORTED_GOOGLE_ADK_VERSIONS

    def test_pyproject_pins_extra(self) -> None:
        pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
        text = pyproject.read_text(encoding="utf-8")
        assert "google-adk>=2.0,<3.0" in text, (
            "[google-adk] extra must keep the google-adk>=2.0,<3.0 pin"
        )

    def test_exported_from_top_level(self) -> None:
        import agent_airlock

        assert agent_airlock.GoogleADKAdapter is GoogleADKAdapter
        assert agent_airlock.GoogleADKMissingError is GoogleADKMissingError
