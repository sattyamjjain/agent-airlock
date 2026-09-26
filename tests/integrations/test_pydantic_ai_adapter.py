"""Tests for the v0.7.1 PydanticAI canonical-leg adapter (ADD-1, 2026-05-04).

The adapter's stub-friendly contract: any object exposing
``toolsets`` (PydanticAI v1.88+ public surface) or ``tools``
(flat-dict test stub) is acceptable. Only objects whose
``__module__`` starts with ``pydantic_ai.*`` go through the SDK
import check.
"""

from __future__ import annotations

import warnings
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from agent_airlock.integrations.pydantic_ai import (
    SUPPORTED_PYDANTIC_AI_VERSIONS,
    PydanticAIAdapter,
    PydanticAIMissingError,
)
from agent_airlock.policy import SecurityPolicy


class _StubTool:
    """A stand-in for a PydanticAI Tool object (uses ``function`` attribute)."""

    def __init__(self, name: str) -> None:
        self.name = name

    def function(self, *args: Any, **kwargs: Any) -> str:
        return f"{self.name}-{args}-{sorted(kwargs.items())}"


class _StubToolset:
    def __init__(self, tools: dict[str, _StubTool]) -> None:
        self.tools = tools


class _StubAgent:
    """A stand-in for a PydanticAI Agent (exposes ``toolsets``)."""

    def __init__(self, toolsets: list[_StubToolset]) -> None:
        self.toolsets = toolsets

    output_validate: Any = None


class TestPydanticAIAdapter:
    """Coverage for ADD-1 (PydanticAI canonical-leg trio)."""

    def test_wrap_agent_returns_decorated_callables(self) -> None:
        """wrap_agent walks toolsets and replaces each tool's function."""
        toolset = _StubToolset({"echo": _StubTool("echo")})
        agent = _StubAgent([toolset])
        adapter = PydanticAIAdapter(attach_output_validate=False)

        wrapped = adapter.wrap_agent(agent)

        assert wrapped is agent
        echo_tool = agent.toolsets[0].tools["echo"]
        result = echo_tool.function(query="ping")
        assert "echo" in result

    def test_wrap_agent_blocks_denied_tool(self) -> None:
        """A denied-tool policy returns a blocked response dict."""
        toolset = _StubToolset({"delete_db": _StubTool("delete_db")})
        agent = _StubAgent([toolset])
        adapter = PydanticAIAdapter(attach_output_validate=False)
        policy = SecurityPolicy(denied_tools=["delete_*"])

        adapter.wrap_agent(agent, policy=policy)

        result = agent.toolsets[0].tools["delete_db"].function(target="users")
        assert isinstance(result, dict), "blocked call must return AirlockResponse dict"
        assert result.get("status") == "blocked"
        assert result.get("success") is False
        assert "delete_db" in str(result.get("error", ""))

    def test_wrap_agent_real_sdk_objects_raise_when_extra_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Real-shaped PydanticAI objects raise PydanticAIMissingError when extra absent."""

        class _FakeRealAgent:
            toolsets: list[_StubToolset] = []

        _FakeRealAgent.__module__ = "pydantic_ai.agent"
        import sys

        monkeypatch.setitem(sys.modules, "pydantic_ai", None)

        adapter = PydanticAIAdapter()
        with pytest.raises(PydanticAIMissingError):
            adapter.wrap_agent(_FakeRealAgent())

    def test_output_validate_hook_wired(self) -> None:
        """attach_output_validate=True (default) installs a sanitiser hook."""
        toolset = _StubToolset({"echo": _StubTool("echo")})
        agent = _StubAgent([toolset])
        adapter = PydanticAIAdapter(attach_output_validate=True)

        adapter.wrap_agent(agent)

        assert callable(agent.output_validate)
        # The hook returns the sanitised value. Use a string with a known
        # PII shape (an email) to confirm sanitization runs.
        result = agent.output_validate("ping me at user@example.com please")
        # sanitize_output returns redacted string; we don't assert on
        # the redaction format (that's the sanitizer's contract) — just
        # that the hook is callable and returns a string.
        assert isinstance(result, str)
        assert len(result) > 0

    def test_supported_version_drift_emits_userwarning(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Real SDK shape with an unsupported version → UserWarning, no fail."""
        import sys
        import types

        fake_pydantic_ai = types.ModuleType("pydantic_ai")
        fake_pydantic_ai.__version__ = "1.99.0"  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "pydantic_ai", fake_pydantic_ai)

        class _FakeRealAgent:
            __module__ = "pydantic_ai.agent"
            toolsets: list[_StubToolset] = [_StubToolset({"x": _StubTool("x")})]

        adapter = PydanticAIAdapter(attach_output_validate=False)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            adapter.wrap_agent(_FakeRealAgent())

        assert any(
            issubclass(w.category, UserWarning)
            and "1.99.0" in str(w.message)
            and "SUPPORTED_PYDANTIC_AI_VERSIONS" in str(w.message)
            for w in caught
        ), f"expected UserWarning about 1.99.0; got {[str(w.message) for w in caught]}"

    def test_pyproject_pins_extra_at_minimum_version(self) -> None:
        """The ``[pydantic-ai]`` extra must pin ``>=1.88.0,<2.0``."""
        pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
        text = pyproject.read_text(encoding="utf-8")
        assert "pydantic-ai>=1.88.0,<3.0" in text, (
            "[pydantic-ai] extra must keep the pydantic-ai>=1.88.0,<3.0 pin. The "
            "ceiling was <2.0, which excluded the 2.x line entirely (stable since "
            "2026-06-23). 2.x keeps `agent.toolsets`, so the tool walk is unchanged; "
            "it drops `output_validate`, which the adapter now warns about."
        )

    def test_supported_versions_tuple_documented(self) -> None:
        assert "1.89.1" in SUPPORTED_PYDANTIC_AI_VERSIONS
        assert "1.88.0" in SUPPORTED_PYDANTIC_AI_VERSIONS


class TestOutputValidateCannotBeSilentlySkipped:
    """PydanticAI 2.x removed ``output_validate``; the adapter must say so.

    Verified against pydantic-ai 2.43.0 in a scratch venv: ``agent.toolsets``
    still exists (so the tool walk keeps working) but ``output_validate`` is
    gone. The adapter used to return quietly in that case, leaving a caller
    with ``attach_output_validate=True`` and no output sanitisation at all.
    """

    def test_missing_hook_warns_instead_of_returning_quietly(self) -> None:
        class _NoOutputValidate:
            """A 2.x-shaped agent: toolsets, but no output_validate."""

            def __init__(self) -> None:
                self.toolsets = [_StubToolset({"echo": _StubTool("echo")})]

        agent = _NoOutputValidate()
        assert not hasattr(agent, "output_validate")

        adapter = PydanticAIAdapter(attach_output_validate=True)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            adapter.wrap_agent(agent)

        assert any(
            issubclass(w.category, UserWarning) and "output_validate" in str(w.message)
            for w in caught
        ), f"expected a UserWarning naming output_validate; got {[str(w.message) for w in caught]}"

    def test_the_warning_says_tools_are_still_guarded(self) -> None:
        """A user who reads it must not conclude the whole adapter is off."""

        class _NoOutputValidate:
            def __init__(self) -> None:
                self.toolsets = [_StubToolset({"echo": _StubTool("echo")})]

        agent = _NoOutputValidate()
        adapter = PydanticAIAdapter(attach_output_validate=True)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            adapter.wrap_agent(agent)

        message = next(str(w.message) for w in caught if issubclass(w.category, UserWarning))
        assert "Tool arguments are still validated" in message
        assert "NOT sanitised" in message

    def test_opting_out_does_not_warn(self) -> None:
        class _NoOutputValidate:
            def __init__(self) -> None:
                self.toolsets = [_StubToolset({"echo": _StubTool("echo")})]

        adapter = PydanticAIAdapter(attach_output_validate=False)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            adapter.wrap_agent(_NoOutputValidate())

        assert not [w for w in caught if issubclass(w.category, UserWarning)]

    def test_a_1x_shaped_agent_still_gets_the_hook(self) -> None:
        """The warning must not fire where the hook genuinely attaches."""
        agent = _StubAgent([_StubToolset({"echo": _StubTool("echo")})])
        adapter = PydanticAIAdapter(attach_output_validate=True)

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            adapter.wrap_agent(agent)

        assert callable(agent.output_validate)
        assert not [w for w in caught if issubclass(w.category, UserWarning)]


class _RunContextShape:
    """Stands in for ``pydantic_ai.RunContext``: injected by the framework, no schema."""


class _FunctionSchemaShape:
    """Mirrors pydantic-ai 2.31.1's ``FunctionSchema`` (``_function_schema.py``).

    An agent run invokes ``tool.function_schema.call`` (``toolsets/function.py``), and
    ``call`` runs ``self.function`` — the function captured when the ``Tool`` was built,
    not ``Tool.function``. The real ``call`` is async and awaits sync tools in a thread;
    the dispatch is what matters here.
    """

    def __init__(self, function: Callable[..., Any], *, takes_ctx: bool) -> None:
        self.function = function
        self.takes_ctx = takes_ctx

    def call(self, args_dict: dict[str, Any], ctx: Any) -> Any:
        args = [ctx] if self.takes_ctx else []
        return self.function(*args, **args_dict)


class _ToolShape:
    """Mirrors a pydantic-ai ``Tool``: ``function``, ``takes_ctx`` and ``function_schema``."""

    def __init__(self, name: str, function: Callable[..., Any], *, takes_ctx: bool = False):
        self.name = name
        self.function = function
        self.takes_ctx = takes_ctx
        self.function_schema = _FunctionSchemaShape(function, takes_ctx=takes_ctx)


def _wrap(tool: _ToolShape, policy: SecurityPolicy | None = None) -> None:
    agent = _StubAgent([_StubToolset({tool.name: tool})])  # type: ignore[dict-item]
    PydanticAIAdapter(attach_output_validate=False).wrap_agent(agent, policy=policy)


def _blocked(result: Any) -> bool:
    return isinstance(result, dict) and result.get("status") == "blocked"


class TestAgentRunsGoThroughAirlock:
    """Regression: only ``tool.function`` was replaced, which an agent run never calls.

    On pydantic-ai 2.31.1 a plain tool and a ``RunContext`` tool both ran under a deny-all
    policy, so real runs were outside Airlock entirely: no validation, policy or audit.
    """

    def test_the_run_path_invokes_the_guarded_callable(self) -> None:
        calls: list[int] = []

        def lookup(n: int) -> int:
            calls.append(n)
            return n

        tool = _ToolShape("lookup", lookup)
        _wrap(tool, policy=SecurityPolicy(denied_tools=["*"]))

        assert _blocked(tool.function_schema.call({"n": 5}, ctx=None))
        assert calls == []
        assert tool.function_schema.function is tool.function

    def test_a_schema_holding_some_other_function_is_left_alone(self) -> None:
        def lookup(n: int) -> int:
            return n

        def other(n: int) -> int:
            return -n

        tool = _ToolShape("lookup", lookup)
        tool.function_schema.function = other
        _wrap(tool)

        assert tool.function_schema.function is other


class TestToolArgumentsAreValidated:
    """Regression: the adapter handed Airlock a ``(*args, **kwargs)`` proxy."""

    def test_a_wrong_type_is_rejected(self) -> None:
        calls: list[Any] = []

        def lookup(n: int) -> int:
            calls.append(n)
            return n

        tool = _ToolShape("lookup", lookup)
        _wrap(tool)

        result = tool.function_schema.call({"n": "5"}, ctx=None)

        assert _blocked(result)
        assert "validation failed" in str(result.get("error"))
        assert calls == []

    def test_the_run_context_is_not_strictly_validated(self) -> None:
        # Without relaxing it, a schema-less RunContext fails Airlock's wrap outright.
        def lookup(ctx: _RunContextShape, n: int) -> int:
            return n

        tool = _ToolShape("lookup", lookup, takes_ctx=True)
        _wrap(tool)

        assert tool.function_schema.call({"n": 5}, _RunContextShape()) == 5
        assert _blocked(tool.function_schema.call({"n": "5"}, _RunContextShape()))
