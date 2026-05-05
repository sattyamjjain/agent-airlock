"""Tests for the v0.7.2 CrewAI canonical-leg adapter (ADD-1, 2026-05-05; closes #5).

The adapter's stub-friendly contract: any object exposing ``agents``
(Crew shape) or ``tools`` (Agent shape) is acceptable. Only objects
whose ``__module__`` starts with ``crewai.*`` go through the SDK
import check.
"""

from __future__ import annotations

import warnings
from pathlib import Path
from typing import Any

import pytest

from agent_airlock.integrations.crewai import (
    SUPPORTED_CREWAI_VERSIONS,
    CrewAIAdapter,
    CrewAIMissingError,
)
from agent_airlock.policy import SecurityPolicy


class _StubBaseTool:
    """A stand-in for a CrewAI ``BaseTool`` subclass (uses ``_run``)."""

    def __init__(self, name: str) -> None:
        self.name = name

    def _run(self, *args: Any, **kwargs: Any) -> str:
        return f"{self.name}-{sorted(kwargs.items())}"


class _StubFuncTool:
    """A stand-in for an ``@tool``-decorated callable (uses ``func``)."""

    def __init__(self, name: str) -> None:
        self.name = name

    def func(self, *args: Any, **kwargs: Any) -> str:
        return f"{self.name}-func-{sorted(kwargs.items())}"


class _StubAgent:
    """A stand-in for a CrewAI ``Agent`` (exposes ``tools`` list)."""

    def __init__(self, tools: list[Any]) -> None:
        self.tools = tools


class _StubTask:
    def __init__(self, tools: list[Any]) -> None:
        self.tools = tools


class _StubCrew:
    def __init__(
        self,
        agents: list[_StubAgent],
        tasks: list[_StubTask] | None = None,
    ) -> None:
        self.agents = agents
        self.tasks = tasks or []


class TestCrewAIAdapter:
    """Coverage for ADD-1 (CrewAI canonical-leg trio)."""

    def test_wrap_crew_returns_decorated_callables(self) -> None:
        """wrap_crew walks every Agent's tools and replaces _run."""
        agent = _StubAgent([_StubBaseTool("search"), _StubFuncTool("scrape")])
        crew = _StubCrew(agents=[agent])
        adapter = CrewAIAdapter()

        wrapped = adapter.wrap_crew(crew)

        assert wrapped is crew
        # _run is replaced; calling through it goes through Airlock.
        result = crew.agents[0].tools[0]._run(query="hello")
        assert "search" in result
        # func is replaced for @tool-decorated stubs.
        result2 = crew.agents[0].tools[1].func(input="x")
        assert "scrape" in result2

    def test_wrap_crew_blocks_denied_tool(self) -> None:
        """A denied-tool policy returns a blocked response dict."""
        agent = _StubAgent([_StubBaseTool("delete_all")])
        crew = _StubCrew(agents=[agent])
        adapter = CrewAIAdapter()
        policy = SecurityPolicy(denied_tools=["delete_*"])

        adapter.wrap_crew(crew, policy=policy)

        result = crew.agents[0].tools[0]._run(target="prod")
        assert isinstance(result, dict)
        assert result.get("status") == "blocked"
        assert result.get("success") is False
        assert "delete_all" in str(result.get("error", ""))

    def test_wrap_crew_real_sdk_objects_raise_when_extra_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Real-shaped CrewAI objects raise CrewAIMissingError when extra absent."""

        class _FakeRealCrew:
            agents: list[_StubAgent] = []

        _FakeRealCrew.__module__ = "crewai.crew"
        import sys

        monkeypatch.setitem(sys.modules, "crewai", None)

        adapter = CrewAIAdapter()
        with pytest.raises(CrewAIMissingError):
            adapter.wrap_crew(_FakeRealCrew())

    def test_wrap_agent_standalone(self) -> None:
        """wrap_agent works without a Crew (standalone researcher pattern)."""
        agent = _StubAgent([_StubBaseTool("read_file"), _StubBaseTool("write_file")])
        adapter = CrewAIAdapter()

        adapter.wrap_agent(agent)

        # Both tools wrapped; calling _run still produces a result.
        for tool in agent.tools:
            result = tool._run(path="/tmp/x")
            assert isinstance(result, str)
            assert tool.name in result

    def test_task_level_tool_overrides_walked(self) -> None:
        """wrap_crew also walks Task(tools=[...]) overrides."""
        agent = _StubAgent([])
        task_tool = _StubBaseTool("specialised")
        task = _StubTask([task_tool])
        crew = _StubCrew(agents=[agent], tasks=[task])
        adapter = CrewAIAdapter()
        policy = SecurityPolicy(denied_tools=["specialised"])

        adapter.wrap_crew(crew, policy=policy)

        # Task-level tool is wrapped, so the policy applies.
        result = crew.tasks[0].tools[0]._run(input="x")
        assert isinstance(result, dict)
        assert result.get("status") == "blocked"

    def test_supported_version_drift_emits_userwarning(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Real SDK shape with an unsupported version → UserWarning, no fail."""
        import sys
        import types

        fake_crewai = types.ModuleType("crewai")
        fake_crewai.__version__ = "1.13.0"  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "crewai", fake_crewai)

        class _FakeRealCrew:
            __module__ = "crewai.crew"
            agents: list[_StubAgent] = [_StubAgent([_StubBaseTool("x")])]

        adapter = CrewAIAdapter()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            adapter.wrap_crew(_FakeRealCrew())

        assert any(
            issubclass(w.category, UserWarning)
            and "1.13.0" in str(w.message)
            and "SUPPORTED_CREWAI_VERSIONS" in str(w.message)
            for w in caught
        ), f"expected UserWarning about 1.13.0; got {[str(w.message) for w in caught]}"

    def test_pyproject_pins_extra_at_minimum_version(self) -> None:
        """The ``[crewai]`` extra must pin ``>=1.14.4,<2.0``."""
        pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
        text = pyproject.read_text(encoding="utf-8")
        assert "crewai>=1.14.4,<2.0" in text, "[crewai] extra must keep crewai>=1.14.4,<2.0 pin"

    def test_supported_versions_tuple_documented(self) -> None:
        assert "1.14.4" in SUPPORTED_CREWAI_VERSIONS
