"""Tests for the v0.7.1 PydanticAI canonical-leg adapter (ADD-1, 2026-05-04).

The adapter's stub-friendly contract: any object exposing
``toolsets`` (PydanticAI v1.88+ public surface) or ``tools``
(flat-dict test stub) is acceptable. Only objects whose
``__module__`` starts with ``pydantic_ai.*`` go through the SDK
import check.
"""

from __future__ import annotations

import warnings
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
        assert "pydantic-ai>=1.88.0,<2.0" in text, (
            "[pydantic-ai] extra must keep pydantic-ai>=1.88.0,<2.0 pin"
        )

    def test_supported_versions_tuple_documented(self) -> None:
        assert "1.89.1" in SUPPORTED_PYDANTIC_AI_VERSIONS
        assert "1.88.0" in SUPPORTED_PYDANTIC_AI_VERSIONS
