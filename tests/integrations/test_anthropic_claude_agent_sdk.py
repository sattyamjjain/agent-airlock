"""Tests for the Anthropic Claude Agent SDK canonical adapter (v0.6.1)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from agent_airlock.integrations.anthropic_claude_agent_sdk import (
    SUPPORTED_SDK_VERSIONS,
    AnthropicClaudeAgentSDKAdapter,
    ClaudeAgentSDKMissingError,
)
from agent_airlock.policy import SecurityPolicy


class _StubTool:
    """A stand-in for a Claude Agent SDK tool object."""

    def __init__(self, name: str) -> None:
        self.name = name

    def forward(self, *args: Any, **kwargs: Any) -> str:
        return f"{self.name}-{args}-{sorted(kwargs.items())}"


class _StubAgent:
    """A stand-in for a Claude Agent SDK Agent object."""

    def __init__(self, tools: dict[str, _StubTool] | list[_StubTool]) -> None:
        self.tools = tools


class TestAnthropicClaudeAgentSDKAdapter:
    """Unit coverage for the canonical-leg adapter."""

    def test_wrap_agent_returns_decorated_callables(self) -> None:
        agent = _StubAgent({"echo": _StubTool("echo")})
        adapter = AnthropicClaudeAgentSDKAdapter()

        wrapped = adapter.wrap_agent(agent)

        assert wrapped is agent
        echo_tool = agent.tools["echo"]  # type: ignore[index]
        # Calling the wrapped forward returns the original payload.
        result = echo_tool.forward(query="ping")
        assert "echo" in result

    def test_wrap_agent_blocks_denied_tool(self) -> None:
        """A denied-tool policy returns a blocked response dict, not the original payload."""
        agent = _StubAgent({"bash": _StubTool("bash")})
        adapter = AnthropicClaudeAgentSDKAdapter()
        policy = SecurityPolicy(denied_tools=["bash"])

        adapter.wrap_agent(agent, policy=policy)

        result = agent.tools["bash"].forward(cmd="ls")  # type: ignore[index]
        assert isinstance(result, dict), "blocked call must return AirlockResponse dict"
        assert result.get("status") == "blocked"
        assert result.get("success") is False
        assert "bash" in str(result.get("error", ""))

    def test_wrap_agent_real_sdk_objects_raise_when_extra_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Real-shaped SDK objects raise ClaudeAgentSDKMissingError when extra absent."""

        class _FakeRealAgent:
            tools: dict[str, _StubTool] = {"x": _StubTool("x")}

        # Spoof the module name so the adapter's "real SDK" check fires.
        _FakeRealAgent.__module__ = "claude_agent_sdk.agent"

        # Force the import inside the adapter to fail.
        import sys

        monkeypatch.setitem(sys.modules, "claude_agent_sdk", None)

        adapter = AnthropicClaudeAgentSDKAdapter()
        with pytest.raises(ClaudeAgentSDKMissingError):
            adapter.wrap_agent(_FakeRealAgent())

    def test_wrap_agent_with_list_tools(self) -> None:
        """List-shaped ``tools`` is also accepted."""
        tools = [_StubTool("a"), _StubTool("b")]
        agent = _StubAgent(tools)
        adapter = AnthropicClaudeAgentSDKAdapter()

        adapter.wrap_agent(agent)

        assert isinstance(agent.tools, list)
        assert len(agent.tools) == 2

    def test_pyproject_pins_extra_at_minimum_version(self) -> None:
        """The ``[claude-agent]`` extra must pin ``>=0.1.58``."""
        pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
        text = pyproject.read_text(encoding="utf-8")
        assert "claude-agent-sdk>=0.1.58" in text, (
            "[claude-agent] extra must keep claude-agent-sdk>=0.1.58 pin"
        )

    def test_supported_versions_tuple_documented(self) -> None:
        """``SUPPORTED_SDK_VERSIONS`` is exported and non-empty."""
        assert "0.1.58" in SUPPORTED_SDK_VERSIONS
