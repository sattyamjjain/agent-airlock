"""Tests for the Anthropic Claude Agent SDK canonical adapter (v0.6.1)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from agent_airlock.integrations.anthropic_claude_agent_sdk import (
    SUPPORTED_SDK_VERSIONS,
    AnthropicClaudeAgentSDKAdapter,
    ClaudeAgentSDKMissingError,
    posttooluse_audit_payload,
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
        """The ``[claude-agent]`` extra must pin ``>=0.1.58,<0.2.0``.

        v0.7.3 widens the floor from a single-version pin to an
        explicit cap-below-0.2 range. The 0.2.x line (Opus 4.7's
        Agent SDK >=0.2.111 requirement) is intentionally out of
        scope until a separate forward-bump.
        """
        pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
        text = pyproject.read_text(encoding="utf-8")
        assert "claude-agent-sdk>=0.1.58,<0.2.0" in text, (
            "[claude-agent] extra must pin claude-agent-sdk>=0.1.58,<0.2.0 (v0.7.3)"
        )

    def test_supported_versions_tuple_documented(self) -> None:
        """``SUPPORTED_SDK_VERSIONS`` is exported and includes 0.1.58 + 0.1.73."""
        assert "0.1.58" in SUPPORTED_SDK_VERSIONS
        assert "0.1.73" in SUPPORTED_SDK_VERSIONS, (
            "v0.7.3 must add 0.1.73 to SUPPORTED_SDK_VERSIONS (PostToolUse duration_ms support)"
        )


class TestPostToolUseDurationMsRegression:
    """v0.7.3 regression — Claude Agent SDK 0.1.73 PostToolUse duration_ms.

    The 0.1.73 release (2026-05-04) added ``duration_ms`` to
    PostToolUse and PostToolUseFailure hook inputs. The adapter must
    forward the field into the audit-receipt body when present and
    remain backward-compatible with 0.1.58 payloads where it's absent.

    Source — Anthropic May 2026 release notes:
    https://pypi.org/project/claude-agent-sdk/
    """

    def test_duration_ms_propagates_when_sdk_supplies_it(self) -> None:
        """SDK 0.1.73+ payloads carry duration_ms; the audit body forwards it."""
        body = posttooluse_audit_payload(
            {
                "tool_name": "Bash",
                "tool_input": {"command": "ls -l"},
                "duration_ms": 142,
            }
        )
        assert body["tool_name"] == "Bash"
        assert body["tool_input"] == {"command": "ls -l"}
        assert body["duration_ms"] == 142
        assert body["sdk_field_durations_present"] is True

    def test_missing_duration_ms_omitted_for_older_sdk_payloads(self) -> None:
        """0.1.58 payloads have no duration_ms; the helper does NOT fabricate one."""
        body = posttooluse_audit_payload(
            {
                "tool_name": "Read",
                "tool_input": {"path": "/etc/hosts"},
            }
        )
        assert body["tool_name"] == "Read"
        assert "duration_ms" not in body, "must not synthesize duration_ms when absent"
        assert body["sdk_field_durations_present"] is False

    def test_zero_duration_ms_preserved_distinctly_from_absent(self) -> None:
        """0ms tool execution is a real payload — must NOT be conflated with absent."""
        body = posttooluse_audit_payload(
            {
                "tool_name": "Echo",
                "duration_ms": 0,
            }
        )
        assert body["duration_ms"] == 0
        assert body["sdk_field_durations_present"] is True
