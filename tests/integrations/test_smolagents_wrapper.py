"""Tests for the smolagents wrapper (Feature D)."""

from __future__ import annotations

import pytest

from agent_airlock.exceptions import AirlockError
from agent_airlock.integrations.smolagents_wrapper import (
    PolicyBundle,
    SmolAgentsToolBlocked,
    wrap_agent,
)


class _FakeTool:
    """Minimal smolagents-shaped tool stub."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.calls: list[tuple[tuple, dict]] = []

    def forward(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return f"{self.name}-result"


class _FakeAgent:
    def __init__(self, tools_shape: str = "dict") -> None:
        if tools_shape == "dict":
            self.tools = {
                "search": _FakeTool("search"),
                "exec": _FakeTool("exec"),
            }
        else:
            self.tools = [_FakeTool("search"), _FakeTool("exec")]


def _no_op_guard(tool_name: str, args: dict) -> None:
    return None


def _block_exec_guard(tool_name: str, args: dict) -> None:
    if tool_name == "exec":
        raise AirlockError("exec tool blocked by policy")


class TestErrorHierarchy:
    def test_subclasses_airlock_error(self) -> None:
        assert issubclass(SmolAgentsToolBlocked, AirlockError)


class TestWrapAgent:
    def test_dict_tools_wrapped(self) -> None:
        agent = _FakeAgent(tools_shape="dict")
        wrapped = wrap_agent(agent, PolicyBundle(bundle_id="b1", guards=(_no_op_guard,)))
        result = wrapped.tools["search"].forward(query="hello")
        assert result == "search-result"

    def test_list_tools_wrapped(self) -> None:
        agent = _FakeAgent(tools_shape="list")
        wrapped = wrap_agent(agent, PolicyBundle(bundle_id="b1", guards=(_no_op_guard,)))
        result = wrapped.tools[0].forward(query="hello")
        assert result == "search-result"

    def test_guard_block_raises_typed(self) -> None:
        agent = _FakeAgent()
        wrapped = wrap_agent(agent, PolicyBundle(bundle_id="b1", guards=(_block_exec_guard,)))
        # Search still allowed.
        wrapped.tools["search"].forward(query="hello")
        # Exec refused.
        with pytest.raises(SmolAgentsToolBlocked) as excinfo:
            wrapped.tools["exec"].forward(cmd="ls")
        assert excinfo.value.tool_name == "exec"

    def test_unrecognised_agent_raises(self) -> None:
        class _NoToolsAgent:
            pass

        with pytest.raises(AirlockError):
            wrap_agent(_NoToolsAgent(), PolicyBundle(bundle_id="b1", guards=()))

    def test_no_guards_allows_everything(self) -> None:
        agent = _FakeAgent()
        wrapped = wrap_agent(agent, PolicyBundle(bundle_id="empty", guards=()))
        assert wrapped.tools["search"].forward(q="x") == "search-result"
        assert wrapped.tools["exec"].forward(cmd="ls") == "exec-result"

    def test_multiple_guards_run_in_order(self) -> None:
        seen: list[str] = []

        def g_a(name: str, args: dict) -> None:
            seen.append(f"a:{name}")

        def g_b(name: str, args: dict) -> None:
            seen.append(f"b:{name}")

        agent = _FakeAgent()
        wrapped = wrap_agent(agent, PolicyBundle(bundle_id="b", guards=(g_a, g_b)))
        wrapped.tools["search"].forward(q="x")
        assert seen == ["a:search", "b:search"]
