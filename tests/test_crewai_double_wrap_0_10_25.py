"""Regressions for 0.10.25: the CrewAI adapter wraps each tool exactly once.

- CrewAI hands ``Task(agent=a)`` the agent's own ``tools`` list (the same object; verified
  on crewai 1.15.27 by the framework smoke matrix), so ``wrap_crew`` walked one list twice
  and stacked a second Airlock layer on every tool: every allowed call was validated and
  audited twice. Wrapping is now idempotent per tool, within a call and across calls.

Layers are counted by what they do: under a one-call-per-hour budget a second layer
spends the token the first one took, so the call is refused. Until the 0.10.28 review a
helper counted them along ``__wrapped__``, which ``named_tool_proxy`` never sets, and
reported one layer on a tool wrapped twice.
"""

from __future__ import annotations

from typing import Any

from agent_airlock.integrations.crewai import CrewAIAdapter
from agent_airlock.policy import SecurityPolicy


class _FuncTool:
    """Stand-in for an ``@tool``-decorated CrewAI tool (guarded at ``func``)."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.calls = 0

        def func(order_id: str) -> str:
            self.calls += 1
            return f"{name}:{order_id}"

        self.func = func


class _Agent:
    def __init__(self, tools: list[Any]) -> None:
        self.tools = tools


class _Task:
    def __init__(self, tools: list[Any]) -> None:
        self.tools = tools


class _Crew:
    def __init__(self, agents: list[_Agent], tasks: list[_Task]) -> None:
        self.agents = agents
        self.tasks = tasks


def _one_call_per_hour() -> SecurityPolicy:
    return SecurityPolicy(
        allowed_tools=["get_order_status"], rate_limits={"get_order_status": "1/hour"}
    )


def _assert_one_layer(tool: _FuncTool) -> None:
    """One Airlock layer spends one token per call: the first call runs, the second is refused."""
    assert tool.func(order_id="A-1001") == "get_order_status:A-1001"
    out: Any = tool.func(order_id="A-1002")
    assert isinstance(out, dict) and out["block_reason"] == "rate_limit"
    assert tool.calls == 1


class TestCrewAIWrapsOnce:
    def test_task_sharing_the_agent_list_gets_one_layer(self) -> None:
        tool = _FuncTool("get_order_status")
        shared = [tool]
        crew = _Crew(agents=[_Agent(shared)], tasks=[_Task(shared)])

        CrewAIAdapter().wrap_crew(crew, policy=_one_call_per_hour())

        _assert_one_layer(tool)

    def test_same_tool_in_two_lists_gets_one_layer(self) -> None:
        tool = _FuncTool("get_order_status")
        crew = _Crew(agents=[_Agent([tool])], tasks=[_Task([tool])])

        CrewAIAdapter().wrap_crew(crew, policy=_one_call_per_hour())

        _assert_one_layer(tool)

    def test_wrapping_twice_is_idempotent(self) -> None:
        tool = _FuncTool("get_order_status")
        crew = _Crew(agents=[_Agent([tool])], tasks=[])
        adapter = CrewAIAdapter()
        policy = _one_call_per_hour()

        adapter.wrap_crew(crew, policy=policy)
        adapter.wrap_crew(crew, policy=policy)
        adapter.wrap_agent(crew.agents[0], policy=policy)

        _assert_one_layer(tool)

    def test_control_a_forced_second_layer_is_seen(self) -> None:
        tool = _FuncTool("get_order_status")
        adapter = CrewAIAdapter()
        policy = _one_call_per_hour()

        adapter._wrap_one(tool, name="get_order_status", policy=policy)
        adapter._wrap_one(tool, name="get_order_status", policy=policy)  # no idempotency check

        out: Any = tool.func(order_id="A-1001")
        assert isinstance(out, dict) and out["block_reason"] == "rate_limit"
        assert tool.calls == 0

    def test_denied_tool_still_refused_once(self) -> None:
        tool = _FuncTool("delete_order")
        shared = [tool]
        crew = _Crew(agents=[_Agent(shared)], tasks=[_Task(shared)])

        CrewAIAdapter().wrap_crew(crew, policy=SecurityPolicy(allowed_tools=["get_order_status"]))

        out: Any = tool.func(order_id="A-1001")
        assert isinstance(out, dict)
        assert out["success"] is False
        assert out["block_reason"] == "policy_violation"
        assert tool.calls == 0
