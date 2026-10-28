"""Regressions for 0.10.25: the CrewAI adapter wraps each tool exactly once.

- CrewAI hands ``Task(agent=a)`` the agent's own ``tools`` list (the same object; verified
  on crewai 1.15.27 by the framework smoke matrix), so ``wrap_crew`` walked one list twice
  and stacked a second Airlock layer on every tool: every allowed call was validated and
  audited twice. Wrapping is now idempotent per tool, within a call and across calls.
"""

from __future__ import annotations

from typing import Any

from agent_airlock.integrations._tool_proxy import GUARDED_MARKER
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


def _guard_layers(callable_: Any) -> int:
    """Count Airlock layers on a tool callable by walking its ``__wrapped__`` chain.

    The marker is shared by every walker since 0.10.28 (``_tool_proxy.GUARDED_MARKER``);
    it was ``__airlock_crewai_guarded__``.
    """
    layers = 0
    current = callable_
    for _ in range(32):
        if getattr(current, GUARDED_MARKER, False):
            layers += 1
        nxt = getattr(current, "__wrapped__", None)
        if nxt is None:
            break
        current = nxt
    return layers


class TestCrewAIWrapsOnce:
    def test_task_sharing_the_agent_list_gets_one_layer(self) -> None:
        tool = _FuncTool("get_order_status")
        shared = [tool]
        crew = _Crew(agents=[_Agent(shared)], tasks=[_Task(shared)])

        CrewAIAdapter().wrap_crew(crew, policy=SecurityPolicy(allowed_tools=["get_order_status"]))

        assert _guard_layers(tool.func) == 1
        assert tool.func(order_id="A-1001") == "get_order_status:A-1001"
        assert tool.calls == 1

    def test_same_tool_in_two_lists_gets_one_layer(self) -> None:
        tool = _FuncTool("get_order_status")
        crew = _Crew(agents=[_Agent([tool])], tasks=[_Task([tool])])

        CrewAIAdapter().wrap_crew(crew, policy=SecurityPolicy(allowed_tools=["get_order_status"]))

        assert _guard_layers(tool.func) == 1

    def test_wrapping_twice_is_idempotent(self) -> None:
        tool = _FuncTool("get_order_status")
        crew = _Crew(agents=[_Agent([tool])], tasks=[])
        adapter = CrewAIAdapter()
        policy = SecurityPolicy(allowed_tools=["get_order_status"])

        adapter.wrap_crew(crew, policy=policy)
        adapter.wrap_crew(crew, policy=policy)
        adapter.wrap_agent(crew.agents[0], policy=policy)

        assert _guard_layers(tool.func) == 1

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
