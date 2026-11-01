"""0.10.29: pydantic-ai deferred approvals, check order and rejected tool calls.

Raised in pydantic/pydantic-ai#9015 ("ask" with no approver attached fails closed, since the
escalation type subclasses the violation), #9085 (the retry ``cause``: ``unknown_tool`` and
``unavailable_tool`` are rejected before any tool runs) and #8839 (an approval says the call
is allowed, not that it is free). The stand-ins mirror pydantic-ai 2.64's call path: a run
toolset's ``call_tool(name, tool_args, ctx, tool)`` runs ``tool.function_schema.call``,
which passes the ``RunContext`` first only to a tool that takes one.
"""

from __future__ import annotations

import asyncio
import inspect
import sys
import time
import types
import warnings
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any

import pytest

from agent_airlock.approvals import InMemoryApprovalLedger, StandingGrant, args_digest
from agent_airlock.exceptions import AirlockError
from agent_airlock.integrations import pydantic_ai_approvals as approvals_module
from agent_airlock.integrations.pydantic_ai import PydanticAIAdapter, PydanticAIMissingError
from agent_airlock.integrations.pydantic_ai_approvals import log_tool_rejections, run_toolset
from agent_airlock.policy import SecurityPolicy


class _ApprovalRequired(Exception):
    """pydantic-ai's ``ApprovalRequired``: ``metadata`` reaches ``DeferredToolRequests``."""

    def __init__(self, metadata: dict[str, Any] | None = None) -> None:
        self.metadata = metadata
        super().__init__()


@pytest.fixture(autouse=True)
def pydantic_ai(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """An installed pydantic-ai, as far as the adapter imports it."""

    @dataclass
    class WrapperToolset:
        wrapped: Any

        async def get_tools(self, ctx: Any) -> Any:
            return await self.wrapped.get_tools(ctx)

        async def call_tool(self, name: str, tool_args: Any, ctx: Any, tool: Any) -> Any:
            return await self.wrapped.call_tool(name, tool_args, ctx, tool)

    package = types.ModuleType("pydantic_ai")
    package.__path__ = []
    exceptions = types.ModuleType("pydantic_ai.exceptions")
    exceptions.ApprovalRequired = _ApprovalRequired  # type: ignore[attr-defined]
    toolsets = types.ModuleType("pydantic_ai.toolsets")
    toolsets.WrapperToolset = WrapperToolset  # type: ignore[attr-defined]
    for name, module in (
        ("pydantic_ai", package),
        ("pydantic_ai.exceptions", exceptions),
        ("pydantic_ai.toolsets", toolsets),
    ):
        monkeypatch.setitem(sys.modules, name, module)
    yield


class _RunContext:
    """``pydantic_ai.RunContext``: the fields this path reads."""

    def __init__(
        self, call_id: str = "call-1", *, approved: bool = False, messages: Any = ()
    ) -> None:
        self.tool_call_id = call_id
        self.tool_call_approved = approved
        self.messages = list(messages)


class _FunctionSchema:
    """``FunctionSchema.call``: runs the captured function, the context first if it takes one."""

    def __init__(self, function: Callable[..., Any], *, takes_ctx: bool) -> None:
        self.function = function
        self.takes_ctx = takes_ctx

    async def call(self, args: dict[str, Any], ctx: Any) -> Any:
        result = self.function(*([ctx] if self.takes_ctx else []), **args)
        return await result if inspect.isawaitable(result) else result


class _Tool:
    def __init__(self, name: str, function: Callable[..., Any], *, takes_ctx: bool) -> None:
        self.name = name
        self.function = function
        self.takes_ctx = takes_ctx
        self.function_schema = _FunctionSchema(function, takes_ctx=takes_ctx)


class _FunctionToolset:
    def __init__(self, tools: dict[str, _Tool]) -> None:
        self.tools = tools

    async def get_tools(self, ctx: Any) -> dict[str, _Tool]:
        return dict(self.tools)

    async def call_tool(self, name: str, tool_args: Any, ctx: Any, tool: Any) -> Any:
        return await self.tools[name].function_schema.call(tool_args, ctx)


class _Agent:
    def __init__(self, toolset: _FunctionToolset) -> None:
        self.toolsets = [toolset]
        self._toolset = toolset

    def _get_toolset(self, **kwargs: Any) -> Any:
        return self._toolset


@dataclass
class _Harness:
    agent: _Agent
    ran: list[dict[str, Any]]

    def call(self, ctx: _RunContext, name: str = "delete_file", **args: Any) -> Any:
        """One step of a run: list the tools, then call one, as pydantic-ai does."""
        toolset = self.agent._get_toolset()

        async def step() -> Any:
            await toolset.get_tools(ctx)
            return await toolset.call_tool(name, args, ctx, self.agent._toolset.tools[name])

        return asyncio.run(step())


def _policy(**extra: Any) -> SecurityPolicy:
    settings: dict[str, Any] = {
        "escalate_tools": {"delete_file": "deletes a file"},
        "rate_limits": {"delete_file": "1/hour"},
        "approval_ledger": InMemoryApprovalLedger(),
    }
    return SecurityPolicy(**{**settings, **extra})


def _harness(
    policy: SecurityPolicy | None = None,
    *,
    takes_ctx: bool = False,
    adapter: PydanticAIAdapter | None = None,
) -> _Harness:
    ran: list[dict[str, Any]] = []

    if takes_ctx:

        def delete_file(ctx: Any, path: str) -> str:
            ran.append({"path": path})
            return f"deleted {path}"

    else:

        def delete_file(path: str) -> str:  # type: ignore[misc]
            ran.append({"path": path})
            return f"deleted {path}"

    agent = _Agent(
        _FunctionToolset({"delete_file": _Tool("delete_file", delete_file, takes_ctx=takes_ctx)})
    )
    adapter = adapter or PydanticAIAdapter(attach_output_validate=False, defer_escalations=True)
    adapter.wrap_agent(agent, policy=policy if policy is not None else _policy())
    return _Harness(agent, ran)


def _reason(result: Any) -> str | None:
    if isinstance(result, dict) and result.get("success") is False:
        return str(result.get("metadata", {}).get("violation_type") or result["block_reason"])
    return None


class TestDeferredApprovals:
    @pytest.mark.parametrize("takes_ctx", [False, True], ids=["tool_plain", "takes_ctx"])
    def test_an_escalated_call_is_deferred_and_spends_nothing(self, takes_ctx: bool) -> None:
        harness = _harness(takes_ctx=takes_ctx)
        with pytest.raises(_ApprovalRequired) as deferred:
            harness.call(_RunContext("call-1"), path="notes.txt")
        assert deferred.value.metadata == {
            "airlock": {"rule": "delete_file", "reason": "deletes a file"}
        }
        assert harness.ran == []
        # The deferral took no rate-limit token: the approved call still has the hour's one.
        assert harness.call(_RunContext("call-1", approved=True), path="notes.txt") == (
            "deleted notes.txt"
        )

    def test_an_approved_call_counts_against_rate_limits(self) -> None:
        harness = _harness()
        assert harness.call(_RunContext("call-1", approved=True), path="a") == "deleted a"
        assert _reason(harness.call(_RunContext("call-2", approved=True), path="b")) == (
            "rate_limit"
        )

    def test_an_approval_is_used_once(self) -> None:
        harness = _harness(_policy(rate_limits={}))
        assert harness.call(_RunContext("call-1", approved=True), path="a") == "deleted a"
        # The same approval again (a resumed history sent twice) records nothing, so the call
        # meets the policy as if nobody had approved it.
        replayed = harness.call(_RunContext("call-1", approved=True), path="a")
        assert _reason(replayed) == "escalation_required"
        assert harness.ran == [{"path": "a"}]

    def test_without_a_run_context_the_policy_decides(self) -> None:
        harness = _harness()
        tool = harness.agent._toolset.tools["delete_file"]
        # A tool_plain tool called outside the run toolset has no run context to read.
        result = asyncio.run(tool.function_schema.call({"path": "a"}, _RunContext()))
        assert _reason(result) == "escalation_required"

    def test_a_call_the_policy_refuses_is_not_put_to_a_human(self) -> None:
        harness = _harness(_policy(denied_tools=["delete_*"]))
        assert _reason(harness.call(_RunContext("call-1"), path="a")) == "tool_denied"

    def test_a_standing_grant_admits_without_deferring(self) -> None:
        grant = StandingGrant(tool="delete_file", arguments={"path": "tmp.txt"})
        harness = _harness(_policy(standing_grants=[grant]))
        assert harness.call(_RunContext("call-1"), path="tmp.txt") == "deleted tmp.txt"

    def test_a_run_context_is_not_part_of_the_approval_digest(self) -> None:
        ledger = InMemoryApprovalLedger()
        policy = _policy(approval_ledger=ledger)
        harness = _harness(
            policy, takes_ctx=True, adapter=PydanticAIAdapter(attach_output_validate=False)
        )
        # A host records an approval of the model's arguments; the RunContext the tool takes
        # first is pydantic-ai's, so it is not in the digest the call claims.
        ledger.grant("delete_file", args_digest({"path": "a"}), expires_at=time.time() + 60)
        tool = harness.agent._toolset.tools["delete_file"]
        assert asyncio.run(tool.function_schema.call({"path": "a"}, _RunContext())) == "deleted a"

    def test_without_defer_escalations_an_escalation_still_fails_closed(self) -> None:
        harness = _harness(adapter=PydanticAIAdapter(attach_output_validate=False))
        assert _reason(harness.call(_RunContext("call-1"), path="a")) == "escalation_required"

    def test_a_second_wrap_that_defers_is_not_skipped(self) -> None:
        harness = _harness(adapter=PydanticAIAdapter(attach_output_validate=False))
        policy = _policy()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            PydanticAIAdapter(attach_output_validate=False, defer_escalations=True).wrap_agent(
                harness.agent, policy=policy
            )
        # Both the tool and the run toolset hook get a second layer, and say so.
        assert len(caught) == 2
        assert all("already guarded with other settings" in str(w.message) for w in caught)
        with pytest.raises(_ApprovalRequired):
            harness.call(_RunContext("call-1"), path="a")

    def test_defer_escalations_needs_an_approval_ledger(self) -> None:
        with pytest.raises(AirlockError, match="approval_ledger"):
            _harness(SecurityPolicy(escalate_tools={"delete_file": "deletes"}))

    def test_defer_escalations_needs_pydantic_ai(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setitem(sys.modules, "pydantic_ai.exceptions", None)
        with pytest.raises(PydanticAIMissingError):
            _harness()


def _part(
    tool: str, call_id: str, *, cause: str = "unknown_tool", attempt: int | None = 1, limit: int = 3
) -> Any:
    retry = types.SimpleNamespace(cause=cause, attempt=attempt, max_retries=limit)
    return types.SimpleNamespace(
        part_kind="tool-return",
        outcome="retried",
        tool_name=tool,
        tool_call_id=call_id,
        retry=retry,
    )


def _request(*parts: Any) -> Any:
    return types.SimpleNamespace(parts=list(parts))


class _Recorder:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    def warning(self, event: str, **fields: Any) -> None:
        self.events.append((event, fields))

    def info(self, event: str, **fields: Any) -> None:
        self.events.append((event, fields))


class TestRejectedToolCalls:
    def test_unknown_and_hidden_calls_are_logged_with_their_retry_count(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        recorder = _Recorder()
        monkeypatch.setattr(approvals_module, "logger", recorder)
        validation = _part("read_file", "call-9", cause="validation_error")
        success = types.SimpleNamespace(part_kind="tool-return", outcome="success", tool_name="x")
        messages = [
            _request(_part("drop_db", "call-1"), validation, success),
            _request(_part("search", "call-2", cause="unavailable_tool", attempt=None)),
        ]
        rejections = log_tool_rejections(messages)
        assert [(r.tool_name, r.cause, r.attempt, r.retries) for r in rejections] == [
            ("drop_db", "unknown_tool", 1, 1),
            ("search", "unavailable_tool", None, 1),
        ]
        assert [event for event, _ in recorder.events] == ["pydantic_ai_tool_rejected"] * 2
        assert recorder.events[0][1]["outcome"] == "retried"

    def test_the_last_retry_gets_a_final_record(self, monkeypatch: pytest.MonkeyPatch) -> None:
        recorder = _Recorder()
        monkeypatch.setattr(approvals_module, "logger", recorder)
        (rejection,) = log_tool_rejections([_request(_part("drop_db", "call-3", attempt=3))])
        assert rejection.final
        assert [event for event, _ in recorder.events] == [
            "pydantic_ai_tool_rejected",
            "pydantic_ai_tool_rejected_final",
        ]

    def test_the_run_toolset_logs_each_rejection_once_and_spends_nothing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        recorder = _Recorder()
        monkeypatch.setattr(approvals_module, "logger", recorder)
        harness = _harness(_policy(rate_limits={"delete_file": "2/hour"}))
        history = [_request(_part("drop_db", "call-1"))]
        # Two steps over the same history: the rejection is logged once, and it took no
        # rate-limit token, so both later calls still fit in the two the hour allows.
        for step, path in ((2, "a"), (3, "b")):
            ctx = _RunContext(f"call-{step}", approved=True, messages=history)
            assert harness.call(ctx, path=path) == f"deleted {path}"
        rejected = [event for event, _ in recorder.events if event == "pydantic_ai_tool_rejected"]
        assert rejected == ["pydantic_ai_tool_rejected"]

    def test_without_pydantic_ai_the_run_toolset_is_left_as_it_was(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setitem(sys.modules, "pydantic_ai.toolsets", None)
        toolset = _FunctionToolset({})
        assert run_toolset(toolset, tracker=None) is toolset


def _one_call_per_hour(tool: str) -> SecurityPolicy:
    return SecurityPolicy(rate_limits={tool: "1/hour"})


class TestTwoWrapsStayTwoLayers:
    """An agent wrapped twice with different settings keeps two layers, run after run.

    Until 0.10.29 only a shim's outermost layer was read, so each wrap's run-time walk found
    the other's layer outside its own and added one more: every run grew the stack.
    Layers are counted by what they do: under a one-call-per-hour limit a second layer of
    that policy spends the only token, and the first call is refused.
    """

    def test_a_pydantic_ai_agent_keeps_its_layers_across_runs(self) -> None:
        ran: list[int] = []

        def read(n: int) -> int:
            ran.append(n)
            return n

        tool = _Tool("read", read, takes_ctx=False)
        agent = _Agent(_FunctionToolset({"read": tool}))
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            PydanticAIAdapter(attach_output_validate=False).wrap_agent(
                agent, policy=_one_call_per_hour("read")
            )
            PydanticAIAdapter(attach_output_validate=False).wrap_agent(
                agent, policy=SecurityPolicy()
            )
            for _ in range(3):  # three runs, each walking the run toolset with both wraps
                agent._get_toolset()
        assert asyncio.run(tool.function_schema.call({"n": 1}, _RunContext())) == 1
        assert _reason(asyncio.run(tool.function_schema.call({"n": 2}, _RunContext()))) == (
            "rate_limit"
        )
        assert ran == [1]

    def test_a_crewai_crew_keeps_its_layers_across_kickoffs(self) -> None:
        from agent_airlock.integrations.crewai import CrewAIAdapter

        calls: list[str] = []

        class FuncTool:
            name = "get_order_status"

            def func(self, order_id: str) -> str:
                calls.append(order_id)
                return order_id

        tool = FuncTool()

        class Crew:
            def __init__(self) -> None:
                self.agents = [types.SimpleNamespace(tools=[tool])]
                self.tasks: list[Any] = []

            def _prepare_tools(self, *args: Any) -> list[Any]:
                return [tool]

        crew = Crew()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            CrewAIAdapter().wrap_crew(crew, policy=_one_call_per_hour("get_order_status"))
            CrewAIAdapter().wrap_crew(crew, policy=SecurityPolicy())
            for _ in range(3):  # three kickoffs
                crew._prepare_tools()
        assert tool.func(order_id="A-1") == "A-1"
        assert _reason(tool.func(order_id="A-2")) == "rate_limit"
        assert calls == ["A-1"]

    def test_a_layer_beneath_counts_as_guarded(self) -> None:
        from agent_airlock.integrations._tool_proxy import guarded_with, mark_guarded

        first, second = object(), object()

        def inner() -> None: ...

        def outer() -> None: ...

        mark_guarded(inner, first)
        mark_guarded(outer, second, beneath=inner)
        assert guarded_with(outer, second) and guarded_with(outer, first)
        assert not guarded_with(outer, object())
