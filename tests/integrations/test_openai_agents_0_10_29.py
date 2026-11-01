"""0.10.29: OpenAI Agents SDK approvals from the run's own interruptions, nested budgets,
and hard and soft refusals as the SDK's tool-guardrail behaviors.

Raised in openai/openai-agents-python#5413 (only approve items taken from the interruptions
of the state you are resuming), #5453 (a parent run with ``max_turns=2`` can still let each
nested agent run up to 10 turns) and #5351 (a halt flag that refuses every later call).
The stand-ins mirror openai-agents v0.24.0: ``RunState.get_interruptions()`` returning
detached copies, ``approve(item)`` / ``reject(item, rejection_message=...)``, a
``ToolApprovalItem`` naming its call by ``call_id`` with JSON ``arguments``, a function
tool's invoker with ``prepare_arguments`` (the arguments the SDK will call the tool with,
defaults filled in) and ``__wrapped__``, ``Agent.as_tool`` running ``Runner.run`` with its
``max_turns`` and ``hooks`` and handing an error to ``failure_error_function``,
``RunHooks.on_llm_start`` before each model call, and ``ToolGuardrailFunctionOutput.allow``
/ ``reject_content`` / ``raise_exception``.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import sys
import types
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest

from agent_airlock import Airlock, AirlockContext, SecurityPolicy
from agent_airlock._arg_walk import bind_arguments, signature_of
from agent_airlock.approvals import InMemoryApprovalLedger, args_digest
from agent_airlock.integrations.openai_agents import (
    InterruptionApprovals,
    airlock_agent_tool,
    airlock_tool_input_guardrail,
    airlock_turn_hooks,
)
from agent_airlock.nested_runs import RunBudgetExhausted, run_budget


class _MaxTurnsExceeded(Exception):
    pass


class _RunContextWrapper:
    def __init__(self, context: Any = None) -> None:
        self.context = context


class _ToolContext(_RunContextWrapper):
    def __init__(self, tool_name: str, context: Any = None) -> None:
        super().__init__(context)
        self.tool_name = tool_name


class _RunHooks:
    """``RunHooksBase``: a no-op for every lifecycle event."""

    async def on_llm_start(self, context: Any, agent: Any, prompt: Any, items: Any) -> None:
        pass

    async def on_agent_end(self, context: Any, agent: Any, output: Any) -> None:
        pass


@dataclass
class _Output:
    output_info: Any
    behavior: dict[str, Any]

    @classmethod
    def allow(cls, output_info: Any = None) -> _Output:
        return cls(output_info, {"type": "allow"})

    @classmethod
    def reject_content(cls, message: str, output_info: Any = None) -> _Output:
        return cls(output_info, {"type": "reject_content", "message": message})

    @classmethod
    def raise_exception(cls, output_info: Any = None) -> _Output:
        return cls(output_info, {"type": "raise_exception"})


@dataclass
class _ToolInputGuardrail:
    guardrail_function: Callable[[Any], Any]
    name: str | None = None


def _default_tool_error_function(ctx: Any, error: Exception) -> str:
    return f"An error occurred while running the tool. Error: {error}"


@pytest.fixture(autouse=True)
def agents(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """openai-agents as far as the adapter imports it."""
    sdk = types.ModuleType("agents")
    exceptions = types.ModuleType("agents.exceptions")
    tool_context = types.ModuleType("agents.tool_context")
    exceptions.MaxTurnsExceeded = _MaxTurnsExceeded  # type: ignore[attr-defined]
    tool_context.ToolContext = _ToolContext  # type: ignore[attr-defined]
    for name, value in {
        "exceptions": exceptions,
        "MaxTurnsExceeded": _MaxTurnsExceeded,
        "RunContextWrapper": _RunContextWrapper,
        "RunHooks": _RunHooks,
        "default_tool_error_function": _default_tool_error_function,
        "ToolGuardrailFunctionOutput": _Output,
        "ToolInputGuardrail": _ToolInputGuardrail,
    }.items():
        setattr(sdk, name, value)
    monkeypatch.setitem(sys.modules, "agents", sdk)
    monkeypatch.setitem(sys.modules, "agents.exceptions", exceptions)
    monkeypatch.setitem(sys.modules, "agents.tool_context", tool_context)
    yield


# --------------------------------------------------------------------------- #
# Function tools and paused runs
# --------------------------------------------------------------------------- #


class _Invoker:
    """``_FailureHandlingFunctionToolInvoker``: runs the tool, hands an error to the
    failure function (``None`` raises it), and prepares a paused call's arguments."""

    def __init__(
        self,
        impl: Callable[[Any, str], Any],
        failure: Callable[[Any, Exception], Any] | None,
        prepare: Callable[[str], tuple[list[Any], dict[str, Any]]] | None = None,
    ) -> None:
        self._impl, self._failure, self._prepare = impl, failure, prepare
        self.bound_to: Any = None

    async def __call__(self, ctx: Any, input: str) -> Any:
        try:
            return await self._impl(ctx, input)
        except Exception as error:
            if self._failure is None:
                raise
            result = self._failure(ctx, error)
            return await result if inspect.isawaitable(result) else result

    def prepare_arguments(self, input: str, tool_name: str) -> Any:
        args, kwargs = self._prepare(input) if self._prepare else ([], {})
        return types.SimpleNamespace(args=args, kwargs=kwargs)

    def __agents_bind_function_tool__(self, tool: Any) -> _Invoker:
        bound = _Invoker(self._impl, self._failure, self._prepare)
        bound.bound_to = tool
        return bound


@dataclass
class _FunctionTool:
    """The SDK's ``FunctionTool``, as far as the adapter reads it.

    The docstring is load-bearing on Python 3.10: without one, ``@dataclass`` builds it
    from ``inspect.signature(cls)``, which follows the ``__wrapped__`` default to None and
    raises.
    """

    name: str
    on_invoke_tool: Any
    __wrapped__: Any = None


def _function_tool(func: Callable[..., Any], defaults: dict[str, Any] | None = None) -> Any:
    """``function_tool(func)``: the SDK calls ``func`` positionally, defaults filled in."""
    names = [n for n in inspect.signature(func).parameters if n != "ctx"]

    def prepare(input: str) -> tuple[list[Any], dict[str, Any]]:
        data = {**(defaults or {}), **json.loads(input)}
        return [data[n] for n in names], {}

    async def impl(ctx: Any, input: str) -> Any:
        return func(*prepare(input)[0])

    invoker = _Invoker(impl, _default_tool_error_function, prepare)
    return _FunctionTool(func.__name__, invoker, func)


@dataclass
class _RawCall:
    call_id: str
    name: str
    arguments: str


@dataclass
class _ApprovalItem:
    """``ToolApprovalItem``: equal only to itself, naming its call through ``raw_item``."""

    raw_item: _RawCall
    agent: Any = None

    @property
    def name(self) -> str:
        return self.raw_item.name

    @property
    def arguments(self) -> str:
        return self.raw_item.arguments

    @property
    def call_id(self) -> str:
        return self.raw_item.call_id

    def __eq__(self, other: object) -> bool:
        return self is other

    def __hash__(self) -> int:
        return id(self)


def _item(call_id: str = "call_1", agent: Any = None, **arguments: Any) -> _ApprovalItem:
    raw = _RawCall(call_id, "delete_file", json.dumps(arguments or {"path": "a.txt"}))
    return _ApprovalItem(raw, agent)


class _RunState:
    def __init__(self, *items: _ApprovalItem) -> None:
        self._pending = list(items)
        self.approved: list[_ApprovalItem] = []
        self.rejected: list[tuple[_ApprovalItem, str | None]] = []
        self.refuse_approval = False

    def get_interruptions(self) -> list[_ApprovalItem]:
        # Detached copies, as the SDK returns them: the same call, not the same object.
        return [_ApprovalItem(_RawCall(**vars(i.raw_item)), i.agent) for i in self._pending]

    def approve(self, item: _ApprovalItem) -> None:
        if self.refuse_approval:
            raise RuntimeError("Cannot approve tool: RunState has no context")
        self.approved.append(item)

    def reject(self, item: _ApprovalItem, *, rejection_message: str | None = None) -> None:
        self.rejected.append((item, rejection_message))


class _RecordingLedger(InMemoryApprovalLedger):
    def __init__(self) -> None:
        super().__init__()
        self.granted: list[tuple[str, str]] = []

    def grant(self, tool_name: str, args_digest: str, *, expires_at: float) -> None:
        self.granted.append((tool_name, args_digest))
        super().grant(tool_name, args_digest, expires_at=expires_at)


def _escalating() -> SecurityPolicy:
    return SecurityPolicy(
        escalate_tools={"delete_file": "deletes a file"}, approval_ledger=_RecordingLedger()
    )


def _granted(policy: SecurityPolicy) -> list[tuple[str, str]]:
    ledger = policy.approval_ledger
    assert isinstance(ledger, _RecordingLedger)
    return ledger.granted


def _guarded(policy: SecurityPolicy) -> tuple[Callable[..., Any], list[str]]:
    ran: list[str] = []

    @Airlock(policy=policy)
    def delete_file(path: str, force: bool = False) -> str:
        ran.append(path)
        return f"deleted {path}"

    return delete_file, ran


def _reason(result: Any) -> str | None:
    if isinstance(result, dict) and result.get("success") is False:
        return str(result["block_reason"])
    return None


class TestInterruptionApprovals:
    def test_an_approved_interruption_runs_once(self) -> None:
        policy = _escalating()
        delete_file, ran = _guarded(policy)
        item = _item()
        state = _RunState(item)
        InterruptionApprovals(policy).approve(state, item)
        assert [i.call_id for i in state.approved] == ["call_1"]
        assert delete_file("a.txt") == "deleted a.txt"  # the resumed call, positional
        assert _reason(delete_file("a.txt")) == "escalation_required"  # spent
        assert ran == ["a.txt"]

    def test_without_an_approval_the_call_fails_closed(self) -> None:
        delete_file, ran = _guarded(_escalating())
        assert _reason(delete_file("a.txt")) == "escalation_required" and ran == []

    def test_an_item_from_another_run_is_refused(self) -> None:
        policy = _escalating()
        delete_file, _ = _guarded(policy)
        theirs, ours = _item("call_9"), _RunState(_item("call_1"))
        with pytest.raises(ValueError, match="not an interruption of the state being resumed"):
            InterruptionApprovals(policy).approve(ours, theirs)
        assert ours.approved == [] and _reason(delete_file("a.txt")) == "escalation_required"

    def test_the_same_call_with_other_arguments_is_refused(self) -> None:
        state = _RunState(_item("call_1", path="a.txt"))
        with pytest.raises(ValueError, match="not an interruption"):
            InterruptionApprovals(_escalating()).approve(state, _item("call_1", path="/etc"))

    def test_two_pending_calls_with_one_identity_are_refused(self) -> None:
        state = _RunState(_item("call_1"), _item("call_1"))
        with pytest.raises(ValueError, match="more than one pending call"):
            InterruptionApprovals(_escalating()).approve(state, _item("call_1"))

    def test_a_call_is_approved_once(self) -> None:
        approvals, item = InterruptionApprovals(_escalating()), _item()
        state = _RunState(item)
        approvals.approve(state, item)
        with pytest.raises(ValueError, match="approved already"):
            approvals.approve(state, item)
        assert len(state.approved) == 1

    def test_a_replay_in_another_run_is_refused(self) -> None:
        approvals = InterruptionApprovals(_escalating())
        approvals.approve(_RunState(_item("call_1")), _item("call_1"))
        # The same call id resurfacing in another run's state: approved once already.
        replayed = _RunState(_item("call_1"))
        with pytest.raises(ValueError, match="approved already"):
            approvals.approve(replayed, _item("call_1"))
        assert replayed.approved == []

    def test_an_approval_the_sdk_refuses_keeps_the_call_approvable(self) -> None:
        policy = _escalating()
        approvals, state = InterruptionApprovals(policy), _RunState(_item())
        state.refuse_approval = True
        with pytest.raises(RuntimeError):
            approvals.approve(state, _item())
        assert _granted(policy) == []
        state.refuse_approval = False
        approvals.approve(state, _item())
        assert len(state.approved) == 1 and len(_granted(policy)) == 1

    def test_the_digest_is_of_the_arguments_the_sdk_calls_with(self) -> None:
        policy = _escalating()
        delete_file, ran = _guarded(policy)
        agent = types.SimpleNamespace(tools=[_function_tool(delete_file, {"force": False})])
        item = _item(agent=agent)  # the model left ``force`` out; the SDK fills it in
        InterruptionApprovals(policy).approve(_RunState(item), item)
        assert delete_file("a.txt", False) == "deleted a.txt" and ran == ["a.txt"]

    def test_without_the_tool_the_json_object_is_digested(self) -> None:
        policy = _escalating()
        delete_file, ran = _guarded(policy)
        item = _item()  # no agent to find the tool on
        InterruptionApprovals(policy).approve(_RunState(item), item)
        # The SDK passes the default the model left out: not the approved arguments.
        assert _reason(delete_file("a.txt", False)) == "escalation_required" and ran == []

    def test_a_call_the_sdk_cannot_prepare_is_digested_as_json(self) -> None:
        policy = _escalating()
        delete_file, ran = _guarded(policy)
        tool = _function_tool(delete_file)
        tool.on_invoke_tool._prepare = None  # validators of its own: the SDK prepares nothing
        item = _item(agent=types.SimpleNamespace(tools=[tool]))
        InterruptionApprovals(policy).approve(_RunState(item), item)
        assert delete_file("a.txt") == "deleted a.txt" and ran == ["a.txt"]

    def test_a_tool_taking_the_run_context_is_digested_without_it(self) -> None:
        policy = _escalating()

        def write(ctx: _RunContextWrapper, path: str) -> str:
            return path

        tool = _function_tool(write)
        tool.name = "delete_file"
        item = _item(agent=types.SimpleNamespace(tools=[tool]))
        InterruptionApprovals(policy).approve(_RunState(item), item)
        bound = bind_arguments(signature_of(write), (object(), "a.txt"), {}, skip_first=True)
        assert _granted(policy) == [("delete_file", args_digest(bound))]
        assert args_digest(bound) == args_digest({"path": "a.txt"})

    def test_arguments_that_are_not_an_object_are_refused(self) -> None:
        item = _ApprovalItem(_RawCall("call_1", "delete_file", "[1]"))
        with pytest.raises(ValueError, match="not a JSON object"):
            InterruptionApprovals(_escalating()).approve(_RunState(item), item)

    def test_a_rejection_goes_to_the_sdk_with_its_message(self) -> None:
        item = _item()
        state = _RunState(item)
        InterruptionApprovals(_escalating()).reject(state, item, message="not today")
        assert [(i.call_id, m) for i, m in state.rejected] == [("call_1", "not today")]
        with pytest.raises(ValueError):
            InterruptionApprovals(_escalating()).reject(_RunState(), item)

    def test_approvals_need_an_approval_ledger(self) -> None:
        with pytest.raises(ValueError, match="approval_ledger"):
            InterruptionApprovals(SecurityPolicy())


# --------------------------------------------------------------------------- #
# Agents as tools
# --------------------------------------------------------------------------- #


@dataclass
class _Agent:
    """An ``Agent`` whose run takes ``turns`` model calls; ``as_tool`` is the SDK's shape."""

    name: str
    turns: int = 1
    calls: int = 0  # model calls made, across its runs
    seen_max_turns: list[int] = field(default_factory=list)

    def as_tool(
        self,
        tool_name: str | None,
        tool_description: str | None,
        *,
        max_turns: int | None = None,
        hooks: Any = None,
        failure_error_function: Any = _default_tool_error_function,
    ) -> _FunctionTool:
        async def run(ctx: Any, input: str) -> Any:  # Runner.run(..., max_turns, hooks)
            cap = max_turns if max_turns is not None else 10
            self.seen_max_turns.append(cap)
            for turn in range(1, self.turns + 1):
                if turn > cap:
                    raise _MaxTurnsExceeded(f"Max turns ({cap}) exceeded")
                if hooks is not None:
                    await hooks.on_llm_start(ctx, self, None, [])
                self.calls += 1
                await asyncio.sleep(0)
            if hooks is not None:
                await hooks.on_agent_end(ctx, self, "done")
            return f"{self.name} answered {json.loads(input)['input']}"

        return _FunctionTool(tool_name or self.name, _Invoker(run, failure_error_function))


def _invoke(tool: Any, prompt: str = "q") -> Any:
    ctx = _ToolContext(tool.name)
    return asyncio.run(tool.on_invoke_tool(ctx, json.dumps({"input": prompt})))


def _refused(answer: Any, kind: str) -> bool:
    spent = "no nested run is left" if kind == "depth" else "no turn is left"
    return isinstance(answer, str) and "AIRLOCK_BLOCK" in answer and spent in answer


class TestNestedAgentTools:
    def test_each_model_call_takes_a_turn_of_the_tree(self) -> None:
        agent = _Agent("researcher", turns=2)
        tool = airlock_agent_tool(agent)
        with run_budget(max_turns=3) as budget:
            assert _invoke(tool) == "researcher answered q"
            assert budget.turns_left == 1
            refused = _invoke(tool)  # needs 2, the tree has 1
        assert _refused(refused, "turns")
        assert agent.calls == 3  # never more than the root allowed

    def test_concurrent_siblings_share_the_turns(self) -> None:
        agent = _Agent("researcher", turns=2)
        tool = airlock_agent_tool(agent)

        async def both() -> list[Any]:
            calls = (tool.on_invoke_tool(_ToolContext(tool.name), '{"input": "q"}') for _ in "ab")
            return list(await asyncio.gather(*calls))

        with run_budget(max_turns=3):
            answers = asyncio.run(both())
        assert agent.calls == 3 and sum(_refused(a, "turns") for a in answers) == 1

    def test_exhausted_depth_is_the_callers_failed_tool_result(self) -> None:
        agent = _Agent("researcher")
        with run_budget(max_depth=0):
            answer = _invoke(airlock_agent_tool(agent))
        assert _refused(answer, "depth") and agent.calls == 0

    def test_a_hard_stop_raises_out_of_the_run(self) -> None:
        agent = _Agent("researcher", turns=2)
        with run_budget(max_depth=0, hard_stop=True), pytest.raises(RunBudgetExhausted):
            _invoke(airlock_agent_tool(agent))
        with run_budget(max_turns=1, hard_stop=True), pytest.raises(RunBudgetExhausted) as hit:
            _invoke(airlock_agent_tool(agent))  # runs dry inside the nested run
        assert hit.value.kind == "turns" and agent.calls == 1

    def test_a_share_is_the_sdks_cap_and_comes_back_unspent(self) -> None:
        agent = _Agent("researcher", turns=3)
        tool = airlock_agent_tool(agent, max_turns=2)
        with run_budget(max_turns=10) as budget:
            assert _refused(_invoke(tool), "turns")
            assert agent.seen_max_turns == [2] and budget.turns_left == 8
            agent.turns = 1
            assert _invoke(tool) == "researcher answered q" and budget.turns_left == 7

    def test_with_no_budget_the_sdks_own_limit_and_error_apply(self) -> None:
        agent = _Agent("researcher", turns=11)
        answer = _invoke(airlock_agent_tool(agent))
        assert answer.startswith("An error occurred") and "Max turns (10)" in answer
        assert "AIRLOCK_BLOCK" not in answer

    def test_your_failure_function_and_hooks_are_still_called(self) -> None:
        seen: list[str] = []

        class Hooks(_RunHooks):
            async def on_llm_start(self, *args: Any) -> None:
                seen.append("llm_start")

            async def on_agent_end(self, *args: Any) -> None:
                seen.append("agent_end")

        agent = _Agent("researcher", turns=2)
        tool = airlock_agent_tool(agent, hooks=Hooks(), failure_error_function=None)
        with run_budget(max_turns=5):
            assert _invoke(tool) == "researcher answered q"
        assert seen == ["llm_start", "llm_start", "agent_end"]
        agent.turns = 11
        with pytest.raises(_MaxTurnsExceeded):  # ``None`` raises the tool's other errors
            _invoke(tool)

    def test_a_copied_tool_keeps_its_budget(self) -> None:
        tool = airlock_agent_tool(_Agent("researcher"))
        copy = tool.on_invoke_tool.__agents_bind_function_tool__("the copy")
        assert type(copy) is type(tool.on_invoke_tool)
        assert copy.bound_to == "the copy"  # the SDK's invoker, rebound, beneath it
        with run_budget(max_depth=0):
            assert _refused(asyncio.run(copy(_ToolContext("t"), '{"input": "q"}')), "depth")

    def test_limits_are_checked_when_the_tool_is_made(self) -> None:
        for bad in (-1, True, 1.5):
            with pytest.raises(ValueError, match="max_turns"):
                airlock_agent_tool(_Agent("researcher"), max_turns=bad)  # type: ignore[arg-type]


class TestRootTurns:
    def test_the_root_runs_own_turns_count(self) -> None:
        hooks = airlock_turn_hooks()
        tool = airlock_agent_tool(_Agent("researcher", turns=1))

        async def root_turn() -> None:
            await hooks.on_llm_start(None, None, None, [])

        with run_budget(max_turns=2):
            asyncio.run(root_turn())  # the root's own model call
            assert _invoke(tool) == "researcher answered q"
            with pytest.raises(RunBudgetExhausted):  # soft, but a root has no caller
                asyncio.run(root_turn())

    def test_with_no_budget_nothing_is_counted(self) -> None:
        asyncio.run(airlock_turn_hooks().on_llm_start(None, None, None, []))


# --------------------------------------------------------------------------- #
# Tool input guardrail
# --------------------------------------------------------------------------- #


def _data(tool: str, context: Any = None) -> Any:
    return types.SimpleNamespace(context=_ToolContext(tool, context), agent=None)


class TestToolInputGuardrail:
    def test_a_halted_run_raises_and_a_refused_call_is_rejected(self) -> None:
        guardrail = airlock_tool_input_guardrail(SecurityPolicy(denied_tools=["drop_*"]))
        run = AirlockContext(agent_id="agent")
        allowed = guardrail.guardrail_function(_data("read_file", run))
        refused = guardrail.guardrail_function(_data("drop_db", run))
        run.halt("a hard stop")
        stopped = guardrail.guardrail_function(_data("read_file", run))
        assert allowed.behavior == {"type": "allow"}
        assert refused.behavior["type"] == "reject_content"
        assert refused.behavior["message"].startswith("AIRLOCK_BLOCK")
        assert stopped.behavior == {"type": "raise_exception"}
        assert stopped.output_info["reason"] == "a hard stop"

    def test_the_run_set_around_the_call_counts(self) -> None:
        guardrail = airlock_tool_input_guardrail()
        with AirlockContext(agent_id="agent") as run:
            run.halt("halted by the host")
            stopped = guardrail.guardrail_function(_data("read_file"))
        assert stopped.behavior["type"] == "raise_exception"

    def test_without_the_sdk_nothing_is_built(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setitem(sys.modules, "agents", None)
        with pytest.raises(ImportError, match="openai-agents"):
            airlock_tool_input_guardrail()
