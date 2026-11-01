"""0.10.29: Airlock at LangGraph's ToolNode, and approvals bound across an interrupt.

Raised in langchain-ai/langgraph#8817 and #8818 (the check belongs in the graph: ToolNode's
``wrap_tool_call``, an ``interrupt()``, or middleware, since the model picks the tool) and
#8938 (treat the checkpoint as untrusted input on load and re-derive the decision). The
stand-ins mirror langgraph 1.2.14's ``ToolCallRequest`` (``tool_call``, ``tool``, ``state``,
``runtime``, ``override``), whose ``runtime.config["configurable"]`` carries the thread,
the task's checkpoint namespace and ``checkpoint_map``, and ``interrupt()``, which raises
on the first run and returns the resume value when the task runs again.
"""

from __future__ import annotations

import asyncio
import dataclasses
import sys
import types
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from pydantic import BaseModel

from agent_airlock.approvals import InMemoryApprovalLedger
from agent_airlock.config import AirlockConfig
from agent_airlock.integrations.langgraph import (
    InterruptApprovals,
    airlock_awrap_tool_call,
    airlock_middleware,
    airlock_wrap_tool_call,
    filter_tools,
)
from agent_airlock.policy import SecurityPolicy


class _ToolMessage:
    """``langchain_core.messages.ToolMessage``: what the wrapper reads and builds."""

    def __init__(self, content: Any, *, tool_call_id: str, name: str = "", status: str = "success"):
        self.content = content
        self.tool_call_id = tool_call_id
        self.name = name
        self.status = status

    def model_copy(self, *, update: dict[str, Any]) -> _ToolMessage:
        copy = _ToolMessage(self.content, tool_call_id=self.tool_call_id, name=self.name)
        copy.status = self.status
        for key, value in update.items():
            setattr(copy, key, value)
        return copy


class _Interrupt(Exception):
    """``GraphInterrupt``: the graph pauses with ``value``."""

    def __init__(self, value: Any) -> None:
        self.value = value
        super().__init__()


_RESUME: list[Any] = []


def _interrupt(value: Any) -> Any:
    """``langgraph.types.interrupt``: raise on the first run, return the resume value after."""
    if _RESUME:
        return _RESUME.pop(0)
    raise _Interrupt(value)


@pytest.fixture(autouse=True)
def frameworks(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """``langchain_core``, ``langgraph`` and ``langchain`` as far as the adapter imports them."""
    modules: dict[str, types.ModuleType] = {}
    for name in (
        "langchain_core",
        "langchain_core.messages",
        "langgraph",
        "langgraph.types",
        "langchain",
        "langchain.agents",
        "langchain.agents.middleware",
    ):
        module = types.ModuleType(name)
        module.__path__ = []  # type: ignore[attr-defined]
        modules[name] = module
        monkeypatch.setitem(sys.modules, name, module)
    modules["langchain_core.messages"].ToolMessage = _ToolMessage  # type: ignore[attr-defined]
    modules["langgraph.types"].interrupt = _interrupt  # type: ignore[attr-defined]
    modules["langchain.agents.middleware"].AgentMiddleware = type("AgentMiddleware", (), {})  # type: ignore[attr-defined]
    _RESUME.clear()
    yield
    _RESUME.clear()


class _PathArgs(BaseModel):
    path: str


class _NoArgs(BaseModel):
    pass


@dataclasses.dataclass
class _Tool:
    """A ``BaseTool``: its name and the schema of what the model fills in."""

    name: str
    tool_call_schema: type[BaseModel] = _PathArgs


@dataclasses.dataclass
class _Runtime:
    config: dict[str, Any]


@dataclasses.dataclass
class _Request:
    """``ToolCallRequest``: ``override`` builds a new one, as ``dataclasses.replace`` does."""

    tool_call: dict[str, Any]
    tool: Any
    state: Any = None
    runtime: Any = None

    def override(self, **overrides: Any) -> _Request:
        return dataclasses.replace(self, **overrides)


TOOLS = {
    "read_file": _Tool("read_file"),
    "delete_file": _Tool("delete_file"),
    "drop_db": _Tool("drop_db", _NoArgs),
}


def _runtime(*, thread: str = "t1", checkpoint: str = "ck-1") -> _Runtime:
    return _Runtime(
        {
            "configurable": {
                "thread_id": thread,
                "checkpoint_ns": "tools:task-1",
                "checkpoint_map": {"": checkpoint},
            }
        }
    )


def _request(name: str, args: dict[str, Any], *, call_id: str = "c1", **runtime: str) -> _Request:
    return _Request(
        {"name": name, "args": args, "id": call_id}, TOOLS.get(name), runtime=_runtime(**runtime)
    )


class _Executor:
    """The node's ``execute``: records each request it runs and answers like a tool."""

    def __init__(self, content: Callable[[dict[str, Any]], Any] | None = None) -> None:
        self.ran: list[dict[str, Any]] = []
        self._content = content or (lambda args: f"ok {args}")

    def __call__(self, request: _Request) -> Any:
        self.ran.append(dict(request.tool_call["args"]))
        return _ToolMessage(
            self._content(request.tool_call["args"]),
            tool_call_id=request.tool_call["id"],
            name=request.tool_call["name"],
        )


def _policy(**extra: Any) -> SecurityPolicy:
    return SecurityPolicy(
        **{
            "denied_tools": ["drop_*"],
            "escalate_tools": {"delete_file": "deletes a file"},
            **extra,
        }
    )


class TestWrapToolCall:
    def test_a_denied_tool_is_an_error_message_and_never_runs(self) -> None:
        execute = _Executor()
        message = airlock_wrap_tool_call(_policy())(_request("drop_db", {}, call_id="c9"), execute)
        assert (message.status, message.tool_call_id, message.name) == ("error", "c9", "drop_db")
        assert message.content.startswith("AIRLOCK_BLOCK")
        assert execute.ran == []

    def test_an_unknown_tool_is_refused_without_running(self) -> None:
        execute = _Executor()
        message = airlock_wrap_tool_call(_policy())(_request("nope", {}), execute)
        assert message.status == "error" and "not a tool this node has" in message.content
        assert execute.ran == []

    def test_an_allowed_tool_runs_with_the_arguments_airlock_admitted(self) -> None:
        execute = _Executor(lambda args: f"mail alice@example.com about {args['path']}")
        request = _request("read_file", {"path": "a.txt", "ghost": 1}, call_id="c2")
        message = airlock_wrap_tool_call(_policy())(request, execute)
        assert execute.ran == [{"path": "a.txt"}]  # the ghost argument never reached the tool
        assert (message.status, message.tool_call_id) == ("success", "c2")
        assert "alice@example.com" not in message.content  # masked

    def test_a_wrong_typed_argument_is_refused_before_it_runs(self) -> None:
        execute = _Executor()
        message = airlock_wrap_tool_call(_policy())(_request("read_file", {"path": 5}), execute)
        assert message.status == "error" and execute.ran == []

    def test_each_call_spends_one_rate_limit_token(self) -> None:
        wrap = airlock_wrap_tool_call(_policy(rate_limits={"read_file": "1/hour"}))
        execute = _Executor()
        assert wrap(_request("read_file", {"path": "a"}), execute).status == "success"
        assert wrap(_request("read_file", {"path": "b"}), execute).status == "error"
        assert execute.ran == [{"path": "a"}]

    def test_a_command_result_is_returned_as_it_is(self) -> None:
        command = object()
        result = airlock_wrap_tool_call(_policy())(
            _request("read_file", {"path": "a"}), lambda r: command
        )
        assert result is command

    def test_an_escalation_with_no_approvals_fails_closed(self) -> None:
        execute = _Executor()
        message = airlock_wrap_tool_call(_policy())(_request("delete_file", {"path": "a"}), execute)
        assert message.status == "error" and "approval" in message.content.lower()
        assert execute.ran == []

    def test_the_async_twin_behaves_the_same(self) -> None:
        awrap = airlock_awrap_tool_call(_policy())

        async def execute(request: _Request) -> Any:
            return _ToolMessage("ran", tool_call_id=request.tool_call["id"])

        allowed = asyncio.run(awrap(_request("read_file", {"path": "a"}), execute))
        denied = asyncio.run(awrap(_request("drop_db", {}), execute))
        unknown = asyncio.run(awrap(_request("nope", {}), execute))
        assert (allowed.status, denied.status, unknown.status) == ("success", "error", "error")

    def test_the_config_is_the_airlocks(self) -> None:
        wrap = airlock_wrap_tool_call(_policy(), config=AirlockConfig(sanitize_output=False))
        execute = _Executor(lambda args: "mail alice@example.com")
        assert (
            wrap(_request("read_file", {"path": "a"}), execute).content == "mail alice@example.com"
        )


class TestFilterTools:
    def test_what_the_policy_refuses_is_not_offered(self) -> None:
        tools = list(TOOLS.values())
        assert [t.name for t in filter_tools(tools, _policy())] == ["read_file", "delete_file"]
        allowlist = SecurityPolicy(allowed_tools=["read_*"])
        assert [t.name for t in filter_tools(tools, allowlist)] == ["read_file"]


class TestMiddleware:
    def test_the_middleware_runs_the_same_check(self) -> None:
        middleware = airlock_middleware(_policy())
        execute = _Executor()
        assert middleware.wrap_tool_call(_request("drop_db", {}), execute).status == "error"
        assert middleware.wrap_tool_call(_request("read_file", {"path": "a"}), execute).status == (
            "success"
        )

    def test_without_langchain_the_middleware_cannot_be_built(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setitem(sys.modules, "langchain.agents.middleware", None)
        with pytest.raises(ImportError):
            airlock_middleware(_policy())


def _approvals() -> tuple[SecurityPolicy, InterruptApprovals]:
    ledger = InMemoryApprovalLedger()
    return _policy(approval_ledger=ledger), InterruptApprovals(b"k" * 32, ledger)


def _asked(wrap: Any, request: _Request) -> Any:
    """Run the call until it interrupts; return what the graph paused with."""
    with pytest.raises(_Interrupt) as paused:
        wrap(request, _Executor())
    return paused.value.value


class TestInterruptApprovals:
    def test_an_escalation_interrupts_with_a_sealed_request(self) -> None:
        policy, approvals = _approvals()
        asked = _asked(
            airlock_wrap_tool_call(policy, approvals=approvals),
            _request("delete_file", {"path": "a"}),
        )
        request = asked["airlock_approval"]
        assert (request["tool"], request["rule"], request["arguments"]) == (
            "delete_file",
            "delete_file",
            {"path": "a"},
        )
        assert request["binding"] and request["seal"]

    def test_an_approved_resume_runs_and_spends_its_token(self) -> None:
        policy, approvals = _approvals()
        policy = _policy(
            approval_ledger=policy.approval_ledger, rate_limits={"delete_file": "1/hour"}
        )
        wrap = airlock_wrap_tool_call(policy, approvals=approvals)
        request = _request("delete_file", {"path": "a"})
        _RESUME.append(approvals.approve(_asked(wrap, request)))
        execute = _Executor()
        assert wrap(request, execute).status == "success"
        assert execute.ran == [{"path": "a"}]

    def test_a_replayed_approval_admits_nothing(self) -> None:
        policy, approvals = _approvals()
        wrap = airlock_wrap_tool_call(policy, approvals=approvals)
        request = _request("delete_file", {"path": "a"})
        resume = approvals.approve(_asked(wrap, request))
        _RESUME.extend([resume, resume])  # the task runs again from the same checkpoint
        assert wrap(request, _Executor()).status == "success"
        replayed = _Executor()
        assert wrap(request, replayed).status == "error" and replayed.ran == []

    def test_a_forged_checkpoint_row_admits_nothing(self) -> None:
        policy, approvals = _approvals()
        wrap = airlock_wrap_tool_call(policy, approvals=approvals)
        request = _request("delete_file", {"path": "a"})
        asked = _asked(wrap, request)["airlock_approval"]
        # A resume value written into the store by someone without the key.
        _RESUME.append(
            {
                "airlock_approval": {
                    "binding": asked["binding"],
                    "nonce": "0" * 32,
                    "token": "f" * 64,
                }
            }
        )
        execute = _Executor()
        assert wrap(request, execute).status == "error" and execute.ran == []

    def test_a_resume_from_another_checkpoint_admits_nothing(self) -> None:
        policy, approvals = _approvals()
        wrap = airlock_wrap_tool_call(policy, approvals=approvals)
        resume = approvals.approve(_asked(wrap, _request("delete_file", {"path": "a"})))
        # The head checkpoint row is gone: the task runs again from an older checkpoint.
        _RESUME.append(resume)
        execute = _Executor()
        older = _request("delete_file", {"path": "a"}, checkpoint="ck-0")
        assert wrap(older, execute).status == "error" and execute.ran == []

    def test_an_approval_for_other_arguments_admits_nothing(self) -> None:
        policy, approvals = _approvals()
        wrap = airlock_wrap_tool_call(policy, approvals=approvals)
        resume = approvals.approve(_asked(wrap, _request("delete_file", {"path": "a"})))
        _RESUME.append(resume)
        execute = _Executor()
        assert wrap(_request("delete_file", {"path": "/etc"}), execute).status == "error"
        assert execute.ran == []

    def test_an_approval_moved_to_another_call_admits_nothing(self) -> None:
        policy, approvals = _approvals()
        wrap = airlock_wrap_tool_call(policy, approvals=approvals)
        resume = approvals.approve(_asked(wrap, _request("delete_file", {"path": "a"})))
        # The real approval's nonce (still unspent in the ledger), relabelled for another
        # call of the same tool: only the token, bound to the first call, tells them apart.
        other = _request("delete_file", {"path": "/etc"}, call_id="c2")
        relabelled = {
            "airlock_approval": {
                **resume["airlock_approval"],
                "binding": approvals.binding(other, "delete_file", {"path": "/etc"}),
            }
        }
        _RESUME.append(relabelled)
        execute = _Executor()
        assert wrap(other, execute).status == "error" and execute.ran == []

    def test_an_altered_request_is_not_signed(self) -> None:
        policy, approvals = _approvals()
        asked = _asked(
            airlock_wrap_tool_call(policy, approvals=approvals),
            _request("delete_file", {"path": "a"}),
        )
        asked["airlock_approval"]["binding"] = "0" * 64
        with pytest.raises(ValueError, match="sealed"):
            approvals.approve(asked)

    def test_approvals_need_an_approval_ledger_and_a_real_key(self) -> None:
        with pytest.raises(ValueError, match="approval_ledger"):
            airlock_wrap_tool_call(
                _policy(), approvals=InterruptApprovals(b"k" * 32, InMemoryApprovalLedger())
            )
        with pytest.raises(ValueError, match="16 bytes"):
            InterruptApprovals(b"short", InMemoryApprovalLedger())
