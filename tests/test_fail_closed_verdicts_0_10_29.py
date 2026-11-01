"""0.10.29: an approval that cannot be read, or comes late, refuses, and says so.

Raised in microsoft/autogen#8301 ("parse the verdict into an enum at the boundary, map
anything unknown to deny"), akaszubski/autonomous-dev#1549 and
raknor-ai/agent-governance-standard#3. On 0.10.28, reproduced before the change:

- Only ``verdict is OversightVerdict.GRANT`` granted, so a malformed verdict (``"grant"``,
  ``"GRANT"``, ``None``) was refused, but as ``escalation_denied``, "denied by human
  approval": a broken approver integration read as a human's decision.
- An approver that returned something other than an ``OversightResponse`` (a str, None)
  raised ``AttributeError`` out of the decorator.
- ``escalation_timeout_seconds`` was passed on the request but never enforced: the approver
  ran inline, so a hung approver held the call, and on the async path the event loop.
- ``SecurityPolicy(allowed_tools=None)`` with the default ``default_deny=False`` admitted
  every tool.

Now an unreadable answer (raised, not an ``OversightResponse``, a verdict outside
``OversightVerdict``) is refused as ``policy_indeterminate`` and logged under that event with
type names only; the approver runs in a worker thread with the deadline enforced (a late
GRANT is dropped); the async path awaits it without blocking the loop; ``SecurityPolicy``
refuses tool lists that are not lists or tuples of str, and with ``default_deny=True`` an
empty allowlist refuses as ``empty_allowlist``.
"""

from __future__ import annotations

import asyncio
import math
import threading
import time
import warnings
from collections.abc import Callable
from typing import Any

import pytest

from agent_airlock import Airlock
from agent_airlock import core as core_module
from agent_airlock import oversight as oversight_module
from agent_airlock import policy as policy_module
from agent_airlock.oversight import (
    OversightResponse,
    OversightTimeoutError,
    OversightVerdict,
    requires_human_oversight,
)
from agent_airlock.policy import PolicyViolation, SecurityPolicy


class _Events:
    """Records the events the patched module loggers emit: ``(event, fields)``."""

    def __init__(self) -> None:
        self.seen: list[tuple[str, dict[str, Any]]] = []

    def _record(self, event: str, **fields: Any) -> None:
        self.seen.append((event, fields))

    debug = info = warning = error = exception = _record

    def named(self, event: str) -> list[dict[str, Any]]:
        return [fields for name, fields in self.seen if name == event]


@pytest.fixture
def events(monkeypatch: pytest.MonkeyPatch) -> _Events:
    recorder = _Events()
    for module in (core_module, policy_module, oversight_module):
        monkeypatch.setattr(module, "logger", recorder)
    return recorder


def _answer(value: Any) -> Callable[[Any], Any]:
    """An approver that answers ``OversightResponse(request_id, verdict=value)``."""

    def approver(request: Any) -> OversightResponse:
        return OversightResponse(request_id=request.request_id, verdict=value)

    return approver


def _gated(approver: Any, *, timeout: float = 300.0) -> tuple[Callable[[], Any], list[str]]:
    """A tool under an escalating policy, and the list its body appends to when it runs."""
    ran: list[str] = []
    policy = SecurityPolicy(
        escalate_tools={"pay": "money moves"},
        approver=approver,
        escalation_timeout_seconds=timeout,
    )

    @Airlock(policy=policy)
    def pay() -> str:
        ran.append("ran")
        return "paid"

    return pay, ran


class TestMalformedVerdicts:
    """A verdict outside ``OversightVerdict`` is not an approval, whatever it says."""

    @pytest.mark.parametrize(
        "verdict",
        ["grant", "GRANT", "deny", "allow", "", None, "APPROVED_PENDING", 1, True],
        ids=repr,
    )
    def test_refused_as_policy_indeterminate(self, verdict: Any, events: _Events) -> None:
        pay, ran = _gated(_answer(verdict))
        result = pay()
        assert isinstance(result, dict)
        assert result["block_reason"] == "policy_indeterminate"
        assert ran == []
        logged = events.named("policy_indeterminate")
        assert logged and logged[0]["verdict_type"] == type(verdict).__name__

    def test_the_log_carries_type_names_not_content(self, events: _Events) -> None:
        pay, _ = _gated(_answer("grant-with-secret-sk-proj-1234"))
        pay()
        assert "sk-proj" not in repr(events.named("policy_indeterminate"))


class TestNonResponseReturns:
    """An approver that answers anything but an ``OversightResponse`` is not an approval."""

    @pytest.mark.parametrize(
        "returned", ["grant", None, {"verdict": "grant"}, OversightVerdict.GRANT], ids=repr
    )
    def test_refused_as_policy_indeterminate(self, returned: Any, events: _Events) -> None:
        pay, ran = _gated(lambda request: returned)
        result = pay()
        assert isinstance(result, dict)
        assert result["block_reason"] == "policy_indeterminate"
        assert ran == []
        assert events.named("policy_indeterminate")[0]["returned"] == type(returned).__name__

    def test_an_approver_that_raises_is_indeterminate(self, events: _Events) -> None:
        def approver(request: Any) -> OversightResponse:
            raise RuntimeError("transport down")

        pay, ran = _gated(approver)
        result = pay()
        assert isinstance(result, dict)
        assert result["block_reason"] == "policy_indeterminate"
        assert ran == []
        assert events.named("policy_indeterminate")[0]["returned"] == "RuntimeError"

    def test_an_async_approver_on_the_sync_path_is_closed_and_refused(self) -> None:
        async def approver(request: Any) -> OversightResponse:
            return OversightResponse(request_id=request.request_id, verdict=OversightVerdict.GRANT)

        pay, ran = _gated(approver)
        with warnings.catch_warnings():
            warnings.simplefilter("error", RuntimeWarning)  # "coroutine was never awaited"
            result = pay()
        assert isinstance(result, dict)
        assert result["block_reason"] == "policy_indeterminate"
        assert ran == []


class TestApproverTimeout:
    """``escalation_timeout_seconds`` is enforced, and a late GRANT is dropped."""

    @staticmethod
    def _late(seconds: float) -> Callable[[Any], OversightResponse]:
        def approver(request: Any) -> OversightResponse:
            time.sleep(seconds)
            return OversightResponse(request_id=request.request_id, verdict=OversightVerdict.GRANT)

        return approver

    def test_sync_refuses_at_the_deadline_and_ignores_the_late_grant(self, events: _Events) -> None:
        pay, ran = _gated(self._late(0.6), timeout=0.2)
        started = time.monotonic()
        result = pay()
        elapsed = time.monotonic() - started
        assert isinstance(result, dict)
        assert result["block_reason"] == "escalation_timeout"
        assert 0.2 <= elapsed < 0.55
        assert events.named("policy_indeterminate")[0]["source"] == "approver_timeout"
        time.sleep(0.6)  # the approver answers GRANT now; nothing reads it
        assert ran == []

    def test_async_refuses_at_the_deadline_and_ignores_the_late_grant(self) -> None:
        ran: list[str] = []
        policy = SecurityPolicy(
            escalate_tools={"pay": "money"},
            approver=self._late(0.6),
            escalation_timeout_seconds=0.2,
        )

        @Airlock(policy=policy)
        async def pay() -> str:
            ran.append("ran")
            return "paid"

        async def run() -> tuple[Any, float]:
            started = time.monotonic()
            result = await pay()
            return result, time.monotonic() - started

        result, elapsed = asyncio.run(run())
        assert isinstance(result, dict)
        assert result["block_reason"] == "escalation_timeout"
        assert 0.2 <= elapsed < 0.55
        time.sleep(0.6)
        assert ran == []

    def test_a_negative_or_nan_deadline_is_rejected(self) -> None:
        for bad in (-1.0, math.nan):
            with pytest.raises(ValueError, match="escalation_timeout_seconds"):
                SecurityPolicy(escalation_timeout_seconds=bad)


class TestAsyncPathDoesNotBlockTheLoop:
    def test_the_loop_runs_while_the_approver_decides(self) -> None:
        def approver(request: Any) -> OversightResponse:
            time.sleep(0.3)
            return OversightResponse(request_id=request.request_id, verdict=OversightVerdict.GRANT)

        policy = SecurityPolicy(escalate_tools={"pay": "money"}, approver=approver)

        @Airlock(policy=policy)
        async def pay() -> str:
            return "paid"

        async def run() -> tuple[Any, int]:
            ticks = 0
            done = asyncio.Event()

            async def ticker() -> None:
                nonlocal ticks
                while not done.is_set():
                    ticks += 1
                    await asyncio.sleep(0.01)

            task = asyncio.create_task(ticker())
            result = await pay()
            done.set()
            await task
            return result, ticks

        result, ticks = asyncio.run(run())
        assert result == "paid"
        assert ticks >= 10  # about 30 while the approver slept, none if the loop was held

    def test_an_async_approver_is_awaited_on_the_async_path(self) -> None:
        async def approver(request: Any) -> OversightResponse:
            await asyncio.sleep(0)
            return OversightResponse(request_id=request.request_id, verdict=OversightVerdict.GRANT)

        @Airlock(policy=SecurityPolicy(escalate_tools={"pay": "money"}, approver=approver))
        async def pay() -> str:
            return "paid"

        assert asyncio.run(pay()) == "paid"


class TestControls:
    """A readable verdict is still read as it always was."""

    def test_enum_grant_runs_the_tool(self, events: _Events) -> None:
        pay, ran = _gated(_answer(OversightVerdict.GRANT))
        assert pay() == "paid"
        assert ran == ["ran"]
        assert events.named("policy_indeterminate") == []

    def test_enum_deny_refuses_as_escalation_denied(self, events: _Events) -> None:
        pay, ran = _gated(_answer(OversightVerdict.DENY))
        result = pay()
        assert isinstance(result, dict)
        assert result["block_reason"] == "escalation_denied"
        assert ran == []
        assert events.named("policy_indeterminate") == []

    def test_enum_timeout_from_the_approver_is_escalation_timeout(self) -> None:
        pay, ran = _gated(_answer(OversightVerdict.TIMEOUT))
        result = pay()
        assert isinstance(result, dict)
        assert result["block_reason"] == "escalation_timeout"
        assert ran == []


class TestPolicyShapes:
    """``SecurityPolicy`` refuses tool lists it cannot read as lists of names."""

    @pytest.mark.parametrize("field", ["allowed_tools", "denied_tools"])
    @pytest.mark.parametrize("value", [None, "read_file", {"read_file"}, ["ok", 3]], ids=repr)
    def test_a_list_that_is_not_a_list_of_str_raises(
        self, field: str, value: Any, events: _Events
    ) -> None:
        with pytest.raises(TypeError, match=field):
            SecurityPolicy(**{field: value})
        assert events.named("policy_indeterminate")[0]["source"] == f"SecurityPolicy.{field}"

    def test_lists_and_tuples_of_str_are_accepted(self) -> None:
        SecurityPolicy(allowed_tools=["read_*"], denied_tools=("rm_*",))

    def test_default_deny_with_an_empty_allowlist_refuses_as_empty_allowlist(
        self, events: _Events
    ) -> None:
        policy = SecurityPolicy(default_deny=True)
        with pytest.raises(PolicyViolation) as raised:
            policy.check_tool_allowed("shell_exec")
        assert raised.value.violation_type == "empty_allowlist"
        assert events.named("policy_indeterminate")[0]["source"] == "empty_allowlist"

    def test_a_wildcard_allowlist_still_allows_with_default_deny(self) -> None:
        SecurityPolicy(allowed_tools=["*"], default_deny=True).check_tool_allowed("anything")


class TestResolverAndFrozenPolicy:
    def test_a_resolver_that_raises_is_logged_as_indeterminate(self, events: _Events) -> None:
        def resolver(context: Any) -> SecurityPolicy:
            raise RuntimeError("policy store unreachable")

        @Airlock(policy=resolver)
        def tool() -> str:
            return "ran"

        result = tool()
        assert isinstance(result, dict)
        assert result["success"] is False
        assert events.named("policy_indeterminate")[0]["source"] == "policy_resolver"

    def test_a_frozen_policy_that_changed_is_logged_as_indeterminate(self, events: _Events) -> None:
        frozen = SecurityPolicy(allowed_tools=["*"]).freeze()
        frozen.allowed_tools.append("injected")

        @Airlock(policy=frozen)
        def tool() -> str:
            return "ran"

        result = tool()
        assert isinstance(result, dict)
        assert events.named("policy_indeterminate")[0]["source"] == "frozen_policy_digest"


class TestOversightDecorator:
    """``requires_human_oversight`` enforces its timeout and flags an unreadable answer."""

    def test_the_timeout_is_enforced(self) -> None:
        def approver(request: Any) -> OversightResponse:
            time.sleep(0.6)
            return OversightResponse(request_id=request.request_id, verdict=OversightVerdict.GRANT)

        ran: list[str] = []

        @requires_human_oversight(approver=approver, timeout_seconds=0.2)
        def deploy() -> None:
            ran.append("ran")

        started = time.monotonic()
        with pytest.raises(OversightTimeoutError):
            deploy()
        assert time.monotonic() - started < 0.55
        time.sleep(0.6)
        assert ran == []

    @pytest.mark.parametrize("returned", ["grant", None], ids=repr)
    def test_an_unreadable_answer_emits_indeterminate_and_still_raises_timeout(
        self, returned: Any
    ) -> None:
        emitted: list[tuple[str, dict[str, Any]]] = []

        @requires_human_oversight(
            approver=lambda request: returned,
            audit_emitter=lambda event, payload: emitted.append((event, payload)),
        )
        def deploy() -> str:
            return "deployed"

        with pytest.raises(OversightTimeoutError):
            deploy()
        assert [event for event, _ in emitted] == ["oversight.request", "oversight.indeterminate"]
        assert emitted[1][1]["returned"] == type(returned).__name__

    def test_a_non_enum_verdict_emits_indeterminate(self) -> None:
        emitted: list[str] = []

        @requires_human_oversight(
            approver=_answer("grant"), audit_emitter=lambda event, _: emitted.append(event)
        )
        def deploy() -> str:
            return "deployed"

        with pytest.raises(OversightTimeoutError):
            deploy()
        assert emitted[-1] == "oversight.indeterminate"

    def test_an_enum_grant_runs(self) -> None:
        """Control."""

        @requires_human_oversight(approver=_answer(OversightVerdict.GRANT))
        def deploy() -> str:
            return "deployed"

        assert deploy() == "deployed"

    def test_the_approver_runs_in_a_daemon_thread(self) -> None:
        seen: list[bool] = []

        def approver(request: Any) -> OversightResponse:
            seen.append(threading.current_thread().daemon)
            return OversightResponse(request_id=request.request_id, verdict=OversightVerdict.GRANT)

        @requires_human_oversight(approver=approver)
        def deploy() -> str:
            return "deployed"

        assert deploy() == "deployed"
        assert seen == [True]
