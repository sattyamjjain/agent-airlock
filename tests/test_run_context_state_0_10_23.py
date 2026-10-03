"""Regression (0.10.23): state a guard keeps on the run's ``AirlockContext`` reaches the call.

``ContextExtractor`` builds a new ``AirlockContext`` for every call, and until 0.10.23 only the
caller's identity was copied onto it. Everything else a guard keeps between calls was written
to, or read from, that throwaway object:

* ``reauth_on_untrusted_reinvocation`` marked untrusted output on it, so the count never reached
  the next call and the guard never fired through ``@Airlock``, with a static policy or a
  resolver; a resolver's policy was not even consulted for the mark.
* the action-contradiction gate read its ``signal_field_key`` from it, so a signal the host set
  on the run's context never tripped the gate, and read the ``authorize_once`` grant from it,
  so a tripped gate could never be re-opened.
* tier-budget reconciliation ran only for a static policy.

The unit tests drove ``check_reauthorization()`` on a hand-marked context, which is why none of
this showed.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

import pytest

from agent_airlock import Airlock, AirlockContext, ModelTierBudget, SecurityPolicy
from agent_airlock.action_contradiction_gate import ActionContradictionGate
from agent_airlock.cost_tracking import CostTracker, _reset_tracker, set_global_tracker
from agent_airlock.policy_presets import strict_tier_budget_policy


def _reauth_policy() -> SecurityPolicy:
    return SecurityPolicy(
        allowed_tools=["search"],
        reauth_on_untrusted_reinvocation=True,
        untrusted_reinvocation_threshold=1,
    )


def _resolver(_context: AirlockContext[Any]) -> SecurityPolicy:
    return _reauth_policy()


# A static policy and a resolver that returns the same policy must behave the same.
POLICIES: dict[str, Callable[[], Any]] = {
    "static": _reauth_policy,
    "resolver": lambda: _resolver,
}


def _search(policy: Any) -> Any:
    @Airlock(policy=policy, return_dict=True)
    def search(q: str) -> str:
        return f"results for {q}"

    return search


def _async_search(policy: Any) -> Any:
    @Airlock(policy=policy, return_dict=True)
    async def search(q: str) -> str:
        return q

    return search


def _search_in_run() -> Any:
    """A reauth-guarded tool whose first argument is a run wrapper holding the context."""

    @Airlock(policy=_reauth_policy(), return_dict=True)
    def search(_run: _Run, q: str) -> str:
        return q

    return search


def _search_in_foreign_run() -> Any:
    @Airlock(policy=_reauth_policy(), return_dict=True)
    def search(_run: _ForeignRun, q: str) -> str:
        return q

    return search


@dataclass
class _Run:
    """A framework's run wrapper whose ``context`` is the host's ``AirlockContext``."""

    context: Any


@dataclass
class _Caller:
    """A run wrapper carrying an identity but no ``AirlockContext``."""

    agent_id: str


@dataclass
class _ForeignRun:
    context: _Caller


class TestReauthFiresThroughTheDecorator:
    @pytest.mark.parametrize("make_policy", POLICIES.values(), ids=POLICIES.keys())
    def test_a_second_call_needs_a_fresh_grant(self, make_policy: Callable[[], Any]) -> None:
        search = _search(make_policy())

        with AirlockContext(agent_id="a1") as run:
            first = search(q="x")
            second = search(q="y")

        assert first["success"] is True
        assert second["success"] is False
        assert second["block_reason"] == "policy_violation"
        assert "re-authorization" in second["error"]
        assert run.untrusted_reinvocation_count == {"search": 1}

    @pytest.mark.parametrize("make_policy", POLICIES.values(), ids=POLICIES.keys())
    def test_authorize_once_on_the_run_context_admits_exactly_one_call(
        self, make_policy: Callable[[], Any]
    ) -> None:
        search = _search(make_policy())

        with AirlockContext(agent_id="a1") as run:
            search(q="x")
            run.authorize_once("search")
            granted = search(q="y")
            refused = search(q="z")

        assert granted["success"] is True
        assert refused["success"] is False
        assert "search" not in run._authorized_once

    @pytest.mark.asyncio
    async def test_an_async_tool_is_tracked_the_same_way(self) -> None:
        search = _async_search(_reauth_policy())

        async with AirlockContext(agent_id="a1") as run:
            first = await search(q="x")
            second = await search(q="y")

        assert first["success"] is True
        assert second["success"] is False
        assert run.untrusted_reinvocation_count == {"search": 1}

    def test_a_context_passed_in_the_first_argument_holds_the_count(self) -> None:
        search = _search_in_run()

        state = AirlockContext[None](agent_id="a1")
        first = search(_Run(context=state), q="x")
        second = search(_Run(context=state), q="y")

        assert first["success"] is True
        assert second["success"] is False
        assert state.untrusted_reinvocation_count == {"search": 1}

    def test_each_run_starts_with_its_own_count(self) -> None:
        search = _search(_reauth_policy())

        with AirlockContext(agent_id="a1"):
            assert search(q="x")["success"] is True
        with AirlockContext(agent_id="a1"):
            assert search(q="x")["success"] is True

    def test_with_no_run_context_the_flag_refuses_instead_of_doing_nothing(self) -> None:
        search = _search(_reauth_policy())

        result = search(q="x")

        assert result["success"] is False
        assert result["block_reason"] == "policy_violation"
        assert "AirlockContext" in result["error"]

    def test_a_run_context_naming_another_agent_is_not_borrowed(self) -> None:
        search = _search_in_foreign_run()

        with AirlockContext(agent_id="a1") as run:
            result = search(_ForeignRun(context=_Caller(agent_id="b2")), q="x")

        assert result["success"] is False
        assert run.untrusted_reinvocation_count == {}

    def test_the_flag_off_needs_no_run_context(self) -> None:
        search = _search(SecurityPolicy(allowed_tools=["search"]))

        assert search(q="x")["success"] is True
        assert search(q="x")["success"] is True


def _send_email(gate: ActionContradictionGate) -> Any:
    @Airlock(policy=SecurityPolicy(action_contradiction_gate=gate), return_dict=True)
    def send_email(to: str, body: str) -> str:
        return "sent"

    return send_email


class TestContradictionGateReadsTheRunContext:
    def test_a_signal_set_on_the_run_context_blocks_a_privileged_call(self) -> None:
        send = _send_email(ActionContradictionGate(signal_field_key="contradiction_seen"))

        with AirlockContext(agent_id="a1", metadata={"contradiction_seen": True}):
            result = send(to="ops@example.com", body="wire the funds")

        assert result["success"] is False
        assert result["block_reason"] == "policy_violation"

    def test_without_the_signal_the_call_runs(self) -> None:
        send = _send_email(ActionContradictionGate(signal_field_key="contradiction_seen"))

        with AirlockContext(agent_id="a1"):
            result = send(to="ops@example.com", body="weekly report")

        assert result["success"] is True

    def test_authorize_once_on_the_run_context_reopens_a_tripped_gate_once(self) -> None:
        send = _send_email(ActionContradictionGate(predicate=lambda _ctx: True))

        with AirlockContext(agent_id="a1") as run:
            tripped = send(to="ops@example.com", body="x")
            run.authorize_once("send_email")
            granted = send(to="ops@example.com", body="x")
            again = send(to="ops@example.com", body="x")

        assert tripped["success"] is False
        assert granted["success"] is True
        assert again["success"] is False


_TEST_PRICING = {"default": {"input": Decimal("0.003"), "output": Decimal("0.015")}}


class TestTierBudgetReconcilesForAResolver:
    @pytest.fixture
    def reconciled(self, monkeypatch: pytest.MonkeyPatch) -> Iterator[list[dict[str, Any]]]:
        set_global_tracker(CostTracker(model="default", pricing=_TEST_PRICING))
        calls: list[dict[str, Any]] = []
        original = ModelTierBudget.reconcile_post_execute

        def spy(self: ModelTierBudget, **kwargs: Any) -> Any:
            calls.append(kwargs)
            return original(self, **kwargs)

        monkeypatch.setattr(ModelTierBudget, "reconcile_post_execute", spy)
        yield calls
        _reset_tracker()

    @pytest.mark.parametrize(
        "policy",
        [strict_tier_budget_policy(), lambda _ctx: strict_tier_budget_policy()],
        ids=["static", "resolver"],
    )
    def test_actual_usage_is_reconciled(self, policy: Any, reconciled: list[Any]) -> None:
        @Airlock(policy=policy, return_dict=True)
        def call(prompt: str) -> dict[str, Any]:
            return {"answer": "42", "token_usage": {"input_tokens": 50, "output_tokens": 100}}

        with AirlockContext(metadata={"airlock_tier": "small", "input_tokens": 50}):
            result = call("hi")

        assert result["success"] is True
        assert len(reconciled) == 1
        assert reconciled[0]["estimate"].tier == "small"
