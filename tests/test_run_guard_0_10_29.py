"""0.10.29: a run halts after a hard stop, and a run that repeats itself is caught.

Until 0.10.29 there was no halt latch: after a fleet freeze or an approval nobody could read,
the model's next call was judged as if nothing had happened. ``AmplificationBudget``
capped the calls in a run, but nothing noticed the same calls coming back again and again.
Raised in openai/openai-agents-python#5351 (once one out-of-plan call set a halt flag, every
later call was refused) and prime-radiant-inc/evener#94 (a failure-count breaker after
dispatch cannot see a loop of calls that each succeed).
"""

from __future__ import annotations

import asyncio
import math
from pathlib import Path
from typing import Any

import pytest

from agent_airlock import Airlock, AirlockConfig, AirlockContext, RunGuard, SecurityPolicy
from agent_airlock import core as core_module
from agent_airlock.conformance.decision_log import DecisionLog
from agent_airlock.oversight import OversightRequest, OversightResponse, OversightVerdict
from agent_airlock.policy import PolicyMutationError
from agent_airlock.self_heal import BlockReason


def _unreadable_approver(request: OversightRequest) -> OversightResponse:
    """An approver whose verdict is the string "grant", which reads as no answer."""
    return OversightResponse(request_id=request.request_id, verdict="grant")  # type: ignore[arg-type]


def _guarded(**guard: Any) -> SecurityPolicy:
    return SecurityPolicy(run_guard=RunGuard(**guard))


def _reason(result: Any) -> str | None:
    """A refusal's violation type, or its block reason when it has none; None when it ran."""
    if isinstance(result, dict) and result.get("success") is False:
        return str(result.get("metadata", {}).get("violation_type") or result["block_reason"])
    return None


def _hard_stop() -> Any:
    policy = SecurityPolicy(
        run_guard=RunGuard(), escalate_tools={"pay": "needs a human"}, approver=_unreadable_approver
    )

    @Airlock(policy=policy)
    def pay(amount: int) -> int:
        return amount

    return pay


@Airlock(policy=_guarded())
def read(path: str) -> str:
    return path


class TestHardStops:
    def test_an_unreadable_approval_halts_every_later_call(self) -> None:
        @Airlock()
        def unguarded(x: int) -> int:
            return x

        with AirlockContext(agent_id="a") as run:
            assert read(path="a") == "a"
            assert _reason(_hard_stop()(amount=1)) == "policy_indeterminate"
            assert run.halted and run.halt_reason == "policy_indeterminate"
            assert _reason(read(path="a")) == "run_halted"
            assert _reason(unguarded(x=1)) == "run_halted"

    def test_queued_calls_under_gather_are_all_refused(self) -> None:
        @Airlock(policy=_guarded())
        async def fetch(n: int) -> int:
            return n

        async def run_it() -> list[Any]:
            with AirlockContext(agent_id="a"):
                _hard_stop()(amount=1)
                return list(await asyncio.gather(*(fetch(n=n) for n in range(5))))

        results = asyncio.run(run_it())
        assert [_reason(result) for result in results] == ["run_halted"] * 5
        assert all("AIRLOCK_BLOCK" in result["error"] for result in results)

    def test_a_call_waiting_on_an_approver_is_refused_when_the_run_halts(self) -> None:
        async def slow_grant(request: OversightRequest) -> OversightResponse:
            await asyncio.sleep(0.05)
            return OversightResponse(request_id=request.request_id, verdict=OversightVerdict.GRANT)

        policy = SecurityPolicy(
            run_guard=RunGuard(), escalate_tools={"wire": "x"}, approver=slow_grant
        )

        @Airlock(policy=policy)
        async def wire(amount: int) -> int:
            return amount

        @Airlock(policy=_hard_stop_policy())
        async def pay(amount: int) -> int:
            return amount

        async def run_it() -> list[Any]:
            with AirlockContext(agent_id="a"):
                return list(await asyncio.gather(wire(amount=1), pay(amount=2)))

        waited, stopped = asyncio.run(run_it())
        assert _reason(stopped) == "policy_indeterminate"
        assert _reason(waited) == "run_halted"

    def test_a_refused_irreversible_call_halts(self) -> None:
        policy = SecurityPolicy(
            denied_tools=["wire_*"], run_guard=RunGuard(irreversible_tools=("wire_*",))
        )

        @Airlock(policy=policy)
        def wire_money(amount: int) -> int:
            return amount

        with AirlockContext(agent_id="a") as run:
            assert _reason(wire_money(amount=1)) == "tool_denied"
            assert run.halted and "wire_money" in str(run.halt_reason)
            assert _reason(read(path="a")) == "run_halted"

    def test_a_refusal_outside_halt_on_does_not_halt(self) -> None:
        @Airlock(policy=SecurityPolicy(denied_tools=["nope"], run_guard=RunGuard()))
        def nope() -> None:
            return None

        with AirlockContext(agent_id="a") as run:
            assert _reason(nope()) == "tool_denied"
            assert not run.halted
            assert read(path="a") == "a"

    def test_halt_on_can_be_widened(self) -> None:
        policy = SecurityPolicy(
            denied_tools=["nope"],
            run_guard=RunGuard(halt_on=frozenset({BlockReason.POLICY_VIOLATION})),
        )

        @Airlock(policy=policy)
        def nope() -> None:
            return None

        with AirlockContext(agent_id="a") as run:
            nope()
            assert run.halt_reason == "policy_violation"

    def test_a_fleet_freeze_halts_the_run_after_the_reset(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(core_module, "_kill_switch_get", lambda: None)
        with AirlockContext(agent_id="a") as run:
            monkeypatch.setattr(core_module, "_kill_switch_frozen", lambda: True)
            assert _reason(read(path="a")) == "kill_switch"
            monkeypatch.setattr(core_module, "_kill_switch_frozen", lambda: False)
            assert _reason(read(path="a")) == "run_halted"
            assert run.halt_reason == "kill_switch"

    def test_the_host_can_halt_a_run_and_only_that_run(self) -> None:
        with AirlockContext(agent_id="a") as run:
            run.halt("operator review")
            with run.with_metadata(step=2):
                halted = read(path="a")
        assert _reason(halted) == "run_halted"
        assert halted["metadata"]["halt_reason"] == "operator review"
        with AirlockContext(agent_id="a"):
            assert read(path="a") == "a"


def _hard_stop_policy() -> SecurityPolicy:
    return SecurityPolicy(
        run_guard=RunGuard(), escalate_tools={"pay": "needs a human"}, approver=_unreadable_approver
    )


class TestLoops:
    def test_a_period_1_loop_is_nudged_then_halted(self) -> None:
        with AirlockContext(agent_id="a") as run:
            results = [read(path="same") for _ in range(6)]
            later = read(path="other")
        assert results[:4] == ["same"] * 4
        assert _reason(results[4]) == "loop_detected"
        assert any("One more repeat" in hint for hint in results[4]["fix_hints"])
        assert _reason(results[5]) == "run_halted"
        assert _reason(later) == "run_halted"
        assert "1-call loop" in str(run.halt_reason)

    def test_a_period_3_loop_trips_at_the_fifth_repeat(self) -> None:
        with AirlockContext(agent_id="a") as run:
            sequence = ["a", "b", "c"] * 5 + ["a"]
            results = [read(path=path) for path in sequence]
        assert results[:14] == sequence[:14]
        assert _reason(results[14]) == "loop_detected"
        assert _reason(results[15]) == "run_halted"
        assert "3-call loop" in str(run.halt_reason)

    def test_varied_arguments_do_not_trip(self) -> None:
        with AirlockContext(agent_id="a") as run:
            results = [read(path=f"page-{n}") for n in range(40)]
        assert results == [f"page-{n}" for n in range(40)]
        assert not run.halted

    def test_a_nudge_heeded_does_not_halt(self) -> None:
        with AirlockContext(agent_id="a") as run:
            for _ in range(5):
                read(path="same")
            follow_up = [read(path=f"new-{n}") for n in range(10)]
        assert follow_up == [f"new-{n}" for n in range(10)]
        assert not run.halted

    def test_the_lengths_are_settings(self) -> None:
        @Airlock(policy=_guarded(loop_repeats=3, max_loop_period=1))
        def short(path: str) -> str:
            return path

        with AirlockContext(agent_id="a"):
            pairs = [short(path=path) for path in ["x", "y"] * 6]
            assert pairs == ["x", "y"] * 6
            assert [_reason(short(path="z")) for _ in range(3)][-1] == "loop_detected"

    def test_loops_are_not_looked_for_when_turned_off(self) -> None:
        @Airlock(policy=_guarded(detect_loops=False))
        def free(path: str) -> str:
            return path

        with AirlockContext(agent_id="a"):
            assert [free(path="same") for _ in range(12)] == ["same"] * 12

    def test_unreadable_arguments_are_one_key(self) -> None:
        @Airlock(policy=_guarded())
        def take(items: list[Any]) -> int:
            return len(items)

        loop: list[Any] = []
        loop.append(loop)
        with AirlockContext(agent_id="a"):
            results = [take(items=loop) for _ in range(5)]
        assert _reason(results[4]) == "loop_detected"

    def test_a_call_under_a_run_guard_outside_a_run_is_refused(self) -> None:
        assert _reason(read(path="a")) == "run_guard_outside_run"


class TestTheSettings:
    @pytest.mark.parametrize(
        "kwargs",
        [
            {"halt_on": frozenset({"not_a_reason"})},
            {"irreversible_tools": ("",)},
            {"loop_repeats": 1},
            {"loop_repeats": 2.5},
            {"max_loop_period": 0},
            {"max_loop_period": 11},
            {"max_loop_period": True},
            {"loop_repeats": math.nan},
        ],
    )
    def test_a_setting_the_guard_cannot_apply_is_refused(self, kwargs: dict[str, Any]) -> None:
        with pytest.raises(ValueError):
            RunGuard(**kwargs)

    def test_block_reasons_and_their_values_both_work(self) -> None:
        assert RunGuard(halt_on=frozenset({BlockReason.KILL_SWITCH})).halt_on == {"kill_switch"}

    def test_the_policy_digest_covers_the_guard(self) -> None:
        plain = SecurityPolicy()._compute_policy_digest()
        assert SecurityPolicy(run_guard=None)._compute_policy_digest() == plain
        assert _guarded()._compute_policy_digest() != plain
        frozen = _guarded().freeze()
        frozen.run_guard = None
        with pytest.raises(PolicyMutationError):
            frozen.verify_frozen()


class TestTheDecisionRecord:
    def test_the_refusals_name_their_steps(self, tmp_path: Path) -> None:
        log = DecisionLog(tmp_path / "decisions.jsonl")

        @Airlock(config=AirlockConfig(decision_log=log), policy=_guarded())
        def logged(path: str) -> str:
            return path

        with AirlockContext(agent_id="a"):
            for _ in range(7):
                logged(path="same")
        layers = [(r.details or {}).get("layer") for r in log.records() if r.stage == "policy"]
        assert layers == ["no_refusal"] * 4 + ["2.3:run_loop", "2.3:run_loop", "0.7:run_halted"]
