"""0.10.29: the per-session state on the call path is bounded.

On b21aec7 the amplification guard kept one ledger per run key and the sequence guard one
trace per session for as long as the process lived (amplification.py:157, :163-167), and
the action-contradiction gate stored a state for every session it saw, tripped or not. A
host that ends runs can drop their state (``SecurityPolicy.reset_run``), but a run ADK
cancels reaches no cleanup hook (google/adk-python#7770), so the stores need a bound of
their own: an LRU ``max_sessions`` that logs each eviction.
"""

from __future__ import annotations

from typing import Any

import pytest

from agent_airlock import Airlock, AirlockContext, SecurityPolicy
from agent_airlock import amplification as amplification_module
from agent_airlock import sequence_guard as sequence_module
from agent_airlock.action_contradiction_gate import (
    ActionContradictionGate,
    ActionContradictionViolation,
)
from agent_airlock.amplification import AmplificationBudget, AmplificationGuard
from agent_airlock.sequence_guard import ENTRY_SENTINEL, SequenceGuard, SequenceViolation


class _Recorder:
    """Stands in for a module's logger and records ``(level, event, fields)``."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def __getattr__(self, level: str) -> Any:
        def record(event: str = "", **fields: Any) -> None:
            self.calls.append((level, event, fields))

        return record

    def events(self, event: str) -> list[dict[str, Any]]:
        return [fields for _, name, fields in self.calls if name == event]


@pytest.fixture
def logs(monkeypatch: pytest.MonkeyPatch) -> _Recorder:
    recorder = _Recorder()
    monkeypatch.setattr(amplification_module, "logger", recorder)
    monkeypatch.setattr(sequence_module, "logger", recorder)
    return recorder


def _budget(**kwargs: Any) -> AmplificationBudget:
    return AmplificationBudget(max_calls_per_run=5, **kwargs)


class TestAmplificationLedgers:
    def test_ten_thousand_runs_keep_the_bound(self, logs: _Recorder) -> None:
        guard = AmplificationGuard(_budget(max_sessions=100))
        for run in range(10_000):
            guard.record_and_check(session_key=f"run-{run}", tool_name="search")
        assert len(guard._ledgers) == 100
        assert next(iter(guard._ledgers)) == "run-9900"
        evicted = logs.events("amplification_ledger_evicted")
        assert len(evicted) == 9_900
        assert evicted[0] == {"session_key": "run-0", "run_call_count": 1, "max_sessions": 100}

    def test_the_least_recently_used_run_goes_first(self, logs: _Recorder) -> None:
        guard = AmplificationGuard(_budget(max_sessions=2))
        for run in ("a", "b", "a", "c"):  # a is used again, so b is the oldest
            guard.record_and_check(session_key=run, tool_name="search")
        assert list(guard._ledgers) == ["a", "c"]
        assert guard.ledger_for("a").call_count == 2
        assert [e["session_key"] for e in logs.events("amplification_ledger_evicted")] == ["b"]

    def test_the_bound_holds_on_the_call_path(self) -> None:
        policy = SecurityPolicy(amplification_budget=_budget(max_sessions=3))

        @Airlock(policy=policy)
        def search(query: str) -> str:
            return query

        for run in range(10):
            with AirlockContext(session_id=f"run-{run}"):
                assert search(query="q") == "q"
        assert policy._amplification_guard is not None
        assert list(policy._amplification_guard._ledgers) == ["run-7", "run-8", "run-9"]

    def test_the_default_and_a_bad_bound(self) -> None:
        assert AmplificationBudget().max_sessions == 10_000
        for bad in (0, -1, True, 1.5):
            with pytest.raises(ValueError, match="max_sessions"):
                _budget(max_sessions=bad)  # type: ignore[arg-type]


def _sequence(**kwargs: Any) -> SequenceGuard:
    dag = {ENTRY_SENTINEL: {"search"}, "search": {"search", "write"}}
    return SequenceGuard(mode="declared", dag=dag, **kwargs)


def _call(guard: SequenceGuard, session: str, tool: str = "search") -> None:
    guard.record_and_check(session_key=session, tool_name=tool, args=(), kwargs={})


class TestSequenceGuardSessions:
    def test_ten_thousand_sessions_keep_the_bound(self, logs: _Recorder) -> None:
        guard = _sequence(max_sessions=100)
        for session in range(10_000):
            _call(guard, f"s-{session}")
        assert len(guard._traces) == 100
        evicted = logs.events("sequence_guard.session_evicted")
        assert len(evicted) == 9_900
        assert evicted[0] == {"session_key": "s-0", "calls": 1, "max_sessions": 100}

    def test_the_least_recently_used_session_goes_first(self, logs: _Recorder) -> None:
        guard = _sequence(max_sessions=2)
        for session in ("a", "b", "a", "c"):
            _call(guard, session)
        assert list(guard._traces) == ["a", "c"] and len(guard.history("a")) == 2
        assert [e["session_key"] for e in logs.events("sequence_guard.session_evicted")] == ["b"]

    def test_an_evicted_session_starts_again_at_its_entry(self, logs: _Recorder) -> None:
        guard = _sequence(max_sessions=1)
        _call(guard, "a")
        _call(guard, "a", "write")  # search -> write is declared
        _call(guard, "b")  # a's trace goes
        with pytest.raises(SequenceViolation):
            _call(guard, "a", "write")  # read as a's first call: write is no entry tool

    def test_the_default_and_a_bad_bound(self) -> None:
        assert _sequence().max_sessions == 10_000
        for bad in (0, -1, True, 1.5):
            with pytest.raises(ValueError, match="max_sessions"):
                _sequence(max_sessions=bad)


def _context(*, tripped: bool = False) -> AirlockContext[Any]:
    return AirlockContext(metadata={"contradiction": True} if tripped else {})


class TestContradictionGateStore:
    def test_a_session_that_never_trips_is_not_stored(self) -> None:
        gate = ActionContradictionGate(signal_field_key="contradiction")
        for session in range(10_000):
            gate.check_action(
                context=_context(), tool_name="send_email", session_key=f"s-{session}"
            )
        assert gate._states == {}

    def test_a_tripped_session_stays_tripped(self) -> None:
        gate = ActionContradictionGate(signal_field_key="contradiction")
        gate.check_action(context=_context(tripped=True), tool_name="search", session_key="s")
        for session in range(1_000):  # other sessions come and go
            gate.check_action(context=_context(), tool_name="search", session_key=f"o-{session}")
        assert list(gate._states) == ["s"] and gate.is_tripped("s")
        with pytest.raises(ActionContradictionViolation):
            gate.check_action(context=_context(), tool_name="send_email", session_key="s")


class TestResetRun:
    def test_one_runs_entries_go_and_the_rest_stay(self) -> None:
        gate = ActionContradictionGate(signal_field_key="contradiction")
        sequence = _sequence()
        policy = SecurityPolicy(
            amplification_budget=_budget(),
            sequence_guard=sequence,
            action_contradiction_gate=gate,
        )
        assert policy._amplification_guard is not None
        for run in ("run-1", "run-2"):
            policy._amplification_guard.record_and_check(session_key=run, tool_name="search")
            _call(sequence, run)
            gate.check_action(context=_context(tripped=True), tool_name="search", session_key=run)
        policy.reset_run("run-1")
        assert list(policy._amplification_guard._ledgers) == ["run-2"]
        assert list(sequence._traces) == ["run-2"] and list(gate._states) == ["run-2"]

    def test_a_policy_without_per_run_state_has_nothing_to_drop(self) -> None:
        SecurityPolicy().reset_run("run-1")
