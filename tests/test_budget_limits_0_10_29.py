"""0.10.29: a budget limit of 0 is a limit, and an exceeded budget stays closed (#407).

``CostTracker._check_budget`` tested each of the four ``BudgetConfig`` limits for
truthiness, so ``0`` (or ``Decimal("0")``) meant no limit: a tracker with
``max_tokens_per_session=0, max_cost_per_session=0`` recorded 2,000 tokens. And
``record()`` raised before it appended the record of the call that crossed a limit, though
that call had already run: with a limit of 10 tokens, calls of 6, 6 and 3 left the total
at 9 after 15 were spent, and the third call was admitted. Raised in #407 (and in
raknor-ai/agent-governance-standard#4 and BerriAI/litellm#43214 for the same shape).

Every limit is now compared with ``is not None``, the crossing call is recorded and latches
the budget closed until ``reset()``, ``check_admission()`` refuses a call before it runs,
and ``track()`` calls it on entry.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest

from agent_airlock.cost_tracking import BudgetConfig, BudgetExceededError, CostTracker, TokenUsage

_PRICING = {"default": {"input": Decimal("0.01"), "output": Decimal("0.01")}}  # per 1K


def _tracker(**limits: Any) -> CostTracker:
    return CostTracker(budget=BudgetConfig(**limits), pricing=_PRICING)


class TestZeroLimits:
    """Each of the four limits set to 0 refuses a call that costs anything."""

    @pytest.mark.parametrize("zero", [0, Decimal("0"), "0", 0.0], ids=repr)
    @pytest.mark.parametrize("name", ["max_cost_per_call", "max_cost_per_session"])
    def test_a_zero_money_limit_refuses(self, name: str, zero: Any) -> None:
        tracker = _tracker(**{name: zero})
        with pytest.raises(BudgetExceededError):
            tracker.record("tool", TokenUsage(input_tokens=1000))

    @pytest.mark.parametrize("name", ["max_tokens_per_call", "max_tokens_per_session"])
    def test_a_zero_token_limit_refuses(self, name: str) -> None:
        tracker = _tracker(**{name: 0})
        with pytest.raises(BudgetExceededError):
            tracker.record("tool", TokenUsage(input_tokens=1))

    def test_the_reported_case_is_refused(self) -> None:
        """#407's tracker: both session limits 0, 2,000 tokens."""
        tracker = _tracker(max_tokens_per_session=0, max_cost_per_session=0)
        with pytest.raises(BudgetExceededError):
            tracker.record("tool", TokenUsage(input_tokens=1000, output_tokens=1000))

    @pytest.mark.parametrize("name", ["max_cost_per_session", "max_tokens_per_session"])
    def test_a_zero_session_limit_refuses_admission_of_the_first_call(self, name: str) -> None:
        with pytest.raises(BudgetExceededError):
            _tracker(**{name: 0}).check_admission()

    def test_a_zero_call_limit_admits_a_call_that_costs_nothing(self) -> None:
        """Control: nothing spent is not over a limit of nothing."""
        tracker = _tracker(max_cost_per_call=0, max_tokens_per_call=0)
        tracker.record("tool", TokenUsage())
        assert tracker.get_summary().total_calls == 1

    def test_a_zero_session_limit_does_not_divide_by_zero_in_the_warning(self) -> None:
        tracker = _tracker(max_cost_per_session=0)
        tracker.record("tool", TokenUsage())  # 0 spent of 0: no warning, no ZeroDivisionError
        with pytest.raises(BudgetExceededError, match="Session cost"):
            tracker.record("tool", TokenUsage(input_tokens=1000))

    @pytest.mark.parametrize(
        "limits",
        [
            {"max_cost_per_call": -1},
            {"max_cost_per_session": "-0.01"},
            {"max_tokens_per_call": -1},
            {"max_tokens_per_session": -5},
            {"max_cost_per_session": "NaN"},
        ],
        ids=lambda limits: next(iter(limits.items()))[0] + "=" + str(next(iter(limits.values()))),
    )
    def test_a_negative_or_nan_limit_is_rejected(self, limits: dict[str, Any]) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            BudgetConfig(**limits)

    def test_no_limits_admits_anything(self) -> None:
        """Control: None is still no limit."""
        tracker = _tracker()
        tracker.check_admission(TokenUsage(input_tokens=10**9))
        tracker.record("tool", TokenUsage(input_tokens=10**6))


class TestExceededLatch:
    """The call that crosses a limit is recorded, and the budget stays closed."""

    def test_crossing_call_is_recorded_and_the_budget_stays_closed(self) -> None:
        tracker = _tracker(max_tokens_per_session=10)
        tracker.record("tool", TokenUsage(input_tokens=6))
        with pytest.raises(BudgetExceededError):
            tracker.record("tool", TokenUsage(input_tokens=6))
        assert tracker.get_summary().total_tokens == 12

        with pytest.raises(BudgetExceededError, match="reset"):
            tracker.check_admission()
        with pytest.raises(BudgetExceededError):
            tracker.record("tool", TokenUsage(input_tokens=3))
        assert tracker.get_summary().total_tokens == 15

    def test_reset_reopens_the_budget(self) -> None:
        tracker = _tracker(max_tokens_per_session=10)
        with pytest.raises(BudgetExceededError):
            tracker.record("tool", TokenUsage(input_tokens=11))
        tracker.reset()
        tracker.check_admission()
        tracker.record("tool", TokenUsage(input_tokens=3))
        assert tracker.get_summary().total_tokens == 3

    def test_a_per_call_breach_latches_too(self) -> None:
        tracker = _tracker(max_tokens_per_call=5)
        with pytest.raises(BudgetExceededError):
            tracker.record("tool", TokenUsage(input_tokens=6))
        with pytest.raises(BudgetExceededError, match="per_call|exceeds"):
            tracker.check_admission(TokenUsage(input_tokens=1))

    def test_callbacks_see_the_crossing_call(self) -> None:
        seen: list[int] = []
        tracker = _tracker(max_tokens_per_session=10)
        tracker.add_callback(lambda record: seen.append(record.tokens.total_tokens))
        with pytest.raises(BudgetExceededError):
            tracker.record("tool", TokenUsage(input_tokens=11))
        assert seen == [11]

    def test_an_estimate_that_would_cross_is_refused_before_the_call(self) -> None:
        tracker = _tracker(max_tokens_per_session=10)
        tracker.record("tool", TokenUsage(input_tokens=8))
        with pytest.raises(BudgetExceededError, match="Session tokens 12"):
            tracker.check_admission(TokenUsage(input_tokens=4))
        tracker.check_admission(TokenUsage(input_tokens=2))  # control: 10 is not over 10

    def test_a_reached_limit_refuses_without_an_estimate(self) -> None:
        tracker = _tracker(max_tokens_per_session=10)
        tracker.record("tool", TokenUsage(input_tokens=10))
        with pytest.raises(BudgetExceededError, match="reached limit"):
            tracker.check_admission()


class TestTrackRefusesBeforeBody:
    """``with tracker.track(...)`` refuses on entry, before the body runs."""

    def test_a_zero_session_cost_never_runs_the_body(self) -> None:
        tracker = _tracker(max_cost_per_session=0)
        ran: list[bool] = []
        with pytest.raises(BudgetExceededError), tracker.track("t"):
            ran.append(True)
        assert ran == []
        assert tracker.get_summary().total_calls == 0

    def test_an_estimate_that_would_cross_never_runs_the_body(self) -> None:
        tracker = _tracker(max_tokens_per_call=100)
        ran: list[bool] = []
        with (
            pytest.raises(BudgetExceededError),
            tracker.track("t", estimate=TokenUsage(input_tokens=500)),
        ):
            ran.append(True)
        assert ran == []

    def test_an_admitted_body_runs_and_is_recorded(self) -> None:
        """Control."""
        tracker = _tracker(max_tokens_per_session=100)
        with tracker.track("t") as call:
            call.set_tokens(input_tokens=10)
        assert tracker.get_summary().total_tokens == 10

    def test_the_crossing_body_ran_and_the_next_entry_is_refused(self) -> None:
        tracker = _tracker(max_tokens_per_session=10)
        with pytest.raises(BudgetExceededError), tracker.track("t") as call:
            call.set_tokens(input_tokens=12)
        with pytest.raises(BudgetExceededError), tracker.track("t"):
            pytest.fail("the body of a refused call ran")
