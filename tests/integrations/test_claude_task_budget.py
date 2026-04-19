"""Tests for the Anthropic ``task_budget`` adapter (v0.5.1+).

Reference:
    https://platform.claude.com/docs/en/build-with-claude/task-budgets
"""

from __future__ import annotations

import pytest

from agent_airlock import CostTracker
from agent_airlock.exceptions import AirlockError
from agent_airlock.integrations.claude_task_budget import (
    BETA_HEADER_VALUE,
    TaskBudgetExhausted,
    build_output_config,
    build_task_budget_headers,
)


class TestHeaderBuilder:
    def test_returns_pinned_beta_value(self) -> None:
        assert build_task_budget_headers() == {"anthropic-beta": "task-budgets-2026-03-13"}

    def test_beta_value_is_the_constant(self) -> None:
        assert build_task_budget_headers()["anthropic-beta"] == BETA_HEADER_VALUE

    def test_ignores_body_side_params(self) -> None:
        """``total_tokens`` and ``soft`` are reserved for symmetry."""
        assert build_task_budget_headers(total_tokens=100, soft=False) == {
            "anthropic-beta": BETA_HEADER_VALUE
        }


class TestOutputConfigBuilder:
    def test_soft_policy_round_trip(self) -> None:
        out = build_output_config(total=1000, remaining=400, soft=True)
        assert out == {
            "task_budget": {
                "total_tokens": 1000,
                "remaining_tokens": 400,
                "policy": "soft",
            }
        }

    def test_hard_policy_round_trip(self) -> None:
        out = build_output_config(total=1000, remaining=400, soft=False)
        assert out["task_budget"]["policy"] == "hard"

    def test_remaining_clamped_to_zero_for_soft(self) -> None:
        """Soft policy does NOT raise when budget is exhausted — it
        clamps to 0 and lets the model see a zeroed countdown."""
        out = build_output_config(total=1000, remaining=-50, soft=True)
        assert out["task_budget"]["remaining_tokens"] == 0
        assert out["task_budget"]["policy"] == "soft"

    def test_hard_policy_raises_when_exhausted(self) -> None:
        with pytest.raises(TaskBudgetExhausted) as exc:
            build_output_config(total=1000, remaining=0, soft=False)
        assert exc.value.total == 1000
        assert exc.value.used == 1000

    def test_hard_policy_raises_when_overshot(self) -> None:
        with pytest.raises(TaskBudgetExhausted):
            build_output_config(total=1000, remaining=-200, soft=False)

    def test_taskbudgetexhausted_is_airlock_error(self) -> None:
        with pytest.raises(AirlockError):
            build_output_config(total=100, remaining=0, soft=False)


class TestCostTrackerIntegration:
    """``CostTracker.to_task_budget`` — the glue that connects existing
    cost tracking to the Claude beta without duplicating state."""

    def test_fresh_tracker_full_budget_remaining(self) -> None:
        tracker = CostTracker()
        payload = tracker.to_task_budget(total=50_000)
        tb = payload["task_budget"]
        assert tb["total_tokens"] == 50_000
        assert tb["remaining_tokens"] == 50_000
        assert tb["policy"] == "soft"

    def test_used_tokens_reduce_remaining(self) -> None:
        tracker = CostTracker()
        with tracker.track("some_tool") as ctx:
            ctx.set_tokens(input_tokens=300, output_tokens=200)
        payload = tracker.to_task_budget(total=1000)
        assert payload["task_budget"]["remaining_tokens"] == 500

    def test_overshoot_clamps_to_zero(self) -> None:
        tracker = CostTracker()
        with tracker.track("greedy_tool") as ctx:
            ctx.set_tokens(input_tokens=800, output_tokens=400)  # 1200 > 1000
        payload = tracker.to_task_budget(total=1000)
        assert payload["task_budget"]["remaining_tokens"] == 0

    def test_hard_policy_flag_plumbs_through(self) -> None:
        tracker = CostTracker()
        payload = tracker.to_task_budget(total=1000, soft=False)
        assert payload["task_budget"]["policy"] == "hard"
