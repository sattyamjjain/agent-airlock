"""Tests for the Anthropic Messages API task-budget builders.

The wire shape (``task-budgets-2026-03-13``)::

    output_config={"task_budget": {"type": "tokens", "total": N, "remaining": M}}

``total`` is at least 20,000; ``remaining`` is optional and there is no ``policy`` field.
Until 0.10.25 the builders produced ``{"task_budget": {"total_tokens", "remaining_tokens",
"policy"}}`` at the top of the body, which the API does not accept.

Reference:
    https://platform.claude.com/docs/en/build-with-claude/task-budgets
"""

from __future__ import annotations

from typing import Any

import pytest

from agent_airlock import CostTracker
from agent_airlock.exceptions import AirlockError
from agent_airlock.integrations.anthropic_claude_agent_sdk import AnthropicClaudeAgentSDKAdapter
from agent_airlock.integrations.claude_task_budget import (
    BETA_HEADER_VALUE,
    MIN_TASK_BUDGET_TOKENS,
    InvalidTaskBudgetError,
    TaskBudgetExhausted,
    build_output_config,
    build_task_budget,
    build_task_budget_headers,
)

_OLD_KEYS = {"total_tokens", "remaining_tokens", "policy"}


def _keys(value: Any) -> set[str]:
    """Every dict key anywhere in ``value``."""
    if isinstance(value, dict):
        return set(value) | {key for child in value.values() for key in _keys(child)}
    return set()


class TestHeaderBuilder:
    def test_returns_pinned_beta_value(self) -> None:
        assert build_task_budget_headers() == {"anthropic-beta": "task-budgets-2026-03-13"}

    def test_beta_value_is_the_constant(self) -> None:
        assert build_task_budget_headers()["anthropic-beta"] == BETA_HEADER_VALUE

    def test_ignores_body_side_params(self) -> None:
        assert build_task_budget_headers(total_tokens=100, soft=False) == {
            "anthropic-beta": BETA_HEADER_VALUE
        }


class TestTaskBudgetShape:
    def test_total_only(self) -> None:
        assert build_task_budget(50_000) == {"type": "tokens", "total": 50_000}

    def test_with_remaining(self) -> None:
        assert build_task_budget(50_000, 30_000) == {
            "type": "tokens",
            "total": 50_000,
            "remaining": 30_000,
        }

    def test_the_minimum_is_accepted(self) -> None:
        assert MIN_TASK_BUDGET_TOKENS == 20_000
        assert build_task_budget(20_000)["total"] == 20_000

    def test_none_of_the_old_keys_survive(self) -> None:
        assert not _keys(build_output_config(50_000, 10_000, soft=False)) & _OLD_KEYS

    def test_output_config_wraps_the_budget(self) -> None:
        assert build_output_config(total=64_000, remaining=1_000) == {
            "output_config": {
                "task_budget": {"type": "tokens", "total": 64_000, "remaining": 1_000}
            }
        }

    def test_output_config_without_remaining(self) -> None:
        assert build_output_config(64_000) == {
            "output_config": {"task_budget": {"type": "tokens", "total": 64_000}}
        }


class TestInvalidBudgetsAreRefusedBeforeTheyAreSent:
    @pytest.mark.parametrize("total", [19_999, 1_000, 0, -5])
    def test_below_the_minimum(self, total: int) -> None:
        with pytest.raises(InvalidTaskBudgetError) as exc:
            build_task_budget(total)
        assert exc.value.total == total

    @pytest.mark.parametrize("total", [True, 50_000.0, "50000", None])
    def test_a_total_that_is_not_an_int(self, total: Any) -> None:
        with pytest.raises(InvalidTaskBudgetError):
            build_task_budget(total)

    @pytest.mark.parametrize("remaining", [True, 1.5, "10"])
    def test_a_remaining_that_is_not_an_int(self, remaining: Any) -> None:
        with pytest.raises(InvalidTaskBudgetError):
            build_task_budget(50_000, remaining)

    def test_remaining_above_total(self) -> None:
        with pytest.raises(InvalidTaskBudgetError) as exc:
            build_task_budget(50_000, 50_001)
        assert exc.value.remaining == 50_001

    def test_it_is_an_airlock_error(self) -> None:
        assert issubclass(InvalidTaskBudgetError, AirlockError)


class TestSoftAndHard:
    def test_soft_clamps_a_negative_remaining(self) -> None:
        assert build_task_budget(50_000, -200)["remaining"] == 0

    def test_soft_keeps_zero(self) -> None:
        assert build_task_budget(50_000, 0)["remaining"] == 0

    def test_hard_raises_when_exhausted(self) -> None:
        with pytest.raises(TaskBudgetExhausted) as exc:
            build_task_budget(50_000, 0, soft=False)
        assert exc.value.total == 50_000
        assert exc.value.used == 50_000

    def test_hard_raises_when_overshot(self) -> None:
        with pytest.raises(TaskBudgetExhausted) as exc:
            build_output_config(50_000, -200, soft=False)
        assert exc.value.used == 50_200

    def test_hard_with_budget_left_sends_no_policy(self) -> None:
        assert build_task_budget(50_000, 10, soft=False) == {
            "type": "tokens",
            "total": 50_000,
            "remaining": 10,
        }

    def test_taskbudgetexhausted_is_airlock_error(self) -> None:
        with pytest.raises(AirlockError):
            build_task_budget(50_000, 0, soft=False)


class TestCostTrackerDelegates:
    """``CostTracker.to_task_budget`` connects tracked usage to the budget builder."""

    def test_fresh_tracker_full_budget_remaining(self) -> None:
        assert CostTracker().to_task_budget(total=50_000) == {
            "type": "tokens",
            "total": 50_000,
            "remaining": 50_000,
        }

    def test_used_tokens_reduce_remaining(self) -> None:
        tracker = CostTracker()
        with tracker.track("some_tool") as ctx:
            ctx.set_tokens(input_tokens=3_000, output_tokens=2_000)
        assert tracker.to_task_budget(total=25_000)["remaining"] == 20_000

    def test_overshoot_clamps_to_zero(self) -> None:
        tracker = CostTracker()
        with tracker.track("greedy_tool") as ctx:
            ctx.set_tokens(input_tokens=20_000, output_tokens=10_000)
        assert tracker.to_task_budget(total=25_000)["remaining"] == 0

    def test_hard_overshoot_raises(self) -> None:
        tracker = CostTracker()
        with tracker.track("greedy_tool") as ctx:
            ctx.set_tokens(input_tokens=20_000, output_tokens=10_000)
        with pytest.raises(TaskBudgetExhausted):
            tracker.to_task_budget(total=25_000, soft=False)

    def test_a_total_below_the_minimum_is_refused(self) -> None:
        with pytest.raises(InvalidTaskBudgetError):
            CostTracker().to_task_budget(total=1_000)

    def test_none_of_the_old_keys_survive(self) -> None:
        assert not _keys(CostTracker().to_task_budget(total=50_000)) & _OLD_KEYS


class TestAgentSdkKitDelegates:
    def test_unset_total_returns_nothing(self) -> None:
        assert AnthropicClaudeAgentSDKAdapter().task_budget_request_kit(remaining=10) == {}

    def test_kit_carries_the_beta_and_the_output_config(self) -> None:
        kit = AnthropicClaudeAgentSDKAdapter(task_budget_total=64_000).task_budget_request_kit(
            remaining=60_000
        )
        assert kit == {
            "betas": [BETA_HEADER_VALUE],
            "body": {
                "output_config": {
                    "task_budget": {"type": "tokens", "total": 64_000, "remaining": 60_000}
                }
            },
        }

    def test_kit_refuses_a_total_below_the_minimum(self) -> None:
        adapter = AnthropicClaudeAgentSDKAdapter(task_budget_total=1_000)
        with pytest.raises(InvalidTaskBudgetError):
            adapter.task_budget_request_kit(remaining=500)
