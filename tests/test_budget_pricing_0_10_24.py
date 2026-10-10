"""Regressions for 0.10.24: both budgets priced calls at the wrong rates.

- ``ModelTierBudget`` priced every call's worst case at the global tracker's own model,
  the ``"default"`` row (Sonnet rates) unless the host set another, whatever ``model_id``
  the call carried. A call to a dearer model was under-estimated and passed a cap it
  breaches: ``claude-opus-4-7`` with 100k input tokens is 60¢ worst case against a 50¢
  frontier cap, and was allowed at the default row's 36¢. A ``model_id`` the table does
  not list now prices at the table's dearest row (a dated snapshot of a listed model,
  ``<key>-YYYYMMDD``, at that model's); an untagged call is unchanged.
- ``AgentSDKCreditBudget`` defaulted to the superseded 2026-06 snapshot. A $10 pool
  allowed a second 1M-in/1M-out Haiku 4.5 call at a counted $9.60 when the real spend is
  $12.00, priced Opus 4.6 and 4.7 at three times their rate, and raised ``ValueError``
  for every Claude 5 model. It now defaults to the current snapshot.
- ``DEFAULT_PRICING`` lacked four models the current snapshot prices (``claude-opus-4-8``,
  ``-4-6``, ``-4-5`` and ``claude-sonnet-4-5``), so those fell to the default row too.
"""

from __future__ import annotations

from collections.abc import Iterator
from decimal import Decimal

import pytest

from agent_airlock import (
    Airlock,
    AirlockBudgetExceeded,
    AirlockContext,
    CostTracker,
    ModelTierBudget,
    TierBudget,
    TokenUsage,
)
from agent_airlock.budget.agent_sdk_credit import (
    AgentSDKCreditBudget,
    AgentSDKCreditVerdict,
    load_anthropic_pricing,
    load_anthropic_pricing_2026_06,
)
from agent_airlock.cost_tracking import DEFAULT_PRICING, _reset_tracker, set_global_tracker
from agent_airlock.policy_presets import strict_tier_budget_policy

#: The strict preset's frontier cap: 50¢ per call, 4000 output tokens worst case.
FRONTIER = TierBudget(max_cost_cents=50, max_output_tokens=4000)


def _frontier_budget() -> ModelTierBudget:
    return ModelTierBudget(tiers={"frontier": FRONTIER}, strict_tier="frontier")


#: A table where the default row is neither the cheapest nor the dearest.
_THREE_ROWS = {
    "default": {"input": Decimal("0.003"), "output": Decimal("0.015")},
    "cheap": {"input": Decimal("0.001"), "output": Decimal("0.005")},
    "dear": {"input": Decimal("0.015"), "output": Decimal("0.075")},
}


@pytest.fixture
def default_global_tracker() -> Iterator[CostTracker]:
    """The tracker ``@Airlock`` prices with when the host configured none."""
    tracker = CostTracker()
    set_global_tracker(tracker)
    yield tracker
    _reset_tracker()


class TestATierBudgetPricesTheCallsOwnModel:
    """The worst case is priced at the ``model_id`` the call carries."""

    def test_an_opus_call_breaches_the_cap_the_default_row_passed(self) -> None:
        budget = _frontier_budget()
        # The 0.10.23 arithmetic, at the default row: 100k * 0.003/1K + 4000 * 0.015/1K = 36¢.
        untagged = budget.check_pre_execute(
            tier_label="frontier", input_tokens=100_000, cost_tracker=CostTracker()
        )
        assert untagged.estimated_cost_cents == 36

        # At opus-4-7's own row: 100k * 0.005/1K + 4000 * 0.025/1K = 60¢ > 50¢.
        with pytest.raises(AirlockBudgetExceeded) as exc_info:
            budget.check_pre_execute(
                tier_label="frontier",
                input_tokens=100_000,
                cost_tracker=CostTracker(),
                model_id="claude-opus-4-7",
            )
        exc = exc_info.value
        assert exc.estimated_cost_cents == 60
        assert exc.priced_as == "claude-opus-4-7"
        assert exc.to_block_metadata()["priced_as"] == "claude-opus-4-7"

    def test_through_the_decorator(self, default_global_tracker: CostTracker) -> None:
        """The audit's repro: a resolver routes opus to frontier, metadata carries the model."""
        policy = strict_tier_budget_policy(
            tier_resolver=lambda model: "frontier" if "opus" in model else "small"
        )

        @Airlock(policy=policy)
        def think() -> str:
            return "thought"

        metadata = {"model_id": "claude-opus-4-7", "input_tokens": 100_000}
        with AirlockContext(agent_id="a1", metadata=metadata):
            result = think()
        assert isinstance(result, dict)
        assert result["success"] is False
        assert result["block_reason"] == "budget_exceeded"
        assert result["metadata"]["estimated_cost_cents"] == 60

    def test_a_cheaper_model_is_priced_at_its_own_row(self) -> None:
        estimate = _frontier_budget().check_pre_execute(
            tier_label="frontier",
            input_tokens=100_000,
            cost_tracker=CostTracker(),
            model_id="claude-haiku-4-5",
        )
        # 100k * 0.001/1K + 4000 * 0.005/1K = 12¢.
        assert estimate.estimated_cost_cents == 12
        assert estimate.priced_as == "claude-haiku-4-5"


class TestAnUnlistedModelIsPricedAtTheDearestRow:
    """A model the table cannot price is never priced at the mid-priced default row."""

    def test_an_unlisted_model_is_priced_at_the_dearest_row(self) -> None:
        budget = ModelTierBudget(
            tiers={"mid": TierBudget(max_cost_cents=10, max_output_tokens=1000)},
            strict_tier="mid",
        )
        tracker = CostTracker(pricing=_THREE_ROWS)
        # At the default row: 10k * 0.003/1K + 1000 * 0.015/1K = 4.5¢ -> 5¢, under the cap.
        assert (
            budget.check_pre_execute(
                tier_label="mid", input_tokens=10_000, cost_tracker=tracker
            ).estimated_cost_cents
            == 5
        )
        # Unlisted: 10k * 0.015/1K + 1000 * 0.075/1K = 22.5¢ -> 23¢.
        with pytest.raises(AirlockBudgetExceeded) as exc_info:
            budget.check_pre_execute(
                tier_label="mid",
                input_tokens=10_000,
                cost_tracker=tracker,
                model_id="claude-opus-9",
            )
        exc = exc_info.value
        assert exc.priced_as == "dear"
        assert exc.estimated_cost_cents == 23
        assert "not in the pricing table" in str(exc)

    def test_the_dearest_row_is_the_dearest_for_this_call(self) -> None:
        """Dearest means for the call's own token mix, not the highest output price."""
        lopsided = {
            "default": {"input": Decimal("0.003"), "output": Decimal("0.015")},
            "input_heavy": {"input": Decimal("0.05"), "output": Decimal("0.001")},
            "output_heavy": {"input": Decimal("0.001"), "output": Decimal("0.05")},
        }
        tracker = CostTracker(pricing=lopsided)
        input_only = ModelTierBudget(tiers={"t": TierBudget()}, strict_tier="t")
        assert (
            input_only.check_pre_execute(
                tier_label="t", input_tokens=10_000, cost_tracker=tracker, model_id="x"
            ).priced_as
            == "input_heavy"
        )
        output_only = ModelTierBudget(
            tiers={"t": TierBudget(max_output_tokens=1000)}, strict_tier="t"
        )
        assert (
            output_only.check_pre_execute(
                tier_label="t", input_tokens=0, cost_tracker=tracker, model_id="x"
            ).priced_as
            == "output_heavy"
        )

    def test_the_fallback_table_prices_an_unlisted_model_at_its_dearest_row(self) -> None:
        estimate = ModelTierBudget(tiers={"t": TierBudget()}, strict_tier="t").check_pre_execute(
            tier_label="t", input_tokens=1000, cost_tracker=CostTracker(), model_id="unlisted"
        )
        dearest = max(DEFAULT_PRICING, key=lambda key: DEFAULT_PRICING[key]["input"])
        assert estimate.priced_as == dearest

    def test_the_refusal_names_the_row_it_priced_at(
        self, default_global_tracker: CostTracker
    ) -> None:
        """The caller learns why: the row used, and how to tag the call so it is listed."""

        @Airlock(policy=strict_tier_budget_policy())
        def think() -> str:
            return "thought"

        with AirlockContext(agent_id="a1", metadata={"model_id": "mystery-model"}):
            unlisted = think()
        assert isinstance(unlisted, dict)
        assert unlisted["metadata"]["priced_as"] == "claude-3-opus"
        assert any("not in the pricing table" in hint for hint in unlisted["fix_hints"])

        with AirlockContext(
            agent_id="a1",
            metadata={"model_id": "claude-opus-4-7", "airlock_tier": "small"},
        ):
            listed = think()
        assert isinstance(listed, dict)
        assert listed["metadata"]["priced_as"] == "claude-opus-4-7"
        assert not any("not in the pricing table" in hint for hint in listed["fix_hints"])

    def test_a_dated_snapshot_is_priced_at_its_model(self) -> None:
        """``<listed key>-YYYYMMDD`` is the same model; anything else unlisted is not."""
        budget = ModelTierBudget(tiers={"t": TierBudget()}, strict_tier="t")
        dated = budget.check_pre_execute(
            tier_label="t",
            input_tokens=1000,
            cost_tracker=CostTracker(),
            model_id="claude-sonnet-4-5-20250929",
        )
        assert dated.priced_as == "claude-sonnet-4-5"
        preview = budget.check_pre_execute(
            tier_label="t",
            input_tokens=1000,
            cost_tracker=CostTracker(),
            model_id="claude-sonnet-4-5-preview",
        )
        assert preview.priced_as != "claude-sonnet-4-5"


class TestAnUntaggedCallIsPricedAsBefore:
    """No ``model_id``: the tracker's own model, exactly as before 0.10.24."""

    def test_the_default_tracker_prices_at_the_default_row(self) -> None:
        estimate = _frontier_budget().check_pre_execute(
            tier_label="frontier", input_tokens=100_000, cost_tracker=CostTracker()
        )
        assert estimate.estimated_cost_cents == 36
        assert estimate.priced_as == "default"

    def test_a_tracker_configured_for_a_model_prices_at_that_row(self) -> None:
        estimate = _frontier_budget().check_pre_execute(
            tier_label="frontier",
            input_tokens=100_000,
            cost_tracker=CostTracker(model="claude-haiku-4-5"),
        )
        assert estimate.estimated_cost_cents == 12
        assert estimate.priced_as == "claude-haiku-4-5"

    def test_a_tracker_model_the_table_lacks_falls_back_to_default(self) -> None:
        estimate = _frontier_budget().check_pre_execute(
            tier_label="frontier",
            input_tokens=100_000,
            cost_tracker=CostTracker(model="not-a-model"),
        )
        assert estimate.estimated_cost_cents == 36
        assert estimate.priced_as == "default"


class TestReconciliationPricesTheSameWay:
    """Post-execute reconciliation prices the actuals at the estimate's row."""

    def test_the_actuals_use_the_estimates_model(self) -> None:
        budget = _frontier_budget()
        tracker = CostTracker()
        # 10k * 0.005/1K + 4000 * 0.025/1K = 15¢ worst case.
        estimate = budget.check_pre_execute(
            tier_label="frontier",
            input_tokens=10_000,
            cost_tracker=tracker,
            model_id="claude-opus-4-7",
        )
        assert estimate.estimated_cost_cents == 15
        record = budget.reconcile_post_execute(
            estimate=estimate,
            actual=TokenUsage(input_tokens=10_000, output_tokens=2_000),
            cost_tracker=tracker,
        )
        # 10k * 0.005/1K + 2000 * 0.025/1K = 10¢; the default row would have said 6¢.
        assert record.actual_cost_cents == 10
        assert record.delta_cents == -5
        assert record.priced_as == "claude-opus-4-7"

    def test_an_unlisted_model_reconciles_at_the_dearest_row(self) -> None:
        budget = ModelTierBudget(tiers={"t": TierBudget()}, strict_tier="t")
        tracker = CostTracker(pricing=_THREE_ROWS)
        estimate = budget.check_pre_execute(
            tier_label="t", input_tokens=1000, cost_tracker=tracker, model_id="unlisted"
        )
        record = budget.reconcile_post_execute(
            estimate=estimate,
            actual=TokenUsage(input_tokens=1000, output_tokens=1000),
            cost_tracker=tracker,
        )
        assert estimate.priced_as == record.priced_as == "dear"

    def test_reconciliation_does_not_record_on_the_tracker(self) -> None:
        """It computes and logs; a BudgetConfig session cap on the tracker never sees it."""
        budget = _frontier_budget()
        tracker = CostTracker()
        estimate = budget.check_pre_execute(
            tier_label="frontier", input_tokens=1000, cost_tracker=tracker
        )
        budget.reconcile_post_execute(
            estimate=estimate,
            actual=TokenUsage(input_tokens=1000, output_tokens=100),
            cost_tracker=tracker,
        )
        assert tracker.get_records() == []


class TestTheFallbackTableListsEveryCurrentModel:
    """``DEFAULT_PRICING`` prices every model the current snapshot prices, at its rates."""

    def test_every_snapshot_model_is_in_the_fallback_table(self) -> None:
        for model, rates in load_anthropic_pricing().items():
            assert model in DEFAULT_PRICING, f"{model} missing from DEFAULT_PRICING"
            per_1k = DEFAULT_PRICING[model]
            assert per_1k["input"] == Decimal(str(rates["input_usd_per_million"])) / 1000
            assert per_1k["output"] == Decimal(str(rates["output_usd_per_million"])) / 1000


class TestTheCreditBudgetDefaultsToTheCurrentCard:
    """``AgentSDKCreditBudget`` prices with the current snapshot unless told otherwise."""

    def test_the_second_haiku_call_exhausts_a_ten_dollar_pool(self) -> None:
        budget = AgentSDKCreditBudget(10.0)
        first = budget.register_call("claude-haiku-4-5", 1_000_000, 1_000_000)
        assert first.allowed is True
        second = budget.register_call("claude-haiku-4-5", 1_000_000, 1_000_000)
        # $1/M in + $5/M out = $6 per call; the June table counted $4.80.
        assert second.spent_usd == pytest.approx(12.0)
        assert second.allowed is False
        assert second.verdict == AgentSDKCreditVerdict.EXHAUSTED

    def test_it_prices_the_claude_5_family(self) -> None:
        decision = AgentSDKCreditBudget(100.0).register_call("claude-opus-5", 1_000_000, 0)
        assert decision.last_call_usd == pytest.approx(5.0)

    @pytest.mark.parametrize(
        ("model", "usd_per_million_in_out"),
        [
            ("claude-fable-5-1", 10.0 + 50.0),
            ("claude-opus-5-5", 4.0 + 20.0),
            ("claude-sonnet-5-5", 2.0 + 10.0),
            ("claude-haiku-5-5", 0.1 + 0.5),
        ],
    )
    def test_it_prices_the_current_lineup(self, model: str, usd_per_million_in_out: float) -> None:
        """The 2026-10 snapshot lists the current models (pricing page read 2026-10-10)."""
        decision = AgentSDKCreditBudget(1000.0).register_call(model, 1_000_000, 1_000_000)
        assert decision.last_call_usd == pytest.approx(usd_per_million_in_out)

    def test_a_tier_budget_prices_the_current_lineup_at_its_own_rows(self) -> None:
        estimate = _frontier_budget().check_pre_execute(
            tier_label="frontier",
            input_tokens=100_000,
            cost_tracker=CostTracker(),
            model_id="claude-opus-5-5",
        )
        # 100k * 0.004/1K + 4000 * 0.020/1K = 48¢: under the 50¢ cap, at its own row.
        assert estimate.priced_as == "claude-opus-5-5"
        assert estimate.estimated_cost_cents == 48

    def test_the_june_card_is_still_reproducible_on_request(self) -> None:
        budget = AgentSDKCreditBudget(10.0, override_pricing=load_anthropic_pricing_2026_06())
        budget.register_call("claude-haiku-4-5", 1_000_000, 1_000_000)
        second = budget.register_call("claude-haiku-4-5", 1_000_000, 1_000_000)
        assert second.spent_usd == pytest.approx(9.6)
        assert second.verdict == AgentSDKCreditVerdict.NEAR_LIMIT
