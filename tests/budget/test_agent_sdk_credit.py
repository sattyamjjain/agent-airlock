"""Tests for the v0.8.0 AgentSDKCreditBudget primitive.

Anthropic 2026-06-15 billing split (Zed blog 2026-05-14): Claude
subscriptions decouple from Claude Code usage when routed through
tools like Zed / Agent SDK. Per-month credit pools:

- $20 Pro
- $100 Max 5x
- $200 Max 20x

This budget primitive lets airlock-wrapped agents debit against
that pool and deny tool calls at 90% / 100% thresholds.

Primary source
--------------
https://zed.dev/blog/anthropic-subscription-changes
"""

from __future__ import annotations

import pytest

from agent_airlock.budget.agent_sdk_credit import (
    AGENT_SDK_TIER_USD,
    AgentSDKCreditBudget,
    AgentSDKCreditDecision,
    AgentSDKCreditVerdict,
    load_anthropic_pricing_2026_06,
)


class TestUnderBudgetAllow:
    """Under 90% spend: every call passes."""

    def test_first_call_under_budget_allowed(self) -> None:
        budget = AgentSDKCreditBudget(monthly_credit_usd=20.0, tier_label="pro")
        decision = budget.register_call(
            model="claude-sonnet-4-6",
            input_tokens=1000,
            output_tokens=200,
        )
        assert isinstance(decision, AgentSDKCreditDecision)
        assert decision.allowed is True
        assert decision.verdict == AgentSDKCreditVerdict.ALLOW
        assert decision.spent_usd > 0
        assert decision.remaining_usd < 20.0


class TestNinetyPercentWarnDeny:
    """Crossing 90% threshold returns NEAR_LIMIT (still allowed) — operator opts out."""

    def test_ninety_percent_emits_near_limit(self) -> None:
        budget = AgentSDKCreditBudget(monthly_credit_usd=1.0, tier_label="pro")
        # Burn ~97.5% of $1 in one call: Opus 4.6 input $15/Mtok × 65k tok = $0.975.
        # Chosen to comfortably land ≥90% without hitting 100% (which would
        # trigger EXHAUSTED instead).
        decision = budget.register_call(
            model="claude-opus-4-6",
            input_tokens=65_000,
            output_tokens=0,
        )
        # The CVE spec says deny-90% but the doc spec says "warn-deny" at 90%
        # — we implement warn-deny: the verdict reflects the threshold but
        # ``allowed`` remains True until 100%.
        assert decision.verdict == AgentSDKCreditVerdict.NEAR_LIMIT
        # Operator policy may choose to convert NEAR_LIMIT → deny; the
        # primitive itself reports the state and lets policy decide.


class TestOneHundredPercentHardDeny:
    """At 100% spend the budget hard-denies."""

    def test_over_budget_hard_denies(self) -> None:
        budget = AgentSDKCreditBudget(monthly_credit_usd=0.10, tier_label="pro")
        # 10k tokens × $15/Mtok = $0.15 → over the $0.10 cap.
        decision = budget.register_call(
            model="claude-opus-4-6",
            input_tokens=10_000,
            output_tokens=0,
        )
        assert decision.allowed is False
        assert decision.verdict == AgentSDKCreditVerdict.EXHAUSTED
        assert decision.remaining_usd <= 0


class TestPersistenceOptional:
    """In-process spend accumulates across register_call calls."""

    def test_spend_accumulates(self) -> None:
        budget = AgentSDKCreditBudget(monthly_credit_usd=100.0, tier_label="max5x")
        d1 = budget.register_call("claude-sonnet-4-6", 1000, 200)
        d2 = budget.register_call("claude-sonnet-4-6", 1000, 200)
        assert d2.spent_usd > d1.spent_usd
        assert d2.remaining_usd < d1.remaining_usd


class TestTierConstants:
    """The Anthropic billing tiers are exposed as module-level constants."""

    def test_pro_tier_constant_is_twenty(self) -> None:
        assert AGENT_SDK_TIER_USD["pro"] == 20.0

    def test_max5x_tier_constant_is_one_hundred(self) -> None:
        assert AGENT_SDK_TIER_USD["max5x"] == 100.0

    def test_max20x_tier_constant_is_two_hundred(self) -> None:
        assert AGENT_SDK_TIER_USD["max20x"] == 200.0


class TestUnknownModelFailsClosed:
    """An unknown model name → ValueError (fail-closed; don't synthesise price)."""

    def test_unknown_model_raises(self) -> None:
        budget = AgentSDKCreditBudget(monthly_credit_usd=100.0)
        with pytest.raises(ValueError, match="unknown.*model"):
            budget.register_call("claude-fictional-7", 1000, 200)


class TestPricingTableLoads:
    """The packaged pricing JSON loads via importlib.resources."""

    def test_pricing_table_loads(self) -> None:
        pricing = load_anthropic_pricing_2026_06()
        assert isinstance(pricing, dict)
        # Must include the three current Claude tiers per the 2026-06 table.
        assert "claude-opus-4-6" in pricing
        assert "claude-sonnet-4-6" in pricing
        assert "claude-haiku-4-5" in pricing
        for _model, rates in pricing.items():
            assert "input_usd_per_million" in rates
            assert "output_usd_per_million" in rates
            assert rates["input_usd_per_million"] > 0
            assert rates["output_usd_per_million"] > 0


class TestBadConstruction:
    def test_negative_credit_rejected(self) -> None:
        with pytest.raises(ValueError, match="positive"):
            AgentSDKCreditBudget(monthly_credit_usd=-5.0)

    def test_zero_credit_rejected(self) -> None:
        with pytest.raises(ValueError, match="positive"):
            AgentSDKCreditBudget(monthly_credit_usd=0.0)
