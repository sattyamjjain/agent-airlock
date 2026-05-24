"""Tests for the per-model-tier cost budget primitive (v0.8.7)."""

from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest

from agent_airlock import (
    Airlock,
    AirlockBudgetExceeded,
    AirlockContext,
    BudgetEstimate,
    CostTracker,
    ModelTierBudget,
    SecurityPolicy,
    TierBudget,
    TokenUsage,
    UnknownTierError,
    reset_context,
    set_current_context,
)
from agent_airlock.cost_tracking import _reset_tracker, set_global_tracker
from agent_airlock.policy_presets import (
    STRICT_MODEL_TIER_BUDGET,
    strict_tier_budget_policy,
)

# Fixed pricing table so tests are deterministic across DEFAULT_PRICING changes.
_TEST_PRICING = {
    "default": {
        "input": Decimal("0.003"),  # 0.3¢ per 1K input tokens
        "output": Decimal("0.015"),  # 1.5¢ per 1K output tokens
    },
}


def _fresh_tracker() -> CostTracker:
    """Return a CostTracker with deterministic pricing for tests."""
    return CostTracker(model="default", pricing=_TEST_PRICING)


def _install_global_test_tracker() -> CostTracker:
    """Install a deterministic global tracker; tests must call _reset_tracker()."""
    tracker = _fresh_tracker()
    set_global_tracker(tracker)
    return tracker


# ---------------------------------------------------------------------------
# TierBudget construction
# ---------------------------------------------------------------------------


class TestTierBudgetConstruction:
    """TierBudget validation."""

    def test_defaults_are_unlimited(self) -> None:
        cap = TierBudget()
        assert cap.max_cost_cents is None
        assert cap.max_output_tokens is None

    def test_negative_cost_cap_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            TierBudget(max_cost_cents=-1)

    def test_negative_token_cap_rejected(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            TierBudget(max_output_tokens=-1)


# ---------------------------------------------------------------------------
# ModelTierBudget construction
# ---------------------------------------------------------------------------


class TestModelTierBudgetConstruction:
    """ModelTierBudget structural validation."""

    def test_requires_at_least_one_tier(self) -> None:
        with pytest.raises(ValueError, match="at least one tier"):
            ModelTierBudget(tiers={}, strict_tier="small")

    def test_strict_tier_must_be_in_tiers(self) -> None:
        with pytest.raises(ValueError, match="strict_tier"):
            ModelTierBudget(
                tiers={"small": TierBudget(max_cost_cents=2)},
                strict_tier="frontier",
            )

    def test_valid_construction(self) -> None:
        budget = ModelTierBudget(
            tiers={"small": TierBudget(max_cost_cents=2)},
            strict_tier="small",
        )
        assert budget.strict_tier == "small"
        assert list(budget.tiers) == ["small"]
        assert budget.tier_resolver is None


# ---------------------------------------------------------------------------
# Tier resolution priority
# ---------------------------------------------------------------------------


class TestTierResolution:
    """Tier-label resolution priority: explicit > resolver > strict_tier."""

    def _budget(self) -> ModelTierBudget:
        return ModelTierBudget(
            tiers={
                "frontier": TierBudget(max_cost_cents=50, max_output_tokens=4000),
                "small": TierBudget(max_cost_cents=2, max_output_tokens=1000),
            },
            strict_tier="small",
        )

    def test_explicit_wins(self) -> None:
        budget = self._budget()
        assert budget.resolve_tier(explicit="frontier") == "frontier"

    def test_explicit_unknown_raises_unknown_tier(self) -> None:
        budget = self._budget()
        with pytest.raises(UnknownTierError):
            budget.resolve_tier(explicit="mythical")

    def test_resolver_used_when_no_explicit(self) -> None:
        budget = ModelTierBudget(
            tiers={
                "frontier": TierBudget(max_cost_cents=50, max_output_tokens=4000),
                "small": TierBudget(max_cost_cents=2, max_output_tokens=1000),
            },
            strict_tier="small",
            tier_resolver=lambda m: "frontier" if "opus" in m else "small",
        )
        assert budget.resolve_tier(model_id="claude-opus-4-7") == "frontier"
        assert budget.resolve_tier(model_id="claude-haiku-4-5") == "small"

    def test_resolver_unknown_label_falls_back_to_strict(self) -> None:
        budget = ModelTierBudget(
            tiers={"small": TierBudget(max_cost_cents=2, max_output_tokens=1000)},
            strict_tier="small",
            tier_resolver=lambda m: "mythical-tier-not-configured",
        )
        # Resolver returns an unknown label → silent fallback to strict_tier
        assert budget.resolve_tier(model_id="any") == "small"

    def test_resolver_exception_falls_back_to_strict(self) -> None:
        def boom(_m: str) -> str:
            raise RuntimeError("router blew up")

        budget = ModelTierBudget(
            tiers={"small": TierBudget(max_cost_cents=2)},
            strict_tier="small",
            tier_resolver=boom,
        )
        assert budget.resolve_tier(model_id="any") == "small"

    def test_no_explicit_no_resolver_uses_strict(self) -> None:
        budget = self._budget()
        assert budget.resolve_tier() == "small"
        # Even with a model_id, no resolver → strict
        assert budget.resolve_tier(model_id="gpt-5") == "small"

    def test_cap_for_unknown_raises(self) -> None:
        budget = self._budget()
        with pytest.raises(UnknownTierError):
            budget.cap_for("mythical")


# ---------------------------------------------------------------------------
# Pre-execute budget check
# ---------------------------------------------------------------------------


class TestPreExecuteCheck:
    """ModelTierBudget.check_pre_execute behavior."""

    def _budget(self) -> ModelTierBudget:
        return ModelTierBudget(
            tiers={
                "frontier": TierBudget(max_cost_cents=50, max_output_tokens=4000),
                "small": TierBudget(max_cost_cents=2, max_output_tokens=1000),
            },
            strict_tier="small",
        )

    def test_under_cap_returns_estimate(self) -> None:
        budget = self._budget()
        tracker = _fresh_tracker()
        estimate = budget.check_pre_execute(
            tier_label="small",
            input_tokens=50,
            cost_tracker=tracker,
        )
        assert isinstance(estimate, BudgetEstimate)
        assert estimate.tier == "small"
        assert estimate.estimated_output_tokens == 1000
        # input 50 * 0.003/1000 + output 1000 * 0.015/1000 = 0.00015 + 0.015 = 0.01515 USD = ~2¢
        assert estimate.estimated_cost_cents == 2

    def test_cost_cap_exceeded_raises_with_tier_and_cap(self) -> None:
        budget = self._budget()
        tracker = _fresh_tracker()
        with pytest.raises(AirlockBudgetExceeded) as exc_info:
            budget.check_pre_execute(
                tier_label="frontier",
                input_tokens=200_000,
                cost_tracker=tracker,
            )
        exc = exc_info.value
        assert exc.tier == "frontier"
        assert exc.cap.max_cost_cents == 50
        assert exc.budget_type == "cost"
        # 200_000 * 0.003/1000 + 4000 * 0.015/1000 = 0.6 + 0.06 = 0.66 USD = 66¢
        assert exc.estimated_cost_cents == 66
        meta = exc.to_block_metadata()
        assert meta["tier"] == "frontier"
        assert meta["cap"]["max_cost_cents"] == 50
        assert meta["budget_type"] == "cost"

    def test_cap_with_no_output_token_cap_uses_input_only_estimate(self) -> None:
        """When max_output_tokens is None, the estimate is input-only (lower bound)."""
        budget = ModelTierBudget(
            tiers={
                "input_only": TierBudget(max_cost_cents=2, max_output_tokens=None),
                "small": TierBudget(max_cost_cents=2, max_output_tokens=1000),
            },
            strict_tier="small",
        )
        tracker = _fresh_tracker()
        estimate = budget.check_pre_execute(
            tier_label="input_only",
            input_tokens=500,
            cost_tracker=tracker,
        )
        # 500 * 0.003/1000 = 0.0015 USD = 0¢ (rounds half up to nearest cent)
        assert estimate.estimated_output_tokens == 0
        assert estimate.estimated_cost_cents == 0

        # 10_000 input tokens: 10000 * 0.003/1000 = 0.03 USD = 3¢ > 2¢ cap
        with pytest.raises(AirlockBudgetExceeded) as exc_info:
            budget.check_pre_execute(
                tier_label="input_only",
                input_tokens=10_000,
                cost_tracker=tracker,
            )
        assert exc_info.value.budget_type == "cost"

    def test_unlimited_tier_never_blocks(self) -> None:
        """A tier with no caps allows any call."""
        budget = ModelTierBudget(
            tiers={"unlimited": TierBudget()},
            strict_tier="unlimited",
        )
        tracker = _fresh_tracker()
        estimate = budget.check_pre_execute(
            tier_label="unlimited",
            input_tokens=10_000_000,
            cost_tracker=tracker,
        )
        assert estimate.tier == "unlimited"

    def test_negative_input_tokens_rejected(self) -> None:
        budget = self._budget()
        tracker = _fresh_tracker()
        with pytest.raises(ValueError, match="non-negative"):
            budget.check_pre_execute(
                tier_label="small",
                input_tokens=-1,
                cost_tracker=tracker,
            )


# ---------------------------------------------------------------------------
# Post-execute reconciliation
# ---------------------------------------------------------------------------


class TestPostExecuteReconciliation:
    """ModelTierBudget.reconcile_post_execute is observability — never raises."""

    def _setup(self) -> tuple[ModelTierBudget, CostTracker, BudgetEstimate]:
        budget = ModelTierBudget(
            tiers={"small": TierBudget(max_cost_cents=2, max_output_tokens=1000)},
            strict_tier="small",
        )
        tracker = _fresh_tracker()
        estimate = budget.check_pre_execute(
            tier_label="small",
            input_tokens=100,
            cost_tracker=tracker,
        )
        return budget, tracker, estimate

    def test_actual_under_estimate_records_negative_delta(self) -> None:
        budget, tracker, estimate = self._setup()
        # Actual output was much lower than worst-case
        record = budget.reconcile_post_execute(
            estimate=estimate,
            actual=TokenUsage(input_tokens=100, output_tokens=50),
            cost_tracker=tracker,
        )
        assert record.delta_cents < 0  # under-estimated (good)
        assert record.output_tokens_over_cap is False
        assert record.input_tokens == 100
        assert record.output_tokens == 50

    def test_actual_over_token_cap_logged_not_raised(self) -> None:
        budget, tracker, estimate = self._setup()
        # Actual output exceeds the tier's cap — observability flag set,
        # but no exception (reconciliation never blocks the result flow).
        record = budget.reconcile_post_execute(
            estimate=estimate,
            actual=TokenUsage(input_tokens=100, output_tokens=2000),  # > 1000 cap
            cost_tracker=tracker,
        )
        assert record.output_tokens_over_cap is True

    def test_reconciliation_does_not_raise_on_session_budget(self) -> None:
        """If a separate BudgetConfig is configured on the tracker, the
        reconciliation path is best-effort and shouldn't propagate
        BudgetExceededError out — that's a different gate."""
        budget, _, estimate = self._setup()
        # Tracker WITHOUT a budget — reconcile_post_execute uses calculate_cost
        # which doesn't trigger the session cap. (Layered session caps are
        # opt-in via BudgetConfig on the tracker, separate from this path.)
        tracker = _fresh_tracker()
        record = budget.reconcile_post_execute(
            estimate=estimate,
            actual=TokenUsage(input_tokens=50, output_tokens=20),
            cost_tracker=tracker,
        )
        assert record.actual_cost_cents >= 0


# ---------------------------------------------------------------------------
# SecurityPolicy integration (digest + check_model_tier_budget)
# ---------------------------------------------------------------------------


class TestSecurityPolicyBudgetField:
    """SecurityPolicy.model_tier_budget field and digest behavior."""

    def test_check_no_op_when_unset(self) -> None:
        policy = SecurityPolicy()
        tracker = _fresh_tracker()
        result = policy.check_model_tier_budget(
            tier_label="anything",
            input_tokens=100,
            cost_tracker=tracker,
        )
        assert result is None

    def test_check_returns_estimate_when_under_cap(self) -> None:
        policy = SecurityPolicy(
            model_tier_budget=ModelTierBudget(
                tiers={"small": TierBudget(max_cost_cents=2, max_output_tokens=1000)},
                strict_tier="small",
            ),
        )
        tracker = _fresh_tracker()
        estimate = policy.check_model_tier_budget(
            tier_label="small",
            input_tokens=50,
            cost_tracker=tracker,
        )
        assert estimate is not None
        assert estimate.tier == "small"

    def test_digest_changes_when_budget_added(self) -> None:
        bare = SecurityPolicy()
        with_budget = SecurityPolicy(
            model_tier_budget=ModelTierBudget(
                tiers={"small": TierBudget(max_cost_cents=2)},
                strict_tier="small",
            ),
        )
        assert bare._compute_policy_digest() != with_budget._compute_policy_digest()

    def test_freeze_carries_budget(self) -> None:
        original = SecurityPolicy(
            model_tier_budget=ModelTierBudget(
                tiers={"small": TierBudget(max_cost_cents=2)},
                strict_tier="small",
            ),
        )
        frozen = original.freeze()
        assert frozen.is_frozen()
        assert frozen.model_tier_budget is original.model_tier_budget
        # verify_frozen with stored digest is a no-op (passes silently)
        frozen.verify_frozen()

    def test_digest_excludes_tier_resolver_callback(self) -> None:
        """Resolver callbacks have non-deterministic identity across
        processes; canonical_payload reduces them to a boolean."""
        b1 = ModelTierBudget(
            tiers={"small": TierBudget(max_cost_cents=2)},
            strict_tier="small",
            tier_resolver=lambda m: "small",
        )
        b2 = ModelTierBudget(
            tiers={"small": TierBudget(max_cost_cents=2)},
            strict_tier="small",
            tier_resolver=lambda m: "small",
        )
        # Different lambdas, same canonical payload
        assert b1.canonical_payload() == b2.canonical_payload()


# ---------------------------------------------------------------------------
# @Airlock integration — the core seam wiring
# ---------------------------------------------------------------------------


class TestCoreIntegration:
    """End-to-end through the @Airlock decorator (sync path)."""

    def setup_method(self) -> None:
        _install_global_test_tracker()

    def teardown_method(self) -> None:
        _reset_tracker()

    def test_frontier_blocks_via_explicit_tier_kwarg(self) -> None:
        policy = strict_tier_budget_policy()

        @Airlock(policy=policy, return_dict=True)
        def call(prompt: str, **_extra: Any) -> str:
            return "ok"

        result = call("hi", _airlock_tier="frontier", _airlock_input_tokens=200_000)
        assert isinstance(result, dict)
        assert result["success"] is False
        assert result["block_reason"] == "budget_exceeded"
        assert result["metadata"]["tier"] == "frontier"
        assert result["metadata"]["budget_type"] == "cost"

    def test_small_tier_succeeds(self) -> None:
        policy = strict_tier_budget_policy()

        @Airlock(policy=policy, return_dict=True)
        def call(prompt: str, **_extra: Any) -> str:
            return "ok"

        result = call("hi", _airlock_tier="small", _airlock_input_tokens=50)
        assert isinstance(result, dict)
        assert result["success"] is True
        assert result["result"] == "ok"

    def test_untagged_call_falls_back_to_strict_tier(self) -> None:
        policy = strict_tier_budget_policy()

        @Airlock(policy=policy, return_dict=True)
        def call(prompt: str, **_extra: Any) -> str:
            return "ok"

        # No _airlock_tier kwarg, no context.metadata, no resolver.
        # Should fall back to strict_tier="small".
        result = call("hi", _airlock_input_tokens=20)
        assert isinstance(result, dict)
        assert result["success"] is True
        # And a too-expensive untagged call IS blocked because small cap is tight.
        result = call("hi", _airlock_input_tokens=2_000_000)
        assert isinstance(result, dict)
        assert result["success"] is False
        assert result["block_reason"] == "budget_exceeded"
        assert result["metadata"]["tier"] == "small"  # deny-by-default tier

    def test_context_metadata_tagging_via_contextvar(self) -> None:
        policy = strict_tier_budget_policy()

        @Airlock(policy=policy, return_dict=True)
        def call(prompt: str) -> str:
            return "ok"

        ctx = AirlockContext[None]()
        ctx.metadata["airlock_tier"] = "mid"
        ctx.metadata["input_tokens"] = 100
        token = set_current_context(ctx)
        try:
            result = call("hi")
        finally:
            reset_context(token)
        assert isinstance(result, dict)
        assert result["success"] is True

    def test_resolver_routes_via_model_id(self) -> None:
        def resolver(model_id: str) -> str:
            return "frontier" if "opus" in model_id else "small"

        policy = strict_tier_budget_policy(tier_resolver=resolver)

        @Airlock(policy=policy, return_dict=True)
        def call(prompt: str) -> str:
            return "ok"

        ctx = AirlockContext[None]()
        ctx.metadata["model_id"] = "claude-opus-4-7"
        ctx.metadata["input_tokens"] = 200_000  # frontier cap is 50¢ — this is 66¢
        token = set_current_context(ctx)
        try:
            result = call("hi")
        finally:
            reset_context(token)
        assert isinstance(result, dict)
        assert result["success"] is False
        assert result["metadata"]["tier"] == "frontier"
        assert result["metadata"]["model_id"] == "claude-opus-4-7"

    def test_unknown_explicit_tier_blocked_as_policy_violation(self) -> None:
        policy = strict_tier_budget_policy()

        @Airlock(policy=policy, return_dict=True)
        def call(prompt: str, **_extra: Any) -> str:
            return "ok"

        result = call("hi", _airlock_tier="mythical")
        assert isinstance(result, dict)
        assert result["success"] is False
        # Caller typo → fail loudly (mapped to policy_violation block reason)
        assert result["block_reason"] == "policy_violation"

    def test_control_kwargs_stripped_before_tool_sees_them(self) -> None:
        policy = strict_tier_budget_policy()

        @Airlock(policy=policy, return_dict=True)
        def call(prompt: str, **_extra: Any) -> dict[str, Any]:
            # If _airlock_tier reached the tool we'd see it in _extra.
            # Assert it does not.
            assert "_airlock_tier" not in _extra
            assert "_airlock_input_tokens" not in _extra
            return {"prompt": prompt}

        result = call("hi", _airlock_tier="small", _airlock_input_tokens=10)
        assert isinstance(result, dict)
        assert result["success"] is True
        assert result["result"] == {"prompt": "hi"}

    def test_post_execute_reconciliation_runs_when_result_carries_token_usage(self) -> None:
        policy = strict_tier_budget_policy()

        @Airlock(policy=policy, return_dict=True)
        def call(prompt: str, **_extra: Any) -> dict[str, Any]:
            return {
                "answer": "42",
                "token_usage": {"input_tokens": 50, "output_tokens": 100},
            }

        result = call("hi", _airlock_tier="small", _airlock_input_tokens=50)
        # Reconciliation is observability — call still succeeds.
        assert isinstance(result, dict)
        assert result["success"] is True


class TestCoreIntegrationAsync:
    """End-to-end through the @Airlock decorator (async path)."""

    def setup_method(self) -> None:
        _install_global_test_tracker()

    def teardown_method(self) -> None:
        _reset_tracker()

    @pytest.mark.asyncio
    async def test_async_blocks_over_budget(self) -> None:
        policy = strict_tier_budget_policy()

        @Airlock(policy=policy, return_dict=True)
        async def call(prompt: str, **_extra: Any) -> str:
            return "ok"

        result = await call("hi", _airlock_tier="frontier", _airlock_input_tokens=200_000)
        assert isinstance(result, dict)
        assert result["success"] is False
        assert result["block_reason"] == "budget_exceeded"
        assert result["metadata"]["tier"] == "frontier"

    @pytest.mark.asyncio
    async def test_async_under_budget_passes(self) -> None:
        policy = strict_tier_budget_policy()

        @Airlock(policy=policy, return_dict=True)
        async def call(prompt: str, **_extra: Any) -> str:
            return "ok"

        result = await call("hi", _airlock_tier="small", _airlock_input_tokens=20)
        assert isinstance(result, dict)
        assert result["success"] is True


# ---------------------------------------------------------------------------
# Preset
# ---------------------------------------------------------------------------


class TestStrictPreset:
    """STRICT_MODEL_TIER_BUDGET + strict_tier_budget_policy()."""

    def test_strict_preset_shape(self) -> None:
        assert STRICT_MODEL_TIER_BUDGET.strict_tier == "small"
        assert set(STRICT_MODEL_TIER_BUDGET.tiers) == {"frontier", "mid", "small"}
        assert STRICT_MODEL_TIER_BUDGET.tiers["frontier"].max_cost_cents == 50
        assert STRICT_MODEL_TIER_BUDGET.tiers["mid"].max_cost_cents == 10
        assert STRICT_MODEL_TIER_BUDGET.tiers["small"].max_cost_cents == 2

    def test_factory_returns_policy_with_budget(self) -> None:
        policy = strict_tier_budget_policy()
        assert isinstance(policy, SecurityPolicy)
        assert policy.model_tier_budget is STRICT_MODEL_TIER_BUDGET

    def test_factory_with_resolver_creates_new_budget(self) -> None:
        def resolver(_m: str) -> str:
            return "small"

        policy = strict_tier_budget_policy(tier_resolver=resolver)
        assert policy.model_tier_budget is not STRICT_MODEL_TIER_BUDGET
        assert policy.model_tier_budget is not None
        assert policy.model_tier_budget.tier_resolver is resolver
