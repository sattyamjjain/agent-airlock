"""Per-model-tier cost budget example (v0.8.7).

Demonstrates the :class:`~agent_airlock.ModelTierBudget` primitive: tag each
tool call with a tier label ("frontier" / "mid" / "small"), and agent-airlock
runs a worst-case cost estimate against the tier's per-call cap BEFORE the
tool executes. Untagged calls fall back to the budget's ``strict_tier``
(deny-by-default — the cheapest tier).

This file shows three routing patterns:

1. **Explicit tagging** — the router decides per call and passes
   ``_airlock_tier="frontier"`` as a control kwarg. Stripped before the
   tool sees it.

2. **Context-metadata tagging** — the router sets
   ``context.metadata["airlock_tier"]``. Useful when ``_airlock_tier``
   would clash with a wrapped framework's kwarg-passing convention.

3. **model_id → tier_resolver** — the router supplies a callback that
   maps model identifiers to tier labels, and tags calls only with
   ``context.metadata["model_id"]``. Keeps the model-tier mapping in
   the router, not in agent-airlock.

Run with: ``python -m examples.model_tier_budget``
"""

from __future__ import annotations

import json
from typing import Any

from agent_airlock import (
    Airlock,
    AirlockContext,
    SecurityPolicy,
    set_current_context,
)
from agent_airlock.policy_presets import (
    STRICT_MODEL_TIER_BUDGET,
    strict_tier_budget_policy,
)


# ---------------------------------------------------------------------------
# Pattern 1: Explicit tagging via ``_airlock_tier`` kwarg
# ---------------------------------------------------------------------------

policy = strict_tier_budget_policy()


@Airlock(policy=policy, return_dict=True)
def summarize(text: str, **_extra: Any) -> str:
    """Toy tool — pretends to summarize. In a real router this would call
    an LLM whose tier the caller decides on a per-call basis.
    """
    return f"SUMMARY: {text[:80]}..."


def _router_tags_per_task(task_description: str) -> str:
    """Trivial router: 'deep' → frontier, 'draft' → small, else mid."""
    lowered = task_description.lower()
    if "deep" in lowered or "analysis" in lowered:
        return "frontier"
    if "draft" in lowered or "quick" in lowered:
        return "small"
    return "mid"


def demo_explicit_tagging() -> None:
    print("=" * 70)
    print("Pattern 1: Router tags each call explicitly with _airlock_tier")
    print("=" * 70)

    # Cheap call: small tier, low input → succeeds.
    result = summarize(
        "Draft a tweet about Python.",
        _airlock_tier=_router_tags_per_task("Draft a tweet"),
        _airlock_input_tokens=50,
    )
    print(f"\n[small/50tk] → {json.dumps(result, indent=2)}")

    # Expensive call: frontier tier with very high input → blocked at
    # worst-case estimate (input + 4000 worst-case output × frontier price).
    result = summarize(
        "Deep analysis of the entire ARM64 ABI specification...",
        _airlock_tier=_router_tags_per_task("Deep analysis"),
        _airlock_input_tokens=200_000,
    )
    print(f"\n[frontier/200k tk] → {json.dumps(result, indent=2)}")

    # Untagged call: falls back to strict_tier='small' (deny-by-default).
    # With reasonable input tokens it succeeds within small's 2¢ cap.
    result = summarize("Hello.", _airlock_input_tokens=20)
    print(f"\n[untagged/20tk → falls back to 'small'] → {json.dumps(result, indent=2)}")


# ---------------------------------------------------------------------------
# Pattern 2: Context-metadata tagging
# ---------------------------------------------------------------------------


def demo_context_metadata_tagging() -> None:
    print("\n" + "=" * 70)
    print("Pattern 2: Tag via context.metadata['airlock_tier']")
    print("=" * 70)

    @Airlock(policy=strict_tier_budget_policy(), return_dict=True)
    def translate(text: str) -> str:
        return f"TRANSLATED: {text}"

    ctx = AirlockContext[None]()
    ctx.metadata["airlock_tier"] = "mid"
    ctx.metadata["input_tokens"] = 100
    token = set_current_context(ctx)
    try:
        # Note: real callers usually pass context via the function's first
        # arg (see ContextExtractor). Here we just set it globally to keep
        # the example terse.
        result = translate("Bonjour le monde.")
        print(f"\n[mid via context.metadata] → {json.dumps(result, indent=2)}")
    finally:
        from agent_airlock import reset_context

        reset_context(token)


# ---------------------------------------------------------------------------
# Pattern 3: tier_resolver callback maps model_id → tier
# ---------------------------------------------------------------------------


def model_to_tier(model_id: str) -> str:
    """Caller-defined mapping from model name to tier label.

    Lives in the caller's router so agent-airlock doesn't carry a
    vendor-specific table.
    """
    if "opus" in model_id or "gpt-5" in model_id:
        return "frontier"
    if "sonnet" in model_id or "gpt-4o" in model_id:
        return "mid"
    return "small"


def demo_tier_resolver() -> None:
    print("\n" + "=" * 70)
    print("Pattern 3: tier_resolver(model_id) → tier label")
    print("=" * 70)

    policy_with_resolver = strict_tier_budget_policy(tier_resolver=model_to_tier)

    @Airlock(policy=policy_with_resolver, return_dict=True)
    def call_llm(prompt: str) -> str:
        return f"RESPONSE: {prompt[:60]}"

    # Set context.metadata['model_id']; airlock invokes the resolver.
    ctx = AirlockContext[None]()
    ctx.metadata["model_id"] = "claude-opus-4-7"
    ctx.metadata["input_tokens"] = 5_000  # Plausible frontier input — keeps within cap.
    token = set_current_context(ctx)
    try:
        result = call_llm("Compare Rust vs C++ ownership models.")
        print(f"\n[model_id=opus → frontier] → {json.dumps(result, indent=2)}")
    finally:
        from agent_airlock import reset_context

        reset_context(token)


# ---------------------------------------------------------------------------
# Pattern 4: Compose with allow-lists
# ---------------------------------------------------------------------------


def demo_combined_with_allowlist() -> None:
    print("\n" + "=" * 70)
    print("Pattern 4: Combine ModelTierBudget with allow/deny lists")
    print("=" * 70)

    combined = SecurityPolicy(
        allowed_tools=["call_llm"],
        denied_tools=["exec_*"],
        model_tier_budget=STRICT_MODEL_TIER_BUDGET,
    )

    @Airlock(policy=combined, return_dict=True)
    def call_llm(prompt: str, **_extra: Any) -> str:
        return f"LLM: {prompt[:40]}"

    result = call_llm("hi", _airlock_tier="small", _airlock_input_tokens=10)
    print(f"\n[allowed + small/10tk] → {json.dumps(result, indent=2)}")


if __name__ == "__main__":
    demo_explicit_tagging()
    demo_context_metadata_tagging()
    demo_tier_resolver()
    demo_combined_with_allowlist()
