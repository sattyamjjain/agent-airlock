"""Per-model-tier cost budget example (v0.8.7).

Demonstrates the :class:`~agent_airlock.ModelTierBudget` primitive: tag each
tool call with a tier label ("frontier" / "mid" / "small"), and agent-airlock
runs a worst-case cost estimate against the tier's per-call cap BEFORE the
tool executes. Untagged calls fall back to the budget's ``strict_tier``
(deny-by-default — the cheapest tier).

A call is tagged through context metadata (``airlock_tier``, ``input_tokens``,
``model_id``), never through the tool's arguments: the model writes those.
Until 0.10.14 ``_airlock_tier`` / ``_airlock_input_tokens`` keyword arguments
were also read, which let a model lower its own estimate.

This file shows four routing patterns:

1. **Tag around the call** — the router decides per call and wraps it in
   ``with AirlockContext(metadata={"airlock_tier": ..., "input_tokens": ...})``.

2. **Tag on a framework context object** — the tool's first argument carries
   the tags, as a ``RunContextWrapper``-style ``ctx.context.metadata``.

3. **model_id → tier_resolver** — the router supplies a callback that
   maps model identifiers to tier labels, and tags calls only with
   ``model_id``. Keeps the model-tier mapping in the router, not in
   agent-airlock.

4. **Compose with allow/deny lists** — the budget is one field of a
   ``SecurityPolicy``.

Run with: ``python -m examples.model_tier_budget``
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from agent_airlock import Airlock, AirlockContext, SecurityPolicy
from agent_airlock.policy_presets import (
    STRICT_MODEL_TIER_BUDGET,
    strict_tier_budget_policy,
)

# ---------------------------------------------------------------------------
# Pattern 1: Tag around the call
# ---------------------------------------------------------------------------

policy = strict_tier_budget_policy()


@Airlock(policy=policy, return_dict=True)
def summarize(text: str) -> str:
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


def _tags(tier: str | None = None, input_tokens: int | None = None) -> AirlockContext[None]:
    metadata: dict[str, Any] = {}
    if tier is not None:
        metadata["airlock_tier"] = tier
    if input_tokens is not None:
        metadata["input_tokens"] = input_tokens
    return AirlockContext[None](metadata=metadata)


def demo_tag_around_the_call() -> None:
    print("=" * 70)
    print("Pattern 1: Router tags each call with AirlockContext metadata")
    print("=" * 70)

    # Cheap call: small tier, low input → succeeds.
    with _tags(_router_tags_per_task("Draft a tweet"), input_tokens=50):
        result = summarize("Draft a tweet about Python.")
    print(f"\n[small/50tk] → {json.dumps(result, indent=2)}")

    # Expensive call: frontier tier with very high input → blocked at
    # worst-case estimate (input + worst-case output × frontier price).
    with _tags(_router_tags_per_task("Deep analysis"), input_tokens=200_000):
        result = summarize("Deep analysis of the entire ARM64 ABI specification...")
    print(f"\n[frontier/200k tk] → {json.dumps(result, indent=2)}")

    # Untagged call: falls back to strict_tier='small' (deny-by-default).
    # With reasonable input tokens it succeeds within small's 2¢ cap.
    with _tags(input_tokens=20):
        result = summarize("Hello.")
    print(f"\n[untagged/20tk → falls back to 'small'] → {json.dumps(result, indent=2)}")


# ---------------------------------------------------------------------------
# Pattern 2: Tag on a framework context object
# ---------------------------------------------------------------------------


@dataclass
class _RunState:
    """What a framework hands a tool as ``ctx.context`` — here, carrying the tags."""

    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class _RunContextWrapper:
    context: _RunState


def demo_context_object_tagging() -> None:
    print("\n" + "=" * 70)
    print("Pattern 2: Tags on the tool's context argument (ctx.context.metadata)")
    print("=" * 70)

    @Airlock(policy=strict_tier_budget_policy(), return_dict=True)
    def translate(ctx: _RunContextWrapper, text: str) -> str:
        return f"TRANSLATED: {text}"

    ctx = _RunContextWrapper(_RunState(metadata={"airlock_tier": "mid", "input_tokens": 100}))
    result = translate(ctx, text="Bonjour le monde.")
    print(f"\n[mid via ctx.context.metadata] → {json.dumps(result, indent=2)}")


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

    # Tag the model_id; airlock invokes the resolver.
    tags = {"model_id": "claude-opus-4-7", "input_tokens": 5_000}  # within the frontier cap
    with AirlockContext[None](metadata=tags):
        result = call_llm("Compare Rust vs C++ ownership models.")
    print(f"\n[model_id=opus → frontier] → {json.dumps(result, indent=2)}")


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
    def call_llm(prompt: str) -> str:
        return f"LLM: {prompt[:40]}"

    with _tags("small", input_tokens=10):
        result = call_llm("hi")
    print(f"\n[allowed + small/10tk] → {json.dumps(result, indent=2)}")


if __name__ == "__main__":
    demo_tag_around_the_call()
    demo_context_object_tagging()
    demo_tier_resolver()
    demo_combined_with_allowlist()
