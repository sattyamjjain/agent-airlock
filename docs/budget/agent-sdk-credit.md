# Agent SDK Credit pool budget (v0.8.0+)

`agent_airlock.budget.agent_sdk_credit.AgentSDKCreditBudget` is a
per-month USD budget primitive that tracks Anthropic API spend and
returns a deny-decision once the pool is exhausted.

## Why

[Anthropic's 2026-06-15 billing split][zed]: Claude subscriptions
decouple from Claude Code when routed through tools like Zed /
Agent SDK. The per-month credit pools:

| Tier | Monthly USD |
|---|---|
| Pro | $20 |
| Max 5x | $100 |
| Max 20x | $200 |

Before this primitive, agent-airlock operators tracking Anthropic
spend had to roll their own. `AgentSDKCreditBudget` formalises the
pool + 90% near-limit + 100% exhausted semantics, with the
2026-06-01 rate card shipped as a packaged JSON fixture.

[zed]: https://zed.dev/blog/anthropic-subscription-changes

## Install

Core. No optional extra. The Anthropic SDK is **not** loaded.

## Quickstart

```python
from agent_airlock import (
    AGENT_SDK_TIER_USD,
    AgentSDKCreditBudget,
    AgentSDKCreditVerdict,
)

# Pick a tier by label, or pass a custom USD cap.
budget = AgentSDKCreditBudget(
    monthly_credit_usd=AGENT_SDK_TIER_USD["max5x"],  # $100
    tier_label="max5x",
)

decision = budget.register_call(
    model="claude-sonnet-4-6",
    input_tokens=1_000,
    output_tokens=200,
)
# decision.allowed → True (under cap)
# decision.spent_usd → ~$0.006
# decision.remaining_usd → ~$99.994
# decision.verdict → AgentSDKCreditVerdict.ALLOW
```

## Threshold semantics

| Verdict | Trigger | `allowed` |
|---|---|---|
| `ALLOW` | spent < 90% of cap | `True` |
| `NEAR_LIMIT` | 90% ≤ spent < 100% | `True` (operator policy may convert) |
| `EXHAUSTED` | spent ≥ 100% | `False` |

`NEAR_LIMIT` is intentionally **not a hard deny** — the primitive
reports the state and lets operator policy decide whether to
convert to a refusal. Operators wanting hard-deny at 90% wrap the
decision in their own policy check.

## Pricing table

The packaged fixture
`src/agent_airlock/data/anthropic_pricing_2026_06.json` carries the
2026-06-01 Anthropic API list rates:

```json
{
  "claude-opus-4-6":   {"input_usd_per_million": 15.0, "output_usd_per_million": 75.0},
  "claude-opus-4-7":   {"input_usd_per_million": 15.0, "output_usd_per_million": 75.0},
  "claude-sonnet-4-6": {"input_usd_per_million":  3.0, "output_usd_per_million": 15.0},
  "claude-haiku-4-5":  {"input_usd_per_million":  0.80, "output_usd_per_million":  4.0}
}
```

Load programmatically via `load_anthropic_pricing_2026_06()`.
Operators on enterprise / annual contracts override with their own
rate card via the `override_pricing=` kwarg.

## Unknown models

The primitive **fails closed** on unknown model ids — `register_call`
raises `ValueError`. We don't synthesise prices for models we
haven't curated.

## Honest scope

- **In-process accumulation only.** Cross-process / cross-restart
  persistence is out of scope for v0.8.0. Operators who need it
  should layer their own sink (e.g. write `decision.spent_usd` to
  Redis after each call).
- **The pricing table is a 2026-06 snapshot.** Anthropic publishes
  rate-card changes irregularly; operators on long-running deploys
  should override with a current rate card via `override_pricing=`
  or update the packaged JSON.
- **No automatic month-rollover.** The primitive's spend counter
  resets only when the operator constructs a new
  `AgentSDKCreditBudget`. A simple month-aware wrapper is
  operator-side responsibility (~10 LOC).

## Primary source

- [Zed blog — Anthropic subscription changes (2026-05-14)][zed]
- Anthropic announcement (linked from the Zed blog) — effective 2026-06-15.
