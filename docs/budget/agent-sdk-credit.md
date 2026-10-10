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
pool + 90% near-limit + 100% exhausted semantics, with dated Anthropic
rate cards shipped as packaged JSON fixtures.

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

Snapshots are **dated and immutable**: when rates move, a new file ships and the
old one stays byte-for-byte, so a receipt written against June prices is still
reproducible in September.

The current fixture is
`src/agent_airlock/data/anthropic_pricing_2026_10.json`, read from the
[official pricing page](https://platform.claude.com/docs/en/about-claude/pricing)
on 2026-10-10, with model ids from the
[models overview](https://platform.claude.com/docs/en/about-claude/models/overview).
`AgentSDKCreditBudget` prices with it unless you pass `override_pricing=`:

```json
{
  "claude-fable-5-1":  {"input_usd_per_million": 10.0, "output_usd_per_million": 50.0},
  "claude-opus-5-5":   {"input_usd_per_million": 4.0, "output_usd_per_million": 20.0},
  "claude-sonnet-5-5": {"input_usd_per_million": 2.0, "output_usd_per_million": 10.0},
  "claude-haiku-5-5":  {"input_usd_per_million": 0.1, "output_usd_per_million":  0.5},
  "claude-opus-5":     {"input_usd_per_million": 5.0, "output_usd_per_million": 25.0},
  "claude-opus-4-8":   {"input_usd_per_million": 5.0, "output_usd_per_million": 25.0},
  "claude-opus-4-7":   {"input_usd_per_million": 5.0, "output_usd_per_million": 25.0},
  "claude-opus-4-6":   {"input_usd_per_million": 5.0, "output_usd_per_million": 25.0},
  "claude-opus-4-5":   {"input_usd_per_million": 5.0, "output_usd_per_million": 25.0},
  "claude-sonnet-5":   {"input_usd_per_million": 2.0, "output_usd_per_million": 10.0},
  "claude-sonnet-4-6": {"input_usd_per_million": 3.0, "output_usd_per_million": 15.0},
  "claude-sonnet-4-5": {"input_usd_per_million": 3.0, "output_usd_per_million": 15.0},
  "claude-haiku-4-5":  {"input_usd_per_million": 1.0, "output_usd_per_million":  5.0}
}
```

Until 0.10.24 the budget defaulted to the June table instead, so with no
`override_pricing=` it counted a Haiku 4.5 call at four fifths of its cost, an
Opus 4.6 or 4.7 call at three times its cost, and raised `ValueError` for every
model the June table lacks, the Claude 5 family included.

**Base input and output only.** Prompt-caching multipliers (cache reads are
0.025x base input on Claude Fable 5.1, 0.05x on Claude Opus 5.5 and Claude
Sonnet 5.5, 0.1x elsewhere), the 50% Batch API discount, data-residency
multipliers and long-context rates all stack on top and are deliberately not
encoded — a budget primitive that silently applied a discount would under-count.
Claude Haiku 5.5 is listed at its rate for prompts up to 100,000 tokens; a longer
prompt costs $0.50 / $2.50 per million, which this table under-counts.

The September snapshot, `anthropic_pricing_2026_09.json`, stays loadable by name
(`load_anthropic_pricing("anthropic_pricing_2026_09.json")`). Every rate it lists
is unchanged; it lacks the Claude 5.5 / 5.1 lineup, so with it those ids raise
`ValueError`.

Load programmatically via `load_anthropic_pricing()`. The previous snapshot is
still loadable via `load_anthropic_pricing_2026_06()`, which now reads the June
file **explicitly** rather than "whatever is current", so code pinned to that
name keeps the rates it was written against. Note it is superseded on three of
its four entries: Opus 4.6 and 4.7 were $15/$75 and are now $5/$25; Haiku 4.5 was
$0.80/$4 and is now $1/$5.

Operators on enterprise / annual contracts override with their own rate card via
the `override_pricing=` kwarg.

## Unknown models

The primitive **fails closed** on unknown model ids — `register_call`
raises `ValueError`. We don't synthesise prices for models we
haven't curated.

## Honest scope

- **In-process accumulation only.** Cross-process / cross-restart
  persistence is out of scope for v0.8.0. Operators who need it
  should layer their own sink (e.g. write `decision.spent_usd` to
  Redis after each call).
- **The pricing table is a dated snapshot of list rates.** Anthropic
  publishes rate-card changes irregularly; operators on long-running
  deploys, or on enterprise rates, should pass their own rate card via
  `override_pricing=`. A refresh ships as a new dated file, never an edit
  to an old one.
- **No automatic month-rollover.** The primitive's spend counter
  resets only when the operator constructs a new
  `AgentSDKCreditBudget`. A simple month-aware wrapper is
  operator-side responsibility (~10 LOC).

## Primary source

- [Zed blog — Anthropic subscription changes (2026-05-14)][zed]
- Anthropic announcement (linked from the Zed blog) — effective 2026-06-15.
