# Managed Agents Outcomes-rubric guard (v0.7.4+)

`agent_airlock.integrations.managed_agents_outcomes_guard.ManagedAgentsOutcomesGuard`
is the runtime gate for Anthropic's **Managed Agents Outcomes rubric**
(beta, shipped at the 2026-05-06 SF Code event). Tool calls
originating from a Managed Agents run carry a rubric verdict ID as
provenance; the guard fails-closed when that anchor is missing or
outside the operator allowlist.

## Why

The Outcomes rubric produces a structured success-criteria verdict
*before* a Managed Agent commits side-effecting tool calls. Without
a runtime gate, an integrator's tool surface has no way to refuse a
call that bypassed the rubric. This guard is the "show me the
rubric anchor" step at the Airlock decorator boundary.

## Install

The guard is core — no optional extra needed. Anthropic's SDK is
**not** imported (the gate is a frozenset[str] lookup). Operators
who don't use Managed Agents pay zero install cost.

## Quickstart

```python
from agent_airlock import (
    Airlock,
    ManagedAgentsOutcomesGuard,
    OutcomesRubricVerdict,
    get_current_context,
)

guard = ManagedAgentsOutcomesGuard(
    allowlist=frozenset({"rub-prod-2026-05-09-a", "rub-prod-2026-05-09-b"}),
)

@Airlock()
def deploy_to_prod(target: str) -> dict:
    ctx = get_current_context()
    decision = guard.evaluate(ctx.metadata.get("provenance"))
    if not decision.allowed:
        raise PermissionError(f"managed-agents rubric gate: {decision.detail}")
    return {"deployed": target}
```

## Companion preset

`agent_airlock.policy_presets.managed_agents_outcomes_2026_05_06_defaults`
returns the recommended config dict. The guard accepts the same
inputs directly; the factory exists for parity with other dict-
returning presets (`mcp_elicitation_guard_2026_04`,
`mcp_config_path_traversal_cve_2026_31402`).

```python
from agent_airlock.policy_presets import managed_agents_outcomes_2026_05_06_defaults

config = managed_agents_outcomes_2026_05_06_defaults(
    allowlist=frozenset({"rub-prod-2026-05-09-a"}),
)
# config["preset_id"] == "managed_agents_outcomes_2026_05_06"
# config["severity"] == "high"
# config["default_action"] == "deny"
# config["allowlist"] == frozenset({"rub-prod-2026-05-09-a"})
# config["provenance_field"] == "managed_agents_outcomes_rubric_id"
```

## Decision shape

`evaluate(provenance)` returns `OutcomesRubricDecision` with four
fields. The `allowed` field intentionally mirrors
[`AllowlistVerdict`](../../src/agent_airlock/runtime/manifest_only_allowlist.py)
so an integrator can chain guards on a single short-circuit
predicate.

| Verdict | When |
|---|---|
| `ALLOW` | rubric ID present and in allowlist |
| `DENY_MISSING_PROVENANCE` | provenance is `None` (no Managed Agents envelope) |
| `DENY_RUBRIC_ID_MISSING` | provenance dict lacks the field, or value is empty / non-string |
| `DENY_RUBRIC_ID_NOT_ALLOWED` | rubric ID present but outside the operator allowlist |

## Custom provenance field

Operators on a non-default Managed Agents harness can override the
field name:

```python
guard = ManagedAgentsOutcomesGuard(
    allowlist=frozenset({"rub-1"}),
    provenance_field="our_internal_rubric_id",
)
```

## Honest scope

- Anthropic's Managed Agents and Outcomes are **beta**. The rubric
  ID format and the field name carrying the anchor in tool-call
  payloads may shift between today (2026-05-06 anchor) and Q3 2026
  GA. The allowlist is a frozenset of strings (no regex), and the
  field name is operator-overridable.
- **Dreaming** memory-curation payloads (the 2026-05-06 research
  preview) are out-of-scope for this guard. Sunday 2026-05-10
  weekly-review candidate for a separate preset.
- Default `allowlist=frozenset()` denies all calls. Operators must
  explicitly enrol the rubric IDs they trust.

## Primary sources

- [Anthropic Managed Agents — Dreaming research preview (2026-05-06)](https://platform.claude.com/docs/en/managed-agents/dreams)
- [Anthropic Code — Routines (2026-05-06)](https://code.claude.com/docs/en/routines)
