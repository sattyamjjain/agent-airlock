# `SecurityPolicy.freeze()` silently dropped five security fields (≤ v0.8.73)

**Affected:** **v0.5.7 → v0.8.73.** `freeze()` itself landed in v0.5.5, but the first field
it could drop (`stdio_mode`) arrived in v0.5.7; each later field is affected from its own
release onward (see the table below)
**Fixed in:** **v0.8.74**
**Regression fixture:** [`tests/test_escalate_verdict.py::TestFreezeIsFieldComplete`](https://github.com/sattyamjjain/agent-airlock/blob/main/tests/test_escalate_verdict.py)
**Found:** 2026-08-17, while wiring the third verdict ([#143](https://github.com/sattyamjjain/agent-airlock/issues/143)) into the freeze digest

## What happened

`SecurityPolicy.freeze()` is the CVE-2026-41349 consent-bypass guard. It returns a frozen
copy of a policy with a SHA-256 digest so that `verify_frozen()` can refuse a policy that
was mutated mid-session — the attack it exists to stop added a tool to `allowed_tools` that
the user never approved.

It built that copy from a **hand-maintained list of constructor keyword arguments**:

```python
frozen = SecurityPolicy(
    allowed_tools=list(self.allowed_tools),
    denied_tools=list(self.denied_tools),
    ...
    model_tier_budget=self.model_tier_budget,
)
```

That list was correct when it was written. Every field added to `SecurityPolicy`
afterwards was simply absent from it, and a dataclass constructor fills an absent field
with its default. So the frozen copy silently reverted those fields to their defaults —
and since the digest is computed *from the frozen copy*, the digest agreed with the
weakened policy. Nothing reported drift, because by the time the digest was taken there
was no drift left to see.

The result inverted the method's purpose: **freezing a hardened policy relaxed it.**

## What was dropped

Verified by direct comparison before the fix:

| Field | Added in | Configured | After `freeze()` |
|---|---|---|---|
| `stdio_mode` | v0.5.7 | `"disabled"` | **`"allowlist"`** — subprocess spawning re-enabled |
| `sequence_guard` | v0.8.12 | a `SequenceGuard` | `None` — behavioural route enforcement off |
| `action_contradiction_gate` | v0.8.15 | a gate | `None` |
| `deserialization_guard` | v0.8.19 | a guard | `None` — pickle/marshal content gate off |
| `trace_redaction` | v0.8.24 | a policy | `None` — redaction off for non-local sinks |

`stdio_mode` is the sharpest of the five: an operator who set `"disabled"` to forbid
subprocess spawns entirely, and then froze the policy for integrity, got `"allowlist"`.

The eleven fields already in the kwarg list (`allowed_tools`, `denied_tools`,
`time_restrictions`, `rate_limits`, `require_agent_id`, `allowed_roles`,
`capability_policy`, `reauth_on_untrusted_reinvocation`,
`untrusted_reinvocation_threshold`, `default_deny`, `model_tier_budget`) were **not**
affected, and the CVE-2026-41349 allow/deny-list protection those cover worked as
documented throughout.

## Are you affected

Only if you call `freeze()`. A policy that is never frozen was never touched by this — the
fields work correctly in normal use.

```python
# On <= 0.8.73 this prints "allowlist". On 0.8.74 it prints "disabled".
from agent_airlock import SecurityPolicy
print(SecurityPolicy(stdio_mode="disabled").freeze().stdio_mode)
```

If you froze a policy that set any of the five fields above, that policy has been running
with those controls off. Re-check the settings after upgrading; no configuration change is
needed, the values simply now survive.

## The fix

`freeze()` now rebuilds by iterating `dataclasses.fields`, so it is complete by
construction and a field added tomorrow cannot regress it. Underscore-prefixed fields are
skipped deliberately — `_time_windows` / `_rate_limiters` are caches `__post_init__`
rebuilds, `_lock` cannot be copied, `_frozen_digest` is set afterwards.

The regression test asserts the *property* rather than today's field list:

```python
dropped = [
    spec.name for spec in dataclasses.fields(policy)
    if not spec.name.startswith("_")
    and getattr(policy, spec.name) != getattr(frozen, spec.name)
]
assert dropped == []
```

A field-by-field test would have needed someone to remember to extend it, which is the
same failure that caused the bug.

## Why this was not caught earlier

There was no test that froze a policy and compared it field-for-field against the original.
The existing `freeze()` tests each checked one specific mutation (`allowed_tools` changed →
`verify_frozen()` raises), which is a real property and it held. The gap was that no test
asked the broader question — *does the frozen copy still say what the original said* — and
the fields added over the following releases were never in anyone's field of view.

The escalation work forced the question only because a new field (`escalate_tools`) had to
be covered by the digest, and the test written for it failed for the wrong reason.
