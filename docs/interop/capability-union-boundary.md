# Capability-union boundary — the runtime half (interop with the static scan)

Two tools cover the same exfiltration risk from opposite ends, and they must agree on the
boundary so their verdicts compose:

- **Static (before load):** agent-audit-kit scans a skill set and **flags** a risky capability
  union — a set of skills that, taken together, could read sensitive data and send it out —
  before the agent ever runs.
- **Runtime (at grant time):** agent-airlock does not scan. It **grants and revokes** capability
  leases, and at the point it issues a lease it evaluates the *union* of capability the calling
  context would hold **if this lease were granted** — not just the capability in the lease
  itself — and **denies by default** when the union crosses the boundary.

This page is the shared definition of that boundary so the two halves stay consistent.

## The boundary

A capability lease is tagged with the exfiltration-relevant **categories** it confers
(`CapabilityCategory`): `filesystem_read`, `credential_access`, `network_egress`. The default
boundary (`EXFILTRATION_BOUNDARY`) is:

> **`{filesystem_read` OR `credential_access}`  +  `{non-allowlisted network_egress}`**  is an
> exfiltration path, and is **denied even when each individual lease is independently
> permitted**.

Notes that make the rule precise:

- **Non-allowlisted egress only.** A `network_egress` lease whose destination is on the policy
  allowlist is not a *sink* — egress to a trusted destination is not exfiltration — so it does
  not trigger the boundary.
- **Combination, not single tools.** The rule fires on a *cross-lease* union: the new lease
  supplies one side and a **distinct prior lease** supplies the other. A single reviewed unit
  that intrinsically confers both (e.g. an `upload_file(path, url)` tool declared
  `FILESYSTEM_READ | NETWORK_HTTPS`) is one lease, not a combination, and is not denied here.
- **Deny names the culprit.** A denial names the **specific prior lease** that combined with the
  new one to trigger it — a deny with no explanation gets configured away within a week.

## Runtime API

```python
from agent_airlock.capability_caps import (
    CapabilityCapEngine, CapabilityRulesConfig, CapabilityCategory, Lease, UnionOverride,
)

engine = CapabilityCapEngine(CapabilityRulesConfig())

# Individually permitted:
engine.grant_lease("agent", Lease("L1", "read_config",
                                  frozenset({CapabilityCategory.FILESYSTEM_READ})))

# The combination is an exfiltration path -> CapabilityUnionDeniedError naming "L1":
engine.grant_lease("agent", Lease("L2", "fetch_url",
                                  frozenset({CapabilityCategory.NETWORK_EGRESS})))
```

- `grant_lease(agent_id, lease, *, boundaries=(EXFILTRATION_BOUNDARY,), override=None,
  decision_log=None)` — issues the lease after the union check; raises
  `CapabilityUnionDeniedError` on a crossing (deny-by-default).
- `revoke_lease(agent_id, lease_id)` — drops a held lease so it no longer counts toward the
  union.
- `evaluate_union_grant(held, new, ...)` — the pure decision function, for testing or custom
  wiring.

## The override escape hatch (deliberate, and loud)

Some legitimate workflows need a source + sink combination. The override is explicit and
**non-repudiable**: pass a `UnionOverride(identity, reason)`. The grant is then allowed, and it
is recorded **loudly** —

- a `structlog` `capability_union_override` **warning** with the identity, reason, boundary, and
  the triggering prior lease(s), and
- a `warn` record in the tamper-evident **decision log** (`decision_log=` argument) naming the
  granting identity, so the escape hatch is auditable after the fact.

```python
engine.grant_lease(
    "agent",
    Lease("L2", "fetch_url", frozenset({CapabilityCategory.NETWORK_EGRESS})),
    override=UnionOverride(identity="secops@corp", reason="approved migration window"),
    decision_log=decision_log,   # the override is written here with the identity
)
```

## Honest scope

The runtime check reasons about the *categories a lease confers* and the *union across leases*.
It is a contract-layer control: it denies an exfiltration-shaped capability union by default and
makes the override auditable. It does **not** inspect payloads, prove that a specific egress will
carry specific data, or replace the static pre-load scan — the two halves are complementary.
