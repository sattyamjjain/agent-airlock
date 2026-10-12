# Adaptive red-team — results

Campaign harness that drives harmless sentinels through agent-airlock's 38
bypass-target guards (plus three value-gate adapters) to find fail-opens. No LLM
judge: a `bypass` requires the guard to admit a candidate **and** an independent
reference detector to confirm the forbidden shape reached a sentinel sink. See
[`benchmarks/adaptive_redteam/README.md`](https://github.com/sattyamjjain/agent-airlock/blob/main/benchmarks/adaptive_redteam/README.md)
and the adapter map in
[`adapters_table.md`](https://github.com/sattyamjjain/agent-airlock/blob/main/benchmarks/adaptive_redteam/adapters_table.md).

## Status: Not yet run

The harness, all 41 adapters, the oracle, the resumable ledger and the Hypothesis
suites are in place and green under the CI profile, but **no campaign wave has
been run yet**, so there are no per-seed results to publish. This section fills in
when the coordinator runs wave 1 (see
[`waves.json`](https://github.com/sattyamjjain/agent-airlock/blob/main/benchmarks/adaptive_redteam/waves.json)).

An automated null is not a safety proof. A seed that returns `0/n` bypasses means
only that this harness, with the candidates an Opus agent produced under a plateau
budget, found none — it leaves room for a bypass a human could find. Every number
below will carry its denominator, its run date (UTC), and the airlock version and
source SHA from the ledger header.

## Results table (fills in per wave)

| wave | guard | seeds | arm | attempts (n) | hard_block | honeypot | bypass | benign_pass | false refusals | bypass rate (95% upper) | date |
|---|---|---|---|---|---|---|---|---|---|---|---|
| — | _not yet run_ | — | — | n=0 | — | — | — | — | — | — | — |

## Findings

None yet. When a wave finds a real bypass it lands as:

1. a failing regression test (frozen `CallSpec`),
2. a `fix(security):` commit, and
3. a row here that stays beside its fix (nothing is dropped), with severity per
   the plan's rubric: Critical (default-posture taint), High (non-default,
   honeypot/audit, kill switch), Medium (unreadable-shape fail-open), Low.

A bypass on a physical-sink adapter (filesystem, egress, deserialization, spawn)
is ground truth; a bypass on a symbolic-sink adapter (the pure validators) is a
candidate finding that an independent reference detector flagged and that still
needs human triage before it is claimed.

## Provenance

Per-seed ledgers (`ledger/<guard>/<guard>.seed<NN>[.nohints].json`) are raw run
output and are gitignored; only this aggregate and any summary JSON are committed.
Each ledger header records the airlock version, source SHA, adapter mode, arm
(`fix_hints` true/false), seed and candidate budget.
