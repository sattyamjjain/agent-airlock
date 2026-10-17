# Adaptive red-team campaign

!!! info "One file, two locations"

    The results below are
    [`benchmarks/adaptive_redteam/RESULTS.md`](https://github.com/sattyamjjain/agent-airlock/blob/main/benchmarks/adaptive_redteam/RESULTS.md),
    included verbatim. They are written by the campaign runner and stay in the
    benchmark package next to the code that produces them. There is no copy under
    `docs/` to fall out of date.

The adaptive red-team campaign is **defensive hardening of agent-airlock's own
guards**. It drives *harmless sentinels* — a canary file under a forbidden temp
root, a bound `127.0.0.1` listener, a `__reduce__` that only appends a marker to
an in-process list, and a recorded spawn argv — through the project's 38
bypass-target guards to find fail-opens, where a guard admits an input it should
refuse.

There is **no LLM judge**. An attempt counts as a bypass only when two independent
facts hold: the guard admitted the candidate, *and* an independent reference
detector (the stdlib, not the guard's own code) confirms the forbidden shape
reached the sentinel sink. A guard refusal is a hard block; a honeypot reply is
its own outcome and is never counted as a bypass; a benign control the guard
admits is a pass; an adapter error is a harness error. The classifier, the five
sentinels, the 41 adapters (modes A/B/C), the resumable schema-1 ledger and the
Hypothesis property/differential suites are described in the package
[README](https://github.com/sattyamjjain/agent-airlock/blob/main/benchmarks/adaptive_redteam/README.md),
with the full target map in
[`adapters_table.md`](https://github.com/sattyamjjain/agent-airlock/blob/main/benchmarks/adaptive_redteam/adapters_table.md)
and the wave plan in
[`waves.json`](https://github.com/sattyamjjain/agent-airlock/blob/main/benchmarks/adaptive_redteam/waves.json).

An automated null is not a safety proof: a seed that returns zero bypasses under a
plateau-bounded candidate budget still leaves room for a bypass a human could
find. Nulls publish as `0/n (≤ 3/n at 95%)`, with every denominator, run date and
source SHA.

--8<-- "benchmarks/adaptive_redteam/RESULTS.md"
