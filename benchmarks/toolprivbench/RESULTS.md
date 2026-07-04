# ToolPrivBench-style least-privilege block-rate — results

Scenario source: **subset harness** (~20 scenarios/pattern; pending full-dataset wiring). Total scenarios: **100**. Last run: **2026-07-04**.

**Method note.** Each scenario is wrapped in agent-airlock's deny-by-default least-privilege `SecurityPolicy` (`default_deny=True`, allowlist = only the low-privilege tool the task needs). The over-privileged tool call is recorded as BLOCKED iff `SecurityPolicy.check_tool_allowed` raises `PolicyViolation`; the low-privilege call must remain ALLOWED (so this is not a blunt deny-all). The transient-failure column re-runs the over-privileged decision after an injected low-privilege-tool failure — ToolPrivBench's amplifier — under the same fixed policy.

## Headline

- Over-privileged calls **blocked**: **100.0%** (100 scenarios)
- Over-privileged calls blocked **after transient failure**: **100.0%**
- Legitimate low-privilege calls **allowed** (precision, not deny-all): **100.0%**
- **OPUR** (over-privileged tool-use rate, ToolPrivBench): **100.0% baseline → 0.0% enforced** (**−100.0%** over 100 low-priv-suffices scenarios)

## Block-rate and OPUR per ToolPrivBench risk pattern

| Risk pattern | OWASP-Agentic | Scenarios | Domains | Over-priv blocked | After transient failure | Low-priv allowed | OPUR-baseline | OPUR-enforced | OPUR Δ |
|---|---|---|---|---|---|---|---|---|---|
| Authority Escalation | ASI03 | 20 | 8 | 100.0% | 100.0% | 100.0% | 100.0% | 0.0% | −100.0% |
| Data Over-Exposure | ASI06 | 20 | 8 | 100.0% | 100.0% | 100.0% | 100.0% | 0.0% | −100.0% |
| Safety Bypass | ASI01 | 20 | 8 | 100.0% | 100.0% | 100.0% | 100.0% | 0.0% | −100.0% |
| Scope Expansion | ASI02 | 20 | 8 | 100.0% | 100.0% | 100.0% | 100.0% | 0.0% | −100.0% |
| Temporal Persistence | ASI04 | 20 | 8 | 100.0% | 100.0% | 100.0% | 100.0% | 0.0% | −100.0% |

## Block-rate per OWASP Agentic Top-10 id

| OWASP-Agentic id | Title (best-effort crosswalk) | Scenarios | Over-priv blocked |
|---|---|---|---|
| ASI01 | Agent Control / Authorization Hijacking | 20 | 100.0% |
| ASI02 | Tool Misuse | 20 | 100.0% |
| ASI03 | Privilege Compromise | 20 | 100.0% |
| ASI04 | Resource / Persistence Abuse | 20 | 100.0% |
| ASI06 | Sensitive-Information Exposure | 20 | 100.0% |

## Risk-pattern → OWASP-Agentic crosswalk

| ToolPrivBench risk pattern | OWASP Agentic Top-10 (2026) |
|---|---|
| Authority Escalation | ASI03 Privilege Compromise |
| Data Over-Exposure | ASI06 Sensitive-Information Exposure |
| Safety Bypass | ASI01 Agent Control / Authorization Hijacking |
| Scope Expansion | ASI02 Tool Misuse |
| Temporal Persistence | ASI04 Resource / Persistence Abuse |

> The crosswalk is this harness's **best-effort alignment**, not an official OWASP designation.

## Honest caveat

This benchmark measures **runtime BLOCK behaviour under fixed presets** — not model behaviour. A 100% block-rate means deny-by-default mechanically refuses any tool not on the least-privilege allowlist (including under the transient-failure amplifier where ToolPrivBench shows prompt-level controls degrade); it is **not** a claim that the agent stopped *choosing* over-privileged tools. The complementary low-privilege allow-rate shows the policy is precise, not a blunt deny-all. Anchor: ToolPrivBench / [arXiv:2606.20023](https://arxiv.org/abs/2606.20023).

## OPUR — over-privileged tool-use rate (ToolPrivBench)

**OPUR-baseline 100.0% → OPUR-enforced 0.0%** (Δ **−100.0%**), computed over the **100** scenarios where a lower-privilege tool would have sufficed.

- **OPUR-baseline** — the recorded over-privileged tool call under a **permissive** policy (no airlock): it is allowed through, so the over-privileged tool is used.
- **OPUR-enforced** — the *same* recorded call under airlock's **least-privilege deny-by-default** policy (allow only the sufficient low-privilege tool): it is blocked, so the over-privileged use is prevented.
- A scenario where the high-privilege tool is **legitimately required** is **excluded** from OPUR — reaching for the powerful tool there is correct, not a violation.

> **Honest scope.** OPUR here measures airlock's **enforcement** on the labelled ToolPrivBench scenarios (does deny-by-default prevent the recorded over-privileged reach), **not** what a model would choose. Every scenario in the shipped subset is an over-privileged-selection scenario, so OPUR-baseline is 100% *by construction of the corpus*; the load-bearing numbers are the **enforced** OPUR and the delta. Deterministic, no model call — reproducible in CI. Anchor: [arXiv:2606.20023](https://arxiv.org/abs/2606.20023).
