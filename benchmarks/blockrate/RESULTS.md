# Cross-tool block-rate comparison — results

Last run: **2026-09-06**. Corpus: **210** tool calls.

## Headline

- agent-airlock block-rate (malicious blocked): **100.0%**
- agent-airlock false-positive rate (benign blocked): **0.0%**
- Per-decision latency: **p50 0.0018 ms**, **p95 0.0249 ms** (in-process, no model call, no network)

The latency line is why this is a different layer from model-in-the-loop guardrails: a deny-by-default policy / argument guard decides in microseconds with no model inference, no API round-trip, and a deterministic verdict.

## Cross-tool block-rate comparison

Same tool-call corpus, three approaches. agent-airlock is **re-run** deterministically below; the two incumbents are **model-in-the-loop** systems (model weights / hosted API) that this in-process harness does not execute, so their coverage is a **scope claim, cited, not re-run** — never a fabricated number.

Corpus: **210** tool calls — **106** malicious (must block), **104** benign (must pass).

| Tool | Approach | Block-rate (malicious) | False-positives (benign) | Re-run? |
|---|---|---|---|---|
| **agent-airlock** (deny-by-default presets) | deterministic, in-process | **100.0%** (106 items) | **0.0%** (104 items) | ✅ yes |
| **Meta LlamaFirewall** | model-in-the-loop (PromptGuard 2 + AlignmentCheck + regex/CodeShield) | _scope-claimed, not re-run_ | _scope-claimed, not re-run_ | ❌ no |
| **Invariant Guardrails** | model-in-the-loop + policy DSL over agent traces (Guardrails/Gateway) | _scope-claimed, not re-run_ | _scope-claimed, not re-run_ | ❌ no |

### agent-airlock per-category

| Category | Malicious blocked | Benign blocked (FP) |
|---|---|---|
| Over-privileged tool selection (ToolPrivBench-derived) | 100/100 (100.0%) | 0/0 (0.0%) |
| Tool-argument injection (eval / subprocess / env / codegen) | 6/6 (100.0%) | 0/0 (0.0%) |
| Benign controls (false-positive set) | 0/0 (0.0%) | 0/104 (0.0%) |

### agent-airlock per OWASP Agentic slot (v2.01)

Every one of the ten slots is listed. A slot the corpus does not reach is shown as **n=0**, not omitted — which of the ten this benchmark *cannot* speak to is the column worth reading first. An item that genuinely maps to two slots is counted in both, so the malicious column sums to more than the corpus size.

| Slot | Risk | Malicious n | Blocked | Block-rate | Benign n | False positives |
|---|---|---|---|---|---|---|
| ASI01 | Agent Goal Hijack (Partial) | 20 | 20 | 100.0% | 20 | 0 |
| ASI02 | Tool Misuse and Exploitation (Full) | 22 | 22 | 100.0% | 21 | 0 |
| ASI03 | Identity and Privilege Abuse (Partial) | 21 | 21 | 100.0% | 21 | 0 |
| ASI04 | Agentic Supply Chain Vulnerabilities (Partial) | 23 | 23 | 100.0% | 21 | 0 |
| ASI05 | Unexpected Code Execution / RCE (Full) | 5 | 5 | 100.0% | 2 | 0 |
| ASI06 | Memory and Context Poisoning (Partial) | 20 | 20 | 100.0% | 20 | 0 |
| ASI07 | Insecure Inter-Agent Communication (Partial) | **0** | — | _not measured_ | **0** | — |
| ASI08 | Cascading Failures (Full) | **0** | — | _not measured_ | **0** | — |
| ASI09 | Human-Agent Trust Exploitation (Partial) | **0** | — | _not measured_ | **0** | — |
| ASI10 | Rogue Agents (Monitor-only) | **0** | — | _not measured_ | **0** | — |

Unmapped corpus items (no slot claimed): **0** malicious, **1** benign. An item is left unmapped when no slot fits it honestly; the count is published rather than absorbed into a neighbouring row.

### Incumbent scope (cited, not re-run)

- **Meta LlamaFirewall** — model-in-the-loop (PromptGuard 2 + AlignmentCheck + regex/CodeShield). Targets prompt-injection / jailbreak inputs, agent-misalignment via chain-of-thought auditing, and insecure-code outputs (CodeShield). Tool-argument exploit shapes (subprocess/env/codegen) and least-privilege tool *selection* are not its stated detection targets; PromptGuard/AlignmentCheck are LLM scanners requiring model weights. Source: <https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall>
- **Invariant Guardrails** — model-in-the-loop + policy DSL over agent traces (Guardrails/Gateway). Rule/DSL + classifier checks over MCP/agent traces — PII, secrets, prompt-injection, tool-flow policies. Detection depends on the operator-authored ruleset and (for some checks) a model classifier; no single fixed in-process block-rate to re-run on this corpus. Source: <https://github.com/invariantlabs-ai/invariant>

> **Honest scope.** agent-airlock's 100% here is on a **self-curated** corpus of exploit shapes it is built to catch — it is a coverage / regression baseline, **not** an adaptive-attacker score, and **not** a head-to-head where the incumbents were run. The contrast that matters is *categorical*: agent-airlock blocks **tool-argument exploit shapes and least-privilege tool selection deterministically in-process**, which the cited prompt-injection / trace-policy systems do not target as fixed in-process checks. Different layers — use both.
>
> **AgentDojo now wired** (this replaces the earlier "not yet wired" note): for an *adaptive-attacker* measurement, airlock runs as an [AgentDojo](https://arxiv.org/abs/2406.13352) defense and blocks **84.4%** of `tool_knowledge` injection→task target tool-calls on the pinned workspace+banking subset — a deterministic upper bound on ASR reduction, with a `--model` path for the real model-in-the-loop ASR. See [`benchmarks/agentdojo/RESULTS.md`](../agentdojo/RESULTS.md).

## Reproduce

```bash
python -m benchmarks.blockrate          # print the summary
python -m benchmarks.blockrate --write   # also (re)write this RESULTS.md
```

_Latency is wall-clock and machine-dependent, so it lives here (stamped) rather than in the drift-gated `BENCHMARK.md` — only the deterministic block-rate goes there._
