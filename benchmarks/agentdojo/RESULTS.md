# AgentDojo — adaptive-attacker robustness (agent-airlock as a defense)

Reproduce (deterministic block-coverage, no model, no API key):

```bash
pip install "agent-airlock[bench]"
python -m benchmarks.agentdojo.run
```

Reproduce (model-in-the-loop utility-under-attack + ASR, needs a key + API spend):

```bash
python -m benchmarks.agentdojo.run --model gpt-4o-mini-2024-07-18 \
  --out benchmarks/agentdojo/RESULTS.md
```

## What this measures

[AgentDojo](https://arxiv.org/abs/2406.13352) (Debenedetti et al., NeurIPS 2024) is a
**model-in-the-loop** adaptive-attacker benchmark. agent-airlock is registered as an
AgentDojo **defense** — the same `validate -> policy -> execute -> sanitize` seam
`@Airlock` applies, installed at AgentDojo's tool-execution pipeline element
(`AirlockToolsExecutor`): deny-by-default `SecurityPolicy` (least-privilege
allow-list) + ghost-argument BLOCK + output sanitizer.

This file reports **two** numbers, and is scrupulous about which is which:

1. a **deterministic block-coverage** number (free, offline, no model) — a defensible
   *upper bound* on airlock's ASR reduction; and
2. the **model-in-the-loop** utility-under-attack + ASR (the actual leaderboard
   metrics), which need an API key and are only shown once really run.

## Result 1 — deterministic block coverage (per-task least-privilege)

Using AgentDojo's real `tool_knowledge` injection tasks' **ground-truth target tool-calls**
on the **workspace, banking, travel, slack** suites (benchmark `v1.2.1`), we
measure how many injection->task pairs airlock's least-privilege policy **blocks at the
tool-call seam**. Blocking any one of an injection's required calls defeats it.

| Suite | injection->task pairs | blocked | block rate | per-suite-union |
| --- | --- | --- | --- | --- |
| workspace | 240 | 222 | **92.5%** | 1/6 (17%) |
| banking | 144 | 102 | **70.8%** | 0/9 (0%) |
| travel | 120 | 114 | **95.0%** | 2/6 (33%) |
| slack | 105 | 86 | **81.9%** | 1/5 (20%) |

**Combined: 524/609 pairs blocked = 86.0%** of
`tool_knowledge` injection->task pairs have their target tool-call blocked by airlock's
deny-by-default least-privilege policy.

> This is a deterministic **upper bound on airlock's ASR reduction** — the fraction of
> attacks whose target action airlock forces to fail *regardless of model*. It is
> **NOT** AgentDojo's model-in-the-loop ASR (that is Result 2), and it is **NOT**
> extrapolated to AgentDojo's full task x injection set.

## Result 2 — model-in-the-loop utility-under-attack + ASR (the leaderboard metrics)

_Not yet run in this checkout._ The two metrics the AgentDojo leaderboard reports —
**utility under attack** (benign task still succeeds with the injection present) and
**ASR** (attack success rate) — require a real model-in-the-loop pass, which needs an
LLM API key and real API spend. To populate this section, run:

```bash
python -m benchmarks.agentdojo.run --model gpt-4o-mini-2024-07-18 \
  --out benchmarks/agentdojo/RESULTS.md
```

with `OPENAI_API_KEY` set. That regenerates this file with a `baseline vs airlock`
table (benign utility / utility-under-attack / ASR / the utility cost of the defense)
for every pinned suite. No number is claimed here until that run produces it.

## What airlock does NOT neutralize (the honest misses)

The **per-suite-union** column allow-lists *every* tool any benign task in the suite
uses, then asks how many injections are still blocked. It drops to **0%** on banking — where the injection abuses a *legitimate* tool (e.g. `send_money` with a malicious recipient) that a suite-wide allow-list still permits, and tops out at **33%** on travel. The gap
between the per-task and per-suite-union columns is the whole point: **least-privilege
scoping** — authorizing only the tools the *current* task needs — is what blocks these
attacks at the tool seam. A coarse, suite-wide allow-list does not. Injections that
abuse a **legitimately-allowed tool with malicious arguments** are **not** caught by the
tool-level policy alone; catching those needs argument-level policy (airlock's strict
Pydantic validation on the specific arg) or the model-in-the-loop run. We report the
misses; we do not claim airlock "blocks everything".

## Where this sits vs a native MCP gateway (the wedge)

A gateway / OAuth resource server authenticates *who* connects and routes the call; it
does not open the tool-call payload and check it against the current task's contract. So
the exact injection classes airlock's contract layer blocks here — **a call to a tool
outside the task's least-privilege scope**, and **an argument key the tool never
declared (ghost-arg BLOCK)** — are precisely the classes a gateway forwards, because
they are well-formed transport-wise and carry a valid token. That is the "contract layer
beneath your gateway" wedge, measured on a third-party adaptive-attacker benchmark rather
than asserted. What a gateway *does* catch that airlock does not (unauthenticated
callers, bad tokens, transport tampering) is complementary — use both.

## Scope, stated plainly

- Suites: **workspace, banking, travel, slack** (all 4 of AgentDojo's suites), attack:
  **tool_knowledge**, benchmark version **v1.2.1**.
- Result 1 is deterministic, offline, reproducible in CI — no model, no API key, no
  network. Result 2 is the real model-in-the-loop pass and is only shown when run.
- **Not** a re-run of model-in-the-loop incumbents and **no fabricated competitor
  number.**
