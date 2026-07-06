# AgentDojo — adaptive-attacker robustness (agent-airlock as a defense)

Reproduce (deterministic, no model, no API key):

```bash
pip install "agent-airlock[bench]"
python -m benchmarks.agentdojo.run
```

## What this measures

[AgentDojo](https://arxiv.org/abs/2406.13352) (Debenedetti et al., NeurIPS 2024) is a
**model-in-the-loop** adaptive-attacker benchmark. agent-airlock is registered as an
AgentDojo **defense** — the same `validate -> policy -> execute -> sanitize` seam
`@Airlock` applies, installed at AgentDojo's tool-execution pipeline element
(`AirlockToolsExecutor`): deny-by-default `SecurityPolicy` (least-privilege
allow-list) + ghost-argument BLOCK + output sanitizer.

The numbers below are **deterministic**: using AgentDojo's real `tool_knowledge` injection
tasks' **ground-truth target tool-calls** on the pinned **workspace + banking**
suites (benchmark `v1.2.1`), we measure how many injection->task pairs
airlock's least-privilege policy **blocks at the tool-call seam**. Blocking any one of
an injection's required calls defeats it.

> This is a deterministic **upper bound on airlock's ASR reduction** — the fraction of
> attacks whose target action airlock forces to fail *regardless of model*. It is
> **NOT** AgentDojo's model-in-the-loop Attack Success Rate, and it is **NOT**
> extrapolated to AgentDojo's full task set. For the real ASR (benign utility /
> utility-under-attack / ASR, defended vs undefended), run the model path:
> `python -m benchmarks.agentdojo.run --model <id>` (needs an API key; costs $).

## Result — deterministic block coverage (per-task least-privilege)

| Suite | injection->task pairs | blocked | block rate | per-suite-union |
| --- | --- | --- | --- | --- |
| workspace | 240 | 222 | **92.5%** | 1/6 (17%) |
| banking | 144 | 102 | **70.8%** | 0/9 (0%) |

**Combined: 324/384 pairs blocked = 84.4%** of
`tool_knowledge` injection->task pairs have their target tool-call blocked by airlock's
deny-by-default least-privilege policy.

## The honest nuance (why scoping is what matters)

The **per-suite-union** column allow-lists *every* tool any benign task in the suite
uses, then asks how many injections are still blocked. It is far lower (0% on banking,
where injections abuse a *legitimate* tool like `send_money` with a malicious
recipient; ~17% on workspace). The gap between the per-task and per-suite-union numbers
is the whole point: **least-privilege scoping** — authorizing only the tools the
*current* task needs — is what blocks these attacks at the tool seam. A coarse,
suite-wide allow-list does not. Injections that abuse a legitimately-allowed tool with
malicious arguments are **not** caught by the tool-level policy alone; catching those
needs argument-level policy or the model-in-the-loop run.

## Scope, stated plainly

- Suites: **workspace, banking** (2 of AgentDojo's 4), attack: **tool_knowledge**,
  benchmark version **v1.2.1**.
- Deterministic, offline, reproducible in CI — no model, no API key, no network.
- **Not** a re-run of model-in-the-loop incumbents and **no fabricated competitor
  number.** The model path exists (`--model`) and reports the true ASR when a key is
  supplied.
