# AgentDojo — adaptive-attacker robustness (agent-airlock as a defense)

Reproduce (deterministic block-coverage, no model, no API key):

```bash
pip install "agent-airlock[bench]"
python -m benchmarks.agentdojo.run
```

Reproduce (model-in-the-loop utility-under-attack + ASR, needs a key + API spend). Pass
`--model` more than once to run several families; each appends a dated block, never
overwriting a prior run:

```bash
python -m benchmarks.agentdojo.run \
  --model gpt-4o-mini-2024-07-18 --model gpt-4o-2024-05-13 \
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

## Result 2 — model-in-the-loop utility-under-attack + ASR (append-only log)

Each dated block below is one run and is never edited after the fact; newer runs are
prepended under the marker.

**Why a second model, and which one.** The 2026-07-31 block below is one model (gpt-4o-mini)
on a 60-pair subset, so its airlock ASR sits in a wide Wilson interval a reviewer can read as
subset selection. The harness now takes `--model` more than once and reports **each model with
its own Wilson CI and its own benign-FPR control**, plus a **pooled figure shown separately**
(not as one measurement), with **token/$ cost recorded per model**.

The intended second model was a different *provider* (Anthropic), to test cross-family
generalisation. At the time of the 2026-08-08 run that was blocked: `agentdojo 0.1.35` is the
latest release and unmaintained, and its model registry lists only retired `claude-3-x` ids —
every Anthropic model the API serves today (claude-4 / claude-5) was unknown to it, and forcing
one in through the enum alone would leave the `tool_knowledge` attack's model-name lookup empty
and produce a meaningless number. So that run uses **`gpt-4o-2024-05-13`**, the larger sibling of
gpt-4o-mini, as the achievable cross-*model* (same-provider, different size) contrast.

That block is now removed without waiting on upstream. `benchmarks/agentdojo/model_registry_shim.py`
registers current Claude ids across **all three** tables agentdojo keys off — `ModelsEnum`
membership, `MODEL_PROVIDERS`, and the `MODEL_NAMES` self-name the attack reads — so the lookup
stays correct and the number stays meaningful (patching the enum alone would not). The
cross-*provider* run is a key away, not an upstream release away:

```bash
python -m benchmarks.agentdojo.run \
  --model claude-sonnet-5 \
  --model gpt-4o-mini-2024-07-18 \
  --out benchmarks/agentdojo/RESULTS.md
```

A `claude-*` `--model` agentdojo does not recognise is auto-registered; `--register-model <id>`
covers a non-claude id or overrides the inferred provider/self-name. The run needs an Anthropic
key and real spend; when it lands, its Wilson interval is published here even if it is wider than
the current subset's, and [#123](https://github.com/sattyamjjain/agent-airlock/issues/123) — held
open for cross-*provider* generalisation — closes.

The finding is published rather than pooled away: airlock cuts ASR on both models, **more on
the stronger gpt-4o (+50pp, 72% → 22%) than on gpt-4o-mini (+30pp, 42% → 12%)**, while gpt-4o's
residual ASR is higher. Cost was captured at the SDK layer (agentdojo calls the provider SDKs
directly, not litellm); total spend ~$5.16.

## Widening plan (#123) — power-calc-sized, ≥3 families (not yet run, pending keys)

The published numbers above rest on a thin sample: two models of **one family** (OpenAI) at a
**60-pair** subset. This section fixes the *sampling* design so the next run is defensible; the
run itself needs three provider keys and real spend and **has not been run yet** — no number
here changes until it has.

**Pair count from a power calculation, not convenience.** `power_sample_size(p1, p2)` in
`run.py` (two-proportion z-test, two-sided) is the source of truth. Sizing to detect a
conservative **15pp** reduction — undefended ASR `p1 = 0.45` → airlock `p2 = 0.30`, `alpha =
0.05`, `power = 0.80` — gives **163 injection→task pairs per arm** (vs the current 60). At an
airlock ASR near 20%, that narrows the 95% Wilson half-width from **±10pp (n=60)** to **±6.1pp
(n=163)** — enough to distinguish a 15pp reduction from zero. Raise `--max-user-tasks` /
`--max-injection-tasks` until the harness reports ≈163 pairs/arm.

**At least three model families, because one model cannot speak for the harness.** **ActBench**
([arXiv:2608.09476](https://arxiv.org/abs/2608.09476)) reports attack-success-rate spanning
**10.1%–94.4% across models under a *fixed* harness** — so a single-model (or single-family)
result cannot support a claim about the defense. The widened run spans three distinct families:
**OpenAI** (`gpt-4o-mini-2024-07-18`, native), **Anthropic** (via
`model_registry_shim.py`), and **Together** (`mistralai/Mixtral-8x7B-Instruct-v0.1`, native,
OpenAI-compatible). Each model is already reported with **its own Wilson CI**, **its own
benign-pass (benign-FPR) control** — a reduction figure without the benign arm cannot
distinguish "the guard works" from "the guard blocks everything" — and **its own measured
token/$ cost**, and the pooled figure is shown separately.

```bash
# needs OPENAI_API_KEY, ANTHROPIC_API_KEY, TOGETHER_API_KEY; caps raised to ≈163 pairs/arm
python -m benchmarks.agentdojo.run \
  --model gpt-4o-mini-2024-07-18 \
  --model claude-sonnet-5 \
  --model mistralai/Mixtral-8x7B-Instruct-v0.1 \
  --max-user-tasks 13 --max-injection-tasks 3 \
  --out benchmarks/agentdojo/RESULTS.md
```

**Commitment.** When this run lands, its per-model Wilson intervals are published here even if
they are wider than the current subset's — and **if the widened sample makes the realised
reduction smaller, the smaller number is published and every place the old one appears
(README benchmark row + gap paragraph) is updated to match.** That outcome is the point of
widening.

<!-- CROSS-MODEL-RUNS: append newest below; never edit dated blocks -->

### 2026-08-08 · cross-model (gpt-4o-mini-2024-07-18, gpt-4o-2024-05-13)

`agentdojo 0.1.35`, attack `tool_knowledge`, benchmark `v1.2.1`, caps <= 5 user / <= 3 injection per suite.
Each row is one model with its **own** Wilson 95% CI and its **own** benign-FPR control.
`cost` is that model's measured token/$ spend for this run.

| model | ASR (undef → airlock) | airlock ASR 95% CI | benign FP cost | n/arm | cost |
| --- | --- | --- | --- | --- | --- |
| `gpt-4o-mini-2024-07-18` | 42% → **12%** (+30%) | [6%, 22%] | +15% | 60 | $0.2383 (814 calls, 1.47M tokens; measured on the initial pass, replayed from cache here) |
| `gpt-4o-2024-05-13` | 72% → **22%** (+50%) | [13%, 34%] | +15% | 60 | 523 calls, 930,865 tokens (904,170 prompt + 26,695 completion), $4.9213 |

Per-model ASR reduction ranges **+30% to +50%** across the 2 models. A defense that generalises should hold its reduction across families; a model
where it does not is a finding, published here rather than pooled away.

**Pooled across models** (reported separately, **not** a single measurement — the models
differ, so this is a weighted average, not one experiment): undefended ASR
57% → airlock **17%** (+40%), airlock
95% Wilson CI [11%, 24%] over 120 attacked
trajectories, benign FP cost +15%. Deterministic upper bound
86%; the pooled realised reduction is +40%
(gap +46%).


### 2026-07-31 · gpt-4o-mini-2024-07-18

Real adaptive-attacker pass, **airlock defense vs no defense**. Model **gpt-4o-mini-2024-07-18**,
`agentdojo 0.1.35`, attack `tool_knowledge`, benchmark `v1.2.1`, run
**2026-07-31** (UTC). Subset: up to **5** user tasks and
**3** injection tasks per suite — a stated subset, **not** the full
609-pair leaderboard cell. Greedy decoding is not guaranteed for this model, so treat
single-run rates as point estimates and read the Wilson interval, not the bare percentage.

| Suite | arm | benign utility | utility under attack | ASR |
| --- | --- | --- | --- | --- |
| workspace | undefended | 100% (5/5) | 87% (13/15) | **13%** (2/15) |
| workspace | airlock | 60% (3/5) | 80% (12/15) | **0%** (0/15) |
| banking | undefended | 40% (2/5) | 20% (3/15) | **40%** (6/15) |
| banking | airlock | 40% (2/5) | 20% (3/15) | **0%** (0/15) |
| travel | undefended | 100% (5/5) | 60% (9/15) | **40%** (6/15) |
| travel | airlock | 100% (5/5) | 93% (14/15) | **7%** (1/15) |
| slack | undefended | 80% (4/5) | 80% (12/15) | **87%** (13/15) |
| slack | airlock | 80% (4/5) | 60% (9/15) | **33%** (5/15) |

**Pooled across suites** (n = 60 attacked trajectories/arm, 20 benign):

| arm | ASR | ASR 95% Wilson CI | benign utility |
| --- | --- | --- | --- |
| undefended | 45% (27/60) | [33%, 58%] | 80% (16/20) |
| **airlock** | **10%** (6/60) | **[5%, 20%]** | 70% (14/20) |

- **ASR reduction (headline): 45% → 10% = +35%** with airlock
  (lower ASR is better); airlock ASR 95% Wilson CI **[5%, 20%]**.
- **Benign false-positive cost: +10%** — benign utility 80% → 70%.
  A false positive here is a benign task the policy breaks by denying a tool the agent
  reached for. The policy allow-lists each task's **minimal ground-truth tools** (matching
  Result 1), so this is the tightest-scoping cost — see the per-suite benign column above
  for where it concentrates; a more permissive per-task allow-list trades some of it back.
  A block rate without this number is not interpretable, which is why it is on the same run.
- **The gap is the finding: deterministic upper bound 86% vs measured
  reduction +35% (gap +51%).** Result 1's 86% is an
  *upper bound* on ASR reduction — the fraction of all 609 injection→task pairs whose target
  tool-call airlock *can* block. The model-in-the-loop reduction here is over 60
  attacked trajectories: a related but distinct quantity on a different sample. The gap
  between "target call blockable" and "attack actually prevented in the loop" is expected —
  the model does not always attempt the blocked call, and some attacks resolve for reasons
  upstream of the tool seam. The deterministic number *bounds*; the model number *realises*.

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
