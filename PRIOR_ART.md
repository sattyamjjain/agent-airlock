# Prior art

This file records external research that this library's **premise** depends on, overlaps
with, or ought to be measured against. It exists so credit is attached to the work that
earned it, and so a reader can tell the difference between *what somebody measured* and
*what this library asserts*.

It is not a bibliography of everything cited in this repo. A paper that motivated one
specific guard is credited on that guard's own page under [`docs/policies/`](./docs/policies/)
and in the [CVE catalog](./docs/cves/index.md); that pattern is unchanged. This file is for
work that bears on the premise of the library rather than on a single check.

**Nothing in this file is a head-to-head result.** Where this library has not been run
against someone else's benchmark, the entry says so in those words.

---

## Task-conditioned least-privilege learning (arXiv:2608.18351)

| | |
|---|---|
| **Title** | Task-Conditioned Least-Privilege Learning for Executable Terminal and MCP Agents |
| **Authors** | Alexander Tu, Michael Tu |
| **Submitted** | 18 August 2026 |
| **Link** | <https://arxiv.org/abs/2608.18351> |

### Recorded figures

Verbatim from the abstract, attributed to the authors:

> after training using this framework on Qwen3.5-4B over 1,500 tasks, the selected seed
> reaches 98.48% safe success across 2,896 evaluation episodes spanning all 500 held-out
> tasks, compared with 64.36% for the base policy, and reduces excess-authority error
> events from 4.56% to 0.79%

Their own conclusion, quoted exactly:

> We conclude learned restraint through least-privilege aware post-training is therefore
> useful as an additional control layer for tool-using agents in executable terminal and
> MCP environments, but it does not replace permission gates and sandboxing.

**Read the whole abstract, not the convenient half.** That closing sentence is the one a
project like this one is tempted to quote alone. The same abstract *opens* by stating that
"Traditional permission gating systems alone for validating agent environments are
insufficient" — and permission gating is the category this library is in. The paper argues
that both layers are necessary and neither is sufficient by itself. Quoting only the half
that flatters the gate would misrepresent it, so both halves are recorded here.

### What they establish that this library assumes

agent-airlock was built on a premise it never measured: that a capable tool-using model
will, in the ordinary course of completing a task *correctly*, reach for authority the task
did not require — and that this is a routine failure mode rather than an exotic one. Every
deny-by-default decision in this codebase is downstream of that assumption.

This paper is the measured version of that premise. **64.36% safe success for the base
policy, and excess-authority error events at 4.56%**, are a number where this library had
only a conviction. The authors built the apparatus that makes the premise checkable —
deterministic verifiers scoring each action before execution and again from observed
effects, against pre-declared task-specific sufficient-authority envelopes — and ran it over
a held-out distribution. Establishing that belongs to them, not here.

The direction of the debt is worth stating precisely: their result does not validate this
library's implementation. It validates its problem statement.

### Where the two do different jobs

Theirs is a property of a **trained policy**, measured over a distribution of tasks. This
library's deny-by-default check is a property of the **call path**, and it holds for a call
the policy has never seen.

That distinction is the whole of it. A 98.48% safe-success rate is a claim about an
evaluation distribution — 2,896 episodes over 500 held-out tasks. It is *not* a claim that
the model **cannot** exceed its authority. Those are different statements, and the gap
between them is where the incident lives.

The two also fail differently, which is the practical reason to want both:

- A learned policy degrades **gracefully and invisibly**. Distribution shift moves the rate
  and nothing announces that it moved. The episodes that were not safe successes (1.52% by
  subtraction from their own figure) are not flagged at runtime as the unsafe ones — if they
  were identifiable at runtime, they would have been prevented at runtime.
- A call-path gate fails **loudly and narrowly**. It refuses one specific call with one
  specific reason, and it refuses identically whether the call came from a well-aligned
  model, a jailbroken one, a prompt injection, a bug in the harness, or a replayed
  transcript — because it never consults the model's intent at all.

Neither property is strictly better. A gate cannot make a model *choose* the right tool;
that is what post-training is for, and the paper measures it. Post-training cannot produce a
refusal that holds for an input nobody sampled; that is what a gate is for.

### What this library has NOT measured against them

**There is no head-to-head. Nobody has run this library's gate on their 500 held-out tasks,
and until somebody does, the honest claim is complementarity and not superiority.**

Specifically, none of the following exists:

- **No run of agent-airlock inside their evaluation harness**, as a control layer or
  otherwise.
- **No measurement of what their 0.79% residual excess-authority rate becomes with a
  deny-by-default gate at the call boundary.** That is the single number that would justify
  the complementarity argument made in the section above, and it is unmeasured. The argument
  is currently reasoning, not evidence.
- **No measurement in the other direction.** There is no evidence here about how much of
  this library's blocking is *redundant* against a least-privilege post-trained policy. A
  gate that only ever refuses calls a well-trained model would not have made is a gate whose
  marginal measured value is zero, and nothing in this repository excludes that possibility
  for the population of agents this paper describes.
- **No shared corpus.** Their sufficient-authority envelopes are task-specific and defined
  by the authors; this library's policies are operator-authored. Nothing maps one onto the
  other, so even the deterministic block-rate methodology used in
  [`BENCHMARK.md`](./BENCHMARK.md) does not transfer without a translation layer nobody has
  written.

This is a gap of work not done rather than a gap of access. It is recorded here so the
absence is on the record instead of being left for a reader to notice.

---

## Why this paper is not in the OWASP coverage matrix

[`docs/owasp-agentic-2026-coverage.md`](./docs/owasp-agentic-2026-coverage.md) was the
obvious home for a cross-reference and it is the wrong one. That document is generated from
`src/agent_airlock/owasp_agentic_coverage/agentic_coverage.yaml` and byte-diffed by
`tests/owasp_agentic_coverage/test_coverage_completeness.py`; every row maps an OWASP risk
id to a **guard module, a preset, and a test path in this repository**. A paper has none of
the three.

Adding a row would have meant inventing a guard/preset/test triple that does not exist, or
widening a machine-checked schema so it could hold a citation. A coverage matrix that lists
things this library does not implement is worth less than one that does not, so the paper is
recorded here instead.
