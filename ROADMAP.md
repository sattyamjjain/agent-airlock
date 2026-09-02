# Roadmap

Every item here comes from a caveat this repo's own [README](README.md) already states in
public. Nothing on this list is invented: it is the set of gaps agent-airlock names about
itself, promoted to tracked work.

**How this list is tracked.** Previously this file said "each item is a GitHub issue with the
`roadmap` label" and linked #122 / #123 / #124. All three are closed and the repo has **zero
open issues**, so that sentence pointed at nothing — a reader clicking through found closed
tickets and no way to tell which work had actually landed. The issues are kept below as
*history*, labelled with what shipped and what did not. The plan itself now lives here, in
this file, because a one-maintainer repo with no open issues does not need an issue tracker
to be the source of truth — it needs the source of truth to be somewhere that is actually
maintained.

Shape is Now / Next / Later, ordered by how bounded the work is, not by importance.

## Shipped since this file was last accurate

- **OWASP ASI04 answered rather than raised (v0.8.84).** The question was whether ASI04 is
  Partial because coverage is incomplete or because part of it is out of scope for an
  in-process argument validator. Enumerated against the codebase, the answer is both.

  Uncovered but in scope, now implemented: **tool-definition rug-pull**. A tool approved once
  could be re-served under the same name with a changed description or `inputSchema`.
  `attested_admission` gates on tool *names*, so nothing refused that call.
  `mcp_spec/tool_definition_pin_guard.py` pins the contract and denies on drift.

  Out of scope by architecture, now stated in the legend rather than left as an open gap:
  model checkpoint compromise, on-disk package compromise, and AIBOM/SCA inventory. Each names
  the layer that covers it.

  The row also under-credited three guards already in the tree
  (`description_manifest_guard`, `schema_ref_guard`, `attested_admission`). The coverage label
  is still Partial. Issue [#124](https://github.com/sattyamjjain/agent-airlock/issues/124) was
  closed 2026-08-06 without the coverage being raised, and this is the work that closed it.

- **An MCP conformance suite is run and the result is published.**
  ([#122](https://github.com/sattyamjjain/agent-airlock/issues/122), closed 2026-08-05.)
  The README no longer says "no MCP conformance suite has been run against this package";
  `@modelcontextprotocol/conformance@0.1.16` runs against the wire-path validators and the
  outcome is published in
  [`benchmarks/mcp_conformance/RESULTS.md`](benchmarks/mcp_conformance/RESULTS.md), with the
  date owned by `scripts/check_benchmark_freshness.py` so it cannot silently rot.
- **A second AgentDojo model was added.**
  ([#123](https://github.com/sattyamjjain/agent-airlock/issues/123), closed 2026-08-12.)
  The 2026-08-08 run put gpt-4o-2024-05-13 (ASR 72% → 22%) next to gpt-4o-mini
  (42% → 12%). This closed the *narrowest* reading of that issue and **not** the gap the
  README still describes — see Now, below.

## Now

**Widen the AgentDojo model-in-the-loop run past a single model family.**

The [AgentDojo gap section](README.md#the-agentdojo-gap--the-most-defensible-number-here)
publishes a deterministic **86.0% (524/609)** upper bound alongside a much smaller *realised*
reduction, and states the two "disagree by ~51pp." Two OpenAI models is still **one family**,
and ActBench ([arXiv:2608.09476](https://arxiv.org/abs/2608.09476)) measured ASR spanning
10.1%–94.4% *across* models under a fixed harness — so a single family cannot speak for the
defense no matter how many of its members are sampled.

The harness is already built for this: the model-registry shim carries current Claude ids and
Together is wired. What remains is a keyed run over OpenAI + Anthropic + Together at the
power-calc-sized **163 pairs/arm** documented under "Widening plan" in
[`benchmarks/agentdojo/RESULTS.md`](benchmarks/agentdojo/RESULTS.md). That would replace a
scoped point estimate with a real cross-family number. It is gated on API budget, not on code.

**~~Give the matched-pair injection null enough sample to mean something.~~ Done 2026-08-26.**

Run at `--trials 18` — 144 cells, n = 36 per harness per arm. The injected arm is **0/36** for
both harnesses, 95% Wilson **[0.0%, 9.6%]** and pooled **[0.0%, 5.1%]**, meeting the n = 35
target this item was written to name. It also produced the first live benign control in four
runs (`codex` 1/36), which does *not* establish discrimination — Fisher exact p = 1.00.
Numbers: [`benchmarks/harness_injection/RESULTS.md`](benchmarks/harness_injection/RESULTS.md).

What is left here is a *different* item, and it is worth stating rather than closing quietly:
at n = 36 a true **2%** action rate still escapes this run about half the time, and `codex`
demonstrated a real behaviour at 1-in-36. Bounding rare behaviour needs n ≈ 74
(`--trials 37`, 296 cells), which is again gated on API budget rather than code.

## Next

_The ASI04 item that sat here was resolved in v0.8.84. It is recorded under
"Shipped since this file was last accurate" rather than deleted, because a roadmap that
quietly drops items reads the same as one that never had them._

## Later

**Write the seven missing feature doc pages.**

Fixing the README's dead links in v0.8.80 surfaced this rather than created it: seven shipped
features have no documentation page at all, and the README rows for them were pointing at
files that had never been written. They now point at the source module, which is honest but
thin. The features and their code:

| Feature | Code | Doc |
|---|---|---|
| `airlock attest receipt` | `attest/` | partial — `docs/attest/layer-contract.md` covers the contract block only |
| `airlock console` | `cli/console.py` | none |
| `policy_bundle.lock` | `pack/` | none |
| `airlock studio` | `studio/` | none |
| `airlock graph serve` | `cli/graph.py` | none |
| `airlock policy compile / explain` | `policy_compiler/` | none |
| `airlock kill-switch` | `kill_switch/` | none |

`scripts/check_links.py` now prevents the 404s from coming back, but a gate that stops you
linking a page you never wrote is not the same as writing it.

**Close the `sandbox=True` validation gap.**

With a real sandbox backend, `@Airlock` serialises the *undecorated* function into the
micro-VM, so no `Annotated` validator runs on that path — `SafePath`, `SafeURL`, and
`HandleField` alike. This is documented in `agent_airlock.handles` and pinned by
`TestSandboxDispatchSkipsTheCheck`, so it cannot regress unnoticed, but it is a real hole:
validation and isolation should not be mutually exclusive. The fix belongs in the sandbox
dispatch path and affects every tool, which is why it has not been done as a side effect of a
feature release.

---

Have a gap we should be honest about that is not on this list?
[Open an issue.](https://github.com/sattyamjjain/agent-airlock/issues/new)
