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

**Give the matched-pair injection null enough sample to mean something.**

The [published null](README.md) is `0/6` per harness per arm with a 95% Wilson interval of
**[0.0%, 39.0%]** — consistent with a true action rate as high as one in three. A **10% upper
bound needs n = 35** (`--trials 18`, 144 cells), and at n = 6 a true 5% rate would still have
produced that exact zero ~74% of the time. The power arithmetic is in
`benchmarks/harness_injection/power.py` and the runner already takes `--trials`. Also gated on
API budget, not on code.

## Next

**Raise OWASP ASI04 (Agentic Supply Chain) coverage from Partial.**
([#124](https://github.com/sattyamjjain/agent-airlock/issues/124) was closed 2026-08-06 — but
the matrix row still reads **Partial** today, so the issue was closed and the coverage was
not raised. Recording that rather than letting a closed ticket imply otherwise.)

The OWASP Agentic Security coverage matrix marks **ASI04** as *Partial* — the README legend's
word for a meaningful control shipping without full mitigation claimed. Today that row is the
Ox MCP STDIO sanitizer, the CVE regression suite, session-snapshot integrity, and the
spawn-time config pin. The README is also explicit about *why* it stays Partial: on-disk
supply-chain compromise that lands before any tool call exists to validate is the wrong layer
for an in-process argument validator, and that boundary is stated deliberately. Raising this
row means either covering more of the runtime supply-chain class, or concluding the remainder
is genuinely out of scope and saying so in the legend instead of leaving it as an open gap.

## Later

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
