# Roadmap

Every item here comes from a caveat this repo's own [README](README.md) already
states in public. Nothing on this list is invented: it is the set of gaps
agent-airlock names about itself, promoted to tracked work. Each item is a
GitHub issue with the [`roadmap`](https://github.com/sattyamjjain/agent-airlock/labels/roadmap)
label.

Shape is Now / Next / Later, ordered by how bounded the work is, not by
importance.

## Now

**Run an MCP conformance suite and publish the result** — [#122](https://github.com/sattyamjjain/agent-airlock/issues/122)

The README is explicit that the `2026-07-28` guards are validators and
forward-compatible hardening, "**not a conformance claim** — no MCP conformance
suite has been run against this package." The work is to run an available
conformance suite against the wire-path validators (`mcp_spec.transport`, header
integrity, the stateless model) and publish the outcome, so that line reports a
measured result instead of an absence.

## Next

**Tighten the realised AgentDojo number beyond the 60-pair / single-model subset** — [#123](https://github.com/sattyamjjain/agent-airlock/issues/123)

The [AgentDojo gap section](README.md#the-agentdojo-gap--the-most-defensible-number-here)
publishes both a deterministic **86.0% (524/609)** upper bound and a much smaller
*realised* model-in-the-loop reduction (ASR **45% to 10%**, 95% Wilson CI
[5%, 20%], gpt-4o-mini on a 60-pair subset), and states the two "disagree by
~51pp." The work is to widen the model-in-the-loop run past the 60-pair subset
and the single model so the realised number and its confidence interval are
measured at scale, narrowing that gap.

## Later

**Raise OWASP ASI04 (Agentic Supply Chain) coverage from Partial** — [#124](https://github.com/sattyamjjain/agent-airlock/issues/124)

The OWASP Agentic Security coverage matrix marks **ASI04 Agentic Supply Chain
Vulnerabilities** as **Partial** — the README legend's word for a meaningful
control shipping without full mitigation claimed. Today that row is the Ox MCP
STDIO sanitizer, the CVE regression suite, session-snapshot integrity, and the
spawn-time config pin. The work is to raise ASI04 toward full coverage of the
runtime supply-chain class the matrix already names, past those shipped controls.

---

Have a gap we should be honest about that is not on this list? Open an issue.
