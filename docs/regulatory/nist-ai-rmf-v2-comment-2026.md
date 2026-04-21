# Public comment — NIST AI RMF v2.0, Agentic-AI Security Subsection

Submission draft. Status: **DRAFT — not yet filed** (portal submission
is a maintainer action). Window opened 2026-04-18; seven-week comment
period.

**Commenter:** Sattyam Jain (open-source maintainer, agent-airlock)
**Project:** https://github.com/sattyamjjain/agent-airlock (MIT, Python)
**Date drafted:** 2026-04-21
**Responding to:** https://www.nist.gov/itl/ai-risk-management-framework/ai-rmf-v2-public-comment-2026-04-18

---

## Summary

agent-airlock is an open-source runtime firewall for AI agents,
shipped as a Python decorator. v0.5.0 (2026-04-18) through v0.5.3
(2026-04-21) landed named regression coverage for ten disclosed
MCP-ecosystem CVEs and a full mapping to the OWASP Top 10 for
Agentic Applications 2026 (ASI01..ASI10). This comment offers
three concrete suggestions for how NIST AI RMF v2.0's agentic-AI
security subsection might benefit from similar framing.

## Concrete ASI01..ASI10 examples as implemented

Agent-airlock's OWASP Agentic mapping is published verbatim in the
project README (cross-linked from the regulatory engagement
section). Every ASI row names:

- the agent-airlock primitive or preset that implements it
- an honest coverage label (**Full** / **Partial** / **Monitor-only**)
- a link to the regression tests proving the primitive fires

Examples:

- **ASI02 Tool Misuse and Exploitation:** Full — `SecurityPolicy`
  deny-by-default allow-lists, RBAC, `SafePath`/`SafeURL`. Named
  CVE coverage includes CVE-2025-59528 (Flowise `Function()` RCE)
  and CVE-2026-33032 (nginx-ui MCPwn). Regression tests at
  `tests/cves/`.
- **ASI04 Supply Chain:** Partial — `stdio_guard_ox_defaults()` for
  the Ox 2026-04 STDIO RCE class, `ox_mcp_supply_chain_2026_04_defaults()`
  covering the 10 CVEs in the OX dossier. Upstream patches remain
  the primary defense; agent-airlock is a second layer.
- **ASI10 Rogue Agents:** Monitor-only — audit telemetry and
  anomaly detection surface the signal; no runtime quarantine
  primitive. The honest label matters: over-claiming coverage
  misleads practitioners.

## Measured latency data

`@Airlock` decorator median latency, on-path, measured by
`pytest-benchmark` on commodity hardware (MacBook M-series):

- v0.5.0 strict-validation: ~77 μs per call
- v0.5.1: ~75 μs (Ox STDIO sanitizer additive)
- v0.5.3: ~81–85 μs (OAuth audit, session-snapshot, response-header
  audit all additive; still sub-100 μs)

Sub-millisecond validation overhead is practical for production
deployment. Implication for the RMF: overhead-based exclusions
from security-controls attestations (e.g. "we can't validate at
runtime, too slow") should be interrogated with real numbers
rather than accepted on face value.

## Recommendation for RMF v2.0

**Treat named-CVE regression coverage as a capability attestation.**

Concrete wording suggestion for the agentic-AI subsection:

> Where an agent-security control claims coverage of a specific
> vulnerability class, the implementation SHOULD carry regression
> tests that (a) reproduce the vulnerable tool-call pattern from
> the disclosing advisory, (b) assert the control blocks the
> pattern, and (c) cite the primary source in the test's module
> docstring. Coverage claims without reproduction tests are
> assertions, not attestations.

This matches what agent-airlock has been doing since v0.5.0. Naming
it in RMF v2.0 would create a common standard that tool buyers can
demand and tool builders can meet.

## Links for reference

- README: https://github.com/sattyamjjain/agent-airlock
- OWASP Agentic table: https://github.com/sattyamjjain/agent-airlock#️-owasp-compliance
- CVE regression suite: https://github.com/sattyamjjain/agent-airlock/tree/main/tests/cves
- CHANGELOG v0.5.0–v0.5.3: https://github.com/sattyamjjain/agent-airlock/blob/main/CHANGELOG.md

## Submission receipt

*(Portal submission URL + NIST-assigned tracking number to be
appended here once the maintainer files the comment through
<https://www.nist.gov/itl/ai-risk-management-framework/ai-rmf-v2-public-comment-2026-04-18>.)*
