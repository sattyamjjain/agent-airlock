---
name: CVE rule request
about: Request an agent-airlock rule, policy preset, or regression test for a disclosed CVE
title: "CVE rule request: CVE-YYYY-NNNNN"
labels: ["cve-rule-request"]
assignees: []
---

<!--
Use this template ONLY for CVEs that are already publicly disclosed (NVD,
vendor advisory, or GHSA). For undisclosed vulnerabilities in agent-airlock
itself, follow SECURITY.md instead.

Primary-source link is required so maintainers can verify the class of bug
and write a regression test that stays green against future versions.
-->

## CVE

**CVE ID:** CVE-YYYY-NNNNN
**Primary source:** <!-- NVD URL, vendor advisory, or GHSA link -->
**Affected component:** <!-- e.g. anthropics/mcp-server-git, Azure MCP Server, mcp-atlassian -->
**Affected versions:** <!-- e.g. < 2025.12.18 -->
**Fixed in:** <!-- upstream fix version, if any -->

## Class of bug

<!-- Tick one or more -->

- [ ] Path traversal / filesystem escape
- [ ] Argument injection (CLI, SQL, shell)
- [ ] SSRF / unsafe URL fetch
- [ ] Authentication bypass at transport layer
- [ ] Prompt injection leading to tool misuse
- [ ] Token leak (query string, logs, audit)
- [ ] Other: <!-- describe -->

## Vulnerable tool-call pattern

<!--
Provide the minimal reproducer: what tool name, what argument shape, what
boundary the attacker crosses. Example:

Tool: `git_diff`
Argument: `ref="--output=/tmp/pwn"`
Boundary: ref value starting with a hyphen is interpreted as a git CLI option.
-->

```text
Tool:
Arguments:
Boundary crossed:
```

## Proposed airlock defence

<!-- Tick one or more -->

- [ ] `SafePath` / filesystem boundary validator
- [ ] `SafeURL` / `EndpointPolicy` (SSRF block-list)
- [ ] Pydantic strict type for the arg (e.g. ref must match `[a-z0-9._/-]+`)
- [ ] Network egress control (`NetworkPolicy`)
- [ ] Capability gating (`@requires(...)`)
- [ ] New policy preset
- [ ] Regression test only (existing primitive already covers it)

## Out-of-scope rationale (if applicable)

<!--
Some CVEs are transport-layer or HTTP-auth bugs that airlock can't block
because we sit in front of tool execution, not the HTTP layer. If that's the
case here, explain so we can document it in `tests/cves/README.md` rather
than writing a misleading test.
-->

## Extra context

<!-- Links to write-ups, PoC repositories, tweets, etc. -->
