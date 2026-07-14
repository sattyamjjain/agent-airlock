# Draft PR — awesome-mcp-servers (clients / tools section)

> **Status: DRAFT for the operator to submit.** Nothing here is auto-submitted.
> Confirm the canonical list repo before opening the PR.

- **Target list:** `awesome-mcp-servers` <!-- verify canonical repo URL, e.g. punkpeye/awesome-mcp-servers -->
- **Section:** **Clients / Tools / Frameworks** — **NOT** the servers list.
  agent-airlock is a library that secures MCP tool calls; it is **not itself an
  MCP server**, so it only belongs in a tools/clients/utilities section (if the
  list has one). If the list is servers-only, **do not submit** — use the
  awesome-mcp-security / awesome-llm-security lists instead.
- **Refresh the test count** to the current README TEST-BADGE at submission time (v0.8.47 = 3,409).

## Entry (list format)

```markdown
- [agent-airlock](https://github.com/sattyamjjain/agent-airlock) — in-process least-privilege decorator for AI tool calls; deny-by-default, PII masking, per-CVE presets, 3,409 tests.
```

## PR title

```
Add agent-airlock to Tools (least-privilege security layer for MCP tool calls)
```

## PR body

```
agent-airlock is a security/utility library for MCP tool calls (not a server):
a deny-by-default @Airlock decorator that strict-validates tool arguments, strips
ghost arguments, masks PII/secrets in output, and ships opt-in per-CVE and
MCP-spec (SEP) presets. FastMCP integration via @secure_tool. MIT, zero-dep core,
3,409 tests. Listed under Tools/Clients since it wraps servers rather than being
one.

Repo: https://github.com/sattyamjjain/agent-airlock
PyPI: https://pypi.org/project/agent-airlock/
```
