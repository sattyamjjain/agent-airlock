# Draft PR — awesome-mcp-security

> **Status: DRAFT for the operator to submit.** Nothing here is auto-submitted.
> Confirm the canonical list repo before opening the PR.

- **Target list:** `awesome-mcp-security` <!-- verify canonical repo URL, e.g. Puliczek/awesome-mcp-security -->
- **Section:** Tools / Defensive tooling
- **Refresh the test count** to the current README TEST-BADGE at submission time (v0.8.47 = 3,409).

## Entry (list format)

```markdown
- [agent-airlock](https://github.com/sattyamjjain/agent-airlock) — in-process least-privilege decorator for AI tool calls; deny-by-default, PII masking, per-CVE presets, 3,409 tests.
```

## PR title

```
Add agent-airlock (in-process least-privilege for MCP tool calls)
```

## PR body

```
agent-airlock is an MIT, zero-dependency (Pydantic-only) decorator that enforces
least-privilege at the tool-call seam: deny-by-default SecurityPolicy, strict
argument validation, ghost-argument stripping, output PII/secret masking, and
opt-in per-CVE / MCP-spec (SEP) presets. Runs in-process (microsecond overhead),
no model call. 3,409 tests, mypy-strict, CI-gated.

Repo: https://github.com/sattyamjjain/agent-airlock
PyPI: https://pypi.org/project/agent-airlock/
```
