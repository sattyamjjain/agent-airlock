# Draft PR — awesome-agent-security

> **Status: DRAFT for the operator to submit.** Nothing here is auto-submitted.
> Confirm the canonical list repo before opening the PR (the agent-security
> lists are less consolidated than the LLM/MCP ones — pick the most active).

- **Target list:** `awesome-agent-security` <!-- verify canonical repo URL -->
- **Section:** Tools / Runtime defenses
- **Refresh the test count** to the current README TEST-BADGE at submission time (v0.8.47 = 3,409).

## Entry (list format)

```markdown
- [agent-airlock](https://github.com/sattyamjjain/agent-airlock) — in-process least-privilege decorator for AI tool calls; deny-by-default, PII masking, per-CVE presets, 3,409 tests.
```

## PR title

```
Add agent-airlock (in-process least-privilege for agent tool calls)
```

## PR body

```
agent-airlock is a decorator (@Airlock) that wraps an agent tool and enforces a
validate → policy → execute → sanitize seam in-process: deny-by-default
least-privilege SecurityPolicy, strict typed argument validation, ghost-argument
stripping, output PII/secret masking, capability gating, and opt-in per-CVE /
MCP-spec presets. Integrates with LangChain, LangGraph, PydanticAI, OpenAI
Agents, Anthropic, CrewAI, and more. MIT, zero-dep core, 3,409 tests.

Repo: https://github.com/sattyamjjain/agent-airlock
PyPI: https://pypi.org/project/agent-airlock/
```
