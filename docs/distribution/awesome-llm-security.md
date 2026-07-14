# Draft PR — awesome-llm-security

> **Status: DRAFT for the operator to submit.** Nothing here is auto-submitted.
> Confirm the canonical list repo before opening the PR.

- **Target list:** `awesome-llm-security` <!-- verify canonical repo URL, e.g. corca-ai/awesome-llm-security -->
- **Section:** Tools / Defense (or "Frameworks / Guardrails")
- **Refresh the test count** to the current README TEST-BADGE at submission time (v0.8.47 = 3,409).

## Entry (list format)

```markdown
- [agent-airlock](https://github.com/sattyamjjain/agent-airlock) — in-process least-privilege decorator for AI tool calls; deny-by-default, PII masking, per-CVE presets, 3,409 tests.
```

## PR title

```
Add agent-airlock (least-privilege tool-call validation for LLM agents)
```

## PR body

```
agent-airlock guards the LLM→tool boundary in-process: it strict-validates tool
arguments (Pydantic, no coercion), strips hallucinated/ghost arguments, enforces
a deny-by-default least-privilege policy, and masks PII/secrets in tool output
(13 PII types incl. India DPDP). Opt-in per-CVE and MCP-spec presets. MIT,
zero-dep core, 3,409 tests.

Repo: https://github.com/sattyamjjain/agent-airlock
PyPI: https://pypi.org/project/agent-airlock/
```
