# Anthropic Claude Agent SDK

`agent_airlock.integrations.anthropic_claude_agent_sdk` is the canonical
adapter for the [Anthropic Claude Agent SDK][sdk-docs]. It is a thin
facade over the existing `claude_*.py` family (managed-agents, auto-memory,
task-budget) so callers can find the entrypoint without learning the
internal module layout.

## Install

```bash
pip install "agent-airlock[claude-agent]"
```

The extra pins `claude-agent-sdk>=0.1.58`. The SDK is *not* imported at
module load — calling `wrap_agent` without the extra installed raises a
clear [`ClaudeAgentSDKMissingError`][error-class] with the install hint
(never an opaque `ImportError` from somewhere deep in the call stack).

## Quickstart

```python
from agent_airlock.integrations.anthropic_claude_agent_sdk import (
    AnthropicClaudeAgentSDKAdapter,
)
from agent_airlock.policy import STRICT_POLICY

# Real SDK shape — claude_agent_sdk.Agent or anything exposing `tools`.
agent = build_my_claude_agent()

adapter = AnthropicClaudeAgentSDKAdapter()
secured = adapter.wrap_agent(agent, policy=STRICT_POLICY)

# Every tool callable is now Airlock-decorated:
# - ghost arguments stripped
# - Pydantic V2 strict validation
# - PolicyViolation raised on denied tools
secured.run("Summarise the latest commit on main.")
```

## What the adapter does

1. **Walks `agent.tools`** (dict or list) and replaces each tool's
   `forward` / `__call__` with an `Airlock(policy=...)`-wrapped shim.
2. **Re-exports the harness defences** from the existing `claude_*.py`
   modules so callers can compose:
   - `ManagedAgentsAuditConfig` — beta-header + toolset-version + tool
     intersection check on the managed-agents request boundary.
   - `AutoMemoryAccessPolicy` + `guarded_read` / `guarded_write` —
     per-tenant scope, byte quota, redaction-on-write.
   - `build_task_budget_headers` + `build_output_config` — populated by
     the adapter's `task_budget_request_kit(remaining=...)` helper.
3. **Pins a `SUPPORTED_SDK_VERSIONS = ("0.1.58",)` tuple** so callers
   can detect SDK drift early. New versions are added once smoke-tested.

## Honest scope

- The adapter does not import the SDK at module load — passing a stub
  agent (any object with a `tools` attribute) works without the extra
  installed. This is what the test suite uses, and it's also useful in
  CI environments without the optional dep.
- Real SDK objects (whose `__module__` starts with `claude_agent_sdk.*`)
  do trigger the import check. If the extra is missing, the adapter
  raises `ClaudeAgentSDKMissingError` with a clear install hint.
- The Claude Agent SDK has churned twice between Sep-2025 and
  Apr-2026. If a release renames `Agent` or shifts the tools dict
  shape, the adapter logs but does not hard-fail — update
  `SUPPORTED_SDK_VERSIONS` once you've smoke-tested the new pin.

## Primary sources

- [Anthropic Claude Agent SDK docs][sdk-docs]
- [Claude Managed Agents launch (2026-04-08)][managed-agents-blog]
- [Claude Auto Memory writeup][auto-memory-blog]
- [Claude task-budgets beta][task-budgets-docs]

[sdk-docs]: https://docs.claude.com/en/agents-and-tools/agent-skills
[managed-agents-blog]: https://claude.com/blog/claude-managed-agents
[auto-memory-blog]: https://claudefa.st/blog/guide/mechanics/auto-dream
[task-budgets-docs]: https://platform.claude.com/docs/en/build-with-claude/task-budgets
[error-class]: https://github.com/sattyamjjain/agent-airlock/blob/main/src/agent_airlock/integrations/anthropic_claude_agent_sdk.py
