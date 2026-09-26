# Anthropic Claude Agent SDK

`agent_airlock.integrations.anthropic_claude_agent_sdk` is the canonical
adapter for the [Anthropic Claude Agent SDK][sdk-docs]. It guards the
tools you serve from an in-process SDK MCP server, and it is a facade over
the existing `claude_*.py` family (managed-agents, auto-memory,
task-budget) so callers can find the entrypoint without learning the
internal module layout.

## Install

```bash
pip install "agent-airlock[claude-agent]"
```

The extra pins `claude-agent-sdk>=0.1.58`. The SDK is *not* imported at
module load — wrapping an object that comes from the SDK without the
extra installed raises a clear [`ClaudeAgentSDKMissingError`][error-class]
with the install hint (never an opaque `ImportError` from somewhere deep
in the call stack).

## Quickstart

```python
from claude_agent_sdk import ClaudeAgentOptions, create_sdk_mcp_server, tool

from agent_airlock.integrations.anthropic_claude_agent_sdk import wrap_tools
from agent_airlock.policy import SecurityPolicy


@tool("greet", "Greet a user", {"name": str})
async def greet(args):
    return {"content": [{"type": "text", "text": f"Hello, {args['name']}!"}]}


policy = SecurityPolicy(rate_limits={"*": "100/hour"})
server = create_sdk_mcp_server("tools", tools=wrap_tools([greet], policy=policy))
options = ClaudeAgentOptions(
    mcp_servers={"tools": server},
    allowed_tools=["mcp__tools__greet"],
)
```

Wrap the tools before building the server, which keeps its own
references. `wrap_tools` returns guarded copies and leaves the originals
as they were. On every call:

- a key the tool's `input_schema` does not declare is a ghost argument,
  stripped before the handler sees it (refused instead when the process
  starts with `AIRLOCK_UNKNOWN_ARGS=block`)
- each declared argument is strictly validated, against the type the SDK
  advertises to the model
- the policy applies under the tool's name, the one the model calls
- what the handler returns is masked for PII and secrets
- a refusal reaches the model as an error result (`is_error: True`)
  carrying Airlock's error and fix hints

## What the adapter does

1. **`wrap_tools(tools, policy=...)`** fronts each `SdkMcpTool`'s handler
   with a proxy whose keyword parameters come from `input_schema`, in the
   three forms the SDK accepts: a `{"name": type}` map (every key
   required), a `TypedDict` (its required keys) or a JSON schema (its
   `required` list). The handler's single `args` dict is spread into those
   parameters, so every gate that reads arguments sees each one.
2. **`AnthropicClaudeAgentSDKAdapter().wrap_agent(obj, policy=...)`** walks
   any object's `tools` attribute (dict or list) and replaces each entry:
   an `SdkMcpTool` with a guarded copy, an object's `forward` or a
   callable with an Airlock-wrapped shim that carries the tool's name and
   signature and is async when the tool is.
3. **Re-exports the harness defences** from the existing `claude_*.py`
   modules so callers can compose:
   - `ManagedAgentsAuditConfig` — beta-header + toolset-version + tool
     intersection check on the managed-agents request boundary.
   - `AutoMemoryAccessPolicy` + `guarded_read` / `guarded_write` —
     per-tenant scope, byte quota, redaction-on-write.
   - `build_task_budget_headers` + `build_output_config` — populated by
     the adapter's `task_budget_request_kit(remaining=...)` helper.
4. **Pins a `SUPPORTED_SDK_VERSIONS` tuple** recording the SDK versions
   the adapter was checked against. Wrapping an SDK object on any other
   version emits a `UserWarning` but still wraps.

## Honest scope

- Each argument is checked against the type the SDK advertises and hands
  the handler, not the Python annotation. The SDK sends a type it does not
  map (a `datetime`, a `Literal`) as a string, so Airlock checks a string;
  a `float` field accepts an integer and passes it on unconverted. Nested
  structure (list items, object properties, enums) is left to the SDK's
  own JSON-schema check, which runs before the handler is called.
- Airlock is stricter than that check in one place: an `integer` field
  refuses `3.0`, which JSON Schema admits.
- A key outside a JSON schema's `properties` is a ghost argument unless
  the schema sets `additionalProperties` to something other than `false`.
  JSON Schema, and the SDK, admit it by default.
- Every key has to be usable as a Python parameter name. A tool whose
  schema declares `from` or `file-path` is refused when you wrap it, with
  an `AirlockError` naming the keys, rather than guarded partially.
- A `typing_extensions.TypedDict` schema is enforced even though the SDK,
  on Python 3.11 and later, does not recognise one and advertises the
  tool with no properties. The model then learns the keys from Airlock's
  fix hints.
- An exception raised by a handler reaches the model as Airlock's generic
  "Unexpected error" result, not as the exception's own message.
- `ClaudeAgentOptions.tools` holds the names of Claude Code's built-in
  tools, which Claude Code runs itself. Airlock cannot wrap those, and
  `wrap_agent` raises an `AirlockError` pointing to `wrap_tools` if it is
  handed one.
- Stub objects (any object with a `tools` attribute, or a tool of the
  `SdkMcpTool` shape) never trigger the SDK import, which is what the
  test suite relies on.
- Verified end to end on `claude-agent-sdk` 0.2.160: guarded tools served
  by `create_sdk_mcp_server` and called through an MCP client session.

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
