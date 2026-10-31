# PydanticAI

`agent_airlock.integrations.pydantic_ai` is the canonical adapter for
[PydanticAI](https://ai.pydantic.dev). It is the v0.7.1 promotion of
the previously example-only PydanticAI integration to **adapter-shipped**.

## Why an adapter (not just `@Airlock()`)

PydanticAI v1.88.0 (2026-04-29) added concrete `Agent`-level extension
hooks — `output_validate`, `output_process`, `prepare_output_tools`. The
adapter binds to those hooks so users don't have to remember the
`@framework_decorator` over `@Airlock()` rule themselves; one
`wrap_agent(agent, policy=...)` call walks every toolset, on
pydantic-ai 2.x the ones a run is given included, and wires the
hooks. A toolset with no local function to wrap (an MCP server, an
external toolset) is named in a warning, not guarded.

## Install

```bash
pip install "agent-airlock[pydantic-ai]"
```

The extra pins `pydantic-ai>=1.88.0,<3.0`. v1.88.0 is the floor because
that's the release that introduced the `output_validate` hook the
adapter binds to (PR pydantic/pydantic-ai#4859).

## Quickstart

```python
from agent_airlock.integrations.pydantic_ai import PydanticAIAdapter
from agent_airlock.policy import STRICT_POLICY
from pydantic_ai import Agent

agent = Agent("openai:gpt-4o", system_prompt="You are a helpful assistant.")

@agent.tool_plain
def get_weather(city: str) -> str:
    return f"Weather in {city}: 22°C"

# wrap_agent walks every toolset and Airlock-decorates each tool callable.
adapter = PydanticAIAdapter()
adapter.wrap_agent(agent, policy=STRICT_POLICY)

# Now every tool call in an agent run goes through Airlock:
# - the policy (a denied tool returns a blocked AirlockResponse instead of running)
# - strict validation of the tool's declared parameters
# - sanitization of each tool's output
# - sanitization of the model's structured output, where output_validate exists (1.x)
result = agent.run_sync("What's the weather in Bangalore?")
```

## What the adapter does

1. **Walks `agent.toolsets`** (PydanticAI v1.88+ public surface) and
   replaces each function-tool's callable with the
   `Airlock(policy=...)`-wrapped version — both `tool.function` and
   `tool.function_schema.function`, which is the one an agent run
   actually calls. The wrapper carries the tool's name, so
   `SecurityPolicy.allowed_tools` / `denied_tools` lists target the
   tool rather than its method, and the tool's signature, so strict
   validation and ghost-argument stripping have parameters to check.
   A `RunContext` first parameter is passed through unvalidated; the
   model never supplies it. The walk follows wrapper toolsets
   (`prefixed`, `filtered`, `renamed`, ...) to the toolset they wrap,
   a `CombinedToolset` to each of its members, and a `DynamicToolset`
   to each toolset its factory builds during a run. Policy lists match
   the name a tool is registered under, not a prefixed or renamed one.
   Wrapping twice under the same policy guards each tool once; a wrap
   under another policy adds a layer, with a `UserWarning`, so both
   apply.

   **Output functions** (`Agent(output_type=[fn])`) are guarded like
   tools: the model writes `fn`'s arguments and PydanticAI runs it, so
   each output processor's `_function_schema.function` is replaced too,
   named for the function. An output type that is a model or a scalar
   calls nothing and is left alone. Until 0.10.28 output functions ran
   unguarded, and skipping the output toolset hid the warning.

2. **Guards the toolset of each run** on an agent that builds it in
   `_get_toolset` (pydantic-ai 2.x): that method is wrapped on this
   agent, so toolsets passed to `run(..., toolsets=[...])`, ones from
   `agent.override(...)` and tools registered after the wrap are walked
   before the run uses them. On a PydanticAI agent with no
   `_get_toolset`, a `UserWarning` says run-time toolsets are not
   guarded. A toolset with no local function to wrap (an MCP server,
   an external or deferred toolset) gets a `UserWarning` naming it, at
   wrap time or when a run first meets it; calls through it are not
   validated by agent-airlock. `PydanticAIAdapter(warn_on_unwrappable=False)`
   turns that warning off.

3. **Attaches `output_validate`** (default `attach_output_validate=True`).
   The hook runs `agent_airlock.sanitizer.sanitize_output` over the
   model's structured output before it leaves the boundary.

4. **Pins `SUPPORTED_PYDANTIC_AI_VERSIONS`** (listed in the module) —
   running a version outside this set emits a `UserWarning` (no hard
   fail). Update the tuple once a new release has been smoke-tested
   against the adapter.

## Check order

A tool call meets pydantic-ai's checks first, then Airlock's:

1. pydantic-ai resolves the tool. A name that does not exist (`unknown_tool`) or a tool not
   available at this step (`unavailable_tool`, say one tool search has not revealed) is
   rejected here and answered as a retry: no tool runs and Airlock never sees the call.
2. pydantic-ai validates the arguments against the tool's schema, in lax mode. A failure is
   a `validation_error` retry, also before any tool runs.
3. pydantic-ai's own approval: `requires_approval=True`, an `ApprovalRequired` from an
   `args_validator`, or, with `defer_escalations=True`, the deferral below.
4. Airlock, around the tool function: the policy and every other gate in order, then the
   tool, then masking of its output.

So the policy never spends a rate-limit token on a call pydantic-ai rejects, or on one
waiting for approval.

## Escalations as deferred approvals

Without more, a call the policy escalates goes to the policy's `approver`, and with none it
is refused as `escalation_required` (pydantic/pydantic-ai#9015). With
`defer_escalations=True` it becomes a pydantic-ai deferred approval instead:

```python
from agent_airlock.approvals import InMemoryApprovalLedger
from agent_airlock.integrations.pydantic_ai import PydanticAIAdapter
from agent_airlock.policy import SecurityPolicy

policy = SecurityPolicy(
    escalate_tools={"delete_file": "deletes a file"},
    approval_ledger=InMemoryApprovalLedger(),
)
PydanticAIAdapter(defer_escalations=True).wrap_agent(agent, policy=policy)
```

- The escalated call raises pydantic-ai's `ApprovalRequired` before Airlock runs, so it
  spends nothing. The run ends with a `DeferredToolRequests` (put it in the agent's
  `output_type`), or a `HandleDeferredToolCalls` handler resolves it inline. Its metadata
  carries `{"airlock": {"rule": ..., "reason": ...}}`.
- When a run resumes with the call approved, the adapter records one approval of exactly
  the arguments the call runs with (`ToolApproved(override_args=...)` included) in the
  policy's `approval_ledger`, and the call claims it at step 2. An approved call is not a
  free one (pydantic/pydantic-ai#8839): it spends its rate-limit token and counts against
  the budgets like any other.
- An approval replayed for a tool call id already used records nothing, so that call meets
  the policy as if nobody had approved it.
- A denied call never reaches the tool or Airlock. Until an approval arrives the tool does
  not run at all: the deferral is raised before it, whatever pydantic-ai then does with a
  run that has nowhere to hand the request (no `DeferredToolRequests` output type, no
  handler).
- `defer_escalations` needs a policy with an `approval_ledger`, and pydantic-ai itself;
  `wrap_agent` raises without them.

The approval comes from whoever answers the `DeferredToolRequests`. pydantic-ai says so
too: approval is not an authorization boundary against a client that can submit its own
history, so serve the resume only to a host you trust.

A run-time context is what a deferral reads. A tool that takes a `RunContext` has its own;
a `tool_plain` tool gets the run's through the run toolset the adapter wraps (pydantic-ai
2.x's `_get_toolset`). Called any other way, an escalated `tool_plain` call goes to the
approver, or is refused.

A `RunContext` is not one of the arguments an approval binds to, since 0.10.29: the
digest a ledger approval or a standing grant is matched by covers what the model wrote.

## Rejected tool calls

The calls pydantic-ai rejects in step 1 never reach Airlock, so the adapter logs them from
the run's messages as each step starts: a `ToolReturnPart` with `outcome="retried"` and a
`retry.cause` of `unknown_tool` or `unavailable_tool` is logged as
`pydantic_ai_tool_rejected`, with the tool call id, pydantic-ai's retry `attempt` and
`max_retries`, and how many rejections answered that call. One whose attempt reached the
limit is also logged as `pydantic_ai_tool_rejected_final`: the model's next try ends the
run. `PydanticAIAdapter(log_rejections=False)` turns it off. For a run's messages in hand,
`log_tool_rejections(result.all_messages())` (from
`agent_airlock.integrations.pydantic_ai_approvals`) logs them the same way and returns them.

## Honest scope

- The adapter does not import `pydantic_ai` at module load — passing a
  stub agent (any object with a `toolsets` or `tools` attribute) works
  without the extra installed. This is what the test suite uses.
- Real PydanticAI objects (whose `__module__` starts with `pydantic_ai.*`)
  do trigger the import check. If the extra is missing, the adapter
  raises `PydanticAIMissingError` with a clear install hint.
- PydanticAI validates tool arguments against its own schema before the
  call, in lax mode: a coercible value such as `"5"` for an `int`
  arrives converted, and an unknown argument is rejected there
  (verified on 2.31.1). Airlock's strict check applies to what
  PydanticAI hands the tool.
- The example-only path (`examples/pydanticai_integration.py`) remains
  documented and still works — `@Airlock()` over a raw
  `@agent.tool_plain` is supported.

## Primary sources

- [PydanticAI v1.89.1 release (2026-05-01)](https://github.com/pydantic/pydantic-ai/releases/tag/v1.89.1)
- [PydanticAI v1.89.0 release (2026-05-01)](https://github.com/pydantic/pydantic-ai/releases/tag/v1.89.0)
- [PydanticAI v1.88.0 release (2026-04-29)](https://github.com/pydantic/pydantic-ai/releases/tag/v1.88.0) — introduces the `output_validate` hook
- [pydantic/pydantic-ai#4859](https://github.com/pydantic/pydantic-ai/pull/4859) — `prepare_output_tools` / `output_validate` PR
- Cross-link to legacy decorator-only path: [`examples/pydanticai_integration.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/examples/pydanticai_integration.py)
