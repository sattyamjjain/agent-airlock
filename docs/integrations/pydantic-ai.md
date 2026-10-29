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
