# Google ADK

`agent_airlock.integrations.google_adk` is the canonical adapter for
[Google's Agent Development Kit](https://google.github.io/adk-docs/).

Google renamed Vertex AI to the **Gemini Enterprise Agent Platform** at
Cloud Next '26 (announced 2026-04-22), folding Agentspace and Agent
Builder under one umbrella and naming ADK as that platform's code-first
development kit. ADK is therefore the supported way to write
tool-calling agents against Gemini in an enterprise account, and until
v0.9.0 it had no agent-airlock adapter.

## Why an adapter (not just `@Airlock()`)

Because for a large class of ADK tools, `@Airlock()` on its own does not
work at all. ADK injects a `tool_context` argument into any tool that
asks for one — session state, memory, artifacts all arrive through it.
Decorate such a tool directly and it fails **at import time**, before any
call happens:

```python
from google.adk.tools.tool_context import ToolContext

@Airlock()                      # raises here, at decoration
def remember(fact: str, tool_context: ToolContext) -> dict: ...
```

```
pydantic.errors.PydanticSchemaGenerationError: Unable to generate
pydantic-core schema for <class 'google.adk.agents.context.Context'>
```

`Airlock` validates through `pydantic.validate_call(strict=True)`, and
`ToolContext` (an alias of `google.adk.agents.context.Context` in ADK
2.9.0) is an arbitrary type Pydantic cannot build a schema for.

`tool_context` is supplied by the ADK runtime, never by the model — ADK
itself excludes it from the declaration the model sees. So the adapter
relaxes exactly those runtime-injected parameters for the validator
(`ADK_INJECTED_PARAMS`, mirroring ADK's own `_ignore_params`) and leaves
every model-supplied parameter under strict validation. The argument
boundary agent-airlock exists to guard is unchanged; the parameters the
model cannot reach stop breaking it.

## Install

```bash
pip install "agent-airlock[google-adk]"
```

The extra pins `google-adk>=2.0,<3.0`. The adapter was introspected
against **2.9.0** (published 2026-09-10) — see
`SUPPORTED_GOOGLE_ADK_VERSIONS`. A different version emits a
`UserWarning` at `wrap_agent` time and no hard failure.

## Quickstart

```python
from google.adk.agents import Agent
from agent_airlock.integrations.google_adk import wrap_agent
from agent_airlock.policy import SecurityPolicy

def get_weather(city: str) -> dict:
    """Get the weather.

    Args:
        city: City name.
    """
    return {"city": city, "temp": 22}

def delete_records(table: str) -> dict:
    """Delete records.

    Args:
        table: Table name.
    """
    return {"deleted": table}

agent = Agent(
    name="ops",
    model="gemini-2.0-flash",
    tools=[get_weather, delete_records],
)

wrap_agent(agent, SecurityPolicy(
    allowed_tools=["get_weather"],
    denied_tools=["delete_*"],
))
```

Every tool call now routes through ghost-argument stripping, Pydantic
strict validation with `fix_hints` on failure, and the policy. A denied
tool returns the `AirlockResponse` blocked dict rather than raising —
that is the repo-wide contract, so the model gets a structured refusal
it can act on.

A full runnable script, which needs no API key and no network, is
[`examples/google_adk_integration.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/examples/google_adk_integration.py).

## What the adapter does

1. **Walks `agent.tools`.** In ADK 2.9.0 that is
   `list[Callable | BaseTool | BaseToolset]`, and ADK keeps bare
   callables bare rather than wrapping them into `FunctionTool` at
   construction. The adapter handles both.

2. **Replaces the callable, keeps the contract.** For a bare callable
   the list entry is swapped; for a `BaseTool` carrying `.func` only
   `.func` moves, so the `name` and `description` ADK computed at tool
   construction survive untouched.

3. **Relaxes runtime-injected parameters** (`tool_context`,
   `input_stream`) for the validator only. Safe because ADK drops those
   by *name*, never building a schema for their type — asserted against
   real ADK in the test suite, so an ADK that switched to type-based
   detection would fail the build rather than silently leak
   `tool_context` into the model-visible schema.

4. **Reports what it could not guard** instead of skipping it silently.

## What is *not* covered

Stated plainly, because a user who believes a tool is guarded when it is
not is worse off than one who is told.

| Shape | Guarded | Why |
|---|---|---|
| Bare callable in `tools` | Yes | Replaced in the list |
| `FunctionTool` / any `BaseTool` with `.func` | Yes | `.func` replaced in place |
| Async tools | Yes | Wrapped as a coroutine function |
| `BaseToolset` (including MCP toolsets) | **No** | `get_tools` is `async` and rebuilds its list per call, so there is no static callable to rewrite |
| Built-ins like `GoogleSearchTool` | **No** | Execute model-side; there is no local callable to guard |

Both unguarded rows raise a `UserWarning` naming the entry. Pass
`warn_on_unwrappable=False` to silence it once you have read it.

Two further boundaries worth naming:

- The adapter guards the **tool-call argument boundary**. It does not
  intercept ADK's `before_tool_callback` / `after_tool_callback`, and it
  does not inspect model output.
- ADK is not imported at module load, so `import agent_airlock` stays
  clean without the extra. Passing a stub agent (any object with a
  `tools` list) works with no ADK installed — that is the test seam.
  Real ADK objects (`__module__` starting with `google.adk`) do trigger
  the import check and raise `GoogleADKMissingError` with an install
  hint if the extra is missing.

## Verified against

Every structural fact above was introspected against `google-adk`
2.9.0, not recalled:

- `LlmAgent.tools` is the tool collection, typed
  `list[Callable | BaseTool | BaseToolset]`
- `FunctionTool` is not a Pydantic model; the user callable is `.func`
- `FunctionTool._ignore_params == ['tool_context', 'input_stream']`
- `BaseToolset.get_tools` is `async`
- `FunctionTool._get_declaration()` compares **equal** before and after
  the wrap

The last one is the claim that matters to a user, and it is pinned by
`TestAgainstRealAdk` in
`tests/integrations/test_google_adk_adapter.py`, which runs wherever the
extra is installed and skips where it is not.

## Primary sources

- [ADK documentation](https://google.github.io/adk-docs/)
- [google/adk-python](https://github.com/google/adk-python)
- [`google-adk` 2.9.0 on PyPI](https://pypi.org/project/google-adk/2.9.0/) — published 2026-09-10, the release this adapter was introspected against
- [Gemini Enterprise Agent Platform (formerly Vertex AI)](https://cloud.google.com/products/gemini-enterprise-agent-platform) — announced at Google Cloud Next '26, 2026-04-22
