# PydanticAI

`agent_airlock.integrations.pydantic_ai` is the canonical adapter for
[PydanticAI](https://ai.pydantic.dev). It is the v0.7.1 promotion of
the previously example-only PydanticAI integration to **adapter-shipped**.

## Why an adapter (not just `@Airlock()`)

PydanticAI v1.88.0 (2026-04-29) added concrete `Agent`-level extension
hooks — `output_validate`, `output_process`, `prepare_output_tools`. The
adapter binds to those hooks so users don't have to remember the
`@framework_decorator` over `@Airlock()` rule themselves; one
`wrap_agent(agent, policy=...)` call walks every toolset and wires
the hooks.

## Install

```bash
pip install "agent-airlock[pydantic-ai]"
```

The extra pins `pydantic-ai>=1.88.0,<2.0`. v1.88.0 is the floor because
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

# Now every tool call routes through the configured policy:
# - ghost-arg stripping
# - Pydantic V2 strict validation
# - PolicyViolation on denied tools
# - sanitization on the model's structured output (output_validate)
result = agent.run_sync("What's the weather in Bangalore?")
```

## What the adapter does

1. **Walks `agent.toolsets`** (PydanticAI v1.88+ public surface) and
   replaces each function-tool's callable with the
   `Airlock(policy=...)`-wrapped version. Tools are re-tagged so
   `SecurityPolicy.allowed_tools` / `denied_tools` lists target the
   tool's name, not its method name.

2. **Attaches `output_validate`** (default `attach_output_validate=True`).
   The hook runs `agent_airlock.sanitizer.sanitize_output` over the
   model's structured output before it leaves the boundary.

3. **Pins `SUPPORTED_PYDANTIC_AI_VERSIONS = ("1.88.0", "1.89.0",
   "1.89.1")`** — running a version outside this set emits a
   `UserWarning` (no hard fail). Update the tuple once a new release
   has been smoke-tested against the adapter.

## Honest scope

- The adapter does not import `pydantic_ai` at module load — passing a
  stub agent (any object with a `toolsets` or `tools` attribute) works
  without the extra installed. This is what the test suite uses.
- Real PydanticAI objects (whose `__module__` starts with `pydantic_ai.*`)
  do trigger the import check. If the extra is missing, the adapter
  raises `PydanticAIMissingError` with a clear install hint.
- The example-only path (`examples/pydanticai_integration.py`) remains
  documented and still works — `@Airlock()` over a raw
  `@agent.tool_plain` is supported.

## Primary sources

- [PydanticAI v1.89.1 release (2026-05-01)](https://github.com/pydantic/pydantic-ai/releases/tag/v1.89.1)
- [PydanticAI v1.89.0 release (2026-05-01)](https://github.com/pydantic/pydantic-ai/releases/tag/v1.89.0)
- [PydanticAI v1.88.0 release (2026-04-29)](https://github.com/pydantic/pydantic-ai/releases/tag/v1.88.0) — introduces the `output_validate` hook
- [pydantic/pydantic-ai#4859](https://github.com/pydantic/pydantic-ai/pull/4859) — `prepare_output_tools` / `output_validate` PR
- Cross-link to legacy decorator-only path: [`examples/pydanticai_integration.py`](../../examples/pydanticai_integration.py)
