# CrewAI

`agent_airlock.integrations.crewai` is the canonical adapter for
[CrewAI](https://github.com/crewAIInc/crewAI). It is the v0.7.2 promotion
of the previously example-only CrewAI integration to **adapter-shipped**
and closes [issue #5](https://github.com/sattyamjjain/agent-airlock/issues/5)
(opened 2026-03-14).

## Why an adapter (not just `@Airlock()`)

CrewAI v1.14.4 (2026-04-30) added native MCP server support and a
`litellm` SSTI bump — that's the floor where the tool-call surface
this adapter binds to became stable. With one `wrap_crew(crew,
policy=...)` call, every Agent's tool registry and every task-level
`Task(tools=[...])` override is walked and Airlock-decorated. Users
no longer have to remember the `@framework_decorator` over
`@Airlock()` rule themselves.

## Install

```bash
pip install "agent-airlock[crewai]"
```

The extra pins `crewai>=1.14.4,<2.0`. v1.14.4 is the floor because
that's the release that introduced native MCP server support — older
versions wire MCP through a different surface and would silently
mis-wire. The v1.14.5a1 / a2 alpha cycle is supported but not the
floor; operators on the alpha track should pin manually.

## Quickstart

```python
from agent_airlock.integrations.crewai import CrewAIAdapter
from agent_airlock.policy import STRICT_POLICY
from crewai import Agent, Crew, Task
from crewai.tools import tool

@tool("Search Tool")
def search(query: str) -> str:
    return f"Results for: {query}"

researcher = Agent(role="Researcher", goal="Investigate", tools=[search])
crew = Crew(agents=[researcher], tasks=[Task(description="...", agent=researcher)])

# wrap_crew walks every Agent's tools (and any Task(tools=[...]) overrides).
adapter = CrewAIAdapter()
adapter.wrap_crew(crew, policy=STRICT_POLICY)

# Now every tool call routes through the configured policy.
result = crew.kickoff()
```

## What the adapter does

1. **Walks `crew.agents`** and for each `Agent`, walks `agent.tools`
   (CrewAI's `BaseTool` registry). Each tool's `_run` (or `func`)
   callable is replaced with the `Airlock(policy=...)`-wrapped
   version. Tools are re-tagged so `SecurityPolicy.allowed_tools` /
   `denied_tools` lists target the tool's name, not its method
   name.

2. **Walks `crew.tasks`** for task-level `Task(tools=[...])`
   overrides — these win over `Agent.tools` at runtime, so they
   need wrapping too.

3. **Pins `SUPPORTED_CREWAI_VERSIONS = ("1.14.4", "1.14.5a1",
   "1.14.5a2")`** — running a version outside this set emits a
   `UserWarning` (no hard fail). Update the tuple once a new
   release has been smoke-tested against the adapter.

4. **`wrap_agent(agent, policy=...)`** is also exposed as a
   single-agent shortcut for the standalone-researcher pattern
   where you don't have a `Crew` yet.

## Honest scope

- The adapter does not import `crewai` at module load — passing a
  stub crew (any object with an `agents` or `tools` attribute)
  works without the extra installed. This is what the test suite
  uses.
- Real CrewAI objects (whose `__module__` starts with `crewai.*`)
  do trigger the import check. If the extra is missing, the
  adapter raises `CrewAIMissingError` with a clear install hint.
- `crewai` is heavy (pulls `litellm`, `chromadb`, `embedchain`);
  kept strictly opt-in via the `[crewai]` extra.
- The example-only path (`examples/crewai_integration.py`) remains
  documented and still works — `@Airlock()` over a raw
  `@tool`-decorated callable is supported.

## Closes

- [#5 — Add CrewAI native integration module](https://github.com/sattyamjjain/agent-airlock/issues/5) (opened 2026-03-14)

## Primary sources

- [CrewAI v1.14.4 release (2026-04-30)](https://github.com/crewAIInc/crewAI/releases/tag/1.14.4) — native MCP server support floor
- [CrewAI v1.14.5a1 release (2026-05-01)](https://github.com/crewAIInc/crewAI/releases/tag/1.14.5a1) — alpha
- [CrewAI v1.14.5a2 release (2026-05-04)](https://github.com/crewAIInc/crewAI/releases/tag/1.14.5a2) — alpha
- Cross-link to legacy decorator-only path: [`examples/crewai_integration.py`](../../examples/crewai_integration.py)
