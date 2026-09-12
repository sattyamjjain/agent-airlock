"""Google ADK + Agent-Airlock: deny-by-default tool calls.

Runnable end to end with **no API key and no network**. It builds a real
``google.adk.agents.Agent``, wraps its tools with a deny-by-default
policy, and then calls the tools directly — the model is never invoked,
because the thing being demonstrated is the argument boundary, not the
model.

Run it:

    pip install "agent-airlock[google-adk]"
    python examples/google_adk_integration.py

Expected: ``get_weather`` returns, ``delete_records`` is blocked, a
ghost argument is stripped, a wrong type is rejected with fix hints, and
the ADK-injected ``tool_context`` still reaches the tool that asks for
it. The script exits non-zero if any of those stops holding.

References:
    - ADK docs: https://google.github.io/adk-docs/
    - Adapter:  ../src/agent_airlock/integrations/google_adk.py
    - Doc page: ../docs/integrations/google-adk.md
"""

from __future__ import annotations

from typing import Any

from agent_airlock.integrations.google_adk import wrap_agent
from agent_airlock.policy import SecurityPolicy

try:
    from google.adk.agents import Agent
    from google.adk.tools.tool_context import ToolContext
except ImportError:
    print("Google ADK is required for this example.")
    print('Install with: pip install "agent-airlock[google-adk]"')
    raise SystemExit(1) from None


# =============================================================================
# Two tools. Plain ADK — no Airlock decorator on them.
#
# The adapter wraps them at `wrap_agent` time, which is the point: you do
# not have to remember the `@framework_decorator` over `@Airlock()` rule,
# and tools that take ADK's injected `tool_context` keep working (a bare
# `@Airlock()` on one of those raises at decoration time).
# =============================================================================


def get_weather(city: str, units: str = "celsius") -> dict[str, Any]:
    """Get the current weather for a city.

    Args:
        city: City name.
        units: Temperature units, celsius or fahrenheit.
    """
    return {"city": city, "units": units, "temp": 22, "sky": "clear"}


def delete_records(table: str, confirm: bool = False) -> dict[str, Any]:
    """Delete every record in a table.

    Args:
        table: Table name.
        confirm: Must be True to proceed.
    """
    return {"deleted": table, "confirmed": confirm}


def remember(fact: str, tool_context: ToolContext) -> dict[str, Any]:
    """Store a fact in ADK session state.

    Args:
        fact: The fact to store.
    """
    # `tool_context` is injected by the ADK runtime, never supplied by the
    # model. Writing to real session state needs a live runner, so this
    # just proves the injected object arrived intact.
    return {"stored": fact, "received_context": tool_context is not None}


# =============================================================================
# Deny-by-default: allow the two reads, deny anything that deletes.
# =============================================================================

POLICY = SecurityPolicy(
    allowed_tools=["get_weather", "remember"],
    denied_tools=["delete_*"],
)


def main() -> int:
    agent = Agent(
        name="ops_assistant",
        model="gemini-2.0-flash",
        instruction="You answer questions about weather and remember facts.",
        tools=[get_weather, delete_records, remember],
    )

    # One call wraps every tool. The agent is mutated in place.
    wrap_agent(agent, POLICY)
    weather_tool, delete_tool, remember_tool = agent.tools

    failures: list[str] = []

    def check(label: str, condition: bool, detail: object) -> None:
        status = "OK  " if condition else "FAIL"
        print(f"  [{status}] {label}: {detail}")
        if not condition:
            failures.append(label)

    print("=" * 68)
    print("Google ADK + Agent-Airlock")
    print("=" * 68)

    print("\n1. Allowed call passes through")
    allowed = weather_tool(city="Bangalore")
    check("get_weather returns", allowed.get("temp") == 22, allowed)

    print("\n2. Denied call is blocked by policy")
    blocked = delete_tool(table="users", confirm=True)
    check(
        "delete_records blocked",
        isinstance(blocked, dict) and blocked.get("status") == "blocked",
        blocked.get("error") if isinstance(blocked, dict) else blocked,
    )

    print("\n3. Ghost argument (invented by the model) is stripped")
    ghost = weather_tool(city="Pune", force=True, priority="urgent")
    check("ghost args gone", ghost.get("city") == "Pune" and "force" not in ghost, ghost)

    print("\n4. Wrong type is rejected, with hints the model can retry against")
    bad = weather_tool(city=12345)
    check(
        "strict validation fires",
        isinstance(bad, dict) and bad.get("block_reason") == "validation_error",
        bad.get("fix_hints") if isinstance(bad, dict) else bad,
    )

    print("\n5. ADK-injected tool_context still reaches the tool")
    # The ADK runtime supplies this; a literal stands in for it here.
    ctx = remember_tool(fact="the sky is blue", tool_context=object())
    check("tool_context delivered", ctx.get("received_context") is True, ctx)

    print("\n6. The tool contract the model sees is unchanged")
    from google.adk.tools.function_tool import FunctionTool

    declared = FunctionTool(func=weather_tool)._get_declaration()
    original = FunctionTool(func=get_weather)._get_declaration()
    check("declaration identical", declared == original, declared.name)

    print()
    print("=" * 68)
    if failures:
        print(f"FAILED: {', '.join(failures)}")
        return 1
    print("All checks passed.")
    print("=" * 68)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
