"""Live contract: ``ManagedAgentToolGate`` in a real Claude Managed Agents session.

Spends API credit; run with ``make test-live`` (``-k managed`` runs only this). It
creates an environment (cloud, limited networking, no package managers, no MCP egress),
a Haiku 5.5 agent whose only enabled tool is ``read`` under ``always_ask``
(``gate.agent_toolset()``), and a session capped at $25.00 of list cost (the budget
amount is in cents, ``"2500"``). The agent is asked to read an allowed file and then a
forbidden one; the gate answers each ``ask``.

What it settles, that only a live session can:

* Built-in calls under ``always_ask`` arrive as ``agent.tool_use`` events with
  ``evaluated_permission: "ask"`` and the input keys the gate reads (``file_path``).
* ``decision.confirmation`` is accepted, an allowed read returns a non-error result,
  and a refused read's ``deny_message`` reaches the agent as an error result carrying
  ``AIRLOCK_BLOCK``.
* ``check_agent_toolset`` accepts the server's echo of ``gate.agent_toolset()``.

The session, the environment and the agent are cleaned up in ``finally`` (the agent
can only be archived), each step on its own so one failure does not skip the rest.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from typing import Any

import pytest

from agent_airlock import ManagedAgentToolGate, RemotePathPolicy
from agent_airlock.integrations.claude_managed_agents import check_agent_toolset

from ._live import LIVE_MODEL, LiveRecorder, event_keys

pytestmark = pytest.mark.live

ALLOWED = "/etc/os-release"
DENIED = "/opt/airlock-live/outside.txt"
MESSAGE = (
    f"Use the read tool to read {ALLOWED}. Then use the read tool to read {DENIED}. "
    "Then reply with the single word DONE."
)
SYSTEM = "You are a test agent. Use only the read tool, and follow the user's steps in order."
#: A hard cap on the session's list cost; ``amount`` is in cents ("2500" is $25.00).
SESSION_BUDGET = {"type": "limit", "max_list_cost": {"amount": "2500", "currency": "USD"}}
DEADLINE_SECONDS = 300


@dataclass
class _Observed:
    reviews: list[dict[str, Any]] = field(default_factory=list)
    results: dict[str, tuple[Any, str]] = field(default_factory=dict)
    event_types: list[str] = field(default_factory=list)
    event_keys: dict[str, list[str]] = field(default_factory=dict)
    stop_reasons: list[Any] = field(default_factory=list)
    list_cost: Any = None
    timed_out: bool = False


@pytest.fixture
def beta(anthropic_client: Any) -> Any:
    missing = [
        name
        for name in ("agents", "sessions", "environments")
        if not hasattr(anthropic_client.beta, name)
    ]
    if missing:
        pytest.skip(f"this anthropic SDK has no client.beta.{', client.beta.'.join(missing)}")
    return anthropic_client.beta


def _text(content: Any) -> str:
    parts = []
    for block in content or []:
        text = block.get("text") if isinstance(block, dict) else getattr(block, "text", None)
        if isinstance(text, str):
            parts.append(text)
    return "\n".join(parts)


def _amount(money: Any) -> Any:
    if money is None:
        return None
    return {"amount": getattr(money, "amount", None), "currency": getattr(money, "currency", None)}


def _handle(
    event: Any, events_api: Any, session_id: str, gate: ManagedAgentToolGate, seen: _Observed
) -> bool:
    """React to one streamed event; True when the session is done."""
    kind = getattr(event, "type", None)
    seen.event_types.append(str(kind))
    seen.event_keys.setdefault(str(kind), event_keys(event))
    if kind in ("agent.tool_use", "agent.mcp_tool_use"):
        decision = gate.review(event, session_id=session_id)
        tool_input = getattr(event, "input", None) or {}
        seen.reviews.append(
            {
                "id": event.id,
                "name": event.name,
                "input_keys": sorted(tool_input),
                "file_path": tool_input.get("file_path"),
                "evaluated_permission": decision.evaluated_permission,
                "allowed": decision.allowed,
                "checks": list(decision.checks),
            }
        )
        if decision.confirmation is not None:
            events_api.send(session_id=session_id, events=[decision.confirmation])
    elif kind == "agent.tool_result":
        seen.results[event.tool_use_id] = (event.is_error, _text(event.content))
    elif kind == "session.usage":
        seen.list_cost = _amount(getattr(event.usage, "list_cost", None))
    elif kind == "session.status_idle":
        reason = getattr(getattr(event, "stop_reason", None), "type", None)
        seen.stop_reasons.append(reason)
        return reason != "requires_action"
    elif kind == "session.status_terminated":
        return True
    return False


def _drive(client: Any, session_id: str, gate: ManagedAgentToolGate, seen: _Observed) -> None:
    """Stream first, then send the message; a watchdog interrupts after the deadline."""
    events_api = client.beta.sessions.events
    with events_api.stream(session_id=session_id) as stream:

        def expire() -> None:
            seen.timed_out = True
            try:
                events_api.send(session_id=session_id, events=[{"type": "user.interrupt"}])
            finally:
                stream.close()

        watchdog = threading.Timer(DEADLINE_SECONDS, expire)
        watchdog.daemon = True
        watchdog.start()
        try:
            events_api.send(
                session_id=session_id,
                events=[{"type": "user.message", "content": [{"type": "text", "text": MESSAGE}]}],
            )
            for event in stream:
                if _handle(event, events_api, session_id, gate, seen):
                    break
        except Exception:
            if not seen.timed_out:
                raise
        finally:
            watchdog.cancel()


def _cleanup(beta: Any, created: dict[str, str]) -> dict[str, str]:
    steps = (
        ("session", lambda ident: beta.sessions.delete(session_id=ident)),
        ("environment", lambda ident: beta.environments.delete(environment_id=ident)),
        ("agent", lambda ident: beta.agents.archive(agent_id=ident)),
    )
    outcome: dict[str, str] = {}
    for name, step in steps:
        if name not in created:
            continue
        try:
            step(created[name])
            outcome[name] = "done"
        except Exception as exc:  # noqa: BLE001 - every step runs; failures are recorded
            outcome[name] = f"failed: {type(exc).__name__} ({created[name]})"
    return outcome


def _provision(beta: Any, gate: ManagedAgentToolGate, tag: str, created: dict[str, str]) -> str:
    """Create the environment, the agent and the session; return the session id.

    Each id goes into ``created`` as soon as it exists, so cleanup finds it even when a
    later step fails. The agent's echoed tools must pass ``check_agent_toolset``.
    """
    environment = beta.environments.create(
        name=f"airlock-live-{tag}",
        config={
            "type": "cloud",
            "networking": {
                "type": "limited",
                "allow_package_managers": False,
                "allow_mcp_servers": False,
            },
        },
    )
    created["environment"] = environment.id
    agent = beta.agents.create(
        name=f"airlock-live-{tag}", model=LIVE_MODEL, system=SYSTEM, tools=[gate.agent_toolset()]
    )
    created["agent"] = agent.id
    check_agent_toolset(agent.tools, allowed_tools=gate.allowed_tools)
    session = beta.sessions.create(
        agent={"type": "agent", "id": agent.id, "version": agent.version},
        environment_id=environment.id,
        budget=SESSION_BUDGET,
        title=f"airlock live gate {tag}",
    )
    created["session"] = session.id
    return str(session.id)


def _record(
    live_recorder: LiveRecorder, created: dict[str, str], seen: _Observed, cleanup: dict[str, str]
) -> None:
    live_recorder.record(
        "managed_agents.gate",
        model_requested=LIVE_MODEL,
        provisioned=sorted(created),
        reviews=seen.reviews,
        results={
            key: {"is_error": value[0], "text_head": value[1][:300]}
            for key, value in seen.results.items()
        },
        event_types=sorted(set(seen.event_types)),
        event_keys=seen.event_keys,
        stop_reasons=seen.stop_reasons,
        list_cost=seen.list_cost,
        timed_out=seen.timed_out,
        cleanup=cleanup,
    )


def _assert_outcome(seen: _Observed) -> None:
    assert not seen.timed_out, f"the session did not finish within {DEADLINE_SECONDS}s"
    asks = [r for r in seen.reviews if r["name"] == "read" and r["evaluated_permission"] == "ask"]
    assert len(asks) >= 2, f"expected two read asks, saw: {seen.reviews}"
    assert all(r["input_keys"] for r in asks), asks
    allowed = [r for r in asks if r["allowed"]]
    denied = [r for r in asks if not r["allowed"]]
    assert allowed, f"the gate allowed no read: {asks}"
    assert denied, f"the gate refused no read: {asks}"
    types = sorted(set(seen.event_types))

    ok = seen.results.get(allowed[0]["id"])
    assert ok is not None, f"no agent.tool_result for the allowed read; saw {types}"
    assert not ok[0], f"the allowed read failed: {ok[1][:300]}"

    refused = seen.results.get(denied[0]["id"])
    assert refused is not None, (
        f"no agent.tool_result for the refused read, so the deny_message was not seen; saw {types}"
    )
    assert refused[0] is True, refused
    assert "AIRLOCK_BLOCK" in refused[1], refused[1][:500]


class TestManagedAgentsGate:
    def test_the_gate_answers_every_ask(
        self, anthropic_client: Any, beta: Any, live_recorder: LiveRecorder
    ) -> None:
        gate = ManagedAgentToolGate(
            {"read"}, path_policy=RemotePathPolicy(allowed_roots=(ALLOWED,))
        )
        created: dict[str, str] = {}
        seen = _Observed()
        try:
            session_id = _provision(beta, gate, uuid.uuid4().hex[:8], created)
            _drive(anthropic_client, session_id, gate, seen)
            usage = getattr(beta.sessions.retrieve(session_id=session_id), "usage", None)
            seen.list_cost = _amount(getattr(usage, "list_cost", None)) or seen.list_cost
        finally:
            _record(live_recorder, created, seen, _cleanup(beta, created))
        _assert_outcome(seen)
