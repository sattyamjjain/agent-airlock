"""Raknor SC-AG-07 fail-closed vectors (v1.1 draft, CC0) against ``@Airlock``.

The 14 vectors come from raknor-ai/agent-governance-standard#3, at the commit named in
``tests/fixtures/third_party/raknor_v1_1_draft/README.md``. Each is a policy state plus one
requested action, observed through the system's API. The mapping to Airlock:

- the action ``tool:x.y`` is a tool named ``x_y``, and every allowlist entry is mapped the
  same way (``*`` stays ``*``); the allowlist is ``allowed_tools``, and ``null`` means the
  field is left unset (an explicit ``allowed_tools=None`` raises ``TypeError``, which
  ``TestFailClosedVerdicts`` pins);
- every tool escalates (``escalate_tools={tool: "vector"}``), so the verdict is the
  approver's answer: ``ALLOW`` is ``OversightVerdict.GRANT``, ``DENY`` is
  ``OversightVerdict.DENY``, any other value is returned as given;
  ``{"raise": ...}`` is an approver that raises, ``{"timeout": true}`` one that answers GRANT
  after a 0.2 s deadline;
- ``load_error: parse`` is a policy resolver that raises; ``signature_valid: false`` is a
  frozen policy changed after ``freeze()`` (``verify_frozen`` refuses);
- ``executed`` is whether the tool body ran; ``event: policy_indeterminate`` is a log event
  of that name (the module loggers are recorded), and ``event: null`` means none.

With ``default_deny=True`` all 14 pass. With the library defaults, a1 and a2 still admit:
an empty allowlist allows every tool until ``default_deny`` flips, which
``test_default_policy_admits_empty_allowlist_until_default_flip`` pins so the gap is
published, not hidden.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest

from agent_airlock import Airlock
from agent_airlock import core as core_module
from agent_airlock import policy as policy_module
from agent_airlock.oversight import OversightResponse, OversightVerdict
from agent_airlock.policy import SecurityPolicy

_VECTORS = Path(__file__).parent / "fixtures/third_party/raknor_v1_1_draft/fail-closed"
_DEADLINE = 0.2


class _Events:
    def __init__(self) -> None:
        self.names: list[str] = []

    def _record(self, event: str, **_fields: Any) -> None:
        self.names.append(event)

    debug = info = warning = error = exception = _record


def _vectors() -> list[dict[str, Any]]:
    data = json.loads((_VECTORS / "vectors.json").read_text(encoding="utf-8"))
    assert data["license"] == "CC0-1.0"
    return list(data["vectors"])


def _tool_name(action: str) -> str:
    return action.removeprefix("tool:").replace(".", "_")


def _approver(verdict: Any) -> Any:
    def approver(request: Any) -> Any:
        if isinstance(verdict, dict) and "raise" in verdict:
            raise RuntimeError(f"vector says raise {verdict['raise']}")
        if isinstance(verdict, dict) and verdict.get("timeout"):
            time.sleep(_DEADLINE * 3)
            return OversightResponse(request_id=request.request_id, verdict=OversightVerdict.GRANT)
        answer = (
            {"ALLOW": OversightVerdict.GRANT, "DENY": OversightVerdict.DENY}.get(verdict, verdict)
            if isinstance(verdict, str)
            else verdict
        )
        return OversightResponse(request_id=request.request_id, verdict=answer)

    return approver


def _policy(vector: dict[str, Any], tool: str, *, default_deny: bool) -> Any:
    """The vector's policy state: a SecurityPolicy, or a resolver for ``load_error``."""
    state = vector["policy"]
    if state.get("load_error"):

        def resolver(context: Any) -> SecurityPolicy:
            raise ValueError("policy file does not parse")

        return resolver
    kwargs: dict[str, Any] = {
        "escalate_tools": {tool: "vector"},
        "approver": _approver(vector["verdict"]),
        "escalation_timeout_seconds": _DEADLINE,
        "default_deny": default_deny,
    }
    if state.get("allowlist") is not None:
        kwargs["allowed_tools"] = [_tool_name(entry) for entry in state["allowlist"]]
    policy = SecurityPolicy(**kwargs)
    if state.get("signature_valid") is False:
        policy = policy.freeze()
        policy.allowed_tools.append("tampered")  # changed after freeze(): the digest drifts
    return policy


def _run(vector: dict[str, Any], monkeypatch: pytest.MonkeyPatch, *, default_deny: bool) -> dict:
    events = _Events()
    monkeypatch.setattr(core_module, "logger", events)
    monkeypatch.setattr(policy_module, "logger", events)
    tool = _tool_name(vector["action"])
    ran: list[bool] = []

    def body() -> str:
        ran.append(True)
        return "ran"

    body.__name__ = tool
    Airlock(policy=_policy(vector, tool, default_deny=default_deny))(body)()
    return {
        "executed": bool(ran),
        "event": "policy_indeterminate" if "policy_indeterminate" in events.names else None,
    }


class TestRaknorFailClosedVectors:
    @pytest.mark.parametrize("vector", _vectors(), ids=lambda vector: vector["id"])
    def test_vector_with_default_deny(
        self, vector: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        assert _run(vector, monkeypatch, default_deny=True) == vector["expect"]

    @pytest.mark.parametrize(
        "vector",
        [
            vector
            for vector in _vectors()
            if vector["id"] not in {"a1-empty-allowlist", "a2-null-allowlist"}
        ],
        ids=lambda vector: vector["id"],
    )
    def test_vector_with_library_defaults(
        self, vector: dict[str, Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        assert _run(vector, monkeypatch, default_deny=False) == vector["expect"]

    def test_default_policy_admits_empty_allowlist_until_default_flip(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """a1 and a2 fail under the library defaults: an empty allowlist allows every tool
        while ``default_deny`` is False. Remove this pin when the default flips (0.11.0)."""
        by_id = {vector["id"]: vector for vector in _vectors()}
        for vector_id in ("a1-empty-allowlist", "a2-null-allowlist"):
            outcome = _run(by_id[vector_id], monkeypatch, default_deny=False)
            assert outcome == {"executed": True, "event": None}, vector_id

    def test_the_vendored_set_is_the_fourteen_vectors(self) -> None:
        """The upstream README counts 4 positive controls; the file marks 3 (a3, a4, b0)."""
        vectors = _vectors()
        assert len(vectors) == 14
        controls = [vector["id"] for vector in vectors if vector.get("positive_control")]
        assert controls == ["a3-explicit-wildcard", "a4-listed-tool", "b0-verdict-explicit-deny"]
