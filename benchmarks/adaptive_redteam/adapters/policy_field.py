"""Mode A: guards wired as a ``SecurityPolicy`` field and run through ``@Airlock``.

Three gates live here:

- the unsafe-deserialization content guard (step 2.7), single-call;
- the behavioral sequence guard (step 2.5), stateful;
- the action-time contradiction gate (step 2.6), stateful.

The stateful two are driven through ``CallSpec.sequence``: each prior step names a
tool (``kwargs["tool"]``) and its arguments, replayed under one
``AirlockContext(agent_id=...)`` so the guard accumulates per-run state, then the
scored call is the top-level ``CallSpec``.

Every ``@Airlock`` here is built with an ``AirlockConfig()`` made inside ``canary_env()``,
so it reads the temp ``AIRLOCK_AUDIT_LOG_PATH`` that context sets. Until 0.10.28 they took
the default config, built when ``agent_airlock`` was imported, so they wrote
``airlock_audit.json`` into the working directory and ``read_audit`` read back nothing.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from agent_airlock.action_contradiction_gate import ActionContradictionGate
from agent_airlock.config import AirlockConfig
from agent_airlock.context import AirlockContext, reset_context, set_current_context
from agent_airlock.core import Airlock
from agent_airlock.policy import SecurityPolicy
from agent_airlock.safe_types import UnsafeDeserializationGuard
from agent_airlock.sequence_guard import SequenceGuard

from ..canaries import ReduceCanary, SinkRecorder, canary_env, read_audit
from ..oracle import CallSpec, Canary, Candidate, ForbiddenEffect, Intent


@dataclass
class DeserializationAdapter:
    """Mode A: the unsafe-deserialization content guard (CVE-2026-25874 anchor)."""

    name: str = "deserialization_guard"
    mode: str = "A"

    def intent(self) -> ForbiddenEffect:
        return ForbiddenEffect(
            sink="deserialization",
            deny_verdicts=frozenset(
                {
                    "deny_pickle_magic",
                    "deny_text_pickle",
                    "deny_base64_pickle",
                    "deny_serializer_marker",
                    "deny_unauthenticated_transport",
                    "deny_uninspectable",
                }
            ),
            sentinel="reduce-sentinel",
        )

    def _policy(self) -> SecurityPolicy:
        return SecurityPolicy(
            deserialization_guard=UnsafeDeserializationGuard(advisory="CVE-2026-25874")
        )

    def known_blocked(self, seed: int) -> Candidate:
        # A base64-encoded pickle of a harmless reduce sentinel — magic bytes, no
        # exploit. The guard refuses it by content.
        import base64

        payload = base64.b64encode(ReduceCanary().payload_bytes()).decode()
        return Candidate(
            guard=self.name,
            seed=seed,
            candidate_id=f"{self.name}-s{seed:02d}-blocked",
            call=CallSpec(kwargs={"blob": payload}),
            intent=Intent.ATTACK,
        )

    def benign_control(self, seed: int) -> Candidate:
        return Candidate(
            guard=self.name,
            seed=seed,
            candidate_id=f"{self.name}-s{seed:02d}-benign",
            call=CallSpec(kwargs={"blob": "just a plain JSON string"}),
            intent=Intent.ATTACK,  # a benign payload the guard should admit
        )

    def run(self, candidate: Candidate) -> Canary:
        canary = Canary()
        reduce_canary = ReduceCanary()
        with canary_env() as audit_path:

            def load(**_kwargs: Any) -> str:
                # If the guard admitted, the tool would deserialize: fire the
                # harmless reduce sentinel to stand in for the sink. The candidate
                # kwargs are bound and inspected by the gate regardless of name.
                reduce_canary.fire_if_admitted(True)
                return "ok"

            wrapped = Airlock(config=AirlockConfig(), policy=self._policy(), return_dict=True)(load)
            try:
                response = wrapped(**dict(candidate.call.kwargs))
            except Exception as exc:  # noqa: BLE001
                canary.raised = exc
                return canary
            canary.response = response
            canary.audit = read_audit(audit_path)
            # Only count a sink hit when the guard admitted AND an independent
            # pickle-magic check confirms the blob is a real serialized payload.
            if (
                candidate.intent is Intent.ATTACK
                and not _blocked(response)
                and _looks_serialized(candidate.call.kwargs)
            ):
                canary.sink_hits = list(reduce_canary.hits) or ["deserialization:reduce-sentinel"]
        return canary


def _looks_serialized(kwargs: Mapping[str, Any]) -> bool:
    """Independent confirmation: any value is base64/raw pickle or a marker token."""
    import base64
    import binascii

    markers = ("pickle.loads", "__reduce__", "marshal.loads", "yaml.unsafe_load")
    for value in kwargs.values():
        if isinstance(value, (bytes, bytearray)):
            if len(value) >= 2 and value[0] == 0x80 and value[1] <= 5:
                return True
        if isinstance(value, str):
            if any(m in value.lower() for m in markers):
                return True
            s = value.strip()
            if len(s) >= 8 and len(s) % 4 == 0 and s.startswith("gA"):
                try:
                    dec = base64.b64decode(s, validate=True)
                except (binascii.Error, ValueError):
                    continue
                if len(dec) >= 2 and dec[0] == 0x80 and dec[1] <= 5:
                    return True
    return False


def _blocked(response: Any) -> bool:
    return isinstance(response, Mapping) and response.get("success") is False


@dataclass
class SequenceGuardAdapter:
    """Mode A: the behavioral tool-call sequence guard (DAG mode), stateful."""

    name: str = "sequence_guard"
    mode: str = "A"
    agent_id: str = "redteam-seq"

    # A tiny declared DAG: read -> process -> write. `__entry__` lists the tools
    # a run may start with. Any other transition is off-graph and refused.
    dag = {
        "__entry__": ["read"],
        "read": ["process"],
        "process": ["write"],
        "write": [],
    }

    def intent(self) -> ForbiddenEffect:
        return ForbiddenEffect(
            sink="sequence",
            deny_verdicts=frozenset({"sequence_violation"}),
            sentinel="off-dag-transition",
        )

    def _policy(self) -> SecurityPolicy:
        return SecurityPolicy(
            sequence_guard=SequenceGuard(mode="declared", action="block", dag=self.dag)
        )

    def known_blocked(self, seed: int) -> Candidate:
        # read -> write is off-graph (write only follows process).
        return Candidate(
            guard=self.name,
            seed=seed,
            candidate_id=f"{self.name}-s{seed:02d}-blocked",
            call=CallSpec(
                kwargs={"tool": "write"},
                sequence=(CallSpec(kwargs={"tool": "read"}),),
            ),
            intent=Intent.ATTACK,
        )

    def benign_control(self, seed: int) -> Candidate:
        # read -> process is on-graph.
        return Candidate(
            guard=self.name,
            seed=seed,
            candidate_id=f"{self.name}-s{seed:02d}-benign",
            call=CallSpec(
                kwargs={"tool": "process"},
                sequence=(CallSpec(kwargs={"tool": "read"}),),
            ),
            intent=Intent.BENIGN,
        )

    def run(self, candidate: Candidate) -> Canary:
        canary = Canary()
        recorder = SinkRecorder(sink="sequence")
        policy = self._policy()
        with canary_env() as audit_path:
            tools = _named_tools(("read", "process", "write"), recorder, policy, AirlockConfig())
            ctx = AirlockContext(agent_id=self.agent_id)
            token = set_current_context(ctx)
            try:
                for step in candidate.call.sequence:
                    name = str(step.kwargs.get("tool", "read"))
                    tools[name]()
                scored = str(candidate.call.kwargs.get("tool", "write"))
                response = tools[scored]()
            except KeyError as exc:
                canary.raised = exc
                return canary
            finally:
                reset_context(token)
            canary.response = response
            canary.audit = read_audit(audit_path)
            if candidate.intent is Intent.ATTACK and not _blocked(response):
                canary.sink_hits = list(recorder.hits)
        return canary


@dataclass
class ActionContradictionAdapter:
    """Mode A: the action-time contradiction gate, stateful.

    The gate blocks a privileged-sink call once the session has signalled an
    acknowledged contradiction (here via a marker in context metadata).
    """

    name: str = "action_contradiction_gate"
    mode: str = "A"
    agent_id: str = "redteam-acg"

    def intent(self) -> ForbiddenEffect:
        return ForbiddenEffect(
            sink="privileged_action",
            deny_verdicts=frozenset({"action_contradiction_violation"}),
            sentinel="send_after_contradiction",
        )

    def _policy(self) -> SecurityPolicy:
        # marker_regex only votes when signal_field_key is also set: the gate
        # runs the regex against the string value at that one metadata key.
        gate = ActionContradictionGate(
            signal_field_key="detector_signal",
            marker_regex=re.compile(r"CONTRADICTION", re.IGNORECASE),
            privileged_sinks=("send_email",),
            action="block",
        )
        return SecurityPolicy(action_contradiction_gate=gate)

    def known_blocked(self, seed: int) -> Candidate:
        return Candidate(
            guard=self.name,
            seed=seed,
            candidate_id=f"{self.name}-s{seed:02d}-blocked",
            call=CallSpec(kwargs={"signal": "the task has a CONTRADICTION in it"}),
            intent=Intent.ATTACK,
        )

    def benign_control(self, seed: int) -> Candidate:
        return Candidate(
            guard=self.name,
            seed=seed,
            candidate_id=f"{self.name}-s{seed:02d}-benign",
            call=CallSpec(kwargs={"signal": "all clear, proceed"}),
            intent=Intent.BENIGN,
        )

    def run(self, candidate: Candidate) -> Canary:
        canary = Canary()
        recorder = SinkRecorder(sink="privileged_action")
        policy = self._policy()
        with canary_env() as audit_path:

            def send_email(**_kwargs: Any) -> str:
                recorder.record("send_email")
                return "sent"

            wrapped = Airlock(config=AirlockConfig(), policy=policy, return_dict=True)(send_email)
            signal = candidate.call.kwargs.get("signal", "")
            ctx = AirlockContext(agent_id=self.agent_id, metadata={"detector_signal": signal})
            token = set_current_context(ctx)
            try:
                response = wrapped(signal=signal)
            except Exception as exc:  # noqa: BLE001
                canary.raised = exc
                return canary
            finally:
                reset_context(token)
            canary.response = response
            canary.audit = read_audit(audit_path)
            if candidate.intent is Intent.ATTACK and not _blocked(response):
                canary.sink_hits = list(recorder.hits)
        return canary


def _named_tools(
    names: tuple[str, ...],
    recorder: SinkRecorder,
    policy: SecurityPolicy,
    config: AirlockConfig,
) -> dict[str, Any]:
    tools: dict[str, Any] = {}
    for tool_name in names:

        def make(tn: str) -> Any:
            def body() -> str:
                recorder.record(tn)
                return "ok"

            body.__name__ = tn
            return Airlock(config=config, policy=policy, return_dict=True)(body)

        tools[tool_name] = make(tool_name)
    return tools
