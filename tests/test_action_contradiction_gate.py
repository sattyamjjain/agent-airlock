"""Tests for the action-time contradiction gate (v0.8.15, arXiv:2605.27157).

Pins the off-by-default + pluggable-detectors + privileged-sink +
authorize_once posture of :class:`ActionContradictionGate` end-to-end:

- Off-by-default invariant: ``SecurityPolicy()`` without the gate is
  zero-overhead and observationally equivalent to v0.8.14.
- All three detector slots (signal_field, marker_regex, predicate)
  trip the gate independently; "any detector trips" semantics.
- Predicate that raises is swallowed (no crash, no false-trip).
- Privileged-sink glob match (default set + operator override).
- Non-privileged tool admitted even with contradiction state set.
- ``authorize_once`` consumes one privileged call, then re-locks
  (sticky-trip invariant).
- ``action="warn"`` logs but does NOT raise.
- ``session_key_kind`` selects which AirlockContext field keys state.
- Thread-safe concurrent ``check_action``.
- ``@Airlock`` end-to-end with the positional context-wrapper pattern
  (the seam's documented context-extraction surface).
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from typing import Any

import pytest

from agent_airlock import Airlock, SecurityPolicy
from agent_airlock.action_contradiction_gate import (
    DEFAULT_PRIVILEGED_SINKS,
    ActionContradictionGate,
    ActionContradictionViolation,
)
from agent_airlock.context import AirlockContext
from agent_airlock.policy import PolicyViolation

# ---------------------------------------------------------------------------
# Test wrappers — the established positional-context pattern the
# @Airlock seam extracts from (OpenAI Agents SDK / RunContextWrapper).
# ---------------------------------------------------------------------------


@dataclass
class _Inner:
    """Inner context the seam pulls fields off via ContextExtractor."""

    agent_id: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class _Wrapper:
    """RunContextWrapper-style wrapper; the seam reads ``.context``."""

    context: _Inner


# ---------------------------------------------------------------------------
# Construction validation
# ---------------------------------------------------------------------------


class TestConstruction:
    def test_rejects_unknown_action(self) -> None:
        with pytest.raises(ValueError, match="action must be"):
            ActionContradictionGate(action="silent")  # type: ignore[arg-type]

    def test_rejects_empty_privileged_sinks(self) -> None:
        with pytest.raises(ValueError, match="privileged_sinks must be non-empty"):
            ActionContradictionGate(privileged_sinks=())

    def test_defaults_inert_when_no_detectors_configured(self) -> None:
        """Construction with all detectors unset is legal — and the gate
        is inert. Lets operators wire the gate and flip detectors on
        later via config-driven overrides."""
        gate = ActionContradictionGate()
        ctx = AirlockContext(agent_id="ag1", metadata={})
        # Even a privileged sink admits when no detector is configured.
        gate.check_action(context=ctx, tool_name="send_email", session_key="ag1")
        assert gate.is_tripped("ag1") is False


# ---------------------------------------------------------------------------
# Detector pluggability — three independent slots
# ---------------------------------------------------------------------------


class TestDetectors:
    def test_signal_field_trips_on_truthy_value(self) -> None:
        gate = ActionContradictionGate(signal_field_key="contradiction_seen")
        ctx = AirlockContext(agent_id="ag", metadata={"contradiction_seen": True})
        with pytest.raises(ActionContradictionViolation) as exc:
            gate.check_action(context=ctx, tool_name="send_email", session_key="ag")
        assert exc.value.detector_kind == "signal_field"
        # Sticky-trip persists even after a check.
        assert gate.is_tripped("ag") is True

    def test_signal_field_does_not_trip_on_falsy(self) -> None:
        gate = ActionContradictionGate(signal_field_key="contradiction_seen")
        ctx = AirlockContext(agent_id="ag", metadata={"contradiction_seen": False})
        gate.check_action(context=ctx, tool_name="send_email", session_key="ag")
        assert gate.is_tripped("ag") is False

    def test_signal_field_absent_key_does_not_trip(self) -> None:
        gate = ActionContradictionGate(signal_field_key="contradiction_seen")
        ctx = AirlockContext(agent_id="ag", metadata={})
        gate.check_action(context=ctx, tool_name="send_email", session_key="ag")
        assert gate.is_tripped("ag") is False

    def test_marker_regex_trips_on_match(self) -> None:
        gate = ActionContradictionGate(
            signal_field_key="trace_excerpt",
            marker_regex=re.compile(r"contradict|conflict", re.IGNORECASE),
        )
        ctx = AirlockContext(
            agent_id="ag",
            metadata={"trace_excerpt": "The retrieved doc conflicts with the claim"},
        )
        with pytest.raises(ActionContradictionViolation) as exc:
            gate.check_action(context=ctx, tool_name="send_email", session_key="ag")
        assert exc.value.detector_kind == "marker_regex"

    def test_marker_regex_no_match_does_not_trip(self) -> None:
        gate = ActionContradictionGate(
            signal_field_key="trace_excerpt",
            marker_regex=re.compile(r"\bDISAGREE\b"),
        )
        ctx = AirlockContext(agent_id="ag", metadata={"trace_excerpt": "all consistent"})
        gate.check_action(context=ctx, tool_name="send_email", session_key="ag")
        assert gate.is_tripped("ag") is False

    def test_predicate_trips_when_true(self) -> None:
        gate = ActionContradictionGate(
            predicate=lambda c: bool(c.metadata.get("conflicting_evidence_count", 0))
        )
        ctx = AirlockContext(agent_id="ag", metadata={"conflicting_evidence_count": 2})
        with pytest.raises(ActionContradictionViolation) as exc:
            gate.check_action(context=ctx, tool_name="send_email", session_key="ag")
        assert exc.value.detector_kind == "predicate"

    def test_predicate_that_raises_is_swallowed(self) -> None:
        """A buggy predicate must NOT crash the gate; the audit log
        carries the predicate_error event but enforcement continues."""

        def buggy_predicate(_ctx: Any) -> bool:
            raise RuntimeError("predicate misconfigured")

        gate = ActionContradictionGate(predicate=buggy_predicate)
        ctx = AirlockContext(agent_id="ag", metadata={})
        # Buggy predicate → no trip → admit even on privileged sink.
        gate.check_action(context=ctx, tool_name="send_email", session_key="ag")
        assert gate.is_tripped("ag") is False

    def test_any_detector_trips(self) -> None:
        """Multiple detectors configured — any one triggers."""
        gate = ActionContradictionGate(
            signal_field_key="never_set",
            predicate=lambda c: True,  # always trips
        )
        ctx = AirlockContext(agent_id="ag", metadata={})
        with pytest.raises(ActionContradictionViolation):
            gate.check_action(context=ctx, tool_name="send_email", session_key="ag")


# ---------------------------------------------------------------------------
# Privileged-sink semantics
# ---------------------------------------------------------------------------


class TestPrivilegedSinks:
    @pytest.fixture
    def tripped_gate(self) -> ActionContradictionGate:
        return ActionContradictionGate(signal_field_key="x")

    @pytest.fixture
    def tripped_ctx(self) -> AirlockContext[Any]:
        return AirlockContext(agent_id="ag", metadata={"x": True})

    @pytest.mark.parametrize(
        "sink_tool",
        [
            "send_email",
            "send_mail",
            "publish_event",
            "post_to_chatter",
            "webhook_dispatch",
            "dispatch_alert",
            "export_records",
            "share_with_external",
            "upload_to_drive",
            "commit_transaction",
            "transfer_funds",
            "wire_payment",
            "pay_invoice",
            "delete_user",
            "drop_table",
            "destroy_resource",
            "purge_cache",
            "outlook_send_email",
            "smtp_relay",
            "salesforce_send_email",
            "create_case",
            "create_lead",
        ],
    )
    def test_all_default_privileged_sinks_blocked_when_tripped(
        self,
        tripped_gate: ActionContradictionGate,
        tripped_ctx: AirlockContext[Any],
        sink_tool: str,
    ) -> None:
        with pytest.raises(ActionContradictionViolation):
            tripped_gate.check_action(context=tripped_ctx, tool_name=sink_tool, session_key="ag")

    @pytest.mark.parametrize(
        "non_sink_tool", ["read_kb", "lookup_doc", "search_index", "fetch_kb_entry"]
    )
    def test_non_privileged_tool_admitted_even_when_tripped(
        self,
        tripped_gate: ActionContradictionGate,
        tripped_ctx: AirlockContext[Any],
        non_sink_tool: str,
    ) -> None:
        # No raise — non-sink calls admit even under tripped state.
        tripped_gate.check_action(context=tripped_ctx, tool_name=non_sink_tool, session_key="ag")
        # Sticky state remains true for the eventual privileged sink.
        assert tripped_gate.is_tripped("ag") is True

    def test_operator_can_narrow_privileged_sinks(self) -> None:
        """Operator override: only ``transfer_*`` matters in this app."""
        gate = ActionContradictionGate(
            signal_field_key="x",
            privileged_sinks=("transfer_*",),
        )
        ctx = AirlockContext(agent_id="ag", metadata={"x": True})
        # send_email is NOT in this app's privileged set — admitted.
        gate.check_action(context=ctx, tool_name="send_email", session_key="ag")
        # But transfer_funds is.
        with pytest.raises(ActionContradictionViolation):
            gate.check_action(context=ctx, tool_name="transfer_funds", session_key="ag")

    def test_default_sink_set_is_non_empty_and_documented(self) -> None:
        """Defensive invariant — the constant must exist + be non-empty
        so an operator who imports it for documentation never sees
        an empty tuple."""
        assert isinstance(DEFAULT_PRIVILEGED_SINKS, tuple)
        assert len(DEFAULT_PRIVILEGED_SINKS) > 0


# ---------------------------------------------------------------------------
# authorize_once flow + sticky-trip invariant
# ---------------------------------------------------------------------------


class TestAuthorizeOnceFlow:
    def test_authorize_once_clears_one_call(self) -> None:
        gate = ActionContradictionGate(signal_field_key="x")
        ctx = AirlockContext(agent_id="ag", metadata={"x": True})

        # First privileged call: blocked.
        with pytest.raises(ActionContradictionViolation):
            gate.check_action(context=ctx, tool_name="send_email", session_key="ag")

        # Grant a one-shot; next call admits without raising.
        ctx.authorize_once("send_email")
        gate.check_action(context=ctx, tool_name="send_email", session_key="ag")

    def test_gate_re_locks_after_one_shot_consumed(self) -> None:
        """Sticky-trip: the next privileged call after the consumed
        one-shot is blocked again. The harness must mint a fresh
        ``authorize_once`` for each privileged action."""
        gate = ActionContradictionGate(signal_field_key="x")
        ctx = AirlockContext(agent_id="ag", metadata={"x": True})

        with pytest.raises(ActionContradictionViolation):
            gate.check_action(context=ctx, tool_name="send_email", session_key="ag")

        ctx.authorize_once("send_email")
        gate.check_action(context=ctx, tool_name="send_email", session_key="ag")

        # Re-locked.
        with pytest.raises(ActionContradictionViolation):
            gate.check_action(context=ctx, tool_name="send_email", session_key="ag")

    def test_grant_for_one_tool_does_not_clear_other(self) -> None:
        gate = ActionContradictionGate(signal_field_key="x")
        ctx = AirlockContext(agent_id="ag", metadata={"x": True})
        ctx.authorize_once("send_email")
        # Other privileged sink stays blocked.
        with pytest.raises(ActionContradictionViolation):
            gate.check_action(context=ctx, tool_name="transfer_funds", session_key="ag")


# ---------------------------------------------------------------------------
# warn vs block + reset
# ---------------------------------------------------------------------------


class TestActionModes:
    def test_warn_mode_does_not_raise(self) -> None:
        gate = ActionContradictionGate(signal_field_key="x", action="warn")
        ctx = AirlockContext(agent_id="ag", metadata={"x": True})
        # Must not raise — admits with a log.
        gate.check_action(context=ctx, tool_name="send_email", session_key="ag")

    def test_reset_clears_per_session_state(self) -> None:
        gate = ActionContradictionGate(signal_field_key="x")
        ctx = AirlockContext(agent_id="ag", metadata={"x": True})
        with pytest.raises(ActionContradictionViolation):
            gate.check_action(context=ctx, tool_name="send_email", session_key="ag")
        assert gate.is_tripped("ag") is True
        gate.reset("ag")
        assert gate.is_tripped("ag") is False

    def test_reset_all_drops_every_session(self) -> None:
        gate = ActionContradictionGate(signal_field_key="x")
        for key in ("a", "b", "c"):
            ctx = AirlockContext(agent_id=key, metadata={"x": True})
            with pytest.raises(ActionContradictionViolation):
                gate.check_action(context=ctx, tool_name="send_email", session_key=key)
        gate.reset()
        for key in ("a", "b", "c"):
            assert gate.is_tripped(key) is False


# ---------------------------------------------------------------------------
# Exception payload — for the existing handle_policy_violation chain
# ---------------------------------------------------------------------------


class TestExceptionPayload:
    def test_violation_subclasses_policy_violation(self) -> None:
        gate = ActionContradictionGate(signal_field_key="x")
        ctx = AirlockContext(agent_id="ag", metadata={"x": True})
        with pytest.raises(ActionContradictionViolation) as exc:
            gate.check_action(context=ctx, tool_name="send_email", session_key="ag")
        assert isinstance(exc.value, PolicyViolation)

    def test_violation_carries_audit_payload(self) -> None:
        gate = ActionContradictionGate(signal_field_key="x")
        ctx = AirlockContext(agent_id="ag", metadata={"x": True})
        with pytest.raises(ActionContradictionViolation) as exc:
            gate.check_action(context=ctx, tool_name="send_email", session_key="ag")
        details = exc.value.details
        assert details["guard"] == "action_contradiction_gate"
        assert details["tool_name"] == "send_email"
        assert details["detector_kind"] == "signal_field"
        assert details["session_key"] == "ag"


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_check_action_consistent_sticky_flag(self) -> None:
        gate = ActionContradictionGate(signal_field_key="x")
        results: list[bool] = []

        def worker() -> None:
            ctx = AirlockContext(agent_id="ag", metadata={"x": True})
            try:
                gate.check_action(context=ctx, tool_name="send_email", session_key="ag")
                results.append(False)  # admitted
            except ActionContradictionViolation:
                results.append(True)  # blocked

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All 20 must have been blocked — no race window admits a call.
        assert results.count(True) == 20
        assert gate.is_tripped("ag") is True


# ---------------------------------------------------------------------------
# SecurityPolicy + @Airlock end-to-end (off-by-default invariant)
# ---------------------------------------------------------------------------


class TestSecurityPolicyIntegration:
    def test_default_policy_has_no_gate(self) -> None:
        """v0.8.14 callers see no behavior change."""
        assert SecurityPolicy().action_contradiction_gate is None

    def test_existing_presets_unaffected(self) -> None:
        from agent_airlock import (
            PERMISSIVE_POLICY,
            READ_ONLY_POLICY,
            STRICT_POLICY,
        )

        for p in (PERMISSIVE_POLICY, READ_ONLY_POLICY, STRICT_POLICY):
            assert p.action_contradiction_gate is None

    def test_airlock_seam_blocks_privileged_sink_on_contradiction(self) -> None:
        gate = ActionContradictionGate(signal_field_key="evidence_contradiction")
        policy = SecurityPolicy(action_contradiction_gate=gate)

        @Airlock(policy=policy)
        def send_email(_ctx: _Wrapper, to: str, body: str) -> str:
            return f"sent to {to}"

        wrapper = _Wrapper(
            context=_Inner(
                agent_id="ag-rag",
                metadata={"evidence_contradiction": True},
            )
        )
        blocked = send_email(wrapper, to="x@x", body="exfil")
        assert isinstance(blocked, dict)
        assert blocked.get("status") == "blocked"
        assert "send_email" in blocked.get("error", "")

    def test_airlock_seam_admits_non_sink_under_contradiction(self) -> None:
        gate = ActionContradictionGate(signal_field_key="evidence_contradiction")
        policy = SecurityPolicy(action_contradiction_gate=gate)

        @Airlock(policy=policy)
        def read_kb(_ctx: _Wrapper, query: str) -> str:
            return f"results: {query}"

        wrapper = _Wrapper(
            context=_Inner(
                agent_id="ag-rag",
                metadata={"evidence_contradiction": True},
            )
        )
        # Non-sink — admitted even with tripped state.
        result = read_kb(wrapper, query="alpha")
        assert result == "results: alpha"

    def test_airlock_seam_admits_clean_session(self) -> None:
        gate = ActionContradictionGate(signal_field_key="evidence_contradiction")
        policy = SecurityPolicy(action_contradiction_gate=gate)

        @Airlock(policy=policy)
        def send_email(_ctx: _Wrapper, to: str, body: str) -> str:
            return f"sent to {to}"

        wrapper = _Wrapper(
            context=_Inner(
                agent_id="ag-clean",
                metadata={"evidence_contradiction": False},
            )
        )
        # No contradiction → admitted.
        assert send_email(wrapper, to="ok@ok", body="hi") == "sent to ok@ok"
