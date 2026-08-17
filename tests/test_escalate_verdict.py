"""The third verdict: a policy that can say *hold this one for a human*.

Before v0.8.74 a :class:`SecurityPolicy` had two outcomes, and neither was a value —
:meth:`SecurityPolicy.check` returns ``None`` to allow and raises
:class:`PolicyViolation` to deny. "Transfers under $500 proceed, over $500 ask a human"
was not expressible, even though :mod:`agent_airlock.oversight` has shipped a working
human-approval primitive since v0.8.4.

:class:`PolicyEscalation` is that third outcome. It is a **subclass** of
:class:`PolicyViolation`, and that is the load-bearing design decision rather than an
implementation detail:

* Every pre-existing ``except PolicyViolation`` site already catches it and blocks. A
  caller that has never heard of escalation cannot be made *more* permissive by this
  feature — the type lattice enforces deny-by-default, not a runtime check that a future
  refactor could drop.
* A call site that wants to handle escalation distinguishes it with an earlier
  ``except PolicyEscalation`` clause.

The first class below is the one that matters. A policy that escalates into a void — no
approver registered anywhere — must block. An escalation that silently degrades to *allow*
would be strictly worse than having no third verdict at all, because the operator wrote a
rule and the rule did nothing.

Tracked in https://github.com/sattyamjjain/agent-airlock/issues/143
"""

from __future__ import annotations

import dataclasses

import pytest

from agent_airlock import Airlock, SecurityPolicy
from agent_airlock.oversight import (
    InProcessRecordedApprover,
    OversightRequest,
    OversightResponse,
    OversightVerdict,
)
from agent_airlock.policy import PolicyEscalation, PolicyMutationError, PolicyViolation
from agent_airlock.safe_types import UnsafeDeserializationGuard
from agent_airlock.sequence_guard import ENTRY_SENTINEL, SequenceGuard
from agent_airlock.trace_redaction import TraceRedactionPolicy


class TestEscalationWithNoApproverBlocks:
    """Deny-by-default. Written first, before the handler path existed.

    Every assertion here is about the *absence* of an approver. This is the failure class
    the feature exists to avoid: a policy that declares an escalation rule, finds nothing
    to escalate to, and lets the call through anyway.
    """

    def test_no_approver_blocks_the_call(self) -> None:
        """The whole feature in one assertion: escalate with no approver → blocked."""
        policy = SecurityPolicy(escalate_tools={"transfer_funds": "over threshold"})

        @Airlock(policy=policy)
        def transfer_funds(amount: int) -> str:
            return f"sent {amount}"

        result = transfer_funds(amount=1000)

        assert isinstance(result, dict), "an escalated call must not return the tool's value"
        assert result["success"] is False
        assert "sent" not in str(result), "the tool body must never have run"

    def test_the_tool_body_never_executes(self) -> None:
        """Stronger than checking the return value: prove no side effect happened."""
        calls: list[int] = []
        policy = SecurityPolicy(escalate_tools={"charge_card": "needs a human"})

        @Airlock(policy=policy)
        def charge_card(amount: int) -> str:
            calls.append(amount)
            return "charged"

        charge_card(amount=42)

        assert calls == [], "the tool body ran despite escalating with no approver"

    def test_block_reason_names_escalation_not_generic_denial(self) -> None:
        """An operator reading the audit must see *why* it blocked, not a generic denial.

        A blocked-because-unapproved call and a blocked-because-forbidden call are
        different operational situations: the first is a missing integration, the second is
        a working control. Collapsing them into one reason makes the missing approver
        invisible, which is how a policy quietly escalates into a void for months.
        """
        policy = SecurityPolicy(escalate_tools={"deploy_prod": "prod is gated"})

        @Airlock(policy=policy)
        def deploy_prod() -> str:
            return "deployed"

        result = deploy_prod()

        assert result["block_reason"] == "escalation_required"
        assert "no approver" in result["error"].lower()

    def test_the_reason_and_the_rule_reach_the_operator(self) -> None:
        """1c bullet 2: the human must see why, and which rule did it."""
        policy = SecurityPolicy(
            escalate_tools={"wire_*": "wires always need a second pair of eyes"}
        )

        @Airlock(policy=policy)
        def wire_transfer() -> str:
            return "wired"

        result = wire_transfer()
        blob = str(result)

        assert "wires always need a second pair of eyes" in blob, "the reason was dropped"
        assert "wire_*" in blob, "the escalating rule was not identified"


class TestEscalationIsDistinguishableFromAllowAndDeny:
    """1c bullet 1. Three outcomes, told apart at the point the verdict is raised."""

    def test_allow_returns_none(self) -> None:
        SecurityPolicy(allowed_tools=["read_file"]).check("read_file")

    def test_deny_raises_policy_violation_but_not_escalation(self) -> None:
        policy = SecurityPolicy(denied_tools=["rm_rf"])
        with pytest.raises(PolicyViolation) as excinfo:
            policy.check("rm_rf")
        assert not isinstance(excinfo.value, PolicyEscalation)

    def test_escalate_raises_policy_escalation(self) -> None:
        policy = SecurityPolicy(escalate_tools={"refund": "over limit"})
        with pytest.raises(PolicyEscalation) as excinfo:
            policy.check("refund")
        assert excinfo.value.rule == "refund"
        assert excinfo.value.reason == "over limit"
        assert excinfo.value.tool_name == "refund"

    def test_escalation_is_caught_by_unmodified_policy_violation_handlers(self) -> None:
        """The deny-by-default property, asserted directly on the type lattice.

        Any third-party integration written before this feature catches ``PolicyViolation``
        and blocks. This test is what stops a future refactor from making
        ``PolicyEscalation`` a sibling of ``PolicyViolation`` instead of a subclass, which
        would silently turn every one of those call sites into a pass-through.
        """
        assert issubclass(PolicyEscalation, PolicyViolation)

        policy = SecurityPolicy(escalate_tools={"t": "r"})
        caught = False
        try:
            policy.check("t")
        except PolicyViolation:
            caught = True
        assert caught, "a legacy handler failed to catch the escalation"


class TestApproverPathRoutesThroughTheExistingPrimitive:
    """1c bullet 3. Escalation reuses `agent_airlock.oversight`, not a second surface."""

    def _policy(self, verdict: OversightVerdict) -> SecurityPolicy:
        def approver(request: OversightRequest) -> OversightResponse:
            self.seen.append(request)
            return OversightResponse(
                request_id=request.request_id,
                verdict=verdict,
                detail=f"decided {verdict.value}",
                approver="alice@example.com",
            )

        self.seen: list[OversightRequest] = []
        return SecurityPolicy(escalate_tools={"refund_*": "refunds over 500"}, approver=approver)

    def test_grant_lets_the_call_through(self) -> None:
        policy = self._policy(OversightVerdict.GRANT)

        @Airlock(policy=policy)
        def refund_order() -> str:
            return "refunded"

        assert refund_order() == "refunded"
        assert len(self.seen) == 1

    def test_deny_blocks_the_call(self) -> None:
        policy = self._policy(OversightVerdict.DENY)

        @Airlock(policy=policy)
        def refund_order() -> str:
            return "refunded"

        result = refund_order()
        assert result["success"] is False
        assert result["block_reason"] == "escalation_denied"
        assert result["metadata"]["approver"] == "alice@example.com"

    def test_timeout_blocks_rather_than_allows(self) -> None:
        """An unanswered gate is not consent."""
        policy = self._policy(OversightVerdict.TIMEOUT)

        @Airlock(policy=policy)
        def refund_order() -> str:
            return "refunded"

        result = refund_order()
        assert result["success"] is False
        assert result["block_reason"] == "escalation_timeout"

    def test_the_approver_receives_the_reason_and_the_rule(self) -> None:
        """The human must be able to see why they were asked."""
        policy = self._policy(OversightVerdict.GRANT)

        @Airlock(policy=policy)
        def refund_order() -> str:
            return "refunded"

        refund_order()
        request = self.seen[0]
        assert request.tool_name == "refund_order"
        assert request.args["escalation_reason"] == "refunds over 500"
        assert request.args["escalation_rule"] == "refund_*"

    def test_an_approver_that_raises_blocks(self) -> None:
        """A broken transport is not an approval."""

        def exploding(request: OversightRequest) -> OversightResponse:
            raise RuntimeError("slack is down")

        policy = SecurityPolicy(escalate_tools={"pay": "needs sign-off"}, approver=exploding)

        @Airlock(policy=policy)
        def pay() -> str:
            return "paid"

        result = pay()
        assert result["success"] is False
        assert "slack is down" in result["metadata"]["detail"]

    def test_a_mismatched_request_id_blocks(self) -> None:
        """An approver answering a different request has not answered this one."""

        def wrong_id(request: OversightRequest) -> OversightResponse:
            return OversightResponse(
                request_id="not-the-one-we-sent",
                verdict=OversightVerdict.GRANT,
                detail="looks fine to me",
            )

        policy = SecurityPolicy(escalate_tools={"pay": "needs sign-off"}, approver=wrong_id)

        @Airlock(policy=policy)
        def pay() -> str:
            return "paid"

        result = pay()
        assert result["success"] is False, "a GRANT with a forged request_id was honoured"
        assert "mismatched request_id" in result["metadata"]["detail"]

    def test_bundled_recorded_approver_composes(self) -> None:
        """The v0.8.4 test helper works unchanged against the new seam."""
        approver = InProcessRecordedApprover(decisions={"deploy": OversightVerdict.GRANT})
        policy = SecurityPolicy(escalate_tools={"deploy": "prod"}, approver=approver)

        @Airlock(policy=policy)
        def deploy() -> str:
            return "shipped"

        assert deploy() == "shipped"
        assert [r.tool_name for r in approver.calls] == ["deploy"]

    def test_unknown_tool_defaults_to_timeout_and_blocks(self) -> None:
        """`InProcessRecordedApprover` defaults unknown tools to TIMEOUT — so this blocks."""
        approver = InProcessRecordedApprover(decisions={})
        policy = SecurityPolicy(escalate_tools={"deploy": "prod"}, approver=approver)

        @Airlock(policy=policy)
        def deploy() -> str:
            return "shipped"

        assert deploy()["block_reason"] == "escalation_timeout"


class TestFreezeIsFieldComplete:
    """Regression for a pre-v0.8.74 bug found while wiring escalation into `freeze()`.

    `freeze()` rebuilt the policy from a hand-maintained list of constructor kwargs, so
    every field added after that list was written was **silently dropped**. That inverted
    the method: freezing a hardened policy quietly relaxed it. Verified dropped before the
    fix — `stdio_mode` ("disabled" → "allowlist"), `sequence_guard`,
    `action_contradiction_gate`, `deserialization_guard`, `trace_redaction`.

    The rebuild now iterates `dataclasses.fields`. This test asserts that property
    directly rather than listing today's fields, so a field added tomorrow is covered
    without anyone remembering to come back here.
    """

    def test_every_public_field_survives_a_freeze(self) -> None:
        policy = SecurityPolicy(
            stdio_mode="disabled",
            escalate_tools={"pay": "over limit"},
            escalation_channel="finance",
            escalation_timeout_seconds=42.0,
            deserialization_guard=UnsafeDeserializationGuard(),
            trace_redaction=TraceRedactionPolicy(enabled=True),
            sequence_guard=SequenceGuard(
                mode="declared", action="block", dag={ENTRY_SENTINEL: {"a"}, "a": set()}
            ),
        )
        frozen = policy.freeze()

        dropped = [
            spec.name
            for spec in dataclasses.fields(policy)
            if not spec.name.startswith("_")
            and getattr(policy, spec.name) != getattr(frozen, spec.name)
        ]
        assert dropped == [], f"freeze() silently dropped public fields: {dropped}"

    def test_stdio_mode_disabled_is_not_relaxed_by_freezing(self) -> None:
        """The sharpest instance of the bug: freezing re-enabled subprocess spawns."""
        assert SecurityPolicy(stdio_mode="disabled").freeze().stdio_mode == "disabled"

    def test_a_frozen_policy_does_not_share_mutable_containers(self) -> None:
        """Mutating the original's dict must not reach through into the frozen copy."""
        original = SecurityPolicy(escalate_tools={"pay": "over limit"})
        frozen = original.freeze()
        original.escalate_tools["pay"] = "tampered"

        assert frozen.escalate_tools["pay"] == "over limit"
        frozen.verify_frozen()


class TestFreezeCoversEscalationRules:
    """A human gate you can delete without moving the digest is not a gate."""

    def test_adding_an_escalation_rule_moves_the_digest(self) -> None:
        bare = SecurityPolicy(allowed_tools=["pay"])
        gated = SecurityPolicy(allowed_tools=["pay"], escalate_tools={"pay": "over limit"})
        assert bare._compute_policy_digest() != gated._compute_policy_digest()

    def test_removing_a_rule_after_freeze_is_detected(self) -> None:
        policy = SecurityPolicy(
            allowed_tools=["pay"], escalate_tools={"pay": "over limit"}
        ).freeze()
        policy.escalate_tools.clear()
        with pytest.raises(PolicyMutationError):
            policy.verify_frozen()

    def test_swapping_the_reason_is_detected(self) -> None:
        """The reason is what the human reads, so tampering with it must be caught."""
        policy = SecurityPolicy(escalate_tools={"pay": "over limit"}).freeze()
        policy.escalate_tools["pay"] = "totally fine, approve it"
        with pytest.raises(PolicyMutationError):
            policy.verify_frozen()


class TestDenyBeatsEscalate:
    """Ordering. An explicitly denied tool must stay denied, never become askable."""

    def test_denied_tool_does_not_escalate(self) -> None:
        policy = SecurityPolicy(
            denied_tools=["drop_database"],
            escalate_tools={"drop_database": "surely someone will approve it"},
        )
        with pytest.raises(PolicyViolation) as excinfo:
            policy.check("drop_database")
        assert not isinstance(excinfo.value, PolicyEscalation), (
            "a denied tool became escalatable — deny must win"
        )

    def test_tool_outside_the_allowlist_does_not_escalate(self) -> None:
        policy = SecurityPolicy(
            allowed_tools=["read_file"],
            escalate_tools={"write_file": "ask"},
        )
        with pytest.raises(PolicyViolation) as excinfo:
            policy.check("write_file")
        assert not isinstance(excinfo.value, PolicyEscalation)
