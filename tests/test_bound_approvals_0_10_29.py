"""0.10.29: an approval binds to the call it approves, is spent once, and expires.

Until 0.10.29 an escalation's ``OversightRequest`` carried only the escalation's reason and
rule, so an approver could not see what it approved; ``authorize_once`` was a set of tool
names, checked and then discarded without a lock, copied by ``with_metadata()``; and nothing
held an approval across processes. Raised in agno-agi/agno#10600 (approved, then the
arguments changed, and the substituted call ran 3 times out of 3), crewAIInc/crewAI#6859,
google/adk-python#7148 (an in-memory claim let two replicas both run the call),
agentarea/agentarea#650 and openai/openai-agents-python#4896.
"""

from __future__ import annotations

import asyncio
import dataclasses
import enum
import json
import math
import os
import subprocess
import sys
import textwrap
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel

import agent_airlock
from agent_airlock import Airlock, AirlockConfig, AirlockContext, SecurityPolicy, approvals
from agent_airlock.approvals import (
    ApprovalLedger,
    GrantStore,
    InMemoryApprovalLedger,
    SQLiteApprovalLedger,
    StandingGrant,
    args_digest,
    consume_grant,
)
from agent_airlock.oversight import (
    OversightRequest,
    OversightResponse,
    OversightVerdict,
    requires_human_oversight,
)
from agent_airlock.policy import PolicyMutationError

# Assembled, so no secret scanner files this module.
SECRET = "sk-proj-" + "FAKEFAKEFAKEFAKEFAKE1234"


def _digest(**arguments: Any) -> str:
    return args_digest(arguments)


class _Clock:
    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def _answer(verdict: OversightVerdict, **fields: Any) -> Any:
    """An approver that records each request and answers ``verdict``."""
    asked: list[OversightRequest] = []

    def approver(request: OversightRequest) -> OversightResponse:
        asked.append(request)
        return OversightResponse(request_id=request.request_id, verdict=verdict, **fields)

    approver.asked = asked  # type: ignore[attr-defined]
    return approver


def _escalating(approver: Any = None, **policy: Any) -> SecurityPolicy:
    return SecurityPolicy(escalate_tools={"pay": "moves money"}, approver=approver, **policy)


def _pay(policy: SecurityPolicy, ran: list[Any], config: AirlockConfig | None = None) -> Any:
    @Airlock(policy=policy, return_dict=True, config=config or AirlockConfig())
    def pay(to: str, amount: int) -> str:
        ran.append((to, amount))
        return f"paid {amount} to {to}"

    return pay


def _reauth_pay(ran: list[Any]) -> Any:
    policy = SecurityPolicy(
        allowed_tools=["pay"],
        reauth_on_untrusted_reinvocation=True,
        untrusted_reinvocation_threshold=1,
    )
    return _pay(policy, ran)


class TestArgsDigest:
    def test_key_order_does_not_matter(self) -> None:
        assert _digest(a=1, b=[1, 2]) == args_digest({"b": [1, 2], "a": 1})

    def test_values_that_json_would_merge_stay_apart(self) -> None:
        pairs = [
            ({"x": math.nan}, {"x": math.inf}),
            ({"x": 1}, {"x": True}),
            ({"x": 1}, {"x": 1.0}),
            ({"x": b"rm -rf /"}, {"x": b"ls"}),
            ({"x": {1: "a"}}, {"x": {"1": "a"}}),
        ]
        for left, right in pairs:
            assert args_digest(left) != args_digest(right), (left, right)

    def test_a_dict_spelled_like_a_tag_is_not_the_value_it_imitates(self) -> None:
        """Model JSON can build any dict: one written like a tag must not borrow its digest."""

        class Order(BaseModel):
            amount: int

        class Session:
            pass

        class Colour(enum.Enum):
            RED = 1

        values: list[Any] = [
            b"hi",
            {1, 2},
            math.nan,
            {1: "a"},
            Order(amount=10),
            Session(),
            Colour.RED,
            datetime(2026, 11, 1),
        ]
        for value in values:
            forged = json.loads(approvals._canonical_json(value))
            assert isinstance(forged, dict), value
            assert _digest(x=value) != _digest(x=forged), value
            assert _digest(x=[value]) != _digest(x=[forged]), value

    def test_a_dict_with_an_ordinary_dunder_key_digests_stably(self) -> None:
        assert _digest(x={"__typename": "User"}) == _digest(x={"__typename": "User"})
        assert _digest(x={"__init__": 1}) == _digest(x={"__init__": 1})
        assert _digest(x={"__init__": 1}) != _digest(x={"__init__": 2})

    def test_a_model_or_dataclass_is_read_by_its_fields(self) -> None:
        class Order(BaseModel):
            amount: int

        @dataclasses.dataclass
        class Wire:
            amount: int

        assert _digest(o=Order(amount=10)) != _digest(o=Order(amount=10_000))
        assert _digest(o=Wire(amount=10)) != _digest(o=Wire(amount=10_000))
        assert _digest(o=Order(amount=10)) == _digest(o=Order(amount=10))

    def test_a_set_is_read_in_any_order(self) -> None:
        assert _digest(s={"b", "a", "c"}) == _digest(s={"c", "a", "b"})

    def test_an_opaque_host_object_stands_as_its_type(self) -> None:
        """Model JSON cannot build one, so a framework's injected context does not move it."""

        class ToolContext:
            pass

        class RunContext:
            pass

        assert _digest(ctx=ToolContext()) == _digest(ctx=ToolContext())
        assert _digest(ctx=ToolContext()) != _digest(ctx=RunContext())

    def test_arguments_too_deep_or_self_containing_cannot_be_read(self) -> None:
        deep: Any = []
        for _ in range(40):
            deep = [deep]
        loop: list[Any] = []
        loop.append(loop)
        for value in (deep, loop):
            with pytest.raises(ValueError):
                _digest(x=value)


class TestAuthorizeOnceBinding:
    def test_a_grant_for_one_call_admits_only_that_call_once(self) -> None:
        ran: list[Any] = []
        pay = _reauth_pay(ran)
        with AirlockContext(agent_id="a1") as run:
            pay(to="bob", amount=5)  # its output counts as untrusted: the next call needs a grant
            run.authorize_once("pay", args_digest=_digest(to="bob", amount=10))
            other = pay(to="mallory", amount=10_000)
            same = pay("bob", 10)  # bound by parameter name, so positional matches
            again = pay(to="bob", amount=10)
        assert other["success"] is False
        assert same["success"] is True
        assert again["success"] is False
        assert ran == [("bob", 5), ("bob", 10)]

    def test_a_grant_naming_no_digest_admits_one_call_as_before(self) -> None:
        ran: list[Any] = []
        pay = _reauth_pay(ran)
        with AirlockContext(agent_id="a1") as run:
            pay(to="bob", amount=5)
            run.authorize_once("pay")
            assert pay(to="anyone", amount=1)["success"] is True
            assert pay(to="anyone", amount=1)["success"] is False

    def test_a_grant_is_refused_at_its_expiry(self) -> None:
        clock = _Clock(100.0)
        store = GrantStore(clock=clock)
        store.add("pay", ttl_seconds=5)
        clock.now = 105.0
        assert store.consume("pay") is False
        store.add("pay", ttl_seconds=5)
        clock.now = 109.999
        assert store.consume("pay") is True

    def test_a_ttl_that_is_not_positive_is_refused(self) -> None:
        for ttl in (0, -1, math.nan, math.inf):
            with pytest.raises(ValueError):
                AirlockContext().authorize_once("pay", ttl_seconds=ttl)

    def test_a_grant_spent_through_a_clone_is_gone_from_the_original(self) -> None:
        run = AirlockContext(agent_id="a1")
        run.authorize_once("pay")
        clone = run.with_metadata(step=2)
        assert consume_grant(clone, "pay") is True
        assert "pay" not in run._authorized_once
        assert consume_grant(run, "pay") is False

    def test_two_concurrent_calls_with_one_grant_run_once(self) -> None:
        ran: list[Any] = []

        @Airlock(
            policy=SecurityPolicy(
                allowed_tools=["pay"],
                reauth_on_untrusted_reinvocation=True,
                untrusted_reinvocation_threshold=1,
            ),
            return_dict=True,
        )
        async def pay(to: str, amount: int) -> str:
            await asyncio.sleep(0)
            ran.append(amount)
            return "paid"

        async def main() -> list[Any]:
            async with AirlockContext(agent_id="a1") as run:
                await pay(to="bob", amount=5)
                run.authorize_once("pay", args_digest=_digest(to="bob", amount=10))
                return list(
                    await asyncio.gather(pay(to="bob", amount=10), pay(to="bob", amount=10))
                )

        results = asyncio.run(main())
        assert sorted(r["success"] for r in results) == [False, True]
        assert ran == [5, 10]

    def test_threads_racing_for_one_grant_spend_it_once(self) -> None:
        run = AirlockContext(agent_id="a1")
        run.authorize_once("pay")
        start = threading.Barrier(8)
        won: list[bool] = []

        def race() -> None:
            start.wait()
            won.append(consume_grant(run, "pay"))

        threads = [threading.Thread(target=race) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert sorted(won) == [False] * 7 + [True]

    def test_the_contradiction_gate_spends_a_bound_grant_only_on_its_call(self) -> None:
        from agent_airlock.action_contradiction_gate import (
            ActionContradictionGate,
            ActionContradictionViolation,
        )

        gate = ActionContradictionGate(signal_field_key="contradiction")
        ctx = AirlockContext(agent_id="a1", metadata={"contradiction": True})
        ctx.authorize_once("send_email", args_digest="d" * 64)
        with pytest.raises(ActionContradictionViolation):
            gate.check_action(
                context=ctx, tool_name="send_email", session_key="a1", args_digest="e" * 64
            )
        gate.check_action(
            context=ctx, tool_name="send_email", session_key="a1", args_digest="d" * 64
        )


class TestTheRequestIsBoundToTheCall:
    def test_the_request_carries_the_digest_and_a_masked_preview(self) -> None:
        approver = _answer(OversightVerdict.GRANT)
        policy = SecurityPolicy(escalate_tools={"send": "leaves the org"}, approver=approver)

        @Airlock(policy=policy, return_dict=True)
        def send(to: str, body: str, api_key: str) -> str:
            return "sent"

        with AirlockContext(agent_id="a1", session_id="s1"):
            send(to="bob@example.com", body=f"use {SECRET}", api_key=SECRET)

        request = approver.asked[0]
        assert request.args_digest == _digest(
            to="bob@example.com", body=f"use {SECRET}", api_key=SECRET
        )
        assert request.args_preview["api_key"] == "[REDACTED]"
        assert SECRET not in repr(request)
        assert "bob@example.com" not in repr(request)
        assert (request.agent_id, request.session_id) == ("a1", "s1")
        assert request.policy_digest == policy._compute_policy_digest()
        assert request.expires_at is not None
        window = datetime.fromisoformat(request.expires_at) - datetime.fromisoformat(
            request.requested_at
        )
        assert window.total_seconds() == policy.escalation_timeout_seconds

    def test_a_decision_about_other_arguments_is_indeterminate(self) -> None:
        ran: list[Any] = []
        pay = _pay(_escalating(_answer(OversightVerdict.GRANT, args_digest="0" * 64)), ran)
        result = pay(to="bob", amount=10)
        assert result["block_reason"] == "policy_indeterminate"
        assert ran == []

    def test_a_decision_echoing_this_digest_or_none_is_read_as_before(self) -> None:
        ran: list[Any] = []
        echoed = _escalating(_answer(OversightVerdict.GRANT, args_digest=_digest(to="b", amount=1)))
        assert _pay(echoed, ran)(to="b", amount=1)["success"] is True
        assert _pay(_escalating(_answer(OversightVerdict.GRANT)), ran)(to="b", amount=1)["success"]

    def test_arguments_changed_while_the_approver_decided_are_refused(self) -> None:
        ran: list[Any] = []
        order = {"amount": 10}

        def approver(request: OversightRequest) -> OversightResponse:
            order["amount"] = 10_000  # another task edits the shared dict meanwhile
            return OversightResponse(request.request_id, OversightVerdict.GRANT)

        @Airlock(policy=_escalating(approver), return_dict=True)
        def pay(order: dict[str, int]) -> str:
            ran.append(dict(order))
            return "paid"

        result = pay(order=order)
        assert result["block_reason"] == "policy_indeterminate"
        assert ran == []

    def test_arguments_that_cannot_be_read_are_refused_without_asking(self) -> None:
        approver = _answer(OversightVerdict.GRANT)

        @Airlock(policy=_escalating(approver), return_dict=True)
        def pay(items: list[Any]) -> str:
            return "paid"

        loop: list[Any] = []
        loop.append(loop)
        assert pay(items=loop)["block_reason"] == "policy_indeterminate"
        assert approver.asked == []

    def test_the_policy_digest_is_the_frozen_policys_too(self) -> None:
        approver = _answer(OversightVerdict.GRANT)
        frozen = _escalating(approver).freeze()
        _pay(frozen, [])(to="b", amount=1)
        assert approver.asked[0].policy_digest == frozen._frozen_digest


class TestTheOversightDecoratorBindsToo:
    def test_the_request_carries_the_digest_and_a_masked_preview(self) -> None:
        approver = _answer(OversightVerdict.GRANT)

        @requires_human_oversight(approver=approver, timeout_seconds=5)
        def rotate(service: str, token: str) -> str:
            return "rotated"

        assert rotate("billing", token=SECRET) == "rotated"
        request = approver.asked[0]
        assert request.args_digest == _digest(service="billing", token=SECRET)
        assert request.args_preview["token"] == "[REDACTED]"
        assert request.expires_at is not None

    def test_a_decision_about_other_arguments_raises(self) -> None:
        @requires_human_oversight(approver=_answer(OversightVerdict.GRANT, args_digest="0" * 64))
        def rotate(service: str) -> str:
            return "rotated"

        with pytest.raises(ValueError, match="other arguments"):
            rotate("billing")

    def test_arguments_changed_while_the_approver_decided_raise(self) -> None:
        target = {"service": "billing"}

        def approver(request: OversightRequest) -> OversightResponse:
            target["service"] = "payroll"
            return OversightResponse(request.request_id, OversightVerdict.GRANT)

        @requires_human_oversight(approver=approver)
        def rotate(where: dict[str, str]) -> str:
            return "rotated"

        with pytest.raises(ValueError, match="changed"):
            rotate(target)


class TestApprovalLedger:
    @pytest.mark.parametrize("kind", ["memory", "sqlite"])
    def test_an_approval_admits_its_call_once_and_no_other(self, kind: str, tmp_path: Path) -> None:
        ledger = self._ledger(kind, tmp_path, _Clock(50.0))
        ledger.grant("pay", "a" * 64, expires_at=100.0)
        assert ledger.claim("pay", "b" * 64, "call-1") is False
        assert ledger.claim("refund", "a" * 64, "call-1") is False
        assert ledger.claim("pay", "a" * 64, "call-1") is True
        assert ledger.claim("pay", "a" * 64, "call-2") is False

    @pytest.mark.parametrize("kind", ["memory", "sqlite"])
    def test_an_approval_is_refused_at_its_expiry(self, kind: str, tmp_path: Path) -> None:
        clock = _Clock(100.0)
        ledger = self._ledger(kind, tmp_path, clock)
        ledger.grant("pay", "a" * 64, expires_at=100.0)
        assert ledger.claim("pay", "a" * 64, "call-1") is False
        clock.now = 99.999
        assert ledger.claim("pay", "a" * 64, "call-1") is True

    def test_both_ledgers_satisfy_the_protocol(self, tmp_path: Path) -> None:
        assert isinstance(InMemoryApprovalLedger(), ApprovalLedger)
        assert isinstance(SQLiteApprovalLedger(tmp_path / "l.db"), ApprovalLedger)

    def test_two_connections_racing_for_one_approval_one_wins(self, tmp_path: Path) -> None:
        """Two replicas in one process: only SQLite's write lock stands between them."""
        db = tmp_path / "ledger.db"
        replicas = [SQLiteApprovalLedger(db), SQLiteApprovalLedger(db)]
        replicas[0].grant("pay", "a" * 64, expires_at=time.time() + 60)
        start = threading.Barrier(2)
        won: list[bool] = []

        def claim(ledger: SQLiteApprovalLedger, call_id: str) -> None:
            start.wait()
            won.append(ledger.claim("pay", "a" * 64, call_id))

        threads = [
            threading.Thread(target=claim, args=(ledger, f"call-{i}"))
            for i, ledger in enumerate(replicas)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert sorted(won) == [False, True]

    def test_two_processes_sharing_a_sqlite_ledger_one_claim_wins(self, tmp_path: Path) -> None:
        db = tmp_path / "ledger.db"
        ledger = SQLiteApprovalLedger(db)
        ledger.grant("pay", "a" * 64, expires_at=time.time() + 60)
        ledger.close()
        script = textwrap.dedent(
            """
            import os, sys, time
            from agent_airlock.approvals import SQLiteApprovalLedger
            db, go, me = sys.argv[1:4]
            ledger = SQLiteApprovalLedger(db)
            open(me + ".ready", "w").close()
            while not os.path.exists(go):
                time.sleep(0.002)
            print(ledger.claim("pay", "a" * 64, me))
            """
        )
        go = tmp_path / "go"
        # The claimers import the package this test imported, wherever it lives.
        source = str(Path(agent_airlock.__file__).resolve().parents[1])
        env = {
            **os.environ,
            "PYTHONPATH": os.pathsep.join([source, os.environ.get("PYTHONPATH", "")]),
            "AIRLOCK_AUDIT_LOG_PATH": str(tmp_path / "audit.json"),
        }
        procs = [
            subprocess.Popen(
                [sys.executable, "-c", script, str(db), str(go), str(tmp_path / f"call-{i}")],
                cwd=tmp_path,
                stdout=subprocess.PIPE,
                text=True,
                env=env,
            )
            for i in range(2)
        ]
        deadline = time.monotonic() + 20
        while not all((tmp_path / f"call-{i}.ready").exists() for i in range(2)):
            assert time.monotonic() < deadline, "the claimers never started"
            time.sleep(0.005)
        go.touch()
        outs = sorted(proc.communicate(timeout=20)[0].strip() for proc in procs)
        assert outs == ["False", "True"]

    def test_an_escalation_claims_from_the_ledger_before_asking(self) -> None:
        approver = _answer(OversightVerdict.DENY)
        ledger = InMemoryApprovalLedger()
        ledger.grant("pay", _digest(to="bob", amount=10), expires_at=time.time() + 60)
        ran: list[Any] = []
        pay = _pay(_escalating(approver, approval_ledger=ledger), ran)
        assert pay(to="bob", amount=10)["success"] is True
        assert approver.asked == []
        assert pay(to="bob", amount=10)["block_reason"] == "escalation_denied"
        assert pay(to="bob", amount=11)["block_reason"] == "escalation_denied"
        assert ran == [("bob", 10)]
        assert len(approver.asked) == 2

    def test_concurrent_calls_with_one_ledger_approval_run_once(self) -> None:
        ledger = InMemoryApprovalLedger()
        ledger.grant("pay", _digest(to="bob", amount=10), expires_at=time.time() + 60)
        ran: list[Any] = []

        @Airlock(policy=_escalating(_answer(OversightVerdict.DENY), approval_ledger=ledger))
        async def pay(to: str, amount: int) -> str:
            await asyncio.sleep(0)
            ran.append(amount)
            return "paid"

        async def main() -> list[Any]:
            return list(await asyncio.gather(*(pay(to="bob", amount=10) for _ in range(4))))

        results = asyncio.run(main())
        assert results.count("paid") == 1
        assert ran == [10]

    def test_a_ledger_that_fails_admits_nothing_and_the_approver_is_asked(self) -> None:
        class Broken:
            def grant(self, tool_name: str, args_digest: str, *, expires_at: float) -> None:
                raise OSError("disk gone")

            def claim(self, tool_name: str, args_digest: str, call_id: str) -> Any:
                raise OSError("disk gone")

        class Truthy(Broken):
            def claim(self, tool_name: str, args_digest: str, call_id: str) -> Any:
                return 1  # truthy, not True

        for ledger in (Broken(), Truthy()):
            approver = _answer(OversightVerdict.DENY)
            result = _pay(_escalating(approver, approval_ledger=ledger), [])(to="b", amount=1)
            assert result["block_reason"] == "escalation_denied"
            assert len(approver.asked) == 1

    @staticmethod
    def _ledger(kind: str, tmp_path: Path, clock: _Clock) -> Any:
        if kind == "memory":
            return InMemoryApprovalLedger(clock=clock)
        return SQLiteApprovalLedger(tmp_path / "ledger.db", clock=clock)


class TestStandingGrants:
    def test_a_standing_grant_admits_its_exact_call_without_asking(self, tmp_path: Path) -> None:
        approver = _answer(OversightVerdict.DENY)
        grant = StandingGrant(tool="pay", arguments={"to": "payroll"})
        audit = tmp_path / "audit.jsonl"
        config = AirlockConfig(enable_audit_log=True, audit_log_path=audit)
        ran: list[Any] = []
        pay = _pay(_escalating(approver, standing_grants=[grant]), ran, config)

        assert pay(to="payroll", amount=5)["success"] is True
        assert approver.asked == []
        assert pay(to="mallory", amount=5)["block_reason"] == "escalation_denied"
        assert len(approver.asked) == 1
        records = [
            json.loads(line)
            for line in audit.read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        ]
        assert [r.get("standing_grant") for r in records] == [grant.grant_id, None]

    def test_a_grant_names_an_exact_tool_and_at_least_one_argument(self) -> None:
        with pytest.raises(ValueError, match="exact tool"):
            StandingGrant(tool="pay_*", arguments={"to": "payroll"})
        with pytest.raises(ValueError, match="at least one"):
            StandingGrant(tool="pay", arguments={})
        with pytest.raises(ValueError):
            loop: list[Any] = []
            loop.append(loop)
            StandingGrant(tool="pay", arguments={"to": loop})

    def test_a_policy_refuses_what_is_not_a_grant_or_repeats_an_id(self) -> None:
        with pytest.raises(TypeError):
            SecurityPolicy(standing_grants=[{"tool": "pay"}])  # type: ignore[list-item]
        one = StandingGrant(tool="pay", arguments={"to": "a"}, grant_id="g1")
        two = StandingGrant(tool="pay", arguments={"to": "b"}, grant_id="g1")
        with pytest.raises(ValueError, match="repeats"):
            SecurityPolicy(standing_grants=[one, two])

    def test_values_compare_as_the_digest_encodes_them(self) -> None:
        grant = StandingGrant(tool="pay", arguments={"amount": 1})
        assert grant.matches("pay", {"amount": 1, "to": "x"})
        assert not grant.matches("pay", {"amount": True})
        assert not grant.matches("pay", {"amount": 1.0})
        assert not grant.matches("pay", {"to": "x"})
        assert not grant.matches("refund", {"amount": 1})

    def test_changing_the_mapping_afterwards_changes_nothing(self) -> None:
        target = {"to": "payroll"}
        grant = StandingGrant(tool="pay", arguments=target)
        target["to"] = "mallory"
        assert grant.matches("pay", {"to": "payroll"})
        assert not grant.matches("pay", {"to": "mallory"})

    def test_a_revoked_grant_asks_again(self) -> None:
        approver = _answer(OversightVerdict.DENY)
        grant = StandingGrant(tool="pay", arguments={"to": "payroll"})
        policy = _escalating(approver, standing_grants=[grant])
        pay = _pay(policy, [])
        assert pay(to="payroll", amount=5)["success"] is True
        assert policy.revoke_standing_grant(grant.grant_id) is True
        assert policy.revoke_standing_grant(grant.grant_id) is False
        assert policy.revoke_standing_grant("sg-unknown") is False
        assert pay(to="payroll", amount=5)["block_reason"] == "escalation_denied"

    def test_freeze_covers_grants_and_keeps_revocations(self) -> None:
        grant = StandingGrant(tool="pay", arguments={"to": "payroll"})
        policy = _escalating(_answer(OversightVerdict.DENY), standing_grants=[grant])
        policy.revoke_standing_grant(grant.grant_id)
        frozen = policy.freeze()
        assert frozen.standing_grant_for("pay", {"to": "payroll"}) is None
        frozen.verify_frozen()  # a revocation only narrows, so it is outside the digest
        frozen.standing_grants.append(StandingGrant(tool="pay", arguments={"to": "mallory"}))
        with pytest.raises(PolicyMutationError):
            frozen.verify_frozen()

    def test_a_policy_without_grants_keeps_its_0_10_28_digest(self) -> None:
        bare = _escalating(_answer(OversightVerdict.DENY))
        with_one = _escalating(
            _answer(OversightVerdict.DENY),
            standing_grants=[StandingGrant(tool="pay", arguments={"to": "x"})],
        )
        assert b"standing_grants" not in bare._canonical_bytes()
        assert bare._compute_policy_digest() != with_one._compute_policy_digest()

    def test_a_one_shot_approval_never_becomes_a_standing_grant(self) -> None:
        approver = _answer(OversightVerdict.GRANT)
        policy = _escalating(approver)
        pay = _pay(policy, [])
        pay(to="bob", amount=5)
        pay(to="bob", amount=5)
        assert len(approver.asked) == 2
        assert policy.standing_grants == []

    def test_a_standing_grant_never_softens_a_denial(self) -> None:
        grant = StandingGrant(tool="pay", arguments={"to": "payroll"})
        policy = SecurityPolicy(
            denied_tools=["pay"], escalate_tools={"pay": "moves money"}, standing_grants=[grant]
        )
        result = _pay(policy, [])(to="payroll", amount=5)
        assert result["block_reason"] == "policy_violation"
