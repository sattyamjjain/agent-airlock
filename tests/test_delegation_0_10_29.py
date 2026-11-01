"""0.10.29: a delegated agent's policy is a subset, its lease is single-use, nested runs
have a budget.

Until 0.10.29 a host could hand a child agent a wider policy than its parent's and nothing
noticed; nothing tied a tool argument to the lease its caller held; and a parent run with
``max_turns=2`` could let each nested agent take its own default. Raised in
openai/codex#36381 (prove the child's authority is a monotonic subset of the parent's, then
issue a one-use receipt), modelcontextprotocol/modelcontextprotocol#3354 (substituted tool
and argument calls still reached the effect) and openai/openai-agents-python#5453 (an
inherited depth and turn budget, a refusal handed back as a failed tool result).
"""

from __future__ import annotations

import asyncio
import contextvars
import fnmatch
import itertools
from dataclasses import fields as dc_fields
from pathlib import Path
from typing import Any

import pytest

from agent_airlock import Airlock, AirlockConfig, AirlockContext, SecurityPolicy
from agent_airlock.amplification import AmplificationBudget
from agent_airlock.approvals import StandingGrant
from agent_airlock.capability_caps import (
    Capability,
    CapabilityCapEngine,
    CapabilityRule,
    CapabilityRulesConfig,
    Lease,
)
from agent_airlock.conformance.decision_log import DecisionLog
from agent_airlock.context import get_current_context
from agent_airlock.delegation import (
    _CARRIED,
    _COMPARED,
    _IGNORED,
    DelegationRefused,
    glob_covers,
    subset_problems,
)
from agent_airlock.lease_scope import lease_scoped
from agent_airlock.nested_runs import (
    RunBudgetExhausted,
    current_run_budget,
    nested_run,
    run_budget,
    spend_turn,
)
from agent_airlock.oversight import OversightRequest, OversightResponse, OversightVerdict
from agent_airlock.run_guard import RunGuard
from agent_airlock.shell_command_policy import ShellCommandPolicy


def _reason(result: Any) -> str | None:
    """A refusal's violation type, or its block reason when it has none; None when it ran."""
    if isinstance(result, dict) and result.get("success") is False:
        return str(result.get("metadata", {}).get("violation_type") or result["block_reason"])
    return None


def _deny(request: OversightRequest) -> OversightResponse:
    return OversightResponse(request_id=request.request_id, verdict=OversightVerdict.DENY)


def _grant(request: OversightRequest) -> OversightResponse:
    return OversightResponse(
        request_id=request.request_id,
        verdict=OversightVerdict.GRANT,
        args_digest=request.args_digest,
    )


@Airlock()
def read_file(path: str) -> str:
    return f"read {path}"


@Airlock()
def write_file(path: str) -> str:
    return f"wrote {path}"


@Airlock()
def delete_db() -> str:
    return "deleted"


class _Run:
    """A host's run wrapper whose ``context`` is an ``AirlockContext``."""

    def __init__(self, context: AirlockContext[Any]) -> None:
        self.context = context


@Airlock()
def drop_table(run: Any) -> str:
    return "dropped"


def _parent() -> SecurityPolicy:
    return SecurityPolicy(
        allowed_tools=["read_*", "write_file", "delete_db"],
        rate_limits={"*": "100/hour"},
    )


class TestNarrow:
    def test_the_allowlist_is_intersected(self) -> None:
        parent = SecurityPolicy(allowed_tools=["read_*", "write_file"])
        child = parent.narrow(allowed_tools=["read_file", "write_*", "deploy"])
        assert child.allowed_tools == ["read_file", "write_file"]
        assert child.is_subset_of(parent)

    def test_an_intersection_that_comes_out_empty_admits_no_tool(self) -> None:
        child = SecurityPolicy(allowed_tools=["read_*"]).narrow(allowed_tools=["deploy"])
        assert child.allowed_tools == [] and child.default_deny

        @Airlock(policy=child)
        def read_notes() -> str:
            return "notes"

        assert _reason(read_notes()) == "empty_allowlist"

    def test_a_parent_that_admits_every_tool_keeps_the_childs_list(self) -> None:
        child = SecurityPolicy().narrow(allowed_tools=["read_*"])
        assert child.allowed_tools == ["read_*"] and child.default_deny

    def test_deny_patterns_are_added_to_the_parents(self) -> None:
        child = SecurityPolicy(denied_tools=["rm_*"]).narrow(denied_tools=["drop_*", "rm_*"])
        assert child.denied_tools == ["rm_*", "drop_*"]

    def test_a_rate_limit_must_be_lower(self) -> None:
        parent = SecurityPolicy(rate_limits={"*": "100/hour"})
        # 10 a minute is a burst of 10 but 600 an hour: faster than the parent.
        with pytest.raises(ValueError, match="not lower"):
            parent.narrow(rate_limits={"*": "10/minute"})
        assert parent.narrow(rate_limits={"*": "50/hour", "send_*": "1/hour"}).rate_limits == {
            "*": "50/hour",
            "send_*": "1/hour",
        }

    def test_the_call_budget_can_only_tighten(self) -> None:
        parent = SecurityPolicy(amplification_budget=AmplificationBudget(max_calls_per_run=10))
        with pytest.raises(ValueError, match="max_calls_per_run"):
            parent.narrow(amplification_budget=AmplificationBudget(max_calls_per_run=20))
        with pytest.raises(ValueError, match="amplification_budget"):
            parent.narrow(
                amplification_budget=AmplificationBudget(max_calls_per_run=5, action="warn")
            )
        child = parent.narrow(amplification_budget=AmplificationBudget(max_calls_per_run=5))
        assert child.is_subset_of(parent)

    def test_the_parents_guards_are_kept(self) -> None:
        guard, shell = RunGuard(), ShellCommandPolicy(allow=("ls",))
        parent = SecurityPolicy(run_guard=guard, shell_command_policy=shell)
        child = parent.narrow(allowed_tools=["ls_tool"])
        assert child.run_guard is guard and child.shell_command_policy is shell

    def test_a_revoked_standing_grant_stays_revoked(self) -> None:
        grant = StandingGrant(tool="pay", arguments={"to": "alice"})
        parent = SecurityPolicy(escalate_tools={"pay": "money"}, standing_grants=[grant])
        parent.revoke_standing_grant(grant.grant_id)
        assert parent.narrow().standing_grant_for("pay", {"to": "alice"}) is None

    @pytest.mark.parametrize("name", ["allowed_tools", "denied_tools"])
    def test_a_tool_list_given_as_a_string_is_refused(self, name: str) -> None:
        with pytest.raises(TypeError, match="list of patterns"):
            SecurityPolicy().narrow(**{name: "read_*"})


def _like(parent: SecurityPolicy, **changes: Any) -> SecurityPolicy:
    """A hand-built child: the parent's fields, with ``changes``."""
    return SecurityPolicy(**{**parent._public_kwargs(), **changes})


class TestIsSubsetOf:
    @pytest.mark.parametrize(
        ("parent", "changes", "problem"),
        [
            pytest.param(_parent(), {"allowed_tools": []}, "allowed_tools", id="admits-all"),
            pytest.param(_parent(), {"allowed_tools": ["*"]}, "allowed_tools", id="wider-pattern"),
            pytest.param(
                SecurityPolicy(denied_tools=["rm_*"]),
                {"denied_tools": []},
                "denied_tools",
                id="drops-a-deny",
            ),
            pytest.param(_parent(), {"rate_limits": {}}, "rate_limits", id="drops-a-rate"),
            pytest.param(
                _parent(), {"rate_limits": {"*": "1000/hour"}}, "rate_limits", id="faster"
            ),
            pytest.param(
                SecurityPolicy(time_restrictions={"deploy_*": "09:00-17:00"}),
                {"time_restrictions": {"deploy_*": "08:00-18:00"}},
                "time_restrictions",
                id="longer-window",
            ),
            pytest.param(
                SecurityPolicy(time_restrictions={"deploy_*": "09:00-17:00"}),
                {"time_restrictions": {"deploy_*": "09:00-17:00", "deploy_now": "00:00-23:59"}},
                "time_restrictions",
                id="a-more-specific-window",
            ),
            pytest.param(
                SecurityPolicy(require_agent_id=True),
                {"require_agent_id": False},
                "require_agent_id",
                id="anonymous",
            ),
            pytest.param(
                SecurityPolicy(allowed_roles=["reader"]),
                {"allowed_roles": ["reader", "admin"]},
                "allowed_roles",
                id="more-roles",
            ),
            pytest.param(
                SecurityPolicy(reauth_on_untrusted_reinvocation=True),
                {"untrusted_reinvocation_threshold": 5},
                "reauth_on_untrusted_reinvocation",
                id="later-reauth",
            ),
            pytest.param(
                SecurityPolicy(escalate_tools={"pay": "money"}),
                {"escalate_tools": {}},
                "escalate_tools",
                id="drops-an-escalation",
            ),
            pytest.param(
                SecurityPolicy(escalate_tools={"pay": "money"}),
                {"approver": _deny},
                "approver",
                id="its-own-approver",
            ),
            pytest.param(
                SecurityPolicy(escalate_tools={"pay": "money"}),
                {"standing_grants": [StandingGrant(tool="pay", arguments={"to": "bob"})]},
                "standing_grants",
                id="a-new-standing-grant",
            ),
            pytest.param(
                SecurityPolicy(amplification_budget=AmplificationBudget(max_calls_per_run=5)),
                {"amplification_budget": None},
                "amplification_budget",
                id="no-budget",
            ),
            pytest.param(
                SecurityPolicy(run_guard=RunGuard()),
                {"run_guard": RunGuard()},
                "run_guard",
                id="another-guard",
            ),
            pytest.param(
                SecurityPolicy(stdio_mode="disabled"),
                {"stdio_mode": "allowlist"},
                "stdio_mode",
                id="stdio",
            ),
        ],
    )
    def test_a_wider_child_is_not_a_subset(
        self, parent: SecurityPolicy, changes: dict[str, Any], problem: str
    ) -> None:
        child = _like(parent, **changes)
        problems = subset_problems(child, parent)
        assert not child.is_subset_of(parent)
        assert any(text.startswith(problem) for text in problems), problems

    def test_a_tie_cannot_reorder_rate_limits_to_the_looser_one(self) -> None:
        # Both patterns match read_file and are as specific as each other, so the first
        # in dictionary order decides: 10 a minute for the parent, 100 for this child.
        parent = SecurityPolicy(rate_limits={"read_*": "10/minute", "*_file": "100/minute"})
        child = _like(parent, rate_limits={"*_file": "100/minute", "read_*": "10/minute"})
        assert not child.is_subset_of(parent)

    def test_tighter_values_are_a_subset(self) -> None:
        parent = SecurityPolicy(
            allowed_tools=["read_*"],
            time_restrictions={"read_*": "09:00-17:00"},
            allowed_roles=["reader", "auditor"],
            escalate_tools={"read_secret": "secrets"},
        )
        child = _like(
            parent,
            allowed_tools=["read_file"],
            time_restrictions={"read_*": "10:00-12:00"},
            allowed_roles=["reader"],
            escalate_tools={"read_secret": "secrets", "read_logs": "logs"},
            require_agent_id=True,
        )
        assert subset_problems(child, parent) == []

    def test_a_field_delegation_does_not_know_is_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from agent_airlock import delegation

        monkeypatch.setattr(delegation, "_COMPARED", _COMPARED - {"rate_limits"})
        policy = SecurityPolicy()
        assert subset_problems(policy, policy) == [
            "rate_limits: a field delegation does not compare"
        ]

    def test_every_public_field_is_compared_or_carried(self) -> None:
        public = {spec.name for spec in dc_fields(SecurityPolicy) if not spec.name.startswith("_")}
        assert public == _COMPARED | _IGNORED | set(_CARRIED)
        assert not (_COMPARED & set(_CARRIED))

    @pytest.mark.parametrize(
        ("outer", "inner", "covers"),
        [
            ("*", "anything_*", True),
            ("read_*", "read_*", True),
            ("read_*", "read_file", True),
            ("read_*", "read_f*", True),
            ("read_*", "rea*", False),
            ("a*z", "ab*yz", True),
            ("a*a", "a*", False),
            ("read_?", "read_x", True),
            ("read_?", "read_*", False),
            # A character class ends in "]": it must not read as a literal tail.
            ("*]", "*[ab]", False),
            ("*_file", "*", False),
        ],
    )
    def test_glob_coverage(self, outer: str, inner: str, covers: bool) -> None:
        assert glob_covers(outer, inner) is covers

    def test_glob_coverage_never_claims_a_name_it_misses(self) -> None:
        patterns = ["*", "a*", "*a", "a*b", "ab*", "?b", "a?", "[ab]a", "a[ab]", "ab", "b*a*"]
        names = [
            "".join(chars) for size in range(5) for chars in itertools.product("ab", repeat=size)
        ]
        for outer, inner in itertools.product(patterns, repeat=2):
            if glob_covers(outer, inner):
                missed = [
                    n
                    for n in names
                    if fnmatch.fnmatchcase(n, inner) and not fnmatch.fnmatchcase(n, outer)
                ]
                assert not missed, (outer, inner, missed)


class TestDelegationLease:
    def test_widening_is_refused_and_a_subset_is_admitted_once(self) -> None:
        parent = _parent()
        root = AirlockContext(agent_id="planner")
        with pytest.raises(DelegationRefused) as refused:
            root.delegate(SecurityPolicy(allowed_tools=["*"]), parent_policy=parent)
        assert any("allowed_tools" in problem for problem in refused.value.problems)

        lease = root.delegate(parent.narrow(allowed_tools=["read_*"]), parent_policy=parent)
        with lease as child:
            assert get_current_context() is child
            assert read_file(path="notes.md") == "read notes.md"
        assert lease.spent
        with pytest.raises(DelegationRefused, match="used already"), lease:
            pass

    def test_a_childs_call_must_pass_its_ceiling(self) -> None:
        parent = _parent()
        lease = AirlockContext(agent_id="planner").delegate(
            parent.narrow(allowed_tools=["read_*"]), parent_policy=parent, agent_id="researcher"
        )
        with lease as child:
            assert child.agent_id == "researcher" and child.ceiling is lease.policy
            refused = delete_db()  # its own policy admits it; the child's does not
        assert _reason(refused) == "tool_not_allowed"
        assert refused["metadata"]["policy"] == "DelegationCeiling"
        assert delete_db() == "deleted"  # outside the child run, the ceiling is gone

    def test_siblings_share_their_parents_rate_limit(self) -> None:
        parent = SecurityPolicy(rate_limits={"read_file": "2/hour"})
        root = AirlockContext(agent_id="planner")
        first = root.delegate(parent.narrow(), parent_policy=parent, agent_id="a")
        second = root.delegate(parent.narrow(), parent_policy=parent, agent_id="b")
        with first:
            assert read_file(path="1") == "read 1"
            assert read_file(path="2") == "read 2"
        with second:
            assert _reason(read_file(path="3")) == "rate_limit"

    def test_siblings_share_their_parents_call_budget(self) -> None:
        parent = SecurityPolicy(amplification_budget=AmplificationBudget(max_calls_per_run=2))
        root = AirlockContext(agent_id="planner", session_id="tree")
        first = root.delegate(parent.narrow(), parent_policy=parent, agent_id="a")
        second = root.delegate(parent.narrow(), parent_policy=parent, agent_id="b")
        with first:
            assert read_file(path="1") == "read 1"
            assert read_file(path="2") == "read 2"
        with second:
            assert _reason(read_file(path="3")) == "amplification_exceeded"

    def test_the_child_policy_cannot_widen_after_issue(self) -> None:
        parent = _parent()
        child_policy = parent.narrow(allowed_tools=["read_*"])
        lease = AirlockContext(agent_id="planner").delegate(child_policy, parent_policy=parent)
        child_policy.allowed_tools.append("delete_db")  # the lease kept a frozen copy
        with lease:
            assert _reason(delete_db()) == "tool_not_allowed"

    def test_a_parent_narrowed_after_issue_refuses_the_entry(self) -> None:
        parent = _parent()
        lease = AirlockContext(agent_id="planner").delegate(
            parent.narrow(allowed_tools=["write_file"]), parent_policy=parent
        )
        parent.allowed_tools.remove("write_file")
        with pytest.raises(DelegationRefused, match="allowed_tools"), lease:
            pass

    def test_a_lease_entered_from_another_run_is_refused(self) -> None:
        parent = _parent()
        lease = AirlockContext(agent_id="planner").delegate(parent.narrow(), parent_policy=parent)
        with AirlockContext(agent_id="someone-else"):
            with pytest.raises(DelegationRefused, match="another run"), lease:
                pass

    def test_a_lease_entered_from_a_child_of_its_run_is_refused(self) -> None:
        parent = _parent()
        root = AirlockContext(agent_id="planner")
        lease = root.delegate(parent.narrow(), parent_policy=parent)
        with root.delegate(parent.narrow(allowed_tools=["read_*"]), parent_policy=parent):
            with pytest.raises(DelegationRefused, match="another run"), lease:
                pass

    def test_a_clone_of_the_child_keeps_its_ceiling(self) -> None:
        parent = _parent()
        lease = AirlockContext(agent_id="planner").delegate(
            parent.narrow(allowed_tools=["read_*"]), parent_policy=parent
        )
        with lease as child, child.with_metadata(step="2"):
            assert _reason(delete_db()) == "tool_not_allowed"

    def test_a_run_wrapper_carries_the_ceiling_where_no_context_is_set(self) -> None:
        parent = _parent()
        lease = AirlockContext(agent_id="planner").delegate(
            parent.narrow(allowed_tools=["read_*"]), parent_policy=parent
        )
        with lease as child:
            # A fresh contextvars context: no ceiling is set around the call, only the
            # run wrapper's AirlockContext carries one.
            result = contextvars.Context().run(drop_table, _Run(child))
        assert _reason(result) == "tool_not_allowed"

    def test_a_call_naming_another_run_still_meets_the_ceiling_it_is_made_under(self) -> None:
        parent = _parent()
        lease = AirlockContext(agent_id="planner").delegate(
            parent.narrow(allowed_tools=["read_*"]), parent_policy=parent
        )
        with lease:
            result = drop_table(_Run(AirlockContext(agent_id="someone-else")))
        assert _reason(result) == "tool_not_allowed"

    def test_a_grandchild_is_checked_against_its_parent(self) -> None:
        root = SecurityPolicy(allowed_tools=["read_file", "write_file"])
        child_policy = root.narrow(allowed_tools=["read_file"])
        with AirlockContext(agent_id="planner").delegate(child_policy, parent_policy=root) as child:
            with pytest.raises(DelegationRefused, match="allowed_tools"):
                child.delegate(root.narrow())  # within the root, not within the child
            with pytest.raises(ValueError, match="leave parent_policy out"):
                child.delegate(child.ceiling or root, parent_policy=root)
            with child.delegate(child_policy.narrow(), agent_id="grandchild") as grandchild:
                assert len(grandchild._ceiling) == 3
                assert _reason(write_file(path="x")) == "tool_not_allowed"

    def test_a_run_with_no_policy_has_nothing_to_narrow(self) -> None:
        with pytest.raises(DelegationRefused, match="no policy to narrow"):
            AirlockContext(agent_id="planner").delegate(SecurityPolicy())

    def test_a_halted_run_cannot_carry_on_through_a_child(self) -> None:
        parent = _parent()
        root = AirlockContext(agent_id="planner")
        lease = root.delegate(parent.narrow(), parent_policy=parent)
        root.halt("a hard stop")
        with lease as child:
            assert child._run_state is root._run_state and child._flow is root._flow
            assert _reason(read_file(path="x")) == "run_halted"

    def test_an_escalation_on_the_ceiling_goes_to_its_approver(self) -> None:
        denying = SecurityPolicy(escalate_tools={"write_file": "writes"}, approver=_deny)
        with AirlockContext(agent_id="planner").delegate(denying.narrow(), parent_policy=denying):
            assert _reason(write_file(path="x")) == "escalation_denied"
        # The parent's approver grants; the child, with none, still asks and is refused.
        granting = SecurityPolicy(escalate_tools={"write_file": "writes"}, approver=_grant)
        with AirlockContext(agent_id="planner").delegate(granting.narrow(), parent_policy=granting):
            assert write_file(path="x") == "wrote x"
        with AirlockContext(agent_id="planner").delegate(
            _like(granting, approver=None), parent_policy=granting
        ):
            assert _reason(write_file(path="x")) == "escalation_required"

    def test_the_childs_call_budget_counts_its_run(self) -> None:
        parent = SecurityPolicy()
        child_policy = parent.narrow(amplification_budget=AmplificationBudget(max_calls_per_run=1))
        with AirlockContext(agent_id="planner", session_id="s1").delegate(
            child_policy, parent_policy=parent
        ):
            assert read_file(path="1") == "read 1"
            assert _reason(read_file(path="2")) == "amplification_exceeded"

    def test_the_decision_record_names_the_ceiling(self, tmp_path: Path) -> None:
        log = DecisionLog(tmp_path / "decisions.jsonl")

        @Airlock(config=AirlockConfig(decision_log=log))
        def drop_table() -> str:
            return "dropped"

        parent = _parent()
        with AirlockContext(agent_id="planner").delegate(parent.narrow(), parent_policy=parent):
            drop_table()
        details = log.records()[0].details or {}
        assert details["layer"] == "2.1:delegation_ceiling"

    def test_an_async_lease(self) -> None:
        parent = _parent()

        @Airlock()
        async def read_async(path: str) -> str:
            return path

        async def run() -> Any:
            lease = AirlockContext(agent_id="planner").delegate(
                parent.narrow(allowed_tools=["write_file"]), parent_policy=parent
            )
            async with lease:
                return await read_async(path="x")

        assert _reason(asyncio.run(run())) == "tool_not_allowed"


def _engine(*rules: CapabilityRule) -> CapabilityCapEngine:
    return CapabilityCapEngine(CapabilityRulesConfig(rules=rules))


def _write_lease(target: str, lease_id: str = "docs") -> Lease:
    return Lease(lease_id=lease_id, capability="write_file", categories=frozenset(), target=target)


def _writer(engine: CapabilityCapEngine) -> Any:
    @Airlock()
    @lease_scoped(arg="path", capability=Capability.WRITE_FILE, engine=engine)
    def save(path: str, text: str = "") -> str:
        return f"saved {path}"

    return save


class TestLeaseScoped:
    def test_an_argument_outside_the_lease_is_refused_though_it_passes_the_schema(self) -> None:
        engine = _engine()
        engine.grant_lease("writer", _write_lease("/repo/docs/*"))
        save = _writer(engine)
        with AirlockContext(agent_id="writer"):
            refused = save(path="/repo/src/main.py", text="x")
            assert save(path="/repo/docs/guide.md") == "saved /repo/docs/guide.md"
        assert refused["block_reason"] == "capability_denied"
        assert refused["metadata"]["violation_type"] == "lease_scope"
        assert "/repo/docs" not in refused["error"]  # the lease's target is not shown
        uses = engine.store.total_used(
            agent_id="writer", capability=Capability.WRITE_FILE, target=None, since_epoch=0
        )
        assert uses == 1

    @pytest.mark.parametrize("path", ["/repo/docs/../secrets/key", "/repo/docs/a\x00b"])
    def test_a_value_not_matched_as_written_is_refused(self, path: str) -> None:
        engine = _engine()
        engine.grant_lease("writer", _write_lease("/repo/docs/*"))
        with AirlockContext(agent_id="writer"):
            assert _reason(_writer(engine)(path=path)) == "lease_scope"

    def test_a_call_that_names_no_agent_holds_no_lease(self) -> None:
        engine = _engine()
        engine.grant_lease("writer", _write_lease("*"))
        refused = _writer(engine)(path="/repo/docs/a.md")
        assert "names no agent" in refused["error"]

    def test_the_default_value_is_checked(self) -> None:
        engine = _engine()
        engine.grant_lease("writer", _write_lease("/repo/docs/*"))

        @Airlock()
        @lease_scoped(arg="path", capability=Capability.WRITE_FILE, engine=engine)
        def save_outside(path: str = "/etc/passwd") -> str:
            return path

        @Airlock()
        @lease_scoped(arg="path", capability=Capability.WRITE_FILE, engine=engine)
        def save_inside(path: str = "/repo/docs/notes.md") -> str:
            return path

        with AirlockContext(agent_id="writer"):
            assert _reason(save_outside()) == "lease_scope"
            assert save_inside() == "/repo/docs/notes.md"

    def test_above_airlock_it_still_counts(self) -> None:
        engine = _engine()
        engine.grant_lease("writer", _write_lease("/repo/docs/*"))

        @lease_scoped(arg="path", capability=Capability.WRITE_FILE, engine=engine)
        @Airlock()
        def save_above(path: str) -> str:
            return path

        with AirlockContext(agent_id="writer"):
            assert _reason(save_above(path="/tmp/x")) == "lease_scope"
            assert save_above(path="/repo/docs/x") == "/repo/docs/x"

    def test_the_engines_cap_can_still_refuse(self) -> None:
        engine = _engine(CapabilityRule(Capability.WRITE_FILE, amount=1, window="hour"))
        engine.grant_lease("writer", _write_lease("/repo/docs/*"))
        save = _writer(engine)
        with AirlockContext(agent_id="writer"):
            assert save(path="/repo/docs/a") == "saved /repo/docs/a"
            assert "cap refused it" in save(path="/repo/docs/b")["error"]

    def test_a_lease_check_that_raises_refuses(self) -> None:
        engine = _engine()

        def broken(agent_id: str) -> tuple[Lease, ...]:
            raise RuntimeError("ledger down")

        engine.held_leases = broken  # type: ignore[method-assign]
        with AirlockContext(agent_id="writer"):
            assert "could not be checked" in _writer(engine)(path="/repo/docs/a")["error"]

    def test_a_child_gets_leases_within_its_parents_and_loses_them_after(self) -> None:
        engine = _engine()
        engine.grant_lease("planner", _write_lease("/repo/*", "repo"))
        parent = SecurityPolicy()
        root = AirlockContext(agent_id="planner")
        save = _writer(engine)
        lease = root.delegate(
            parent.narrow(),
            parent_policy=parent,
            agent_id="docs-writer",
            engine=engine,
            leases=[_write_lease("/repo/docs/*")],
        )
        with lease:
            assert save(path="/repo/docs/a.md") == "saved /repo/docs/a.md"
            assert _reason(save(path="/repo/src/a.py")) == "lease_scope"
        assert engine.held_leases("docs-writer") == ()

    @pytest.mark.parametrize(
        ("agent_id", "lease", "problem"),
        [
            ("docs-writer", _write_lease("/etc/*"), "no lease the parent holds covers"),
            ("planner", _write_lease("/repo/docs/*"), "its own agent_id"),
            (None, _write_lease("/repo/docs/*"), "its own agent_id"),
        ],
    )
    def test_a_child_lease_must_be_within_the_parents(
        self, agent_id: str | None, lease: Lease, problem: str
    ) -> None:
        engine = _engine()
        engine.grant_lease("planner", _write_lease("/repo/*", "repo"))
        with pytest.raises(DelegationRefused, match=problem):
            AirlockContext(agent_id="planner").delegate(
                SecurityPolicy(),
                parent_policy=SecurityPolicy(),
                agent_id=agent_id,
                engine=engine,
                leases=[lease],
            )

    def test_a_delegation_is_metered_as_delegate_to_agent(self) -> None:
        engine = _engine(CapabilityRule(Capability.DELEGATE_TO_AGENT, amount=1, window="hour"))
        parent = SecurityPolicy()
        root = AirlockContext(agent_id="planner")
        with root.delegate(parent.narrow(), parent_policy=parent, engine=engine):
            pass
        second = root.delegate(parent.narrow(), parent_policy=parent, engine=engine)
        with pytest.raises(DelegationRefused, match="delegate_to_agent"), second:
            pass

    def test_the_declaration_is_checked(self) -> None:
        from agent_airlock import Capability as CapabilityFlag

        engine = _engine()
        with pytest.raises(ValueError, match="name a parameter"):
            lease_scoped(arg="not a name", capability=Capability.WRITE_FILE, engine=engine)
        with pytest.raises(TypeError, match="capability_caps.Capability"):
            lease_scoped(arg="path", capability=CapabilityFlag.FILESYSTEM_WRITE, engine=engine)  # type: ignore[arg-type]
        with pytest.raises(TypeError, match="CapabilityCapEngine"):
            lease_scoped(arg="path", capability=Capability.WRITE_FILE, engine=object())  # type: ignore[arg-type]


@Airlock()
def ask_subagent(depth: int) -> Any:
    """An agent run as a tool: a nested run whose agent asks for one more."""
    with nested_run():
        return ask_subagent(depth=depth + 1) if depth < 3 else "answered"


class TestRunBudget:
    def test_exhausted_depth_gives_the_parent_a_failed_tool_result(self) -> None:
        with run_budget(max_depth=1):
            result = ask_subagent(depth=0)
        # The second nested run had no level left: the agent that asked for it got a
        # failed tool result, and the run it was in carried on to return it.
        assert result["block_reason"] == "run_budget_exhausted"
        assert result["metadata"]["budget"] == "depth"

    def test_a_hard_stop_the_root_set_raises_out_of_the_run(self) -> None:
        with run_budget(max_depth=1, hard_stop=True), pytest.raises(RunBudgetExhausted) as stop:
            ask_subagent(depth=0)
        assert stop.value.hard_stop and stop.value.kind == "depth"

    def test_siblings_share_the_roots_turns(self) -> None:
        with run_budget(max_turns=5) as root:
            with nested_run(max_turns=10) as first:
                assert first.turns_left == 5  # all that is left, not its own 10
                first.spend_turns(3)
            assert root.turns_left == 2  # the two it did not spend came back
            with nested_run() as second:
                assert second.turns_left == 2
                second.spend_turns(2)
            with pytest.raises(RunBudgetExhausted) as exhausted, nested_run():
                pass
        assert exhausted.value.kind == "turns"

    def test_concurrent_siblings_draw_on_the_same_turns(self) -> None:
        spent: list[str] = []

        async def sibling(name: str) -> None:
            with nested_run():  # no share of its own: none is reserved for it
                for _ in range(2):
                    try:
                        spend_turn()
                    except RunBudgetExhausted:
                        spent.append(f"{name}: refused")
                        return
                    spent.append(name)
                    await asyncio.sleep(0)

        async def tree() -> None:
            await asyncio.gather(sibling("a"), sibling("b"))

        with run_budget(max_turns=3):
            asyncio.run(tree())
        assert sorted(spent) == ["a", "a", "b", "b: refused"]

    def test_a_turn_past_the_budget_is_refused_and_none_is_spent(self) -> None:
        with run_budget(max_turns=2) as budget:
            spend_turn()
            with pytest.raises(RunBudgetExhausted):
                spend_turn(2)
            assert budget.turns_left == 1

    def test_a_budget_inside_another_can_only_tighten_it(self) -> None:
        with run_budget(max_depth=1, max_turns=4):
            with run_budget(max_depth=5, max_turns=10) as inner:
                assert inner.depth_left == 1 and inner.turns_left == 4
            with pytest.raises(ValueError, match="root's to set"), run_budget(hard_stop=True):
                pass

    @pytest.mark.parametrize("bad", [-1, True, 1.5, "2"])
    def test_a_limit_is_a_whole_number(self, bad: Any) -> None:
        with pytest.raises(ValueError, match="whole number"), nested_run(max_depth=bad):
            pass
        with pytest.raises(ValueError, match="whole number"):
            spend_turn(bad if bad != -1 else 0)

    def test_without_a_budget_a_nested_run_sets_its_own(self) -> None:
        assert current_run_budget() is None
        with nested_run(max_depth=0), pytest.raises(RunBudgetExhausted), nested_run():
            pass

    def test_the_budget_follows_an_asyncio_task_and_copied_contexts(self) -> None:
        async def depth_in_task() -> int | None:
            budget = current_run_budget()
            return budget.depth_left if budget else None

        with run_budget(max_depth=2), nested_run():
            assert asyncio.run(depth_in_task()) == 1
            assert contextvars.copy_context().run(lambda: current_run_budget()) is not None

    def test_a_delegation_takes_a_level_of_depth(self) -> None:
        parent = SecurityPolicy()
        lease = AirlockContext(agent_id="planner").delegate(parent.narrow(), parent_policy=parent)
        with run_budget(max_depth=0), pytest.raises(RunBudgetExhausted), lease:
            pass
        assert lease.spent  # a lease is spent by its first use, whatever came of it
