"""0.10.29: a refusal says whether a retry can help, and rate limits count calls that run.

Until 0.10.29 a refusal carried no retry signal; only the most specific rate pattern applied,
so ``{"*": "3/hour", "search_*": "100/hour"}`` let 100 searches through; one bucket per
policy served every agent in the process; and the rate token was spent at step 2, before a
later gate or the approver refused the call. Raised in anthropics/claude-code#85422,
IBM/mcp-context-forge#6230 and pydantic/pydantic-ai#8839.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from agent_airlock import Airlock, AirlockContext, SecurityPolicy
from agent_airlock import amplification as amplification_module
from agent_airlock.amplification import AmplificationBudget
from agent_airlock.delegation import subset_problems
from agent_airlock.effect_guard import EffectGuard
from agent_airlock.oversight import OversightRequest, OversightResponse, OversightVerdict
from agent_airlock.self_heal import AirlockResponse, BlockReason, handle_rate_limit
from agent_airlock.tool_arg_sink_guard import ToolArgSinkGuard


def _search(policy: SecurityPolicy) -> Any:
    @Airlock(policy=policy, return_dict=True)
    def search_web(query: str) -> str:
        return f"results for {query}"

    return search_web


class TestRetryable:
    @pytest.mark.parametrize(
        ("reason", "expected"),
        [
            (BlockReason.KILL_SWITCH, False),
            (BlockReason.STARTUP_HOOK, False),
            (BlockReason.BUDGET_EXCEEDED, False),
            (BlockReason.AMPLIFICATION_EXCEEDED, False),
            (BlockReason.ESCALATION_DENIED, False),
            (BlockReason.POLICY_INDETERMINATE, False),
            (BlockReason.RUN_HALTED, False),
            (BlockReason.RUN_BUDGET_EXHAUSTED, False),
            (BlockReason.EFFECT_STATUS_UNKNOWN, False),
            (BlockReason.VALIDATION_ERROR, True),
            (BlockReason.TOOL_ARG_SINK, True),
            (BlockReason.ARGUMENT_SECRET, True),
            (BlockReason.PATH_VIOLATION, None),
        ],
    )
    def test_each_block_reason_says_whether_a_retry_can_help(
        self, reason: BlockReason, expected: bool | None
    ) -> None:
        response = AirlockResponse.blocked_response(reason=reason, error="AIRLOCK_BLOCK: x")
        assert response.retryable is expected
        assert response.to_dict().get("retryable") is expected

    def test_a_rate_limit_with_its_reset_time_is_retryable(self) -> None:
        assert handle_rate_limit("search", limit="1/hour", reset_seconds=60).retryable is True

    def test_a_success_says_nothing(self) -> None:
        assert "retryable" not in AirlockResponse.success_response("ok").to_dict()

    def test_a_tool_the_policy_does_not_allow_is_never_retryable(self) -> None:
        denied = _search(SecurityPolicy(denied_tools=["search_*"]))(query="x")
        unlisted = _search(SecurityPolicy(allowed_tools=["read_*"]))(query="x")
        assert denied["retryable"] is False
        assert unlisted["retryable"] is False

    def test_the_call_path_marks_validation_and_rate_refusals_retryable(self) -> None:
        search = _search(SecurityPolicy(rate_limits={"search_*": "1/hour"}))
        assert search(query=12)["retryable"] is True  # a wrong-typed argument
        search(query="x")
        limited = search(query="y")
        assert limited["block_reason"] == "rate_limit"
        assert limited["retryable"] is True

    def test_an_explicit_value_wins_over_the_default(self) -> None:
        response = AirlockResponse(
            success=False,
            status="blocked",
            block_reason=BlockReason.VALIDATION_ERROR,
            retryable=False,
        )
        assert response.retryable is False


class TestRateLimitMode:
    LIMITS = {"*": "3/hour", "search_*": "100/hour"}

    def test_all_patterns_must_have_a_token(self) -> None:
        search = _search(SecurityPolicy(rate_limits=self.LIMITS, rate_limit_mode="all"))
        results = [search(query=str(i)) for i in range(5)]
        assert [r["success"] for r in results] == [True, True, True, False, False]
        assert results[3]["block_reason"] == "rate_limit"

    def test_the_most_specific_pattern_alone_by_default(self) -> None:
        search = _search(SecurityPolicy(rate_limits=self.LIMITS))
        assert all(search(query=str(i))["success"] for i in range(5))

    def test_a_refused_call_takes_no_token_from_any_bucket(self) -> None:
        policy = SecurityPolicy(
            rate_limits={"*": "100/hour", "search_*": "1/hour"}, rate_limit_mode="all"
        )
        search = _search(policy)
        search(query="a")
        assert search(query="b")["block_reason"] == "rate_limit"
        assert policy._rate_limiters["*"].remaining() == 99

    def test_an_unknown_mode_or_scope_is_refused(self) -> None:
        with pytest.raises(ValueError):
            SecurityPolicy(rate_limit_mode="any")  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            SecurityPolicy(rate_limit_scope="tenant")  # type: ignore[arg-type]


class TestRateLimitScope:
    def test_each_agent_has_its_own_bucket(self) -> None:
        search = _search(SecurityPolicy(rate_limits={"*": "1/hour"}, rate_limit_scope="agent"))
        with AirlockContext(agent_id="a"):
            assert search(query="x")["success"] is True
            assert search(query="y")["block_reason"] == "rate_limit"
        with AirlockContext(agent_id="b"):
            assert search(query="x")["success"] is True

    def test_by_default_every_agent_shares_the_policys_bucket(self) -> None:
        search = _search(SecurityPolicy(rate_limits={"*": "1/hour"}))
        with AirlockContext(agent_id="a"):
            search(query="x")
        with AirlockContext(agent_id="b"):
            assert search(query="x")["block_reason"] == "rate_limit"


class TestOnlyCallsThatRunSpendATokens:
    def test_a_call_the_approver_denies_spends_no_rate_token(self) -> None:
        verdicts = iter([OversightVerdict.DENY, OversightVerdict.GRANT])

        def approver(request: OversightRequest) -> OversightResponse:
            return OversightResponse(request.request_id, next(verdicts))

        policy = SecurityPolicy(
            rate_limits={"pay": "1/hour"}, escalate_tools={"pay": "moves money"}, approver=approver
        )

        @Airlock(policy=policy, return_dict=True)
        def pay(amount: int) -> str:
            return "paid"

        assert pay(amount=5)["block_reason"] == "escalation_denied"
        assert pay(amount=5)["success"] is True

    def test_a_call_a_later_gate_refuses_spends_no_rate_token(self) -> None:
        policy = SecurityPolicy(
            rate_limits={"run_cmd": "1/hour"},
            tool_arg_sink_guard=ToolArgSinkGuard(shell_args=("cmd",)),
        )

        @Airlock(policy=policy, return_dict=True)
        def run_cmd(cmd: str) -> str:
            return "ran"

        assert run_cmd(cmd="ls; rm -rf /")["block_reason"] == "tool_arg_sink"
        assert run_cmd(cmd="ls")["success"] is True
        assert run_cmd(cmd="ls")["block_reason"] == "rate_limit"

    def test_a_granted_call_keeps_its_token(self) -> None:
        def approver(request: OversightRequest) -> OversightResponse:
            return OversightResponse(request.request_id, OversightVerdict.GRANT)

        policy = SecurityPolicy(
            rate_limits={"pay": "1/hour"}, escalate_tools={"pay": "moves money"}, approver=approver
        )

        @Airlock(policy=policy, return_dict=True)
        def pay(amount: int) -> str:
            return "paid"

        assert pay(amount=5)["success"] is True
        assert pay(amount=5)["block_reason"] == "rate_limit"

    def test_check_returns_what_it_charged_and_refunds_it_once(self) -> None:
        policy = SecurityPolicy(rate_limits={"*": "3/hour"})
        first = policy.check("search_web")
        policy.check("search_web")
        assert policy._rate_limiters["*"].remaining() == 1
        first.refund()
        first.refund()  # a second refund gives nothing back
        assert policy._rate_limiters["*"].remaining() == 2


class TestWallClockCap:
    def test_a_run_is_refused_at_its_deadline(self, monkeypatch: pytest.MonkeyPatch) -> None:
        clock = {"now": 1000.0}
        monkeypatch.setattr(amplification_module, "_now", lambda: clock["now"])
        policy = SecurityPolicy(amplification_budget=AmplificationBudget(max_wall_seconds=60))
        search = _search(policy)
        with AirlockContext(agent_id="a", session_id="run-1"):
            assert search(query="first")["success"] is True
            clock["now"] = 1059.9
            assert search(query="in time")["success"] is True
            clock["now"] = 1060.0
            late = search(query="late")
        assert late["block_reason"] == "amplification_exceeded"
        assert late["retryable"] is False

    def test_the_cap_counts_from_each_runs_first_call(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        clock = {"now": 1000.0}
        monkeypatch.setattr(amplification_module, "_now", lambda: clock["now"])
        search = _search(
            SecurityPolicy(amplification_budget=AmplificationBudget(max_wall_seconds=60))
        )
        with AirlockContext(agent_id="a", session_id="run-1"):
            search(query="x")
        clock["now"] = 1100.0
        with AirlockContext(agent_id="a", session_id="run-2"):
            assert search(query="x")["success"] is True

    def test_the_cap_alone_configures_the_budget(self) -> None:
        assert AmplificationBudget(max_wall_seconds=30).is_configured()

    @pytest.mark.parametrize("seconds", [0, -1, float("nan")])
    def test_a_cap_that_is_not_positive_is_refused(self, seconds: float) -> None:
        with pytest.raises(ValueError):
            AmplificationBudget(max_wall_seconds=seconds)


class TestDigests:
    def test_policies_that_keep_the_defaults_keep_their_digest(self) -> None:
        plain = SecurityPolicy(
            rate_limits={"*": "3/hour"},
            amplification_budget=AmplificationBudget(max_calls_per_run=5),
        )
        payload = plain._canonical_bytes()
        assert b"rate_limit_mode" not in payload
        assert b"rate_limit_scope" not in payload
        assert b"max_wall_seconds" not in payload
        assert b"max_sessions" not in payload

    def test_changing_a_new_setting_moves_the_digest(self) -> None:
        base = SecurityPolicy(rate_limits={"*": "3/hour"})._compute_policy_digest()
        for changed in (
            SecurityPolicy(rate_limits={"*": "3/hour"}, rate_limit_mode="all"),
            SecurityPolicy(rate_limits={"*": "3/hour"}, rate_limit_scope="agent"),
        ):
            assert changed._compute_policy_digest() != base

    def test_changing_a_new_budget_setting_moves_the_digest(self) -> None:
        def digest(**budget: Any) -> str:
            policy = SecurityPolicy(
                amplification_budget=AmplificationBudget(max_calls_per_run=5, **budget)
            )
            return policy._compute_policy_digest()

        assert len({digest(), digest(max_wall_seconds=60), digest(max_sessions=50)}) == 3


class TestBesideTheOtherGates:
    """The rate contract meets a delegated run's ceilings and the effect guard's replays."""

    def test_a_ceilings_token_comes_back_when_a_later_gate_refuses(self) -> None:
        parent = SecurityPolicy(rate_limits={"run_cmd": "1/hour"})

        @Airlock(
            policy=SecurityPolicy(tool_arg_sink_guard=ToolArgSinkGuard(shell_args=("cmd",))),
            return_dict=True,
        )
        def run_cmd(cmd: str) -> str:
            return "ran"

        lease = AirlockContext(agent_id="planner").delegate(
            parent.narrow(), parent_policy=parent, agent_id="worker"
        )
        with lease:
            assert run_cmd(cmd="ls; rm -rf /")["block_reason"] == "tool_arg_sink"
            assert run_cmd(cmd="ls")["success"] is True
            assert run_cmd(cmd="ls")["block_reason"] == "rate_limit"

    def test_a_replayed_call_gives_its_token_back(self) -> None:
        runs: list[int] = []
        policy = SecurityPolicy(effect_guard=EffectGuard(), rate_limits={"charge": "2/hour"})

        @Airlock(policy=policy)
        def charge(account: str, cents: int) -> dict[str, Any]:
            runs.append(cents)
            return {"charge_id": f"ch_{len(runs)}"}

        def call(call_id: str) -> Any:
            with AirlockContext(agent_id="a1", metadata={"tool_call_id": call_id}):
                return charge(account="a", cents=500)

        assert call("call-1") == {"charge_id": "ch_1"}
        assert call("call-1") == {"charge_id": "ch_1"}  # the replay: the tool did not run
        assert call("call-2") == {"charge_id": "ch_2"}
        assert call("call-3")["block_reason"] == "rate_limit"
        assert runs == [500, 500]

    def test_an_async_replay_gives_its_token_back(self) -> None:
        runs: list[int] = []
        policy = SecurityPolicy(effect_guard=EffectGuard(), rate_limits={"charge": "2/hour"})

        @Airlock(policy=policy)
        async def charge(account: str, cents: int) -> dict[str, Any]:
            runs.append(cents)
            return {"charge_id": f"ch_{len(runs)}"}

        async def call(call_id: str) -> Any:
            with AirlockContext(agent_id="a1", metadata={"tool_call_id": call_id}):
                return await charge(account="a", cents=500)

        async def calls() -> list[Any]:
            return [await call(call_id) for call_id in ("call-1", "call-1", "call-2", "call-3")]

        first, replay, second, limited = asyncio.run(calls())
        assert first == replay == {"charge_id": "ch_1"} and second == {"charge_id": "ch_2"}
        assert limited["block_reason"] == "rate_limit"
        assert runs == [500, 500]


class TestNarrowingTheNewSettings:
    """``narrow()`` and ``is_subset_of()`` compare the 0.10.29 rate and budget settings."""

    def test_narrow_keeps_the_parents_mode_and_scope(self) -> None:
        parent = SecurityPolicy(
            rate_limits={"*": "10/hour"}, rate_limit_mode="all", rate_limit_scope="agent"
        )
        child = parent.narrow()
        assert (child.rate_limit_mode, child.rate_limit_scope) == ("all", "agent")
        assert child.is_subset_of(parent)

    @pytest.mark.parametrize(
        ("parent", "child", "problem"),
        [
            pytest.param(
                {"rate_limit_mode": "all"},
                {"rate_limit_mode": "most_specific"},
                "rate_limit_mode",
                id="fewer-patterns",
            ),
            pytest.param({}, {"rate_limit_scope": "agent"}, "rate_limit_scope", id="per-agent"),
            pytest.param(
                {"amplification_budget": AmplificationBudget(max_wall_seconds=60)},
                {"amplification_budget": AmplificationBudget(max_wall_seconds=120)},
                "amplification_budget",
                id="later-deadline",
            ),
            pytest.param(
                {"amplification_budget": AmplificationBudget(max_wall_seconds=60)},
                {"amplification_budget": AmplificationBudget(max_calls_per_run=100)},
                "amplification_budget",
                id="no-deadline",
            ),
            pytest.param(
                {"amplification_budget": AmplificationBudget(max_calls_per_run=5)},
                {"amplification_budget": AmplificationBudget(max_calls_per_run=5, max_sessions=1)},
                "amplification_budget",
                id="fewer-ledgers",
            ),
        ],
    )
    def test_a_looser_setting_is_not_a_subset(
        self, parent: dict[str, Any], child: dict[str, Any], problem: str
    ) -> None:
        parent_policy = SecurityPolicy(rate_limits={"*": "10/hour"}, **parent)
        child_policy = SecurityPolicy(**{**parent_policy._public_kwargs(), **child})
        problems = subset_problems(child_policy, parent_policy)
        assert any(text.startswith(problem) for text in problems), problems

    def test_a_tighter_setting_is_a_subset(self) -> None:
        parent = SecurityPolicy(
            rate_limits={"*": "10/hour"},
            rate_limit_scope="agent",
            amplification_budget=AmplificationBudget(max_wall_seconds=60),
        )
        child = SecurityPolicy(
            **{
                **parent._public_kwargs(),
                "rate_limit_mode": "all",
                "rate_limit_scope": "policy",
                "amplification_budget": AmplificationBudget(max_wall_seconds=30),
            }
        )
        assert subset_problems(child, parent) == []
