"""Convergent Detour Hijacking — the attack shape, and exactly what the layer records.

Convergent Detour Hijacking (CDH), `arXiv:2608.12273
<https://arxiv.org/abs/2608.12273>`_ (2026-08-12), is a text-only attack on skill-based LLM
agents. A malicious skill *description* wins tool selection under shared semantic cover, its
*body* reuses that same rationale to fabricate plausible dependencies, those dependencies
recruit unnecessary but entirely benign skills into a **bounded** detour, and the trajectory
then re-enters the original route so the task still completes.

The reported numbers on DeepSeek-V4-Pro: the matched attacker coordinator is selected in
**80.02%** of tasks, and among coordinator-hit runs that complete, token consumption rises
**66.91%** and end-to-end execution time **92.45%**, while aggregate task completion stays
comparable.

That last clause is the whole problem. **Outcome-based evaluation cannot see this attack**,
because by construction the outcome is correct. The cost is the payload.

Why this belongs in agent-airlock's test suite: a deny-by-default contract layer sits on
every tool call, so the recruited calls pass through a seam that an outcome checker never
touches. That makes airlock one of the few places the detour is observable at all — and it
makes the exact limits of what it records worth pinning down rather than assuming.

What this module establishes, in order:

1. The fixture is a faithful CDH shape: the task completes, and every recruited call is
   benign, permitted, and successful.
2. Outcome-based evaluation is blind to it. Direct and detour runs are indistinguishable by
   return value, block count, and error count.
3. **The recruited calls ARE visible** in the per-call audit record. This is the real
   capability and it is asserted, not assumed.
4. **The amplification IS now recorded, and detected.** v0.8.74 added an opt-in
   ``SecurityPolicy.amplification_budget``: the run's call count is compared against a
   declared baseline, five ``run_*`` fields carry the comparison onto every ``AuditRecord``,
   and an over-budget run is refused. The unit is calls, not dollars — the paper's token and
   wall-time figures are not universally observable at this seam, and the field names say so
   rather than estimating. Closes issue #142.
5. `SequenceGuard` in DECLARED mode does catch the detour today, at the cost of the operator
   having declared the route up front.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from agent_airlock import (
    Airlock,
    AirlockConfig,
    AmplificationBudget,
    SecurityPolicy,
    detour_hijacking_defaults,
)
from agent_airlock.anomaly import AnomalyDetector, AnomalyDetectorConfig
from agent_airlock.sequence_guard import ENTRY_SENTINEL, SequenceGuard, SequenceViolation

# --------------------------------------------------------------------------------------
# The fixture: one task, two trajectories, identical result.
# --------------------------------------------------------------------------------------

#: The legitimate route. Two calls, and the second one produces the answer.
DIRECT_ROUTE: tuple[str, ...] = ("fetch_document", "summarize_text")

#: The CDH trajectory. `resolve_skill_dependencies` is the attacker-controlled coordinator
#: that won selection on its description alone; the three skills after it are the recruited
#: benign detour whose dependency on the task was fabricated. `summarize_text` is the
#: re-entry that preserves task completion.
DETOUR_ROUTE: tuple[str, ...] = (
    "fetch_document",
    "resolve_skill_dependencies",
    "detect_document_encoding",
    "normalize_whitespace",
    "estimate_reading_time",
    "summarize_text",
)

#: The calls the detour adds. Every one is an ordinary, useful, non-malicious skill — which
#: is precisely why no content-based check fires on any of them.
RECRUITED: tuple[str, ...] = tuple(t for t in DETOUR_ROUTE if t not in DIRECT_ROUTE)

#: What a correct run returns. Both trajectories produce this.
EXPECTED_ANSWER = "Q3 revenue rose 12%."


@dataclass
class _Session:
    """The inner context object a harness supplies (OpenAI-SDK `.context` shape)."""

    session_id: str
    agent_id: str = "analyst-agent"


@dataclass
class _Wrapper:
    """A `RunContextWrapper`-alike: airlock reads `session_id` through `.context`."""

    context: _Session


def _build_tools(audit_path: Path, policy: SecurityPolicy | None = None) -> dict[str, Any]:
    """Airlock-wrapped stand-ins for every skill in both trajectories.

    Each returns a plausible value and none of them fails, so the only thing separating the
    two runs is which skills were invoked and how many.
    """
    config = AirlockConfig(enable_audit_log=True, audit_log_path=audit_path)

    def _make(name: str, value: Any) -> Any:
        # `_wrapper` is unused by the body on purpose: airlock reads it positionally in
        # `ContextExtractor.extract_from_args` to recover the session, so the parameter is
        # load-bearing for the decorator even though the tool itself ignores it.
        def _tool(_wrapper: _Wrapper) -> Any:
            return value

        _tool.__name__ = name
        _tool.__qualname__ = name
        decorated = Airlock(config=config, policy=policy)(_tool)
        return decorated

    return {
        "fetch_document": _make("fetch_document", "Q3 revenue rose 12 percent."),
        # The coordinator. Benign-looking output; its damage was done at selection time.
        "resolve_skill_dependencies": _make("resolve_skill_dependencies", list(RECRUITED[1:])),
        "detect_document_encoding": _make("detect_document_encoding", "utf-8"),
        "normalize_whitespace": _make("normalize_whitespace", "Q3 revenue rose 12 percent."),
        "estimate_reading_time": _make("estimate_reading_time", 1),
        "summarize_text": _make("summarize_text", EXPECTED_ANSWER),
    }


def _run_all(
    route: tuple[str, ...],
    audit_path: Path,
    session_id: str,
    policy: SecurityPolicy | None = None,
) -> list[Any]:
    """Drive one trajectory and return EVERY call's result, in order.

    A blocked call returns an ``AirlockResponse`` dict rather than the tool's value, so
    the caller can see exactly where in the trajectory a control fired.
    """
    tools = _build_tools(audit_path, policy)
    wrapper = _Wrapper(context=_Session(session_id=session_id))
    return [tools[tool_name](wrapper) for tool_name in route]


def _run(
    route: tuple[str, ...],
    audit_path: Path,
    session_id: str,
    policy: SecurityPolicy | None = None,
) -> Any:
    """Drive one trajectory end to end and return the final tool's value."""
    return _run_all(route, audit_path, session_id, policy)[-1]


def _audit_records(audit_path: Path, session_id: str) -> list[dict[str, Any]]:
    """Every audit line belonging to one session, in order."""
    if not audit_path.exists():
        return []
    out: list[dict[str, Any]] = []
    for line in audit_path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        record = json.loads(line)
        if record.get("session_id") == session_id:
            out.append(record)
    return out


# --------------------------------------------------------------------------------------


class TestDetourFixtureIsFaithful:
    """Guards on the fixture itself, so the later assertions mean what they claim."""

    def test_detour_preserves_the_route(self) -> None:
        """The detour must contain the original route in order, not replace it.

        CDH re-enters the legitimate trajectory. A fixture that diverged permanently would
        be modelling a different, far more detectable attack.
        """
        positions = [DETOUR_ROUTE.index(step) for step in DIRECT_ROUTE]
        assert positions == sorted(positions)
        assert DETOUR_ROUTE[-1] == DIRECT_ROUTE[-1]

    def test_detour_is_bounded(self) -> None:
        """A bounded detour, per the paper. Unbounded recruitment is a rate problem."""
        assert 0 < len(RECRUITED) < len(DETOUR_ROUTE)
        assert len(DETOUR_ROUTE) > len(DIRECT_ROUTE)

    def test_recruited_skills_are_benign(self) -> None:
        """No recruited call names a dangerous capability.

        This is the property that defeats content inspection: there is nothing to find in
        `detect_document_encoding`. The attack is in the *fact of the call*, not its payload.
        """
        dangerous = ("delete", "drop", "rm_", "exec", "send", "transfer", "write")
        for name in RECRUITED:
            assert not any(token in name for token in dangerous), name


class TestOutcomeEvaluationIsBlind:
    """The premise: correct outcomes do not guarantee trajectory integrity."""

    def test_both_trajectories_return_the_same_answer(self, tmp_path: Path) -> None:
        direct = _run(DIRECT_ROUTE, tmp_path / "direct.jsonl", "sess-direct")
        detour = _run(DETOUR_ROUTE, tmp_path / "detour.jsonl", "sess-detour")
        assert direct == detour == EXPECTED_ANSWER

    def test_the_detour_run_is_clean_by_every_failure_metric(self, tmp_path: Path) -> None:
        """Zero blocks, zero errors. There is no failure signal to alert on."""
        audit_path = tmp_path / "detour.jsonl"
        _run(DETOUR_ROUTE, audit_path, "sess-detour")
        records = _audit_records(audit_path, "sess-detour")

        assert records, "the run produced no audit records at all"
        assert all(record["blocked"] is False for record in records)
        assert all(record.get("error") is None for record in records)

    def test_anomaly_detector_stays_silent_on_the_detour(self) -> None:
        """None of the four `AnomalyType` signals fires on a detour run.

        `AnomalyDetector` watches call rate, endpoint diversity, error rate, and consecutive
        blocks. A detour has a zero error rate, zero blocks, no endpoint, and a call count
        far under `max_calls_per_window`, so it is the *quietest possible run* by these
        metrics. This is not a defect in the detector, whose remit is different — it is why
        the detour needs its own answer.
        """
        detector = AnomalyDetector(AnomalyDetectorConfig())
        events = [
            detector.record_call(tool_name=name, session_id="sess-detour") for name in DETOUR_ROUTE
        ]
        assert events == [None] * len(DETOUR_ROUTE)


class TestPerRunRecordMakesRecruitedCallsVisible:
    """The capability. Every recruited call reaches the audit log as its own record."""

    def test_every_recruited_call_is_recorded(self, tmp_path: Path) -> None:
        audit_path = tmp_path / "detour.jsonl"
        _run(DETOUR_ROUTE, audit_path, "sess-detour")
        recorded = [record["tool_name"] for record in _audit_records(audit_path, "sess-detour")]

        assert recorded == list(DETOUR_ROUTE)
        for name in RECRUITED:
            assert name in recorded, f"{name} was recruited but never recorded"

    def test_call_count_separates_the_two_trajectories(self, tmp_path: Path) -> None:
        """The signal outcome-based evaluation lacks: the two runs differ in the ledger.

        This is the load-bearing assertion of the module. An outcome checker sees one
        identical answer twice; the contract layer sees two and six calls.
        """
        audit_path = tmp_path / "both.jsonl"
        _run(DIRECT_ROUTE, audit_path, "sess-direct")
        _run(DETOUR_ROUTE, audit_path, "sess-detour")

        direct = _audit_records(audit_path, "sess-direct")
        detour = _audit_records(audit_path, "sess-detour")

        assert len(direct) == len(DIRECT_ROUTE)
        assert len(detour) == len(DETOUR_ROUTE)
        assert len(detour) > len(direct)

    def test_records_are_groupable_into_a_run(self, tmp_path: Path) -> None:
        """Grouping works only because the harness passed a context carrying `session_id`.

        Without that context object, `AirlockContext.session_id` is `None` and every record
        in the file is anonymous — the calls are all still logged, but they cannot be
        assembled into a run, which is what any detour analysis needs first.
        """
        audit_path = tmp_path / "detour.jsonl"
        _run(DETOUR_ROUTE, audit_path, "sess-detour")
        records = _audit_records(audit_path, "sess-detour")

        assert {record["session_id"] for record in records} == {"sess-detour"}
        assert {record["agent_id"] for record in records} == {"analyst-agent"}

    def test_without_a_context_the_run_cannot_be_reconstructed(self, tmp_path: Path) -> None:
        """The same trajectory, driven with no context object, loses its run identity."""
        audit_path = tmp_path / "anonymous.jsonl"
        config = AirlockConfig(enable_audit_log=True, audit_log_path=audit_path)

        @Airlock(config=config)
        def summarize_text() -> str:
            return EXPECTED_ANSWER

        summarize_text()

        lines = [
            json.loads(line)
            for line in audit_path.read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        ]
        assert lines, "the call was not logged at all"
        assert all("session_id" not in record for record in lines)


class TestResourceAmplificationIsRecordedAndDetected:
    """Closed in v0.8.74. The calls were always visible; now the amplification is too.

    This class previously asserted the *absence* of cost accounting — it was a tripwire
    designed to fail loudly the day someone closed the gap, rather than let it be closed
    in silence. It has been rewritten in place, which is the tripwire working as intended.

    What changed: `SecurityPolicy.amplification_budget` declares what a run should cost,
    `AmplificationGuard` counts calls against it, and five `run_*` fields carry the
    comparison onto every `AuditRecord`.

    What deliberately did **not** change: the unit is CALLS, not dollars. The paper
    measures tokens (+66.91%) and wall time (+92.45%); airlock observes neither
    universally, so it reports the unit it genuinely has and the field names say so.
    `run_input_tokens` is populated only from a caller-supplied `_airlock_input_tokens`
    and is never estimated.

    Closes https://github.com/sattyamjjain/agent-airlock/issues/142
    """

    #: A budget declaring the direct route's two calls as normal, tripping at 1.5x.
    def _budget_policy(self) -> SecurityPolicy:
        return SecurityPolicy(
            amplification_budget=detour_hijacking_defaults(baseline_calls_per_run=len(DIRECT_ROUTE))
        )

    def test_audit_record_now_carries_the_run_fields(self, tmp_path: Path) -> None:
        """The field that did not exist. Inverse of the old assertion."""
        audit_path = tmp_path / "detour.jsonl"
        _run(DETOUR_ROUTE, audit_path, "sess-detour", policy=self._budget_policy())
        records = _audit_records(audit_path, "sess-detour")

        assert records
        last = records[-1]
        assert last["run_call_count"] == len(DETOUR_ROUTE)
        assert last["run_baseline_calls"] == len(DIRECT_ROUTE)
        assert last["run_amplification_ratio"] == 3.0

    def test_the_check_fires_on_the_detour(self, tmp_path: Path) -> None:
        """2c: detectable, not merely visible. The run is refused mid-detour."""
        audit_path = tmp_path / "detour.jsonl"
        results = _run_all(DETOUR_ROUTE, audit_path, "sess-detour", policy=self._budget_policy())

        blocked = [r for r in results if isinstance(r, dict)]
        assert blocked, "the detour ran to completion without tripping the budget"
        assert blocked[0]["block_reason"] == "amplification_exceeded"
        assert "amplification" in blocked[0]["error"]

    def test_the_direct_route_is_not_flagged(self, tmp_path: Path) -> None:
        """The control. A budget that also refuses the legitimate route is useless."""
        audit_path = tmp_path / "direct.jsonl"
        results = _run_all(DIRECT_ROUTE, audit_path, "sess-direct", policy=self._budget_policy())

        assert all(not isinstance(r, dict) for r in results), "the direct route was blocked"
        records = _audit_records(audit_path, "sess-direct")
        assert records[-1]["run_amplification_ratio"] == 1.0
        assert records[-1]["amplification_verdict"] == "ok"

    def test_a_budget_with_no_threshold_blocks(self) -> None:
        """Deny-by-default: opting in without a threshold must not be a silent no-op.

        This is issue #142's own failure mode — a field nobody reads — applied to the fix
        itself. An operator who enables amplification checking and configures nothing has
        expressed an intent the configuration cannot satisfy.
        """
        policy = SecurityPolicy(amplification_budget=AmplificationBudget())

        @Airlock(policy=policy)
        def anything() -> str:
            return "ran"

        result = anything()
        assert isinstance(result, dict)
        assert result["metadata"]["amplification_verdict"] == "unconfigured"

    def test_warn_action_records_without_blocking(self, tmp_path: Path) -> None:
        """The baseline-establishing mode: get the numbers before enforcing them."""
        audit_path = tmp_path / "warn.jsonl"
        policy = SecurityPolicy(
            amplification_budget=AmplificationBudget(
                baseline_calls_per_run=len(DIRECT_ROUTE),
                max_amplification_ratio=1.5,
                action="warn",
            )
        )
        results = _run_all(DETOUR_ROUTE, audit_path, "sess-warn", policy=policy)

        assert all(not isinstance(r, dict) for r in results), "warn mode blocked a call"
        records = _audit_records(audit_path, "sess-warn")
        assert records[-1]["amplification_verdict"] == "over_budget"

    def test_no_budget_leaves_the_record_byte_identical(self, tmp_path: Path) -> None:
        """Opt-in means opt-in. A v0.8.73 policy produces a v0.8.73 record."""
        audit_path = tmp_path / "nobudget.jsonl"
        _run(DETOUR_ROUTE, audit_path, "sess-detour")
        records = _audit_records(audit_path, "sess-detour")

        leaked = {k for r in records for k in r if k.startswith("run_") or "amplification" in k}
        assert leaked == set(), f"amplification fields leaked without a budget: {leaked}"

    def test_tokens_are_carried_but_never_estimated(self, tmp_path: Path) -> None:
        """`run_input_tokens` reflects what the caller supplied, and nothing more."""
        audit_path = tmp_path / "tokens.jsonl"
        config = AirlockConfig(enable_audit_log=True, audit_log_path=audit_path)
        policy = SecurityPolicy(
            amplification_budget=AmplificationBudget(max_calls_per_run=10),
        )

        @Airlock(config=config, policy=policy)
        def summarize_text(_wrapper: _Wrapper) -> str:
            return EXPECTED_ANSWER

        wrapper = _Wrapper(context=_Session(session_id="sess-tok"))
        summarize_text(wrapper, _airlock_input_tokens=1200)
        summarize_text(wrapper, _airlock_input_tokens=800)

        records = _audit_records(audit_path, "sess-tok")
        assert records[-1]["run_input_tokens"] == 2000, "token counts did not accumulate"

    def test_duration_is_still_per_call_and_never_summed(self, tmp_path: Path) -> None:
        """Unchanged and still true: `duration_ms` cannot reconstruct the wall-time figure.

        Kept from the original class. Adding call accounting did not turn `duration_ms`
        into an end-to-end timer, and nothing here should imply otherwise — it excludes
        model latency, which is where a detour spends most of what it wastes.
        """
        audit_path = tmp_path / "detour.jsonl"
        _run(DETOUR_ROUTE, audit_path, "sess-detour")
        records = _audit_records(audit_path, "sess-detour")

        assert all("duration_ms" in record for record in records)
        assert not any("total" in key or "elapsed" in key for record in records for key in record)

    def test_the_anomaly_detector_still_does_not_fire(self) -> None:
        """The detour remains invisible to `AnomalyDetector`, and that is still correct.

        The amplification budget is a *separate* control, not a fifth `AnomalyType`. This
        assertion stays so the boundary is explicit: closing #142 did not widen the
        detector's remit, it added the control the detector was never meant to be.
        """
        detector = AnomalyDetector(AnomalyDetectorConfig())
        events = [
            detector.record_call(tool_name=name, session_id="sess-detour") for name in DETOUR_ROUTE
        ]
        assert not any(events)


class TestSequenceGuardCatchesTheDeclaredRoute:
    """What already works, and what it costs the operator.

    `SequenceGuard` in DECLARED mode is the one control in the layer that does refuse a
    detour today, because a detour is by definition a transition outside the expected route.
    The price is that the operator must write the route down first, and the paper's premise
    is that a skill-based agent's legitimate route is not known in advance.
    """

    def _declared_guard(self) -> SequenceGuard:
        return SequenceGuard(
            mode="declared",
            action="block",
            dag={
                ENTRY_SENTINEL: {"fetch_document"},
                "fetch_document": {"summarize_text"},
                "summarize_text": set(),
            },
        )

    def test_direct_route_passes(self) -> None:
        guard = self._declared_guard()
        for name in DIRECT_ROUTE:
            guard.record_and_check(session_key="sess-direct", tool_name=name, args=(), kwargs={})

    def test_detour_is_blocked_at_the_coordinator(self) -> None:
        """The block lands on the coordinator, the first step off the declared route."""
        guard = self._declared_guard()
        guard.record_and_check(
            session_key="sess-detour", tool_name="fetch_document", args=(), kwargs={}
        )
        with pytest.raises(SequenceViolation) as excinfo:
            guard.record_and_check(
                session_key="sess-detour",
                tool_name="resolve_skill_dependencies",
                args=(),
                kwargs={},
            )
        assert "resolve_skill_dependencies" in str(excinfo.value)

    def test_declared_mode_requires_knowing_the_route_in_advance(self) -> None:
        """Declaring the detour's own tools as legitimate makes the guard admit it.

        Stated plainly because it bounds the mitigation: DECLARED mode enforces a route the
        operator supplies, so it cannot help where the legitimate route is discovered at
        runtime, which is the setting CDH targets.
        """
        permissive = SequenceGuard(
            mode="declared",
            action="block",
            dag={
                ENTRY_SENTINEL: {"fetch_document"},
                "fetch_document": {"resolve_skill_dependencies", "summarize_text"},
                "resolve_skill_dependencies": {"detect_document_encoding"},
                "detect_document_encoding": {"normalize_whitespace"},
                "normalize_whitespace": {"estimate_reading_time"},
                "estimate_reading_time": {"summarize_text"},
                "summarize_text": set(),
            },
        )
        for name in DETOUR_ROUTE:
            permissive.record_and_check(
                session_key="sess-detour", tool_name=name, args=(), kwargs={}
            )
