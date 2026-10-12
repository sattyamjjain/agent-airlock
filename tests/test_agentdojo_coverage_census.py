"""Result 1's bound is always shown beside the full pair census.

``524/609`` was published as if 609 were AgentDojo's whole v1.2.1 set. It is the subset
of pairs whose injection's ground truth names a tool call; the four suites define 949
attacked pairs, and for 340 of them (workspace ``injection_task_6``-``13``, travel
``injection_task_6``) the ground truth names no call the policy can check. The renderer
now always prints the denominator. The rendering and power-calculation checks run in the
default gate; the census itself needs ``agentdojo`` and skips without the ``[bench]`` extra.
"""

from __future__ import annotations

import pytest
from benchmarks.agentdojo.run import (
    DEFAULT_MAX_INJECTION_TASKS,
    DEFAULT_MAX_USER_TASKS,
    PINNED_SUITES,
    V121_ALL_PAIRS,
    V121_TARGET_PAIRS,
    DeterministicReport,
    SuiteCoverage,
    compact_task_ids,
    power_sample_size,
    render_coverage_census,
)

_WORKSPACE_UNTARGETED = [f"injection_task_{i}" for i in range(6, 14)]


def _published_report() -> DeterministicReport:
    """The published v1.2.1 numbers, as a report (no agentdojo needed)."""
    return DeterministicReport(
        suites=[
            SuiteCoverage(
                "workspace",
                pairs=240,
                blocked_pairs=222,
                all_pairs=560,
                untargeted_injections=list(_WORKSPACE_UNTARGETED),
            ),
            SuiteCoverage("banking", pairs=144, blocked_pairs=102, all_pairs=144),
            SuiteCoverage(
                "travel",
                pairs=120,
                blocked_pairs=114,
                all_pairs=140,
                untargeted_injections=["injection_task_6"],
            ),
            SuiteCoverage("slack", pairs=105, blocked_pairs=86, all_pairs=105),
        ]
    )


class TestCensusLine:
    def test_the_blocked_count_never_appears_without_the_full_denominator(self) -> None:
        line = render_coverage_census(_published_report())
        assert line == (
            "524/609 pairs blocked = 86.0%, out of 949 attacked pairs; 340 pairs have no "
            "tool-call target the policy can check (workspace injection_task_6-13; "
            "travel injection_task_6)"
        )

    def test_unreadable_ground_truth_is_listed_with_the_untargeted(self) -> None:
        report = DeterministicReport(
            suites=[
                SuiteCoverage(
                    "slack",
                    pairs=1,
                    blocked_pairs=1,
                    all_pairs=2,
                    unreadable_injections=["injection_task_9"],
                )
            ]
        )
        assert "slack injection_task_9" in render_coverage_census(report)

    @pytest.mark.parametrize(
        ("ids", "expected"),
        [
            (_WORKSPACE_UNTARGETED, "injection_task_6-13"),
            (["injection_task_6"], "injection_task_6"),
            (
                ["injection_task_2", "injection_task_0", "injection_task_3"],
                "injection_task_0, injection_task_2-3",
            ),
            (["odd_id"], "odd_id"),
            ([], ""),
        ],
    )
    def test_compact_task_ids(self, ids: list[str], expected: str) -> None:
        assert compact_task_ids(ids) == expected


class TestDefaultCaps:
    def test_the_default_caps_meet_the_power_calculation(self) -> None:
        """168 pairs per arm; the widening plan's 13 user tasks gave 156, short of 163."""
        needed = power_sample_size(0.45, 0.30)
        per_arm = DEFAULT_MAX_USER_TASKS * DEFAULT_MAX_INJECTION_TASKS * len(PINNED_SUITES)
        assert needed == 163
        assert per_arm == 168 >= needed
        assert 13 * DEFAULT_MAX_INJECTION_TASKS * len(PINNED_SUITES) < needed


@pytest.fixture(scope="module")
def real_report() -> DeterministicReport:
    pytest.importorskip("agentdojo", reason="agentdojo is a bench-only extra")
    from benchmarks.agentdojo.run import run_deterministic

    return run_deterministic()


class TestRealCensus:
    def test_the_v121_totals(self, real_report: DeterministicReport) -> None:
        assert real_report.total_all_pairs == V121_ALL_PAIRS == 949
        assert real_report.total_pairs == V121_TARGET_PAIRS == 609
        assert real_report.total_blocked_pairs == 524
        assert real_report.total_untargeted_pairs == 340

    def test_which_injections_name_no_tool_call(self, real_report: DeterministicReport) -> None:
        untargeted = {s.suite: s.untargeted_injections for s in real_report.suites}
        assert untargeted == {
            "workspace": _WORKSPACE_UNTARGETED,
            "banking": [],
            "travel": ["injection_task_6"],
            "slack": [],
        }
        assert all(not s.unreadable_injections for s in real_report.suites)

    def test_every_block_is_an_allow_list_refusal(self, real_report: DeterministicReport) -> None:
        """Ground-truth calls always match their schema, so ghost-argument BLOCK never fires
        in Result 1 (RESULTS.md claimed it did until 0.10.25)."""
        assert real_report.total_ghost_arg_blocks == 0

    def test_the_rendered_line_matches_the_published_one(
        self, real_report: DeterministicReport
    ) -> None:
        assert render_coverage_census(real_report) == render_coverage_census(_published_report())

    def test_the_default_model_pass_runs_168_pairs_per_arm(
        self, real_report: DeterministicReport
    ) -> None:
        from benchmarks.agentdojo.run import select_tasks

        selections = select_tasks(
            PINNED_SUITES, DEFAULT_MAX_USER_TASKS, DEFAULT_MAX_INJECTION_TASKS
        )
        assert sum(s.pairs for s in selections) == 168
        # travel's dict order puts injection_task_6 first: its 14 pairs have no target.
        assert {s.suite: s.untargeted for s in selections}["travel"] == ["injection_task_6"]
        assert sum(s.targeted_pairs for s in selections) == 154
