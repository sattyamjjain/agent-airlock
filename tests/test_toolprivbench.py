"""End-to-end smoke test for the ToolPrivBench-style least-privilege benchmark.

Asserts the harness runs over the fixture set and that deny-by-default
mechanically blocks the over-privileged tool while allowing the low-privilege
one — including under the transient-failure amplifier.
"""

from __future__ import annotations

from benchmarks.toolprivbench import (
    DOMAINS,
    RISK_PATTERNS,
    load_scenarios,
    run_benchmark,
    run_scenario,
)
from benchmarks.toolprivbench.report import render_results_md
from benchmarks.toolprivbench.scenarios import subset_scenarios


class TestScenarioSet:
    def test_subset_covers_all_patterns_and_domains(self) -> None:
        scenarios = subset_scenarios()
        assert len(scenarios) == 20 * len(RISK_PATTERNS)
        assert {s.risk_pattern for s in scenarios} == set(RISK_PATTERNS)
        assert {s.domain for s in scenarios} == set(DOMAINS)

    def test_every_scenario_maps_to_an_owasp_id(self) -> None:
        for s in subset_scenarios():
            assert s.owasp_id == RISK_PATTERNS[s.risk_pattern]

    def test_load_scenarios_falls_back_to_subset(self) -> None:
        scenarios, source = load_scenarios()
        # No official dataset vendored → subset harness.
        assert source == "subset"
        assert len(scenarios) == 100

    def test_subset_is_deterministic(self) -> None:
        assert [s.scenario_id for s in subset_scenarios()] == [
            s.scenario_id for s in subset_scenarios()
        ]


class TestHarnessBlocks:
    def test_each_scenario_blocks_overpriv_allows_lowpriv(self) -> None:
        for s in subset_scenarios():
            r = run_scenario(s)
            assert r.over_priv_blocked, f"over-priv not blocked: {s.scenario_id}"
            assert r.low_priv_allowed, f"low-priv wrongly blocked: {s.scenario_id}"
            assert r.over_priv_blocked_after_failure, (
                f"transient-failure re-run not blocked: {s.scenario_id}"
            )
            assert r.correct

    def test_benchmark_end_to_end(self) -> None:
        report = run_benchmark()
        assert report.total == 100
        # Deny-by-default mechanically blocks every over-privileged call ...
        assert report.overall_block_rate == 1.0
        assert report.overall_block_rate_after_failure == 1.0
        # ... while remaining precise (legitimate low-priv calls pass).
        assert report.overall_low_priv_allow_rate == 1.0

    def test_per_pattern_and_owasp_aggregation(self) -> None:
        report = run_benchmark()
        assert set(report.by_pattern) == set(RISK_PATTERNS)
        for stats in report.by_pattern.values():
            assert stats.total == 20
            assert stats.block_rate == 1.0
        # OWASP ids are the crosswalk targets.
        assert set(report.by_owasp) == set(RISK_PATTERNS.values())


class TestReportRender:
    def test_results_md_renders_with_headline_and_caveat(self) -> None:
        md = render_results_md(run_benchmark(), "2026-06-22")
        assert "least-privilege block-rate" in md
        assert "100.0%" in md
        assert "subset harness" in md
        assert "runtime BLOCK behaviour" in md
        assert "arxiv.org/abs/2606.20023" in md
        # every risk pattern appears in the table
        for pattern in RISK_PATTERNS:
            assert pattern in md
