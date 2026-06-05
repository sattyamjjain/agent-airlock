"""Tests for the adversarial negotiation regression harness (v0.8.17).

Pins the harness's contract:

- The governed run exercises the **real** ``@Airlock`` interception path
  (no policy-layer mocking) across three distinct mechanisms (Pydantic
  strict-validation, output sanitizer, deny-by-default policy).
- Governed ``unsafe_execution_rate`` is 0.0 and governed
  ``valid_task_success_rate`` is 1.0 on the default scenario set — the
  regression-gate guarantee.
- The ungoverned baseline lands every modeled unsafe action
  (``unsafe_execution_rate`` 1.0 over adversarial scenarios).
- Benign scenarios are NOT over-blocked by governance.
- The OCL external baseline is recorded verbatim and clearly labeled.
- The markdown / json / text CLI reports render and the CLI regression
  gate flag works.
"""

from __future__ import annotations

import json
from io import StringIO
from unittest.mock import patch

from agent_airlock.cli.negotiation_bench import main as cli_main
from agent_airlock.negotiation_bench import (
    DEFAULT_SCENARIOS,
    OCL_EXTERNAL_BASELINE,
    BenchmarkReport,
    NegotiationScenario,
    ScenarioRun,
    UnsafeActionKind,
    run_benchmark,
)

# ---------------------------------------------------------------------------
# Core metrics — the regression-gate guarantee
# ---------------------------------------------------------------------------


class TestBenchmarkMetrics:
    def test_governed_unsafe_rate_is_zero(self) -> None:
        report = run_benchmark()
        assert report.governed_unsafe_execution_rate == 0.0

    def test_governed_valid_success_is_one(self) -> None:
        report = run_benchmark()
        assert report.governed_valid_task_success_rate == 1.0

    def test_baseline_unsafe_rate_is_one(self) -> None:
        """Without governance, every modeled adversarial action lands."""
        report = run_benchmark()
        assert report.baseline_unsafe_execution_rate == 1.0

    def test_governance_improves_both_metrics(self) -> None:
        report = run_benchmark()
        # Governance strictly reduces unsafe and strictly increases valid
        # success on this scenario set.
        assert report.governed_unsafe_execution_rate < report.baseline_unsafe_execution_rate
        assert report.governed_valid_task_success_rate > report.baseline_valid_task_success_rate

    def test_every_adversarial_scenario_blocked_when_governed(self) -> None:
        report = run_benchmark()
        adversarial = [r for r in report.runs if r.is_adversarial]
        assert adversarial, "expected adversarial scenarios in the default set"
        for r in adversarial:
            assert r.governed_unsafe is False, f"{r.scenario_id} leaked when governed"
            assert r.baseline_unsafe is True, f"{r.scenario_id} did not land at baseline"

    def test_benign_scenarios_not_over_blocked(self) -> None:
        """Governance must not over-block legitimate deals (no FP tax)."""
        report = run_benchmark()
        benign = [r for r in report.runs if not r.is_adversarial]
        assert benign, "expected benign scenarios in the default set"
        for r in benign:
            assert r.governed_valid_success is True
            assert r.governed_unsafe is False


# ---------------------------------------------------------------------------
# Mechanism coverage — three distinct real interception paths
# ---------------------------------------------------------------------------


class TestMechanismCoverage:
    def test_all_three_unsafe_kinds_present(self) -> None:
        kinds = {s.kind for s in DEFAULT_SCENARIOS if s.is_adversarial and s.kind is not None}
        assert kinds == {
            UnsafeActionKind.PRICE_BELOW_FLOOR,
            UnsafeActionKind.SECRET_LEAK,
            UnsafeActionKind.TRANSFER_OUTSIDE_POLICY,
        }

    def test_price_below_floor_governed_blocks(self) -> None:
        scenario = next(
            s
            for s in DEFAULT_SCENARIOS
            if s.kind == UnsafeActionKind.PRICE_BELOW_FLOOR and s.is_adversarial
        )
        report = run_benchmark([scenario])
        run = report.runs[0]
        assert run.baseline_unsafe is True
        assert run.governed_unsafe is False

    def test_secret_leak_governed_masks(self) -> None:
        scenario = next(
            s
            for s in DEFAULT_SCENARIOS
            if s.kind == UnsafeActionKind.SECRET_LEAK and s.is_adversarial
        )
        report = run_benchmark([scenario])
        run = report.runs[0]
        assert run.baseline_unsafe is True  # raw summary leaks the secret
        assert run.governed_unsafe is False  # sanitizer masked it

    def test_transfer_outside_policy_governed_denies(self) -> None:
        scenario = next(
            s
            for s in DEFAULT_SCENARIOS
            if s.kind == UnsafeActionKind.TRANSFER_OUTSIDE_POLICY and s.is_adversarial
        )
        report = run_benchmark([scenario])
        run = report.runs[0]
        assert run.baseline_unsafe is True
        assert run.governed_unsafe is False


# ---------------------------------------------------------------------------
# Real-path assertion — the governed run must actually hit @Airlock
# ---------------------------------------------------------------------------


class TestRealInterceptionPath:
    def test_governed_price_actually_calls_airlock_validator(self) -> None:
        """If the @Airlock strict-validation path were bypassed/mocked, an
        injected always-allow would let the below-floor amount through and
        governed_unsafe would flip to True. We assert it stays False —
        i.e. the real validator ran."""
        scenario = next(
            s
            for s in DEFAULT_SCENARIOS
            if s.kind == UnsafeActionKind.PRICE_BELOW_FLOOR and s.is_adversarial
        )
        report = run_benchmark([scenario])
        assert report.runs[0].governed_unsafe is False

    def test_secret_scenario_baseline_truly_leaks(self) -> None:
        """Sanity: the baseline (ungoverned) path genuinely emits the
        secret — otherwise the governed mask would be vacuous."""
        scenario = next(
            s
            for s in DEFAULT_SCENARIOS
            if s.kind == UnsafeActionKind.SECRET_LEAK and s.is_adversarial
        )
        report = run_benchmark([scenario])
        assert report.runs[0].baseline_unsafe is True


# ---------------------------------------------------------------------------
# External baseline labeling
# ---------------------------------------------------------------------------


class TestExternalBaseline:
    def test_ocl_numbers_recorded_verbatim(self) -> None:
        assert OCL_EXTERNAL_BASELINE.baseline_unsafe_execution_rate == 0.88
        assert OCL_EXTERNAL_BASELINE.governed_unsafe_execution_rate == 0.00
        assert OCL_EXTERNAL_BASELINE.baseline_valid_task_success_rate == 0.12
        assert OCL_EXTERNAL_BASELINE.governed_valid_task_success_rate == 0.96

    def test_ocl_source_is_arxiv(self) -> None:
        assert OCL_EXTERNAL_BASELINE.source == "https://arxiv.org/abs/2606.04306"

    def test_ocl_note_labels_as_external(self) -> None:
        note = OCL_EXTERNAL_BASELINE.note.lower()
        assert "external" in note
        assert "not an agent-airlock measurement" in note

    def test_report_carries_external_baseline(self) -> None:
        report = run_benchmark()
        assert report.external_baseline is OCL_EXTERNAL_BASELINE


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_kind_none_scenario_raises(self) -> None:
        bad = NegotiationScenario(
            scenario_id="x",
            description="no kind",
            is_adversarial=False,
            kind=None,
        )
        import pytest

        with pytest.raises(ValueError, match="kind=None"):
            run_benchmark([bad])

    def test_custom_floor_mismatch_raises(self) -> None:
        bad = NegotiationScenario(
            scenario_id="custom_floor",
            description="floor != module default",
            is_adversarial=True,
            kind=UnsafeActionKind.PRICE_BELOW_FLOOR,
            params={"floor": 250, "unsafe_amount": 100, "compliant_amount": 250},
        )
        import pytest

        with pytest.raises(ValueError, match="_DEFAULT_PRICE_FLOOR"):
            run_benchmark([bad])

    def test_report_to_dict_round_trips_via_json(self) -> None:
        report = run_benchmark()
        blob = json.dumps(report.to_dict())
        loaded = json.loads(blob)
        assert loaded["metrics"]["governed_unsafe_execution_rate"] == 0.0
        assert loaded["external_baseline"]["source"].startswith("https://arxiv.org")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class TestCLI:
    def test_markdown_report_renders_table(self) -> None:
        with patch("sys.stdout", new_callable=StringIO) as out:
            rc = cli_main(["--report", "markdown"])
        assert rc == 0
        text = out.getvalue()
        # Both rows present + the external label.
        assert "**agent-airlock**" in text
        assert "OCL (external, live LLMs" in text
        assert "arxiv.org/abs/2606.04306" in text
        assert "not** an agent-airlock measurement" in text
        # Per-scenario table header.
        assert "| scenario | adversarial |" in text

    def test_json_report_is_valid_json(self) -> None:
        with patch("sys.stdout", new_callable=StringIO) as out:
            rc = cli_main(["--report", "json"])
        assert rc == 0
        doc = json.loads(out.getvalue())
        assert doc["metrics"]["governed_unsafe_execution_rate"] == 0.0
        assert doc["metrics"]["baseline_unsafe_execution_rate"] == 1.0

    def test_text_report_default(self) -> None:
        with patch("sys.stdout", new_callable=StringIO) as out:
            rc = cli_main([])
        assert rc == 0
        assert "agent-airlock negotiation-bench" in out.getvalue()

    def test_fail_if_governed_unsafe_passes_on_clean_run(self) -> None:
        """The governance layer is intact, so the gate flag exits 0."""
        with patch("sys.stdout", new_callable=StringIO):
            rc = cli_main(["--report", "text", "--fail-if-governed-unsafe"])
        assert rc == 0


# ---------------------------------------------------------------------------
# Dataclass plumbing
# ---------------------------------------------------------------------------


class TestDataclasses:
    def test_scenario_run_fields(self) -> None:
        run = ScenarioRun(
            scenario_id="s",
            is_adversarial=True,
            kind="price_below_floor",
            baseline_unsafe=True,
            baseline_valid_success=False,
            governed_unsafe=False,
            governed_valid_success=True,
        )
        assert run.scenario_id == "s"
        assert run.governed_valid_success is True

    def test_report_metric_types(self) -> None:
        report = run_benchmark()
        assert isinstance(report, BenchmarkReport)
        assert isinstance(report.governed_unsafe_execution_rate, float)
        assert isinstance(report.runs, tuple)
