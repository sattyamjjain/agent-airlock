"""The injection benchmark must know its own power, and the doc must quote it correctly.

`docs/benchmarks/injection-multi-harness.md` publishes a null — 0 acted events, n = 6 per
harness per arm — together with the 95% Wilson intervals that make the null readable. Those
figures started life as hand arithmetic in a write-up, which is exactly the shape of claim
this repo already gates by machine elsewhere: `check_benchmark_freshness.py` for the dates,
`test_numeric_claim_parity.py` for the counts.

So the interval arithmetic lives in `benchmarks/harness_injection/power.py`, and the tests
below assert that the numbers *printed in the doc* are the numbers the code produces. Edit
one without the other and this fails.

The first class is the load-bearing one: a power table that overstated what a run can
conclude would turn "we bounded it at 10%" into a claim nobody measured.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from benchmarks.harness_injection.power import (
    AIRLOCK_MODES,
    Z_95,
    describe,
    fisher_exact_two_sided,
    power_table,
    probability_of_observing_zero,
    rule_of_three_upper_bound,
    trials_for_upper_bound,
    wilson_interval,
    wilson_upper_bound_for_zero,
)

_DOC = Path(__file__).resolve().parents[1] / "docs" / "benchmarks" / "injection-multi-harness.md"

#: (n, the percentage the doc publishes for it) — every zero-event bound the doc prints.
#: Updated for the 2026-08-26 run: the n=24 "all cells" row went away when the matrix stopped
#: being all-zero, and n=36 / n=72 arrived as the bounds that run actually licenses.
_PUBLISHED_INTERVALS = [
    (6, "39.0%"),
    (12, "24.3%"),
    (20, "16.1%"),
    (36, "9.6%"),
    (72, "5.1%"),
    (74, "4.9%"),
]


class TestTheTableNeverOverstatesItsPower:
    """A bound that is looser than advertised is the one error that matters here."""

    def test_the_returned_n_actually_achieves_the_target(self) -> None:
        for target in (0.5, 0.25, 0.10, 0.05, 0.01):
            n = trials_for_upper_bound(target)
            assert wilson_upper_bound_for_zero(n) <= target, target

    def test_the_returned_n_is_the_smallest_one_that_does(self) -> None:
        """Off-by-one in the safe direction is still wrong — it overstates the cost."""
        for target in (0.5, 0.25, 0.10, 0.05, 0.01):
            n = trials_for_upper_bound(target)
            assert wilson_upper_bound_for_zero(n - 1) > target, target

    def test_a_bigger_sample_never_gives_a_wider_bound(self) -> None:
        bounds = [wilson_upper_bound_for_zero(n) for n in range(1, 200)]
        assert bounds == sorted(bounds, reverse=True)


class TestPublishedFiguresReproduce:
    """The doc's intervals must come out of this code, not out of someone's calculator."""

    @pytest.mark.parametrize(("n", "published"), _PUBLISHED_INTERVALS)
    def test_each_published_wilson_bound_is_reproducible(self, n: int, published: str) -> None:
        assert f"{wilson_upper_bound_for_zero(n) * 100:.1f}%" == published

    @pytest.mark.parametrize(("n", "published"), _PUBLISHED_INTERVALS)
    def test_each_published_bound_appears_in_the_doc(self, n: int, published: str) -> None:
        assert published in _DOC.read_text(encoding="utf-8")

    def test_the_published_rule_of_three_column_reproduces(self) -> None:
        assert f"{rule_of_three_upper_bound(6) * 100:.1f}%" == "50.0%"
        assert f"{rule_of_three_upper_bound(12) * 100:.1f}%" == "25.0%"
        assert f"{rule_of_three_upper_bound(24) * 100:.1f}%" == "12.5%"

    def test_z_is_the_value_the_doc_was_computed_with(self) -> None:
        """The exact quantile shifts the n=12 row; pinning z keeps code and doc in step."""
        assert Z_95 == 1.96

    def test_the_ten_percent_answer_the_doc_states_is_the_computed_one(self) -> None:
        needed = trials_for_upper_bound(0.10)
        assert needed == 35
        doc = _DOC.read_text(encoding="utf-8")
        assert "n = 35" in doc
        # …and the --trials value that reaches it, since that is what an operator types.
        assert f"--trials {-(-needed // AIRLOCK_MODES)}" in doc


class TestTheMathItself:
    def test_wilson_matches_the_closed_form_for_zero_events(self) -> None:
        for n in (1, 6, 12, 37, 500):
            assert wilson_upper_bound_for_zero(n) == pytest.approx(Z_95**2 / (n + Z_95**2))

    def test_rule_of_three_is_optimistic_at_small_n_and_converges(self) -> None:
        assert rule_of_three_upper_bound(6) > wilson_upper_bound_for_zero(6)
        assert rule_of_three_upper_bound(200) < wilson_upper_bound_for_zero(200)

    def test_rule_of_three_is_capped_at_one(self) -> None:
        assert rule_of_three_upper_bound(1) == 1.0
        assert rule_of_three_upper_bound(2) == 1.0

    def test_probability_of_a_zero_falls_as_the_sample_grows(self) -> None:
        assert probability_of_observing_zero(0.05, 6) == pytest.approx(0.7351, abs=1e-4)
        assert probability_of_observing_zero(0.05, 36) == pytest.approx(0.1577, abs=1e-4)

    def test_a_true_rate_of_zero_always_yields_a_zero(self) -> None:
        assert probability_of_observing_zero(0.0, 1000) == 1.0

    def test_a_true_rate_of_one_never_does(self) -> None:
        assert probability_of_observing_zero(1.0, 1) == 0.0

    def test_invalid_inputs_raise_rather_than_returning_a_misleading_number(self) -> None:
        with pytest.raises(ValueError):
            wilson_upper_bound_for_zero(0)
        with pytest.raises(ValueError):
            rule_of_three_upper_bound(-1)
        with pytest.raises(ValueError):
            trials_for_upper_bound(0)
        with pytest.raises(ValueError):
            trials_for_upper_bound(1.5)
        with pytest.raises(ValueError):
            probability_of_observing_zero(1.5, 10)


class TestPowerTable:
    def test_a_trials_step_buys_two_observations_because_of_the_airlock_modes(self) -> None:
        row = power_table([7])[0]
        assert row.n_per_cell == 7 * AIRLOCK_MODES == 14

    def test_the_cell_count_matches_the_published_matrix(self) -> None:
        """2 harnesses x 2 arms x 2 modes x 3 trials = the 24 cells the doc reports."""
        assert power_table([3], harnesses=2, arms=2)[0].total_cells == 24

    def test_the_published_run_row_is_the_one_the_doc_describes(self) -> None:
        row = power_table([3])[0]
        wilson, rule_of_three, _miss = row.as_percent()
        assert (row.n_per_cell, wilson, rule_of_three) == (6, "39.0%", "50.0%")

    def test_describe_names_the_ten_percent_target(self) -> None:
        text = describe(3)
        assert "n = 35" in text
        assert "--trials 18" in text

    def test_describe_reports_the_miss_rate_not_only_the_bound(self) -> None:
        """ "How high could it be" and "would I have noticed" are different questions."""
        assert re.search(r"true rate were 5%.*\d+% of the time", describe(3))


class TestTheRunnerExposesTrials:
    """`--trials` has to reach the matrix, or the power table describes a run nobody can ask for."""

    def test_the_cli_accepts_trials_and_threads_it_into_the_report(self) -> None:
        from benchmarks.harness_injection.runner import RunReport

        assert RunReport(trials=18).trials == 18

    def test_the_dry_run_prints_the_power_for_the_requested_trials(self, capsys) -> None:
        from benchmarks.harness_injection.__main__ import main

        assert main(["--trials", "18"]) == 0
        out = capsys.readouterr().out
        assert "Power at --trials 18" in out
        assert "9.6%" in out


class TestGeneralWilsonInterval:
    """The 2026-08-26 run put a non-zero count in the results table for the first time."""

    @pytest.mark.parametrize("n", [6, 12, 24, 36, 72, 144])
    def test_it_reproduces_the_zero_event_closed_form(self, n: int) -> None:
        """Two derivations of the same quantity must agree, or one of them is wrong."""
        lower, upper = wilson_interval(0, n)
        assert lower == 0.0
        assert upper == pytest.approx(wilson_upper_bound_for_zero(n), abs=1e-12)

    def test_the_published_codex_benign_interval(self) -> None:
        lower, upper = wilson_interval(1, 36)
        assert (f"{lower * 100:.1f}%", f"{upper * 100:.1f}%") == ("0.5%", "14.2%")

    def test_a_non_zero_count_has_a_lower_bound_above_zero(self) -> None:
        """An observed event means the rate is not zero, and the interval must say so."""
        assert wilson_interval(1, 36)[0] > 0.0

    @pytest.mark.parametrize("bad", [(-1, 10), (11, 10), (0, 0), (0, -5)])
    def test_it_rejects_impossible_inputs(self, bad: tuple[int, int]) -> None:
        with pytest.raises(ValueError):
            wilson_interval(*bad)


class TestFisherExactTwoSided:
    """One event across two equal arms is not evidence of a difference between them."""

    def test_the_published_codex_asymmetry_is_not_significant(self) -> None:
        """benign 1/36 vs injected 0/36 — the table looks asymmetric, the data does not."""
        assert fisher_exact_two_sided(1, 35, 0, 36) == pytest.approx(1.0)

    def test_the_pooled_asymmetry_is_not_significant_either(self) -> None:
        assert fisher_exact_two_sided(1, 71, 0, 72) == pytest.approx(1.0)

    def test_a_real_separation_does_reach_significance(self) -> None:
        """Guard against a function that just always returns 1.0."""
        assert fisher_exact_two_sided(30, 6, 2, 34) < 0.001

    def test_it_is_symmetric_in_the_rows(self) -> None:
        assert fisher_exact_two_sided(1, 35, 0, 36) == pytest.approx(
            fisher_exact_two_sided(0, 36, 1, 35)
        )

    def test_p_is_a_probability(self) -> None:
        for table in ((1, 35, 0, 36), (5, 31, 2, 34), (0, 10, 0, 10)):
            assert 0.0 <= fisher_exact_two_sided(*table) <= 1.0

    @pytest.mark.parametrize("bad", [(-1, 1, 1, 1), (0, 0, 0, 0)])
    def test_it_rejects_impossible_tables(self, bad: tuple[int, int, int, int]) -> None:
        with pytest.raises(ValueError):
            fisher_exact_two_sided(*bad)


class TestTheLiveControlIntervalIsPublishedAndReproducible:
    """The 1/36 benign row is the doc's first non-zero interval; gate it like the others."""

    def test_the_bounds_come_out_of_the_code(self) -> None:
        lower, upper = wilson_interval(1, 36)
        assert (f"{lower * 100:.1f}%", f"{upper * 100:.1f}%") == ("0.5%", "14.2%")

    def test_they_appear_in_the_doc(self) -> None:
        text = _DOC.read_text(encoding="utf-8")
        assert "[0.5%, 14.2%]" in text

    def test_the_doc_states_the_asymmetry_is_not_significant(self) -> None:
        """A lopsided table published without its p-value is the thing to prevent."""
        assert "p = 1.00" in _DOC.read_text(encoding="utf-8")
