"""Cross-model AgentDojo harness: rendering, cost accounting, append-only log.

These exercise the parts of ``benchmarks/agentdojo/run.py`` that need neither
``agentdojo`` nor an API key (the module imports with the bench extra absent),
so they run in the default gate. The paid model-in-the-loop execution is covered
by ``tests/benchmarks/test_agentdojo_smoke.py`` (skipped without the extra).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from benchmarks.agentdojo.run import (
    _RUNS_MARKER,
    ArmCounts,
    CostMeter,
    ModelRun,
    TaskSelection,
    append_run_to_results,
    render_cross_model_comparison,
)


def _run(model: str, undef_asr_k: int, air_asr_k: int, *, usd: float = 0.02) -> ModelRun:
    """One synthetic model run: 15 attacked trajectories/arm, benign held equal."""
    results = {
        "banking": {
            "undefended": ArmCounts(4, 5, 2, 15, undef_asr_k, 15),
            "airlock": ArmCounts(4, 5, 3, 15, air_asr_k, 15),
        }
    }
    cost = CostMeter()
    cost.record(prompt_tokens=1000, completion_tokens=200, usd=usd)
    return ModelRun(model, results, cost, "0.1.35", "2026-08-05", 5, 3)


class TestCostMeter:
    def test_unmeasured_says_so(self) -> None:
        assert "unmeasured" in CostMeter().summary()

    def test_accumulates_tokens_and_dollars(self) -> None:
        m = CostMeter()
        m.record(prompt_tokens=100, completion_tokens=50, usd=0.01)
        m.record(prompt_tokens=200, completion_tokens=10, usd=0.02)
        assert m.calls == 2
        assert m.total_tokens == 360
        assert round(m.usd, 4) == 0.03
        assert m.measured
        assert "$0.0300" in m.summary()

    def test_an_unpriced_call_reads_unmeasured_never_zero(self) -> None:
        """Until 0.10.25 an unpriced model's calls added $0 and the summary printed
        ``$0.0000`` as if measured. A call with no list price now makes the dollar figure
        read "unmeasured" and names the model."""
        m = CostMeter()
        m.record(prompt_tokens=1000, completion_tokens=100, usd=None, model="mystery-model-1")
        summary = m.summary()
        assert "unmeasured" in summary
        assert "mystery-model-1" in summary
        assert "$0.0000" not in summary

    def test_one_unpriced_call_poisons_the_total(self) -> None:
        m = CostMeter()
        m.record(prompt_tokens=10, completion_tokens=1, usd=0.5)
        m.record(prompt_tokens=10, completion_tokens=1, usd=None, model="mystery-model-1")
        assert "1 of 2 calls have no list price" in m.summary()
        assert "$0.5000" not in m.summary()

    def test_cache_tokens_are_counted_and_shown(self) -> None:
        m = CostMeter()
        m.record(
            prompt_tokens=100,
            completion_tokens=20,
            usd=0.001,
            cache_read_tokens=3000,
            cache_write_tokens=900,
        )
        assert m.total_tokens == 4020
        summary = m.summary()
        assert "3,000 cache read" in summary
        assert "900 cache write" in summary


class TestCrossModelRender:
    def test_per_model_rows_with_own_ci_and_cost(self) -> None:
        block = render_cross_model_comparison(
            [_run("gpt-4o-mini-2024-07-18", 9, 2, usd=0.0123)], 0.86
        )
        assert "gpt-4o-mini-2024-07-18" in block
        assert "95% CI" in block
        assert "$0.0123" in block  # cost is recorded, not omitted

    def test_pooled_is_labelled_not_a_single_measurement(self) -> None:
        block = render_cross_model_comparison([_run("m", 9, 2)], 0.86)
        assert "Pooled across models" in block
        assert "reported separately" in block
        assert "not** a single measurement" in block or "not a single measurement" in block

    def test_weaker_second_model_is_shown_not_hidden(self) -> None:
        # model A: 60% -> 13% (strong); model B: 60% -> 40% (weak). The spread
        # must appear so a smaller second-model reduction is published, not pooled away.
        block = render_cross_model_comparison([_run("strong", 9, 2), _run("weak", 9, 6)], 0.86)
        assert "ranges" in block  # per-model spread line present
        assert "+47%" in block and "+20%" in block  # both reductions shown verbatim

    def test_empty_runs_render_empty(self) -> None:
        assert render_cross_model_comparison([], 0.86) == ""

    def test_the_attack_is_named_as_a_fixed_template(self) -> None:
        block = render_cross_model_comparison([_run("m", 9, 2)], 0.86)
        assert "fixed template" in block
        assert "not an adaptive" in block

    def test_settings_and_call_outcomes_are_published(self) -> None:
        run = _run("claude-haiku-5-5", 9, 2)
        run.settings = {"effort": "medium", "thinking": "adaptive", "max_tokens": 16000}
        run.call_outcomes = {"ok": 40, "refusal": 2, "max_tokens": 1}
        block = render_cross_model_comparison([run], 0.86)
        assert "| `claude-haiku-5-5` | medium | adaptive | 16000 | 43 |" in block
        assert "max_tokens 1, refusal 2" in block

    def test_the_injection_selection_marks_untargeted_tasks(self) -> None:
        run = _run("m", 9, 2)
        run.selection = [
            TaskSelection(
                suite="travel",
                user_ids=["user_task_0", "user_task_1"],
                injection_ids=["injection_task_6", "injection_task_0"],
                untargeted=["injection_task_6"],
            )
        ]
        block = render_cross_model_comparison([run], 0.86)
        assert "travel `6*, 0` (2 user tasks)" in block


class TestAppendOnlyLog:
    def _seed(self, tmp_path: Path) -> Path:
        p = tmp_path / "RESULTS.md"
        p.write_text(
            "# AgentDojo\n\n## Result 2\n\n"
            f"{_RUNS_MARKER}\n\n"
            "### 2026-07-31 · gpt-4o-mini-2024-07-18\n\nASR 45% -> 10% (the frozen run).\n",
            encoding="utf-8",
        )
        return p

    def test_append_preserves_prior_run_and_prepends(self, tmp_path: Path) -> None:
        p = self._seed(tmp_path)
        new = render_cross_model_comparison([_run("claude-3-5-haiku-20241022", 9, 4)], 0.86)
        out = append_run_to_results(p, new)
        # the frozen 2026-07-31 numbers survive verbatim
        assert "ASR 45% -> 10% (the frozen run)." in out
        assert "### 2026-07-31 · gpt-4o-mini-2024-07-18" in out
        # the new run lands under the marker, ABOVE the older dated block
        assert out.index(_RUNS_MARKER) < out.index("claude-3-5-haiku-20241022")
        assert out.index("claude-3-5-haiku-20241022") < out.index("2026-07-31")

    def test_refuses_duplicate_heading_without_force(self, tmp_path: Path) -> None:
        p = self._seed(tmp_path)
        block = render_cross_model_comparison([_run("m", 9, 2)], 0.86)
        append_run_to_results(p, block)
        with pytest.raises(ValueError, match="already exists"):
            append_run_to_results(p, block)  # same date+models heading
        append_run_to_results(p, block, force=True)  # force appends a second block; keeps the first

    def test_missing_marker_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "no_marker.md"
        p.write_text("# nope\n", encoding="utf-8")
        with pytest.raises(ValueError, match="no append marker"):
            append_run_to_results(p, "### 2026-08-05 · x\n\nbody")


class TestEveryRegisterableModelIsPriced:
    """An unpriced model must never come back as a dollar figure that looks like a result.

    ``_price_usd`` returns ``None`` for an unpriced model (it returned ``0.0`` until
    0.10.25), and ``CostMeter`` then reads "unmeasured"; but a paid arm would still come
    back with no dollar figure, and the widening plan's whole point is a defensible cost
    per arm. Until 2026-09-12 three of the four ids
    ``model_registry_shim.DEFAULT_CURRENT_CLAUDE`` registered had no entry in
    ``_MODEL_PRICES``, and until 0.10.25 ``claude-haiku-5-5`` had none either.

    This gate fails the next time someone adds a model to the shim without
    pricing it, which is the ordering the benchmark's own README asks for:
    "List prices should be set before spending, not after."
    """

    def test_every_default_claude_id_is_priced(self) -> None:
        from benchmarks.agentdojo.model_registry_shim import DEFAULT_CURRENT_CLAUDE
        from benchmarks.agentdojo.run import _price_usd

        unpriced = [m for m in DEFAULT_CURRENT_CLAUDE if not _price_usd(m, 1_000_000, 0)]
        assert not unpriced, (
            f"model_registry_shim registers {unpriced} but _MODEL_PRICES has no entry, "
            "so a paid arm using them would record no dollar figure. Add the list price "
            "with its source and date before running, not after."
        )

    def test_an_unpriced_model_is_none_not_zero(self) -> None:
        from benchmarks.agentdojo.run import _price_usd

        assert _price_usd("some-lab/unpriced-model-x", 1_000_000, 1_000_000) is None
        assert _price_usd(None, 1_000_000, 0) is None

    @pytest.mark.parametrize(
        ("model_id", "input_rate", "output_rate"),
        [
            # Before 0.10.25 claude-opus-5-5 prefix-matched claude-opus-5 ($5/$25) and
            # claude-haiku-5-5 matched nothing and recorded $0.
            ("claude-opus-5-5", 4.00, 20.00),
            ("claude-sonnet-5-5", 2.00, 10.00),
            ("claude-haiku-5-5", 0.10, 0.50),
            ("claude-fable-5-1", 10.00, 50.00),
        ],
    )
    def test_the_5_5_and_5_1_ids_have_their_own_rates(
        self, model_id: str, input_rate: float, output_rate: float
    ) -> None:
        from benchmarks.agentdojo.run import _price_usd

        assert _price_usd(model_id, 1_000_000, 0) == pytest.approx(input_rate)
        assert _price_usd(model_id, 0, 1_000_000) == pytest.approx(output_rate)

    def test_the_table_agrees_with_the_dated_snapshot(self) -> None:
        """The exact-id rows must match the snapshot the shared ledger prices from."""
        from benchmarks._claude.pricing import rates_for
        from benchmarks.agentdojo.run import _MODEL_PRICES

        for model_id in ("claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5"):
            rates = rates_for(model_id)
            assert _MODEL_PRICES[model_id] == pytest.approx((rates.input, rates.output))
        assert _MODEL_PRICES["claude-fable-5-1"] == pytest.approx(
            (rates_for("claude-fable-5-1").input, rates_for("claude-fable-5-1").output)
        )

    def test_a_dated_snapshot_finds_its_family_by_longest_prefix(self) -> None:
        from benchmarks.agentdojo.run import _price_usd

        assert _price_usd("claude-haiku-4-5-20251001", 1_000_000, 0) == pytest.approx(1.00)

    def test_the_widening_plans_together_model_is_priced(self) -> None:
        """The third family named in benchmarks/agentdojo/RESULTS.md."""
        from benchmarks.agentdojo.run import _price_usd

        assert _price_usd("mistralai/Mixtral-8x7B-Instruct-v0.1", 1_000_000, 0) > 0.0

    def test_prefix_match_does_not_shadow_a_current_id(self) -> None:
        """``_price_usd`` returns on the first ``startswith`` hit, so order matters.

        A bare ``claude-opus`` key inserted above ``claude-opus-5`` would silently
        price Opus 5 at the older model's rate. Assert the rate actually resolved,
        not merely that something non-zero came back.
        """
        from benchmarks.agentdojo.run import _price_usd

        # 1M input tokens at the published $5/MTok base input rate.
        assert _price_usd("claude-opus-5", 1_000_000, 0) == pytest.approx(5.00)
        # 1M output tokens at $25/MTok.
        assert _price_usd("claude-opus-5", 0, 1_000_000) == pytest.approx(25.00)
        # Sonnet 5 must not pick up Sonnet 4.6's $3/$15.
        assert _price_usd("claude-sonnet-5", 1_000_000, 0) == pytest.approx(2.00)
