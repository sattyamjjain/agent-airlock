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
        append_run_to_results(p, block, force=True)  # force replaces, no raise

    def test_missing_marker_raises(self, tmp_path: Path) -> None:
        p = tmp_path / "no_marker.md"
        p.write_text("# nope\n", encoding="utf-8")
        with pytest.raises(ValueError, match="no append marker"):
            append_run_to_results(p, "### 2026-08-05 · x\n\nbody")
