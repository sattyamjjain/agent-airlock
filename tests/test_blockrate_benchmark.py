"""Smoke + invariants for the cross-tool block-rate comparison benchmark.

Keeps the published comparison honest and reproducible:
- the corpus is non-empty and carries both malicious and benign items;
- agent-airlock blocks every malicious item and zero benign ones on this
  self-curated corpus (the documented baseline — not an adaptive-attacker score);
- the incumbents are represented as scope-claimed, NOT re-run (no fabricated
  competitor number ever enters the table);
- the BENCHMARK.md comparison section renders deterministically (so the
  generate_benchmark.py --check drift gate stays stable).
"""

from __future__ import annotations

from benchmarks.blockrate import (
    COMPETITORS,
    load_corpus,
    render_comparison_section,
    run_blockrate,
)


class TestCorpus:
    def test_corpus_has_both_classes(self) -> None:
        corpus = load_corpus()
        assert len(corpus) > 20
        assert any(c.expected_block for c in corpus), "needs malicious items"
        assert any(not c.expected_block for c in corpus), "needs benign controls"

    def test_categories_present(self) -> None:
        cats = {c.category for c in load_corpus()}
        assert {"over_privileged_selection", "argument_injection", "benign"} <= cats


class TestBlockRate:
    def test_blocks_all_malicious_no_false_positives(self) -> None:
        report = run_blockrate(measure_latency=False)
        assert report.overall_block_rate == 1.0, "every malicious item must block"
        assert report.overall_fp_rate == 0.0, "no benign item may block"

    def test_per_category_precision(self) -> None:
        report = run_blockrate(measure_latency=False)
        for stats in report.by_category.values():
            if stats.malicious_total:
                assert stats.block_rate == 1.0
            assert stats.benign_blocked == 0


class TestIncumbentsNotReRun:
    def test_competitors_are_scope_claimed_not_re_run(self) -> None:
        assert COMPETITORS, "the comparison must name the incumbents"
        for comp in COMPETITORS:
            assert comp.re_run is False, f"{comp.name} must NOT carry a re-run number"
            assert comp.source.startswith("https://"), "each claim must cite a source"

    def test_section_marks_competitors_not_re_run(self) -> None:
        section = render_comparison_section(run_blockrate(measure_latency=False))
        assert "scope-claimed, not re-run" in section
        for comp in COMPETITORS:
            assert comp.name in section
        # No fabricated competitor percentage: the only percentages belong to
        # agent-airlock rows; competitor cells carry the italic caveat instead.
        assert "Meta LlamaFirewall** | model-in-the-loop" in section


class TestDeterministicRender:
    def test_comparison_section_is_stable(self) -> None:
        # Two independent runs must render byte-identical (no latency, no clock)
        # — this is what lets it live in the drift-gated BENCHMARK.md.
        a = render_comparison_section(run_blockrate(measure_latency=False))
        b = render_comparison_section(run_blockrate(measure_latency=False))
        assert a == b
