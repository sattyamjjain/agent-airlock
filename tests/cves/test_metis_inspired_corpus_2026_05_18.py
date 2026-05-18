"""Integration regression for the v0.8.2 Metis-inspired corpus.

This test loads the JSON corpus fixture, runs every entry through the
default agent-airlock guard chain (EvalRCEGuard + StdioCommandInjectionGuard),
and asserts that block rate has not regressed below baseline − 5%.

Honest framing
--------------
This is NOT the Metis attacker reproduction. Metis (arXiv:2605.10067)
is an adaptive POMDP attacker that targets a closed-loop LLM. Here
we exercise a fixed corpus of exploit-shape inputs against the
agent-airlock guard chain — the metric is **block rate** (inverse of
ASR), and the gate fires on downward drift.

Primary source
--------------
- Paper (motivation only): https://arxiv.org/abs/2605.10067
- CVE-2026-44717 (eval RCE class): https://nvd.nist.gov/vuln/detail/CVE-2026-44717
- HelpNetSecurity 2026-05-05 (MCP STDIO command injection):
  https://www.helpnetsecurity.com/2026/05/05/ai-agent-security-skills-blind-spots/
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_airlock.regression_corpus import (
    CorpusEntry,
    MetisInspiredCorpusBlockRateDecision,
    MetisInspiredCorpusBlockRateGuard,
    MetisInspiredCorpusBlockRateVerdict,
)

FIXTURE = Path(__file__).parent / "corpora" / "metis_inspired_corpus_2026_05_18.json"


def _load_corpus() -> tuple[list[CorpusEntry], float, float]:
    """Parse the JSON corpus fixture into typed entries + baseline/threshold."""
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
    entries = [
        CorpusEntry(
            prompt_id=e["prompt_id"],
            tool_name=e["tool_name"],
            args=e["args"],
            anchor=e["anchor"],
            expected_block=e["expected_block"],
        )
        for e in raw["entries"]
    ]
    return entries, float(raw["baseline_block_rate"]), float(raw["drift_threshold"])


class TestCorpusFixture:
    """The packaged JSON corpus loads cleanly and has the expected shape."""

    def test_corpus_loads(self) -> None:
        entries, baseline, threshold = _load_corpus()
        assert len(entries) >= 20, "corpus should have at least 20 entries"
        assert 0.0 <= baseline <= 1.0
        assert threshold > 0.0

    def test_every_entry_has_anchor(self) -> None:
        entries, _, _ = _load_corpus()
        for e in entries:
            assert e.anchor, f"entry {e.prompt_id} missing anchor"

    def test_every_entry_has_unique_prompt_id(self) -> None:
        entries, _, _ = _load_corpus()
        ids = [e.prompt_id for e in entries]
        assert len(ids) == len(set(ids)), "prompt_id values must be unique"

    def test_corpus_has_both_exploit_and_benign(self) -> None:
        """A useful regression corpus needs both positive and negative cases."""
        entries, _, _ = _load_corpus()
        exploit = [e for e in entries if e.expected_block]
        benign = [e for e in entries if not e.expected_block]
        assert exploit, "no exploit-shape entries — block rate would be trivially zero"
        assert benign, "no benign entries — can't detect false-positive drift"


class TestReleaseGate:
    """The release-gate assertion against the default guard chain."""

    def test_default_chain_meets_baseline_block_rate(self) -> None:
        entries, baseline, threshold = _load_corpus()
        guard = MetisInspiredCorpusBlockRateGuard(
            corpus=entries,
            baseline_block_rate=baseline,
            drift_threshold=threshold,
        )
        decision = guard.evaluate()
        assert isinstance(decision, MetisInspiredCorpusBlockRateDecision)
        assert decision.allowed is True, (
            f"block_rate={decision.block_rate:.4f} regressed below "
            f"baseline {baseline:.4f} − threshold {threshold:.4f}: {decision.detail}"
        )
        assert decision.verdict == MetisInspiredCorpusBlockRateVerdict.ALLOW

    def test_decision_carries_outcomes_for_all_entries(self) -> None:
        entries, baseline, threshold = _load_corpus()
        guard = MetisInspiredCorpusBlockRateGuard(
            corpus=entries,
            baseline_block_rate=baseline,
            drift_threshold=threshold,
        )
        decision = guard.evaluate()
        assert len(decision.outcomes) == len(entries)
        assert decision.total_prompts == len(entries)

    def test_eval_shape_prompts_are_blocked(self) -> None:
        """Every CVE-2026-44717 entry with expected_block=True should be blocked."""
        entries, baseline, threshold = _load_corpus()
        guard = MetisInspiredCorpusBlockRateGuard(
            corpus=entries,
            baseline_block_rate=baseline,
            drift_threshold=threshold,
        )
        decision = guard.evaluate()
        by_id = {o.prompt_id: o for o in decision.outcomes}
        for entry in entries:
            if entry.anchor == "CVE-2026-44717" and entry.expected_block:
                assert by_id[entry.prompt_id].blocked, (
                    f"CVE-2026-44717 entry {entry.prompt_id} not blocked — EvalRCEGuard regression"
                )

    def test_benign_prompts_not_blocked(self) -> None:
        """Every entry with expected_block=False should pass the chain."""
        entries, baseline, threshold = _load_corpus()
        guard = MetisInspiredCorpusBlockRateGuard(
            corpus=entries,
            baseline_block_rate=baseline,
            drift_threshold=threshold,
        )
        decision = guard.evaluate()
        by_id = {o.prompt_id: o for o in decision.outcomes}
        for entry in entries:
            if not entry.expected_block:
                assert not by_id[entry.prompt_id].blocked, (
                    f"benign entry {entry.prompt_id} (anchor={entry.anchor}) "
                    "was blocked — false-positive regression"
                )

    def test_simulated_lenient_chain_trips_the_gate(self) -> None:
        """A no-op guard chain proves the regression detector itself works."""
        entries, baseline, threshold = _load_corpus()
        guard = MetisInspiredCorpusBlockRateGuard(
            corpus=entries,
            baseline_block_rate=baseline,
            drift_threshold=threshold,
            guard_chain=lambda _e: False,  # blocks nothing
        )
        decision = guard.evaluate()
        assert decision.allowed is False
        assert decision.verdict == MetisInspiredCorpusBlockRateVerdict.DENY_BLOCK_RATE_REGRESSION


class TestFactoryShape:
    """``policy_presets.metis_inspired_corpus_block_rate_regression_defaults_2026_05_18`` factory."""

    def test_factory_is_importable(self) -> None:
        from agent_airlock.policy_presets import (
            metis_inspired_corpus_block_rate_regression_defaults_2026_05_18,
        )

        assert callable(metis_inspired_corpus_block_rate_regression_defaults_2026_05_18)

    def test_factory_returns_expected_shape(self) -> None:
        from agent_airlock.policy_presets import (
            metis_inspired_corpus_block_rate_regression_defaults_2026_05_18,
        )

        cfg = metis_inspired_corpus_block_rate_regression_defaults_2026_05_18()
        assert cfg["preset_id"] == "metis_inspired_corpus_block_rate_regression_2026_05_18"
        assert cfg["severity"] == "high"
        assert cfg["default_action"] == "fail_release_gate"
        assert "arxiv.org/abs/2605.10067" in cfg["advisory_url"]
        assert "anchor_paper" in cfg
        # Numeric defaults are reasonable.
        assert 0.0 <= cfg["baseline_block_rate"] <= 1.0
        assert cfg["drift_threshold"] > 0.0

    def test_factory_overrides_propagate(self) -> None:
        from agent_airlock.policy_presets import (
            metis_inspired_corpus_block_rate_regression_defaults_2026_05_18,
        )

        cfg = metis_inspired_corpus_block_rate_regression_defaults_2026_05_18(
            baseline_block_rate=0.95,
            drift_threshold=0.10,
        )
        assert cfg["baseline_block_rate"] == pytest.approx(0.95)
        assert cfg["drift_threshold"] == pytest.approx(0.10)

    def test_factory_rejects_out_of_range_baseline(self) -> None:
        from agent_airlock.policy_presets import (
            metis_inspired_corpus_block_rate_regression_defaults_2026_05_18,
        )

        with pytest.raises(ValueError, match="baseline_block_rate"):
            metis_inspired_corpus_block_rate_regression_defaults_2026_05_18(baseline_block_rate=1.5)
