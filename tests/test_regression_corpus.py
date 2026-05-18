"""Tests for the v0.8.2 ``MetisInspiredCorpusBlockRateGuard`` primitive.

Honest framing
--------------
This module is NOT the Metis attacker. Metis (arXiv:2605.10067, ICML
2026) is an **adaptive POMDP attacker** that runs against a closed-loop
LLM and measures response-level Attack Success Rate (ASR). agent-airlock
is a tool-call argument validator that never sees model responses.

What v0.8.2 ships is a **deterministic prompt-shape corpus regression**
inspired by the Metis paper's failure-mode taxonomy and built primarily
from agent-airlock's existing CVE fixtures. The metric is the inverse
of ASR — **block rate**, the fraction of exploit-shape prompts that
at least one guard in the chain refuses. A release gate enforces that
block rate must NOT drop below ``baseline_block_rate - 0.05`` (a
guard that becomes more lenient lowers block rate; the gate catches
that drift).

Primary source
--------------
https://arxiv.org/abs/2605.10067 (Metis, ICML 2026) — cited as
motivation for adopting a structured exploit-shape taxonomy as a
release-gate input. The paper's prompts / POMDP attacker code are
NOT reused here.
"""

from __future__ import annotations

import pytest

from agent_airlock.regression_corpus import (
    CorpusEntry,
    MetisInspiredCorpusBlockRateDecision,
    MetisInspiredCorpusBlockRateGuard,
    MetisInspiredCorpusBlockRateVerdict,
)

# ----------------------------------------------------------------------
# Fixtures: a tiny synthetic corpus + a tiny mock guard chain
# ----------------------------------------------------------------------


def _synthetic_corpus() -> list[CorpusEntry]:
    """Three eval-shape prompts + two benign prompts.

    The synthetic corpus is intentionally tiny so the math is
    auditable: 3/5 = 0.6 block rate when all three eval prompts
    are caught and no benign prompts are mis-blocked.
    """
    return [
        CorpusEntry(
            prompt_id="synth-eval-001",
            tool_name="calculate",
            args={"expression": "eval('1+1')"},
            anchor="CVE-2026-44717",
            expected_block=True,
        ),
        CorpusEntry(
            prompt_id="synth-eval-002",
            tool_name="calculate",
            args={"expression": "__import__('os').system('id')"},
            anchor="CVE-2026-44717",
            expected_block=True,
        ),
        CorpusEntry(
            prompt_id="synth-eval-003",
            tool_name="parse",
            args={"expression": "parse_expr(user_input)"},
            anchor="CVE-2026-44717",
            expected_block=True,
        ),
        CorpusEntry(
            prompt_id="synth-benign-001",
            tool_name="calculate",
            args={"expression": "2 + 2"},
            anchor="benign",
            expected_block=False,
        ),
        CorpusEntry(
            prompt_id="synth-benign-002",
            tool_name="calculate",
            args={"expression": "sin(x)"},
            anchor="benign",
            expected_block=False,
        ),
    ]


# ----------------------------------------------------------------------
# RED tests
# ----------------------------------------------------------------------


class TestBlockRateMath:
    """Verify the block-rate computation against an auditable tiny corpus."""

    def test_default_guard_chain_blocks_eval_prompts(self) -> None:
        guard = MetisInspiredCorpusBlockRateGuard(
            corpus=_synthetic_corpus(),
            baseline_block_rate=0.6,
            drift_threshold=0.05,
        )
        decision = guard.evaluate()
        assert isinstance(decision, MetisInspiredCorpusBlockRateDecision)
        # All three eval prompts blocked, both benign prompts allowed →
        # block_rate = 3/5 = 0.6.
        assert decision.block_rate == pytest.approx(0.6)
        assert decision.total_prompts == 5
        assert decision.blocked_count == 3

    def test_decision_allowed_when_block_rate_meets_baseline(self) -> None:
        guard = MetisInspiredCorpusBlockRateGuard(
            corpus=_synthetic_corpus(),
            baseline_block_rate=0.6,
            drift_threshold=0.05,
        )
        decision = guard.evaluate()
        assert decision.allowed is True
        assert decision.verdict == MetisInspiredCorpusBlockRateVerdict.ALLOW
        # drift_delta is block_rate - baseline_block_rate.
        assert decision.drift_delta == pytest.approx(0.0)

    def test_decision_allowed_when_block_rate_inside_threshold(self) -> None:
        """A block rate at baseline − 0.04 (inside 5% threshold) still allows."""
        guard = MetisInspiredCorpusBlockRateGuard(
            corpus=_synthetic_corpus(),
            baseline_block_rate=0.64,  # actual will be 0.6; drift = -0.04
            drift_threshold=0.05,
        )
        decision = guard.evaluate()
        assert decision.allowed is True
        assert decision.verdict == MetisInspiredCorpusBlockRateVerdict.ALLOW
        assert decision.drift_delta == pytest.approx(-0.04, abs=1e-9)


class TestBlockRateRegression:
    """The release-gate denial when block rate drops below threshold."""

    def test_decision_denied_when_block_rate_drops_below_threshold(self) -> None:
        """A block rate at baseline − 0.10 (beyond 5% threshold) denies."""
        guard = MetisInspiredCorpusBlockRateGuard(
            corpus=_synthetic_corpus(),
            baseline_block_rate=0.7,  # actual will be 0.6; drift = -0.10
            drift_threshold=0.05,
        )
        decision = guard.evaluate()
        assert decision.allowed is False
        assert decision.verdict == MetisInspiredCorpusBlockRateVerdict.DENY_BLOCK_RATE_REGRESSION
        assert decision.drift_delta == pytest.approx(-0.10, abs=1e-9)

    def test_high_block_rate_above_baseline_still_allows(self) -> None:
        """A block rate ABOVE baseline (e.g. new guard caught more) is fine."""
        guard = MetisInspiredCorpusBlockRateGuard(
            corpus=_synthetic_corpus(),
            baseline_block_rate=0.5,  # actual 0.6; drift = +0.10
            drift_threshold=0.05,
        )
        decision = guard.evaluate()
        assert decision.allowed is True  # rising block rate is good
        assert decision.verdict == MetisInspiredCorpusBlockRateVerdict.ALLOW
        assert decision.drift_delta == pytest.approx(0.10, abs=1e-9)


class TestDecisionShape:
    """Mirror the v0.7.x / v0.8.x decision family shape."""

    def test_decision_is_frozen(self) -> None:
        guard = MetisInspiredCorpusBlockRateGuard(
            corpus=_synthetic_corpus(),
            baseline_block_rate=0.6,
        )
        decision = guard.evaluate()
        with pytest.raises((AttributeError, Exception)):  # FrozenInstanceError
            decision.allowed = False  # type: ignore[misc]

    def test_corpus_entry_is_frozen(self) -> None:
        e = _synthetic_corpus()[0]
        with pytest.raises((AttributeError, Exception)):
            e.prompt_id = "x"  # type: ignore[misc]

    def test_decision_exposes_allowed_bool(self) -> None:
        """Mirrors AllowlistVerdict / EvalRCEDecision / OpenAPIDriftDecision shape."""
        guard = MetisInspiredCorpusBlockRateGuard(
            corpus=_synthetic_corpus(),
            baseline_block_rate=0.6,
        )
        decision = guard.evaluate()
        assert isinstance(decision.allowed, bool)


class TestConstructionValidation:
    """Bad operator inputs are rejected up front."""

    def test_empty_corpus_rejected(self) -> None:
        with pytest.raises(ValueError, match="corpus.*empty"):
            MetisInspiredCorpusBlockRateGuard(
                corpus=[],
                baseline_block_rate=0.5,
            )

    def test_baseline_out_of_range_rejected(self) -> None:
        with pytest.raises(ValueError, match="baseline_block_rate"):
            MetisInspiredCorpusBlockRateGuard(
                corpus=_synthetic_corpus(),
                baseline_block_rate=1.5,
            )

    def test_drift_threshold_negative_rejected(self) -> None:
        with pytest.raises(ValueError, match="drift_threshold"):
            MetisInspiredCorpusBlockRateGuard(
                corpus=_synthetic_corpus(),
                baseline_block_rate=0.5,
                drift_threshold=-0.01,
            )


class TestPerPromptOutcomes:
    """The decision exposes per-prompt outcomes so the CLI can build a report."""

    def test_decision_carries_per_prompt_outcomes(self) -> None:
        guard = MetisInspiredCorpusBlockRateGuard(
            corpus=_synthetic_corpus(),
            baseline_block_rate=0.6,
        )
        decision = guard.evaluate()
        # outcomes is a tuple of (prompt_id, blocked: bool, anchor: str)
        assert len(decision.outcomes) == 5
        ids = [o.prompt_id for o in decision.outcomes]
        assert "synth-eval-001" in ids
        assert "synth-benign-001" in ids
        # Each eval prompt should have blocked=True
        evals = [o for o in decision.outcomes if o.prompt_id.startswith("synth-eval")]
        assert all(o.blocked for o in evals)


class TestCustomGuardChain:
    """Operators can pass a custom guard chain."""

    def test_custom_chain_changes_block_rate(self) -> None:
        """A no-op guard chain blocks nothing → block_rate = 0."""

        def _noop_chain(entry: CorpusEntry) -> bool:
            return False  # never blocks

        guard = MetisInspiredCorpusBlockRateGuard(
            corpus=_synthetic_corpus(),
            baseline_block_rate=0.0,
            guard_chain=_noop_chain,
        )
        decision = guard.evaluate()
        assert decision.block_rate == 0.0
        assert decision.blocked_count == 0
