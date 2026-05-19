"""Deterministic exploit-shape corpus regression (v0.8.2+, Metis-paper inspired).

What this is
------------
A release-gate primitive that runs a fixed corpus of exploit-shape
prompts through agent-airlock's guard chain and asserts that the
fraction blocked has not regressed below an operator-set baseline.

What this is NOT
----------------
This is NOT the Metis attacker. Metis (arXiv:2605.10067, ICML 2026)
is an **adaptive POMDP attacker** that targets a closed-loop LLM and
measures response-level Attack Success Rate (ASR). agent-airlock is
a tool-call argument validator that never sees model responses —
the two threat models do not compose directly.

What this primitive does is the inverse of ASR: it measures **block
rate** = ``blocked_count / total_prompts`` on a deterministic corpus
of exploit-shape inputs. The corpus is built from agent-airlock's
existing CVE fixtures and uses the Metis paper's taxonomy of failure
modes (closed-loop reasoning trajectories, semantic-gradient
refinement, metacognitive policy optimisation) as motivation for
what categories to cover — not as a source of prompts.

The release gate is **drift downward**: a guard chain that becomes
more lenient lowers block rate; we deny when
``block_rate < baseline_block_rate - drift_threshold`` (default 5%).
A block rate ABOVE baseline is fine — new guards catching more
exploits is the goal.

Why this is honest
------------------
- We do NOT claim to reproduce Metis's POMDP attacker. The corpus is
  fixed; Metis is adaptive.
- We do NOT claim Metis-paper-comparable ASR numbers. The metric is
  block rate on agent-airlock's own threat surface (tool-call
  arguments), not jailbreak ASR on a hosted LLM.
- We DO cite Metis as the motivation for treating the exploit-shape
  taxonomy as a release-gate input. That citation is in the docstring,
  not in the metric name.

Primary source
--------------
https://arxiv.org/abs/2605.10067
"""

from __future__ import annotations

import enum
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

import structlog

logger = structlog.get_logger("agent-airlock.regression_corpus")


GuardChain = Callable[["CorpusEntry"], bool]
"""A guard chain is a function that returns True iff the entry is blocked."""


class MetisInspiredCorpusBlockRateVerdict(str, enum.Enum):
    """Stable reason codes for :class:`MetisInspiredCorpusBlockRateDecision`."""

    ALLOW = "allow"
    DENY_BLOCK_RATE_REGRESSION = "deny_block_rate_regression"


@dataclass(frozen=True)
class CorpusEntry:
    """A single prompt-shape entry in the regression corpus.

    Attributes:
        prompt_id: Stable identifier for the prompt (used in reports).
        tool_name: Tool the prompt is targeting. Informational — the
            default guard chain inspects ``args`` shape regardless of
            tool name; custom chains can use this to scope.
        args: The proposed tool-call arguments. The guard chain
            inspects values here for exploit-shape patterns.
        anchor: CVE id / paper ref / category label. Used for
            traceability in reports.
        expected_block: True if a correct guard chain SHOULD block
            this prompt (eval-shape, command-injection, etc.).
            False for benign baseline prompts.
        violation_category: Optional category label (v0.8.3+) for
            per-category coverage reporting. The HarnessAudit-Bench
            paper (arXiv:2605.14271) uses ``resource_access`` and
            ``info_transfer`` as its top-level taxonomy; operators
            can adopt those labels or use their own. ``None`` means
            the entry is excluded from per-category counts.
    """

    prompt_id: str
    tool_name: str
    args: dict[str, Any]
    anchor: str
    expected_block: bool
    violation_category: str | None = None


@dataclass(frozen=True)
class CategoryCount:
    """Per-category total + blocked count for a corpus run (v0.8.3+).

    The HarnessAudit-Bench paper (arXiv:2605.14271, 2026-05-14)
    identified ``resource_access`` and ``info_transfer`` as the two
    violation categories that concentrate most observed failures in
    production agent harnesses. agent-airlock adopts that taxonomy
    as a corpus schema extension: each :class:`CorpusEntry` may carry
    a ``violation_category`` label, and the decision dataclass
    exposes one :class:`CategoryCount` per distinct category seen.

    Attributes:
        category: The category label (e.g. ``"resource_access"``).
        total: Number of corpus entries carrying this category.
        blocked: Number of those entries the guard chain refused.

    NOTE: This is NOT a HarnessAudit-Bench scoring surface — the
    benchmark's artifacts have not been published as of 2026-05-19.
    The dataclass adopts the paper's taxonomy without claiming
    metric equivalence.
    """

    category: str
    total: int
    blocked: int


@dataclass(frozen=True)
class CorpusPromptOutcome:
    """The result of running a single corpus entry through the guard chain.

    Attributes:
        prompt_id: Echo of :attr:`CorpusEntry.prompt_id`.
        blocked: True iff the guard chain refused this entry.
        anchor: Echo of :attr:`CorpusEntry.anchor`.
        expected_block: Echo of :attr:`CorpusEntry.expected_block` —
            lets a report flag false-positives (blocked benign) and
            false-negatives (allowed exploit-shape).
    """

    prompt_id: str
    blocked: bool
    anchor: str
    expected_block: bool


@dataclass(frozen=True)
class MetisInspiredCorpusBlockRateDecision:
    """Outcome of a single :meth:`MetisInspiredCorpusBlockRateGuard.evaluate` call.

    Mirrors the v0.7.x / v0.8.x decision family — every guard / gate
    exposes ``allowed: bool`` for chain-friendly composition.

    Attributes:
        allowed: True iff block rate is at or above
            ``baseline_block_rate - drift_threshold``.
        verdict: Stable :class:`MetisInspiredCorpusBlockRateVerdict` value.
        detail: Free-form explanation suitable for logs.
        block_rate: ``blocked_count / total_prompts``.
        baseline_block_rate: The locked baseline the operator set.
        drift_delta: ``block_rate - baseline_block_rate`` (negative
            means a drop; positive means new guards caught more).
        threshold: The allowed downward drift before the gate fires.
        total_prompts: Number of entries in the corpus.
        blocked_count: Number of entries the chain blocked.
        outcomes: Per-prompt outcomes for report generation.
    """

    allowed: bool
    verdict: MetisInspiredCorpusBlockRateVerdict
    detail: str
    block_rate: float
    baseline_block_rate: float
    drift_delta: float
    threshold: float
    total_prompts: int
    blocked_count: int
    outcomes: tuple[CorpusPromptOutcome, ...]
    category_counts: tuple[CategoryCount, ...] = ()


def _default_guard_chain(entry: CorpusEntry) -> bool:
    """Default chain: EvalRCEGuard + StdioCommandInjectionGuard.

    Imported lazily so this module loads even when the optional
    integrations aren't present. Each guard's decision exposes
    ``allowed: bool``; the chain blocks iff any returns
    ``allowed=False``.
    """
    # Inline import keeps the module import-light.
    from .mcp_spec.eval_rce_guard import EvalRCEGuard

    eval_guard = EvalRCEGuard()
    if not eval_guard.evaluate(entry.args).allowed:
        return True

    # StdioCommandInjectionGuard expects ``command`` and ``args``
    # keys per its argv contract. Pass through directly if the entry
    # already supplies them; otherwise coerce string-valued args into
    # an ``args`` argv list so the metachar scan sees them.
    try:
        from .mcp_spec.stdio_command_injection_guard import StdioCommandInjectionGuard

        stdio_guard = StdioCommandInjectionGuard()
        if "command" in entry.args or "args" in entry.args:
            stdio_payload: dict[str, Any] = dict(entry.args)
        else:
            argv_strings = [v for v in entry.args.values() if isinstance(v, str)]
            stdio_payload = {"args": argv_strings} if argv_strings else {}
        if stdio_payload and not stdio_guard.evaluate(stdio_payload).allowed:
            return True
    except Exception:  # noqa: BLE001
        # Optional path; never fail the gate because the chain
        # could not be assembled — the test suite catches that
        # via a dedicated integration test.
        logger.debug("stdio_guard_chain_skip", reason="signature_skew_or_missing")

    return False


class MetisInspiredCorpusBlockRateGuard:
    """Release-gate primitive: corpus → block-rate → decision.

    Args:
        corpus: Iterable of :class:`CorpusEntry`. Must be non-empty.
        baseline_block_rate: The operator-locked baseline block rate
            in ``[0.0, 1.0]``. Lock this at first-run by recording
            whatever the chain produces, then set this value in CI.
        drift_threshold: Allowed downward drift before the gate
            fires. Default 0.05 (5%). Must be non-negative.
        guard_chain: Optional custom chain. Defaults to
            :func:`_default_guard_chain` (EvalRCEGuard +
            StdioCommandInjectionGuard).

    Raises:
        ValueError: ``corpus`` is empty, or ``baseline_block_rate`` is
            outside ``[0.0, 1.0]``, or ``drift_threshold`` is negative.
    """

    def __init__(
        self,
        *,
        corpus: Iterable[CorpusEntry],
        baseline_block_rate: float,
        drift_threshold: float = 0.05,
        guard_chain: GuardChain | None = None,
    ) -> None:
        corpus_list = list(corpus)
        if not corpus_list:
            raise ValueError("corpus is empty; supply at least one CorpusEntry")
        if not (0.0 <= baseline_block_rate <= 1.0):
            raise ValueError(
                f"baseline_block_rate must be in [0.0, 1.0]; got {baseline_block_rate!r}"
            )
        if drift_threshold < 0.0:
            raise ValueError(f"drift_threshold must be non-negative; got {drift_threshold!r}")
        self._corpus = tuple(corpus_list)
        self._baseline_block_rate = float(baseline_block_rate)
        self._drift_threshold = float(drift_threshold)
        self._guard_chain: GuardChain = guard_chain or _default_guard_chain

    def evaluate(self) -> MetisInspiredCorpusBlockRateDecision:
        """Run the corpus through the chain and produce a decision."""
        outcomes: list[CorpusPromptOutcome] = []
        blocked_count = 0
        # Per-category counters (v0.8.3+). Entries with ``violation_category=None``
        # are excluded from the category counts; legacy corpora that
        # carry no category labels yield an empty ``category_counts`` tuple.
        category_totals: dict[str, int] = {}
        category_blocked: dict[str, int] = {}
        for entry in self._corpus:
            try:
                blocked = bool(self._guard_chain(entry))
            except Exception as exc:  # noqa: BLE001
                # A guard that raises is a chain-level fault — treat
                # the entry as NOT blocked so the regression surfaces
                # the change rather than masking it with a silent
                # exception-swallow.
                logger.warning(
                    "regression_corpus_guard_chain_error",
                    prompt_id=entry.prompt_id,
                    error=str(exc),
                )
                blocked = False
            outcomes.append(
                CorpusPromptOutcome(
                    prompt_id=entry.prompt_id,
                    blocked=blocked,
                    anchor=entry.anchor,
                    expected_block=entry.expected_block,
                )
            )
            if blocked:
                blocked_count += 1
            if entry.violation_category is not None:
                cat = entry.violation_category
                category_totals[cat] = category_totals.get(cat, 0) + 1
                if blocked:
                    category_blocked[cat] = category_blocked.get(cat, 0) + 1

        category_counts = tuple(
            CategoryCount(
                category=cat,
                total=category_totals[cat],
                blocked=category_blocked.get(cat, 0),
            )
            for cat in sorted(category_totals)
        )

        total = len(self._corpus)
        block_rate = blocked_count / total
        drift_delta = block_rate - self._baseline_block_rate
        # Allow iff drift_delta >= -threshold (rising block rate is fine).
        allowed = drift_delta >= -self._drift_threshold

        if allowed:
            verdict = MetisInspiredCorpusBlockRateVerdict.ALLOW
            detail = (
                f"block_rate={block_rate:.4f} (baseline={self._baseline_block_rate:.4f}, "
                f"drift={drift_delta:+.4f}); within {self._drift_threshold:.4f} threshold"
            )
        else:
            verdict = MetisInspiredCorpusBlockRateVerdict.DENY_BLOCK_RATE_REGRESSION
            detail = (
                f"block_rate={block_rate:.4f} dropped below baseline "
                f"({self._baseline_block_rate:.4f}) by {-drift_delta:.4f} "
                f"(threshold={self._drift_threshold:.4f}); guard chain regressed"
            )
            logger.warning(
                "regression_corpus_block_rate_regression",
                block_rate=block_rate,
                baseline=self._baseline_block_rate,
                drift_delta=drift_delta,
                threshold=self._drift_threshold,
            )

        return MetisInspiredCorpusBlockRateDecision(
            allowed=allowed,
            verdict=verdict,
            detail=detail,
            block_rate=block_rate,
            baseline_block_rate=self._baseline_block_rate,
            drift_delta=drift_delta,
            threshold=self._drift_threshold,
            total_prompts=total,
            blocked_count=blocked_count,
            outcomes=tuple(outcomes),
            category_counts=category_counts,
        )


__all__ = [
    "CategoryCount",
    "CorpusEntry",
    "CorpusPromptOutcome",
    "GuardChain",
    "MetisInspiredCorpusBlockRateDecision",
    "MetisInspiredCorpusBlockRateGuard",
    "MetisInspiredCorpusBlockRateVerdict",
]
