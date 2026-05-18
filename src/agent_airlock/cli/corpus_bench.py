"""``airlock corpus-bench`` CLI (v0.8.2+).

Runs the v0.8.2 Metis-inspired exploit-shape corpus through the
default agent-airlock guard chain and reports the block rate (inverse
of ASR) and gate verdict.

Honest framing
--------------
This CLI does NOT reproduce the Metis paper's POMDP attacker. Metis
(arXiv:2605.10067) measures response-level Attack Success Rate on a
closed-loop LLM; agent-airlock measures **block rate** on a fixed
exploit-shape corpus at the tool-call boundary. The two metrics
report on different surfaces.

Usage::

    python -m agent_airlock.cli.corpus_bench \\
        --corpus-path tests/cves/corpora/metis_inspired_corpus_2026_05_18.json \\
        --report json

Exit codes::

    0 — gate passed (block rate at/above baseline − threshold)
    1 — generic error (corpus path missing, JSON parse failure)
    2 — argparse usage error
    3 — gate FAILED (block rate regressed below baseline − threshold)
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path
from typing import Any

import structlog

from ..regression_corpus import (
    CorpusEntry,
    MetisInspiredCorpusBlockRateDecision,
    MetisInspiredCorpusBlockRateGuard,
)


def _configure_structlog_to_stderr() -> None:
    """Route structlog output to stderr so stdout remains clean for the report.

    The guard chain emits ``structlog.warning(...)`` calls during normal
    operation (e.g. when an eval sink fires). Those messages are
    operator-visible diagnostics, not machine-readable output, so they
    belong on stderr — stdout is reserved for the JSON / Markdown /
    text report a calling tool will parse.
    """
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(colors=False),
        ],
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        wrapper_class=structlog.make_filtering_bound_logger(20),  # INFO
        cache_logger_on_first_use=True,
    )


_GATE_FAILED_EXIT = 3


def _load_corpus(path: Path) -> tuple[list[CorpusEntry], float, float]:
    """Parse the JSON corpus fixture into typed entries + baseline/threshold."""
    raw = json.loads(path.read_text(encoding="utf-8"))
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
    baseline = float(raw.get("baseline_block_rate", 0.0))
    threshold = float(raw.get("drift_threshold", 0.05))
    return entries, baseline, threshold


def _decision_payload(decision: MetisInspiredCorpusBlockRateDecision) -> dict[str, Any]:
    return {
        "preset_id": "metis_inspired_corpus_block_rate_regression_2026_05_18",
        "allowed": decision.allowed,
        "verdict": decision.verdict.value,
        "detail": decision.detail,
        "block_rate": decision.block_rate,
        "baseline_block_rate": decision.baseline_block_rate,
        "drift_delta": decision.drift_delta,
        "threshold": decision.threshold,
        "total_prompts": decision.total_prompts,
        "blocked_count": decision.blocked_count,
        "outcomes": [dataclasses.asdict(o) for o in decision.outcomes],
    }


def _emit_text(decision: MetisInspiredCorpusBlockRateDecision) -> None:
    print(
        f"block_rate={decision.block_rate:.4f} "
        f"baseline={decision.baseline_block_rate:.4f} "
        f"drift={decision.drift_delta:+.4f} "
        f"threshold={decision.threshold:.4f} "
        f"verdict={decision.verdict.value} "
        f"({decision.blocked_count}/{decision.total_prompts} blocked)"
    )


def _emit_json(decision: MetisInspiredCorpusBlockRateDecision) -> None:
    print(json.dumps(_decision_payload(decision), indent=2))


def _emit_markdown(decision: MetisInspiredCorpusBlockRateDecision) -> None:
    print("# agent-airlock corpus-bench report")
    print()
    print("- preset_id: `metis_inspired_corpus_block_rate_regression_2026_05_18`")
    print(f"- block_rate: **{decision.block_rate:.4f}**")
    print(f"- baseline_block_rate: {decision.baseline_block_rate:.4f}")
    print(f"- drift_delta: {decision.drift_delta:+.4f}")
    print(f"- threshold: {decision.threshold:.4f}")
    print(f"- verdict: `{decision.verdict.value}`")
    print(f"- detail: {decision.detail}")
    print()
    print("## Per-prompt outcomes")
    print()
    print("| prompt_id | blocked | expected_block | anchor |")
    print("|---|---|---|---|")
    for o in decision.outcomes:
        print(
            f"| `{o.prompt_id}` | {'✅' if o.blocked else '❌'} "
            f"| {'expected' if o.expected_block else 'benign'} | `{o.anchor}` |"
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="airlock corpus-bench",
        description=(
            "Run the v0.8.2 Metis-inspired exploit-shape corpus through the "
            "default agent-airlock guard chain. Reports block rate (inverse "
            "of ASR) and a release-gate verdict."
        ),
    )
    parser.add_argument(
        "--corpus-path",
        required=True,
        type=Path,
        help="Path to the corpus JSON fixture.",
    )
    parser.add_argument(
        "--report",
        choices=["text", "json", "md"],
        default="text",
        help="Output format (default: text).",
    )
    parser.add_argument(
        "--baseline",
        type=float,
        default=None,
        help=(
            "Override the baseline_block_rate from the fixture "
            "(operators can use this to lock a tighter gate in CI)."
        ),
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=None,
        help="Override the drift_threshold from the fixture.",
    )
    args = parser.parse_args(argv)
    _configure_structlog_to_stderr()

    corpus_path: Path = args.corpus_path
    if not corpus_path.exists():
        print(
            f"corpus-bench: corpus path not found: {corpus_path}",
            file=sys.stderr,
        )
        return 1

    try:
        entries, fixture_baseline, fixture_threshold = _load_corpus(corpus_path)
    except (json.JSONDecodeError, KeyError, ValueError) as exc:
        print(f"corpus-bench: failed to parse corpus: {exc}", file=sys.stderr)
        return 1

    baseline = args.baseline if args.baseline is not None else fixture_baseline
    threshold = args.threshold if args.threshold is not None else fixture_threshold

    try:
        guard = MetisInspiredCorpusBlockRateGuard(
            corpus=entries,
            baseline_block_rate=baseline,
            drift_threshold=threshold,
        )
    except ValueError as exc:
        print(f"corpus-bench: bad config: {exc}", file=sys.stderr)
        return 1

    decision = guard.evaluate()

    if args.report == "json":
        _emit_json(decision)
    elif args.report == "md":
        _emit_markdown(decision)
    else:
        _emit_text(decision)

    return 0 if decision.allowed else _GATE_FAILED_EXIT


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = ["main"]
