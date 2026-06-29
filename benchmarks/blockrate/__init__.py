"""Cross-tool block-rate comparison (agent-airlock vs named incumbents).

Public, MIT, re-runnable. Reports agent-airlock's deterministic in-process
block-rate + per-decision latency on a shared tool-call corpus, contrasted with
the *cited, not re-run* detection scope of model-in-the-loop incumbents (Meta
LlamaFirewall, Invariant Guardrails). See ``BENCHMARK.md`` (block-rate) and
``benchmarks/blockrate/RESULTS.md`` (block-rate + latency).
"""

from __future__ import annotations

from .corpus import ToolCall, load_corpus
from .report import render_comparison_section, render_results_md
from .runner import (
    COMPETITORS,
    BlockRateReport,
    CompetitorScope,
    ToolResult,
    run_blockrate,
)

__all__ = [
    "COMPETITORS",
    "BlockRateReport",
    "CompetitorScope",
    "ToolCall",
    "ToolResult",
    "load_corpus",
    "render_comparison_section",
    "render_results_md",
    "run_blockrate",
]
