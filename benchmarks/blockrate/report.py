"""Render the block-rate comparison to markdown.

Two renderers, because two consumers with different determinism needs:

- :func:`render_comparison_section` — **deterministic** block-rate + scope
  claims only (NO latency). Embedded into the drift-gated ``BENCHMARK.md`` so
  ``generate_benchmark.py --check`` stays a stable CI gate.
- :func:`render_results_md` — the full standalone ``benchmarks/blockrate/
  RESULTS.md`` including p50/p95 latency, stamped with a run date.
"""

from __future__ import annotations

from .runner import BlockRateReport

_CATEGORY_TITLES = {
    "over_privileged_selection": "Over-privileged tool selection (ToolPrivBench-derived)",
    "argument_injection": "Tool-argument injection (eval / subprocess / env / codegen)",
    "benign": "Benign controls (false-positive set)",
}


def _pct(x: float) -> str:
    return f"{x * 100:.1f}%"


def render_comparison_section(report: BlockRateReport) -> str:
    """Deterministic comparison block (no latency) for BENCHMARK.md."""
    mal = sum(s.malicious_total for s in report.by_category.values())
    ben = sum(s.benign_total for s in report.by_category.values())
    lines: list[str] = []
    lines.append("## Cross-tool block-rate comparison")
    lines.append("")
    lines.append(
        "Same tool-call corpus, three approaches. agent-airlock is **re-run** "
        "deterministically below; the two incumbents are **model-in-the-loop** "
        "systems (model weights / hosted API) that this in-process harness does "
        "not execute, so their coverage is a **scope claim, cited, not re-run** "
        "— never a fabricated number."
    )
    lines.append("")
    lines.append(
        f"Corpus: **{report.total}** tool calls — **{mal}** malicious "
        f"(must block), **{ben}** benign (must pass)."
    )
    lines.append("")
    lines.append(
        "| Tool | Approach | Block-rate (malicious) | False-positives (benign) | Re-run? |"
    )
    lines.append("|---|---|---|---|---|")
    lines.append(
        f"| **agent-airlock** (deny-by-default presets) | deterministic, in-process | "
        f"**{_pct(report.overall_block_rate)}** ({mal} items) | "
        f"**{_pct(report.overall_fp_rate)}** ({ben} items) | ✅ yes |"
    )
    for comp in report.competitors:
        lines.append(
            f"| **{comp.name}** | {comp.approach} | _scope-claimed, not re-run_ "
            f"| _scope-claimed, not re-run_ | ❌ no |"
        )
    lines.append("")
    lines.append("### agent-airlock per-category")
    lines.append("")
    lines.append("| Category | Malicious blocked | Benign blocked (FP) |")
    lines.append("|---|---|---|")
    for cat, stats in report.by_category.items():
        title = _CATEGORY_TITLES.get(cat, cat)
        lines.append(
            f"| {title} | {stats.malicious_blocked}/{stats.malicious_total} "
            f"({_pct(stats.block_rate)}) | {stats.benign_blocked}/{stats.benign_total} "
            f"({_pct(stats.fp_rate)}) |"
        )
    lines.append("")
    lines.append("### Incumbent scope (cited, not re-run)")
    lines.append("")
    for comp in report.competitors:
        lines.append(
            f"- **{comp.name}** — {comp.approach}. {comp.coverage_note} Source: <{comp.source}>"
        )
    lines.append("")
    lines.append(
        "> **Honest scope.** agent-airlock's 100% here is on a **self-curated** "
        "corpus of exploit shapes it is built to catch — it is a coverage / "
        "regression baseline, **not** an adaptive-attacker score, and **not** a "
        "head-to-head where the incumbents were run. The contrast that matters "
        "is *categorical*: agent-airlock blocks **tool-argument exploit shapes "
        "and least-privilege tool selection deterministically in-process**, "
        "which the cited prompt-injection / trace-policy systems do not target "
        "as fixed in-process checks. Different layers — use both."
    )
    lines.append("")
    return "\n".join(lines)


def render_results_md(report: BlockRateReport, run_date: str) -> str:
    """Full standalone RESULTS.md including latency, stamped with run_date."""
    lines: list[str] = []
    lines.append("# Cross-tool block-rate comparison — results")
    lines.append("")
    lines.append(f"Last run: **{run_date}**. Corpus: **{report.total}** tool calls.")
    lines.append("")
    lines.append("## Headline")
    lines.append("")
    lines.append(
        f"- agent-airlock block-rate (malicious blocked): **{_pct(report.overall_block_rate)}**"
    )
    lines.append(
        f"- agent-airlock false-positive rate (benign blocked): **{_pct(report.overall_fp_rate)}**"
    )
    lines.append(
        f"- Per-decision latency: **p50 {report.latency_pct(50):.4f} ms**, "
        f"**p95 {report.latency_pct(95):.4f} ms** (in-process, no model call, no network)"
    )
    lines.append("")
    lines.append(
        "The latency line is why this is a different layer from model-in-the-loop "
        "guardrails: a deny-by-default policy / argument guard decides in "
        "microseconds with no model inference, no API round-trip, and a "
        "deterministic verdict."
    )
    lines.append("")
    lines.append(render_comparison_section(report))
    lines.append("## Reproduce")
    lines.append("")
    lines.append("```bash")
    lines.append("python -m benchmarks.blockrate          # print the summary")
    lines.append("python -m benchmarks.blockrate --write   # also (re)write this RESULTS.md")
    lines.append("```")
    lines.append("")
    lines.append(
        "_Latency is wall-clock and machine-dependent, so it lives here (stamped) "
        "rather than in the drift-gated `BENCHMARK.md` — only the deterministic "
        "block-rate goes there._"
    )
    lines.append("")
    return "\n".join(lines)
