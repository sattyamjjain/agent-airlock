"""Render the block-rate comparison to markdown.

Two renderers, because two consumers with different determinism needs:

- :func:`render_comparison_section` — **deterministic** block-rate + scope
  claims only (NO latency). Embedded into the drift-gated ``BENCHMARK.md`` so
  ``generate_benchmark.py --check`` stays a stable CI gate.
- :func:`render_results_md` — the full standalone ``benchmarks/blockrate/
  RESULTS.md`` including p50/p95 latency, stamped with a run date.
"""

from __future__ import annotations

from dataclasses import dataclass

from agent_airlock.owasp_agentic_coverage.render import COVERAGE_PATH, load_coverage

from .corpus import ASI_SLOTS, asi_slots
from .runner import BlockRateReport

_CATEGORY_TITLES = {
    "over_privileged_selection": "Over-privileged tool selection (ToolPrivBench-derived)",
    "argument_injection": "Tool-argument injection (eval / subprocess / env / codegen)",
    "benign": "Benign controls (false-positive set)",
}

#: Risk names are read from the shipped coverage matrix rather than restated
#: here, so the benchmark table and ``agentic_coverage.yaml`` cannot drift into
#: disagreeing about what a slot is called.
_AGENTIC_COVERAGE_PATH = COVERAGE_PATH.parent / "agentic_coverage.yaml"


def _pct(x: float) -> str:
    return f"{x * 100:.1f}%"


@dataclass
class AsiStats:
    """Per-slot counts. ``malicious_total == 0`` is a reported result, not a gap."""

    malicious_total: int = 0
    malicious_blocked: int = 0
    benign_total: int = 0
    benign_false_positives: int = 0

    @property
    def block_rate(self) -> float:
        return self.malicious_blocked / self.malicious_total if self.malicious_total else 0.0


def asi_breakdown(report: BlockRateReport) -> dict[str, AsiStats]:
    """Aggregate the run per OWASP Agentic slot.

    Every one of the ten slots is present in the result, including those the
    corpus never reaches — a slot with no items is the most informative row on
    the page, so it is counted and rendered rather than dropped. An item mapped
    to two slots counts once in each: the columns are per-slot coverage, not a
    partition of the corpus, and the totals therefore exceed the corpus size.
    """
    out = {slot: AsiStats() for slot in ASI_SLOTS}
    for call, blocked in report.results:
        for slot in asi_slots(call):
            stats = out.setdefault(slot, AsiStats())
            if call.expected_block:
                stats.malicious_total += 1
                stats.malicious_blocked += int(blocked)
            else:
                stats.benign_total += 1
                stats.benign_false_positives += int(blocked)
    return out


def unmapped_counts(report: BlockRateReport) -> tuple[int, int]:
    """``(malicious, benign)`` items carrying no slot, for the footer line."""
    mal = ben = 0
    for call, _blocked in report.results:
        if not asi_slots(call):
            if call.expected_block:
                mal += 1
            else:
                ben += 1
    return mal, ben


def render_asi_section(report: BlockRateReport) -> str:
    """Per-OWASP-Agentic-slot block rate, all ten slots, n=0 rows included."""
    stats = asi_breakdown(report)
    names = {e.risk_id: e.risk_name for e in load_coverage(_AGENTIC_COVERAGE_PATH).entries}
    lines: list[str] = []
    lines.append("### agent-airlock per OWASP Agentic slot (v2.01)")
    lines.append("")
    lines.append(
        "Every one of the ten slots is listed. A slot the corpus does not reach "
        "is shown as **n=0**, not omitted — which of the ten this benchmark "
        "*cannot* speak to is the column worth reading first. An item that "
        "genuinely maps to two slots is counted in both, so the malicious column "
        "sums to more than the corpus size."
    )
    lines.append("")
    lines.append(
        "| Slot | Risk | Malicious n | Blocked | Block-rate | Benign n | False positives |"
    )
    lines.append("|---|---|---|---|---|---|---|")
    for slot in ASI_SLOTS:
        s = stats[slot]
        name = names.get(slot, "—")
        if s.malicious_total == 0 and s.benign_total == 0:
            lines.append(
                f"| {slot} | {name} | **0** | — | _not measured_ | **0** | — |"
            )
            continue
        rate = _pct(s.block_rate) if s.malicious_total else "_not measured_"
        blocked = str(s.malicious_blocked) if s.malicious_total else "—"
        lines.append(
            f"| {slot} | {name} | {s.malicious_total} | {blocked} | {rate} | "
            f"{s.benign_total} | {s.benign_false_positives} |"
        )
    lines.append("")
    mal_unmapped, ben_unmapped = unmapped_counts(report)
    lines.append(
        f"Unmapped corpus items (no slot claimed): **{mal_unmapped}** malicious, "
        f"**{ben_unmapped}** benign. An item is left unmapped when no slot fits it "
        "honestly; the count is published rather than absorbed into a neighbouring row."
    )
    lines.append("")
    return "\n".join(lines)


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
    lines.append(render_asi_section(report))
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
    # The comparison section is shared with the drift-gated BENCHMARK.md. The
    # AgentDojo continuation below is appended HERE and not there because its
    # relative link resolves from benchmarks/blockrate/ but not from the repo
    # root, and check_links.py would fail on the root copy. Appended without a
    # blank line so it stays inside the honest-scope blockquote.
    lines.append(render_comparison_section(report).rstrip("\n"))
    lines.append(">")
    lines.append(
        "> **AgentDojo now wired** (this replaces the earlier \"not yet wired\" note): "
        "for an *adaptive-attacker* measurement, airlock runs as an "
        "[AgentDojo](https://arxiv.org/abs/2406.13352) defense and blocks **84.4%** of "
        "`tool_knowledge` injection→task target tool-calls on the pinned "
        "workspace+banking subset — a deterministic upper bound on ASR reduction, with "
        "a `--model` path for the real model-in-the-loop ASR. See "
        "[`benchmarks/agentdojo/RESULTS.md`](../agentdojo/RESULTS.md)."
    )
    lines.append("")
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
