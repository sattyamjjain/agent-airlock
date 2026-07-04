"""Render a :class:`BenchmarkReport` to the RESULTS.md markdown table."""

from __future__ import annotations

from .harness import BenchmarkReport
from .scenarios import RISK_PATTERNS

_OWASP_TITLES = {
    "ASI01": "Agent Control / Authorization Hijacking",
    "ASI02": "Tool Misuse",
    "ASI03": "Privilege Compromise",
    "ASI04": "Resource / Persistence Abuse",
    "ASI06": "Sensitive-Information Exposure",
}


def _pct(x: float) -> str:
    return f"{x * 100:.1f}%"


def render_results_md(report: BenchmarkReport, run_date: str) -> str:
    """Render the full RESULTS.md content for ``report`` stamped with ``run_date``."""
    label = (
        "official ToolPrivBench dataset"
        if report.source == "official"
        else ("**subset harness** (~20 scenarios/pattern; pending full-dataset wiring)")
    )
    lines: list[str] = []
    lines.append("# ToolPrivBench-style least-privilege block-rate — results")
    lines.append("")
    lines.append(
        f"Scenario source: {label}. Total scenarios: **{report.total}**. Last run: **{run_date}**."
    )
    lines.append("")
    lines.append(
        "**Method note.** Each scenario is wrapped in agent-airlock's "
        "deny-by-default least-privilege `SecurityPolicy` "
        "(`default_deny=True`, allowlist = only the low-privilege tool the task "
        "needs). The over-privileged tool call is recorded as BLOCKED iff "
        "`SecurityPolicy.check_tool_allowed` raises `PolicyViolation`; the "
        "low-privilege call must remain ALLOWED (so this is not a blunt "
        "deny-all). The transient-failure column re-runs the over-privileged "
        "decision after an injected low-privilege-tool failure — ToolPrivBench's "
        "amplifier — under the same fixed policy."
    )
    lines.append("")

    # Headline
    lines.append("## Headline")
    lines.append("")
    lines.append(
        f"- Over-privileged calls **blocked**: **{_pct(report.overall_block_rate)}** "
        f"({report.total} scenarios)"
    )
    lines.append(
        f"- Over-privileged calls blocked **after transient failure**: "
        f"**{_pct(report.overall_block_rate_after_failure)}**"
    )
    lines.append(
        f"- Legitimate low-privilege calls **allowed** (precision, not deny-all): "
        f"**{_pct(report.overall_low_priv_allow_rate)}**"
    )
    if report.opur is not None:
        opur = report.opur
        lines.append(
            f"- **OPUR** (over-privileged tool-use rate, ToolPrivBench): "
            f"**{_pct(opur.opur_baseline)} baseline → {_pct(opur.opur_enforced)} enforced** "
            f"(**−{_pct(opur.opur_delta)}** over {opur.denominator} low-priv-suffices scenarios)"
        )
    lines.append("")

    # Per risk pattern (block-rate + OPUR baseline/enforced/delta side by side)
    lines.append("## Block-rate and OPUR per ToolPrivBench risk pattern")
    lines.append("")
    lines.append(
        "| Risk pattern | OWASP-Agentic | Scenarios | Domains | Over-priv blocked | "
        "After transient failure | Low-priv allowed | OPUR-baseline | OPUR-enforced | OPUR Δ |"
    )
    lines.append("|---|---|---|---|---|---|---|---|---|---|")
    opur_by_pattern = report.opur.by_pattern if report.opur is not None else {}
    for pattern, stats in report.by_pattern.items():
        owasp = RISK_PATTERNS[pattern]
        o = opur_by_pattern.get(pattern)
        opur_cells = (
            f" {_pct(o.opur_baseline)} | {_pct(o.opur_enforced)} | −{_pct(o.opur_delta)} |"
            if o is not None
            else " — | — | — |"
        )
        lines.append(
            f"| {pattern} | {owasp} | {stats.total} | {len(stats.domains)} | "
            f"{_pct(stats.block_rate)} | {_pct(stats.block_rate_after_failure)} | "
            f"{_pct(stats.low_priv_allow_rate)} |{opur_cells}"
        )
    lines.append("")

    # Per OWASP id
    lines.append("## Block-rate per OWASP Agentic Top-10 id")
    lines.append("")
    lines.append(
        "| OWASP-Agentic id | Title (best-effort crosswalk) | Scenarios | Over-priv blocked |"
    )
    lines.append("|---|---|---|---|")
    for owasp, stats in report.by_owasp.items():
        title = _OWASP_TITLES.get(owasp, "—")
        lines.append(f"| {owasp} | {title} | {stats.total} | {_pct(stats.block_rate)} |")
    lines.append("")

    # Crosswalk + caveat
    lines.append("## Risk-pattern → OWASP-Agentic crosswalk")
    lines.append("")
    lines.append("| ToolPrivBench risk pattern | OWASP Agentic Top-10 (2026) |")
    lines.append("|---|---|")
    for pattern, owasp in RISK_PATTERNS.items():
        lines.append(f"| {pattern} | {owasp} {_OWASP_TITLES.get(owasp, '')} |")
    lines.append("")
    lines.append(
        "> The crosswalk is this harness's **best-effort alignment**, not an "
        "official OWASP designation."
    )
    lines.append("")
    lines.append("## Honest caveat")
    lines.append("")
    lines.append(
        "This benchmark measures **runtime BLOCK behaviour under fixed presets** "
        "— not model behaviour. A 100% block-rate means deny-by-default "
        "mechanically refuses any tool not on the least-privilege allowlist "
        "(including under the transient-failure amplifier where ToolPrivBench "
        "shows prompt-level controls degrade); it is **not** a claim that the "
        "agent stopped *choosing* over-privileged tools. The complementary "
        "low-privilege allow-rate shows the policy is precise, not a blunt "
        "deny-all. Anchor: ToolPrivBench / "
        "[arXiv:2606.20023](https://arxiv.org/abs/2606.20023)."
    )
    lines.append("")

    if report.opur is not None:
        opur = report.opur
        lines.append("## OPUR — over-privileged tool-use rate (ToolPrivBench)")
        lines.append("")
        lines.append(
            f"**OPUR-baseline {_pct(opur.opur_baseline)} → OPUR-enforced "
            f"{_pct(opur.opur_enforced)}** (Δ **−{_pct(opur.opur_delta)}**), computed over "
            f"the **{opur.denominator}** scenarios where a lower-privilege tool would have "
            "sufficed."
        )
        lines.append("")
        lines.append(
            "- **OPUR-baseline** — the recorded over-privileged tool call under a "
            "**permissive** policy (no airlock): it is allowed through, so the "
            "over-privileged tool is used."
        )
        lines.append(
            "- **OPUR-enforced** — the *same* recorded call under airlock's "
            "**least-privilege deny-by-default** policy (allow only the sufficient "
            "low-privilege tool): it is blocked, so the over-privileged use is prevented."
        )
        lines.append(
            "- A scenario where the high-privilege tool is **legitimately required** is "
            "**excluded** from OPUR — reaching for the powerful tool there is correct, "
            "not a violation."
        )
        lines.append("")
        lines.append(
            "> **Honest scope.** OPUR here measures airlock's **enforcement** on the "
            "labelled ToolPrivBench scenarios (does deny-by-default prevent the recorded "
            "over-privileged reach), **not** what a model would choose. Every scenario in "
            "the shipped subset is an over-privileged-selection scenario, so OPUR-baseline "
            "is 100% *by construction of the corpus*; the load-bearing numbers are the "
            "**enforced** OPUR and the delta. Deterministic, no model call — reproducible "
            "in CI. Anchor: [arXiv:2606.20023](https://arxiv.org/abs/2606.20023)."
        )
        lines.append("")

    return "\n".join(lines)
