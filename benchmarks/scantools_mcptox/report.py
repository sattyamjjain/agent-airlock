"""Human-readable rendering of the scan-tools MCPTox contract-coverage report."""

from __future__ import annotations

from .runner import McptoxReport


def format_report(report: McptoxReport) -> str:
    """Render ``report`` as a plain-text block."""
    lines = [
        "=== scan-tools × MCPTox (contract-checking coverage) ===",
        "",
        "Fixtures reconstructed from the tool-poisoning technique in MCPTox",
        "(arXiv:2508.14925) — NOT the paper's 1,312-case live corpus, and NOT its",
        "model-in-the-loop Attack Success Rate. This is static contract coverage.",
        "",
        f"Poisoned fixtures : {report.poisoned_total}",
        f"  detected (SCAN002 trust-boundary) : {report.detected}",
        f"  detection rate (coverage)         : {report.detection_rate:.1%}",
        "",
        f"Benign fixtures   : {report.benign_total}",
        f"  false positives : {report.false_positives}",
        f"  precision       : {report.precision:.1%}",
        "",
        "By injection shape:",
    ]
    for tech, stat in sorted(report.by_technique.items()):
        lines.append(f"  {tech:24} {stat.detected}/{stat.total}  ({stat.rate:.0%})")
    lines += [
        "",
        "Note: declarative_side_effect fixtures carry no imperative marker and are",
        "expected misses — the trust-boundary check targets injection-*shaped* text.",
        "Differentiated from content-signature poisoning scanners (MCP-Scan, eSentire",
        "MCP-Scanner): scan-tools also checks arg-surface / capability / type contracts.",
    ]
    return "\n".join(lines)
