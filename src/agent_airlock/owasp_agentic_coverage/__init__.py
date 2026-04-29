"""Published OWASP Agentic Top-10 coverage matrix (v0.5.9+).

Microsoft Agent Governance Toolkit advertises "10/10 OWASP Agentic
risks at sub-ms p99". Airlock has matching coverage but did not
publish a dated, machine-readable matrix tying each OWASP-Agentic
2026 risk ID to a specific guard / preset / test. This module is the
matrix.

The data is held in :data:`COVERAGE_PATH` (a YAML file checked into
the repo) and parsed by :func:`load_coverage`. A CI gate
(``.github/workflows/owasp_coverage_gate.yml.sample``) fails on:

* Any risk with no guard module mapping.
* Any ``last_verified`` older than 30 days.

Both rules catch silent coverage regression — adding a new guard but
forgetting to update the matrix, or letting a guard drift unverified
for a quarter.

Reference
---------
* OWASP Top 10 for LLM and Agentic Applications 2026 (Q1 spec):
  https://genai.owasp.org/llm-top-10/
* Microsoft Agent Governance Toolkit (head-on competitor's claim):
  https://opensource.microsoft.com/blog/2026/04/02/introducing-the-agent-governance-toolkit-open-source-runtime-security-for-ai-agents/
"""

from __future__ import annotations

from .render import (
    Coverage,
    CoverageEntry,
    load_coverage,
    render_json,
    render_markdown,
)

__all__ = [
    "Coverage",
    "CoverageEntry",
    "load_coverage",
    "render_json",
    "render_markdown",
]
