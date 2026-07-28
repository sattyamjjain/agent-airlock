"""Published OWASP coverage matrices (v0.5.9+).

Two dated, machine-readable matrices tie each OWASP risk ID to a specific guard
module / preset / test, so a coverage claim is **evidence, not prose**:

* :data:`COVERAGE_PATH` (``coverage.yaml``) — the **OWASP LLM Top-10 2026** risks
  (LLM01-LLM10).
* ``agentic_coverage.yaml`` — the **OWASP Agentic Top-10 2026** risks
  (ASI01-ASI10), rendered to ``docs/owasp-agentic-2026-coverage.md``.

Both are parsed by :func:`load_coverage` (which takes an optional ``path``). A CI
gate (``docs/security/owasp-coverage-gate-ci.yml.sample``) fails on:

* Any risk with no guard module mapping.
* Any ``last_verified`` older than 30 days.

Both rules catch silent coverage regression — adding a new guard but forgetting
to update the matrix, or letting a guard drift unverified for a quarter. The
tests additionally assert every ``guard_module`` imports, every ``test_path``
exists, and (for the Agentic matrix) every ``preset`` is a live
``policy_presets.list_active()`` factory.

Reference
---------
* OWASP Top 10 for LLM Applications 2026:
  https://genai.owasp.org/llm-top-10/
* OWASP Top 10 for Agentic Applications 2026 (v2.01, published 2025-12-09,
  updated 2026-06-01):
  https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
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
