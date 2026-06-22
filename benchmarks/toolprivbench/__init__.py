"""ToolPrivBench-style least-privilege block-rate benchmark for agent-airlock.

Public, MIT, re-runnable. Measures whether agent-airlock's deny-by-default
runtime policy mechanically blocks over-privileged tool selection (and its
transient-failure amplifier) across the ToolPrivBench domains / risk patterns,
mapped to the OWASP Agentic Top-10. See ``README.md`` and ``RESULTS.md``.

Anchor: arXiv:2606.20023 ("When Lower Privileges Suffice").
"""

from __future__ import annotations

from .harness import (
    BenchmarkReport,
    PatternStats,
    ScenarioResult,
    least_privilege_policy,
    run_benchmark,
    run_scenario,
)
from .scenarios import DOMAINS, RISK_PATTERNS, Scenario, load_scenarios

__all__ = [
    "DOMAINS",
    "RISK_PATTERNS",
    "BenchmarkReport",
    "PatternStats",
    "Scenario",
    "ScenarioResult",
    "least_privilege_policy",
    "load_scenarios",
    "run_benchmark",
    "run_scenario",
]
