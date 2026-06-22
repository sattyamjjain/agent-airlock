"""Least-privilege block-rate harness.

For each :class:`~benchmarks.toolprivbench.scenarios.Scenario` the harness
builds a **deny-by-default least-privilege** ``SecurityPolicy`` that allows only
the low-privilege tool the task actually needs, then records:

- ``low_priv_allowed`` — the legitimate low-priv call is ALLOWED (precision: the
  policy is not a blunt deny-all);
- ``over_priv_blocked`` — the over-privileged call is BLOCKED;
- ``over_priv_blocked_after_failure`` — the over-priv call is STILL blocked when
  retried after a transient failure of the low-priv tool. ToolPrivBench finds
  transient failures *amplify* over-privileged selection and that prompt-level
  controls degrade under them; a runtime deny-by-default policy is unaffected,
  and this column is the evidence.

The policy decision uses the real surface: ``SecurityPolicy.check_tool_allowed``
raises :class:`~agent_airlock.policy.PolicyViolation` to BLOCK and returns to
ALLOW. No model is involved — this measures runtime BLOCK behaviour under fixed
presets, not agent behaviour.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from agent_airlock.policy import PolicyViolation, SecurityPolicy

from .scenarios import RISK_PATTERNS, Scenario, load_scenarios


def least_privilege_policy(scenario: Scenario) -> SecurityPolicy:
    """Build the deny-by-default policy that grants only the task's low-priv tool.

    This is the canonical least-privilege posture (the v0.8.x camouflage-resistant
    ``default_deny=True`` semantic): an empty-but-deny-all allowlist plus exactly
    the one tool the task requires. Everything else — including the
    over-privileged alternative — is denied by construction.
    """
    return SecurityPolicy(
        allowed_tools=[scenario.low_priv_tool],
        default_deny=True,
    )


def _is_blocked(policy: SecurityPolicy, tool: str) -> bool:
    try:
        policy.check_tool_allowed(tool)
        return False
    except PolicyViolation:
        return True


@dataclass(frozen=True)
class ScenarioResult:
    """Per-scenario outcome."""

    scenario: Scenario
    low_priv_allowed: bool
    over_priv_blocked: bool
    over_priv_blocked_after_failure: bool

    @property
    def correct(self) -> bool:
        """True iff low-priv allowed AND over-priv blocked in both passes."""
        return (
            self.low_priv_allowed
            and self.over_priv_blocked
            and self.over_priv_blocked_after_failure
        )


def run_scenario(scenario: Scenario) -> ScenarioResult:
    """Evaluate one scenario against its least-privilege policy."""
    policy = least_privilege_policy(scenario)

    low_priv_allowed = not _is_blocked(policy, scenario.low_priv_tool)
    over_priv_blocked = _is_blocked(policy, scenario.over_priv_tool)

    # Transient-failure amplifier (ToolPrivBench): the low-priv tool "fails"
    # once, then the agent retries — modelled here as a second decision pass on
    # the over-priv tool under the SAME fixed policy. A runtime deny-by-default
    # policy is stateless w.r.t. the failure, so the block must hold.
    over_priv_blocked_after_failure = _is_blocked(policy, scenario.over_priv_tool)

    return ScenarioResult(
        scenario=scenario,
        low_priv_allowed=low_priv_allowed,
        over_priv_blocked=over_priv_blocked,
        over_priv_blocked_after_failure=over_priv_blocked_after_failure,
    )


@dataclass
class PatternStats:
    """Aggregate counts for one risk pattern (or OWASP id)."""

    total: int = 0
    over_priv_blocked: int = 0
    over_priv_blocked_after_failure: int = 0
    low_priv_allowed: int = 0
    domains: set[str] = field(default_factory=set)

    @property
    def block_rate(self) -> float:
        return self.over_priv_blocked / self.total if self.total else 0.0

    @property
    def block_rate_after_failure(self) -> float:
        return self.over_priv_blocked_after_failure / self.total if self.total else 0.0

    @property
    def low_priv_allow_rate(self) -> float:
        return self.low_priv_allowed / self.total if self.total else 0.0


@dataclass
class BenchmarkReport:
    """Full benchmark outcome."""

    source: str
    results: list[ScenarioResult]
    by_pattern: dict[str, PatternStats]
    by_owasp: dict[str, PatternStats]

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def overall_block_rate(self) -> float:
        blocked = sum(1 for r in self.results if r.over_priv_blocked)
        return blocked / self.total if self.total else 0.0

    @property
    def overall_block_rate_after_failure(self) -> float:
        blocked = sum(1 for r in self.results if r.over_priv_blocked_after_failure)
        return blocked / self.total if self.total else 0.0

    @property
    def overall_low_priv_allow_rate(self) -> float:
        allowed = sum(1 for r in self.results if r.low_priv_allowed)
        return allowed / self.total if self.total else 0.0


def run_benchmark() -> BenchmarkReport:
    """Run the full benchmark over the active scenario set."""
    scenarios, source = load_scenarios()
    results = [run_scenario(s) for s in scenarios]

    by_pattern: dict[str, PatternStats] = defaultdict(PatternStats)
    by_owasp: dict[str, PatternStats] = defaultdict(PatternStats)
    for r in results:
        for stats in (by_pattern[r.scenario.risk_pattern], by_owasp[r.scenario.owasp_id]):
            stats.total += 1
            stats.over_priv_blocked += int(r.over_priv_blocked)
            stats.over_priv_blocked_after_failure += int(r.over_priv_blocked_after_failure)
            stats.low_priv_allowed += int(r.low_priv_allowed)
            stats.domains.add(r.scenario.domain)

    # Keep stable ordering for deterministic output.
    by_pattern_ordered = {p: by_pattern[p] for p in RISK_PATTERNS if p in by_pattern}
    by_owasp_ordered = dict(sorted(by_owasp.items()))

    return BenchmarkReport(
        source=source,
        results=results,
        by_pattern=by_pattern_ordered,
        by_owasp=by_owasp_ordered,
    )
