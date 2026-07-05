"""Run ``scan-tools`` over the taxonomy-derived MCPTox fixtures and score coverage.

The metric is deterministic and offline: no model call, no live server. Each
fixture is checked under the **permissive** policy so that only the Server-Card
trust-boundary check (SCAN002) can bite — isolating description-poisoning from the
orthogonal arg-surface / capability / type contract checks.

Definitions:

* A poisoned fixture is **detected** iff ``scan-tools`` raises a SCAN002 violation.
* A benign fixture is a **false positive** iff it raises a SCAN002 violation.
* ``detection_rate`` = detected / poisoned  (a.k.a. contract-checking coverage).
* ``precision``      = detected / (detected + false_positives).

Coverage is reported **as-is**: the declarative-side-effect fixtures carry no
imperative marker and are expected misses, so the number is deliberately not 100%.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from agent_airlock.scan import resolve_policy, scan_tool

from .corpus import PoisonCase, load_corpus

_TRUST_CODE = "SCAN002"


def _is_flagged(case: PoisonCase) -> bool:
    """True iff scan-tools raises the trust-boundary violation for this tool."""
    result = scan_tool(case.tool, resolve_policy("permissive"))
    return any(v.code == _TRUST_CODE for v in result.violations)


@dataclass
class TechniqueStat:
    technique: str
    total: int = 0
    detected: int = 0

    @property
    def rate(self) -> float:
        return self.detected / self.total if self.total else 0.0


@dataclass
class McptoxReport:
    poisoned_total: int = 0
    detected: int = 0
    benign_total: int = 0
    false_positives: int = 0
    by_technique: dict[str, TechniqueStat] = field(default_factory=dict)

    @property
    def detection_rate(self) -> float:
        return self.detected / self.poisoned_total if self.poisoned_total else 0.0

    @property
    def precision(self) -> float:
        tp_fp = self.detected + self.false_positives
        return self.detected / tp_fp if tp_fp else 1.0

    def to_dict(self) -> dict[str, object]:
        return {
            "poisoned_total": self.poisoned_total,
            "detected": self.detected,
            "detection_rate": round(self.detection_rate, 4),
            "benign_total": self.benign_total,
            "false_positives": self.false_positives,
            "precision": round(self.precision, 4),
            "by_technique": {
                t: {"total": s.total, "detected": s.detected, "rate": round(s.rate, 4)}
                for t, s in sorted(self.by_technique.items())
            },
        }


def run_benchmark() -> McptoxReport:
    """Score ``scan-tools`` over the labeled fixtures (deterministic)."""
    report = McptoxReport()
    by_tech: dict[str, TechniqueStat] = defaultdict(lambda: TechniqueStat(technique=""))
    for case in load_corpus():
        flagged = _is_flagged(case)
        if case.label == "poisoned":
            report.poisoned_total += 1
            stat = by_tech[case.technique]
            stat.technique = case.technique
            stat.total += 1
            if flagged:
                report.detected += 1
                stat.detected += 1
        else:
            report.benign_total += 1
            if flagged:
                report.false_positives += 1
    report.by_technique = dict(by_tech)
    return report
