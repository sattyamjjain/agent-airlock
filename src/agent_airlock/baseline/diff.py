"""Per-dimension drift scoring between two profiles (v0.5.8+)."""

from __future__ import annotations

from dataclasses import dataclass

from .profiler import Profile


@dataclass(frozen=True)
class DriftReport:
    """Per-dimension drift score in [0, 1]."""

    tool_mix: float
    egress_hosts: float
    tokens: float
    latency: float
    overall: float


def _tvd(a: dict[str, float], b: dict[str, float]) -> float:
    """Total-variation distance between two probability mass functions."""
    keys = set(a) | set(b)
    if not keys:
        return 0.0
    return 0.5 * sum(abs(a.get(k, 0.0) - b.get(k, 0.0)) for k in keys)


def _jaccard_distance(a: dict[str, int], b: dict[str, int]) -> float:
    """1 - |A∩B| / |A∪B| over host-set membership."""
    if not a and not b:
        return 0.0
    sa = {k for k, v in a.items() if v > 0}
    sb = {k for k, v in b.items() if v > 0}
    union = sa | sb
    if not union:
        return 0.0
    return 1.0 - len(sa & sb) / len(union)


def _scalar_drift(a: float, b: float) -> float:
    """|Δ| / max(a, b, 1) clamped to [0, 1]."""
    denom = max(a, b, 1.0)
    return min(1.0, abs(a - b) / denom)


def drift_score(reference: Profile, current: Profile) -> DriftReport:
    """Compute per-dimension drift between two profiles.

    The reference is the trusted baseline (e.g. the 7-day window
    captured before deploy); the current is what the agent has been
    doing since. All four scores are in [0, 1]; ``overall`` is the
    arithmetic mean.
    """
    tool = _tvd(reference.tool_mix, current.tool_mix)
    egress = _jaccard_distance(reference.egress_hosts, current.egress_hosts)
    # Compare the median-ish (mean) and tail (p95) for tokens; pick the larger.
    tokens = max(
        _scalar_drift(reference.tokens_mean, current.tokens_mean),
        _scalar_drift(reference.tokens_p95, current.tokens_p95),
    )
    latency = max(
        _scalar_drift(reference.latency_p50, current.latency_p50),
        _scalar_drift(reference.latency_p95, current.latency_p95),
    )
    overall = (tool + egress + tokens + latency) / 4.0
    return DriftReport(
        tool_mix=tool,
        egress_hosts=egress,
        tokens=tokens,
        latency=latency,
        overall=overall,
    )


__all__ = ["DriftReport", "drift_score"]
