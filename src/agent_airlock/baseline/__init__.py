"""Per-agent behavioral baselines (v0.5.8+).

Motivation
----------
[VentureBeat RSAC 2026 (2026-04-22)](https://venturebeat.com/security/rsac-2026-agentic-soc-agent-telemetry-security-gap)
called out that every major vendor shipped runtime intercept and
none shipped per-agent behavioral baselines. Microsoft Agent
Governance Toolkit ships sub-millisecond intercept; agent-airlock's
defensible wedge for the next 6 months is **per-agent baselines +
drift score**.

A baseline is a 7-day rolling profile of:

- Tool-call mix (which tools, with what frequency)
- Egress destinations (hostnames the agent reaches)
- Token-spend distribution (mean / p95 per call)
- Latency distribution (p50 / p95 per call)

Drift is reported as a 0–1 score per dimension. A preset can declare
``requires_baseline: true`` and refuse to run an agent whose
baseline is missing or whose drift exceeds threshold.

The on-disk store is sqlite3-backed and shares the WAL pattern from
``agent_commerce_caps``.

Surfaces
--------
- :func:`record_event` — append a tool call to the baseline store
- :class:`Profile` — typed snapshot of an agent's last 7 days
- :func:`build_profile` — compute / refresh the snapshot
- :func:`drift_score` — diff two profiles, returning a per-dimension
  score in [0, 1]

CLI: see ``airlock.cli.baseline``.
"""

from __future__ import annotations

from .diff import DriftReport, drift_score
from .profiler import Profile, build_profile, record_event
from .store import BaselineStore, SQLiteBaselineStore

__all__ = [
    "BaselineStore",
    "DriftReport",
    "Profile",
    "SQLiteBaselineStore",
    "build_profile",
    "drift_score",
    "record_event",
]
