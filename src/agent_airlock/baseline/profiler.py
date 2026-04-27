"""Profile builder + record_event helper (v0.5.8+)."""

from __future__ import annotations

import statistics
import time
from dataclasses import dataclass

from .store import BaselineStore, Event

_SEVEN_DAYS_SECONDS = 7 * 24 * 3600


@dataclass(frozen=True)
class Profile:
    """A 7-day rolling profile snapshot."""

    agent_id: str
    window_seconds: int
    event_count: int
    tool_mix: dict[str, float]  # tool_name -> fraction in [0, 1]
    egress_hosts: dict[str, int]  # host -> call count
    tokens_mean: float
    tokens_p95: float
    latency_p50: float
    latency_p95: float


def record_event(
    store: BaselineStore,
    *,
    agent_id: str,
    tool_name: str,
    egress_host: str = "",
    tokens: int = 0,
    latency_ms: float = 0.0,
    now_epoch: float | None = None,
) -> None:
    """Append one tool call to the baseline store."""
    ts = now_epoch if now_epoch is not None else time.time()
    store.append_event(
        Event(
            agent_id=agent_id,
            ts_epoch=ts,
            tool_name=tool_name,
            egress_host=egress_host,
            tokens=tokens,
            latency_ms=latency_ms,
        )
    )


def _percentile(values: list[float], p: float) -> float:
    """p in [0, 100]. Linear interpolation; safe on empty list (returns 0)."""
    if not values:
        return 0.0
    s = sorted(values)
    if len(s) == 1:
        return s[0]
    k = (len(s) - 1) * (p / 100.0)
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    frac = k - lo
    return s[lo] + (s[hi] - s[lo]) * frac


def build_profile(
    store: BaselineStore,
    agent_id: str,
    *,
    window_seconds: int = _SEVEN_DAYS_SECONDS,
    now_epoch: float | None = None,
) -> Profile:
    """Compute a fresh :class:`Profile` over the last ``window_seconds``."""
    now = now_epoch if now_epoch is not None else time.time()
    since = now - window_seconds
    events = store.events_since(agent_id, since)

    if not events:
        return Profile(
            agent_id=agent_id,
            window_seconds=window_seconds,
            event_count=0,
            tool_mix={},
            egress_hosts={},
            tokens_mean=0.0,
            tokens_p95=0.0,
            latency_p50=0.0,
            latency_p95=0.0,
        )

    tools: dict[str, int] = {}
    hosts: dict[str, int] = {}
    tokens: list[float] = []
    latencies: list[float] = []
    for e in events:
        tools[e.tool_name] = tools.get(e.tool_name, 0) + 1
        if e.egress_host:
            hosts[e.egress_host] = hosts.get(e.egress_host, 0) + 1
        tokens.append(float(e.tokens))
        latencies.append(float(e.latency_ms))

    total = sum(tools.values())
    tool_mix = {name: count / total for name, count in tools.items()}

    return Profile(
        agent_id=agent_id,
        window_seconds=window_seconds,
        event_count=len(events),
        tool_mix=tool_mix,
        egress_hosts=hosts,
        tokens_mean=statistics.fmean(tokens),
        tokens_p95=_percentile(tokens, 95),
        latency_p50=_percentile(latencies, 50),
        latency_p95=_percentile(latencies, 95),
    )


__all__ = ["Profile", "build_profile", "record_event"]
