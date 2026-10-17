"""Adaptive red-team campaign harness for agent-airlock's own guards.

This package drives *harmless sentinels* (canary files, a 127.0.0.1 listener, a
``__reduce__`` that appends a marker to an in-process list, recorded spawn argv)
through agent-airlock's guards to find fail-opens. It never authors, stores, or
runs a working exploit, and it makes no network, LLM, or paid API calls.

Entry points:

- :mod:`benchmarks.adaptive_redteam.oracle` — ground-truth classification.
- :mod:`benchmarks.adaptive_redteam.canaries` — the sentinel sinks.
- :mod:`benchmarks.adaptive_redteam.adapters` — one adapter per guard target.
- :mod:`benchmarks.adaptive_redteam.run_session` — the resumable CLI runner.
- :mod:`benchmarks.adaptive_redteam.stats` — rule-of-three bounds and histograms.
"""

from __future__ import annotations

SCHEMA_VERSION = 1

__all__ = ["SCHEMA_VERSION"]
