"""Adversarial and comparative benchmark harnesses for agent-airlock.

One package per harness, each run from the repo root as ``python -m benchmarks.<pkg>``
(``benchmarks.<pkg>.run`` for ``agentdojo`` and ``mcp_conformance``); see
``benchmarks/CLAUDE.md``. The pytest-benchmark latency suite is ``tests/benchmarks/``
(``make bench``). The top-level ``bench_airlock.py`` / ``benchmark_*.py`` scripts predate
the packages and nothing runs them.
"""
