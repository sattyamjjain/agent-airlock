"""Benchmark the happy-path overhead of an `@Airlock`-wrapped call.

The numbers we care about:

- `bench_airlock_passthrough` — unmodified call through `@Airlock()` with
  no policy, no sanitizer, no sandbox. Measures the raw decorator overhead.
- `bench_airlock_with_strict_validation` — an `@Airlock()` call where the
  function has typed parameters that Pydantic validates strictly.

We run these in-process against the real decorator; `pytest-benchmark`
handles warmup + statistical sampling. A launch-day regression gate can
diff against a saved baseline (see `tests/benchmarks/__init__.py`).
"""

from __future__ import annotations

from agent_airlock import Airlock


def _make_passthrough():
    @Airlock()
    def fn(x: int, y: int) -> int:
        return x + y

    return fn


def _make_strict():
    @Airlock()
    def fn(name: str, count: int) -> str:
        return f"{name}-{count}"

    return fn


def test_airlock_passthrough_overhead(benchmark):
    fn = _make_passthrough()
    result = benchmark(fn, x=1, y=2)
    assert result == 3


def test_airlock_strict_validation_overhead(benchmark):
    fn = _make_strict()
    result = benchmark(fn, name="alice", count=42)
    assert result == "alice-42"
