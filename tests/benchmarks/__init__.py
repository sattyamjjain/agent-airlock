"""pytest-benchmark suite for agent-airlock hot paths.

Run with:
    pytest tests/benchmarks/ --benchmark-only

Save a baseline:
    pytest tests/benchmarks/ --benchmark-only --benchmark-save=baseline

Compare against baseline (fail CI on >15% regression):
    pytest tests/benchmarks/ --benchmark-only \
        --benchmark-compare=0001 --benchmark-compare-fail=mean:15%
"""
