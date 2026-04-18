# Benchmarks

Microbenchmarks for agent-airlock hot paths. Covered paths:

- `test_bench_core.py` — happy-path overhead of an `@Airlock()` call (raw
  decorator + Pydantic strict validation).
- `test_bench_sanitizer.py` — output sanitizer on a mixed-PII blob and on a
  4 KB clean payload.
- `test_bench_mcp_oauth.py` — MCP 2025-11-25 PKCE round-trip and
  `validate_access_token_audience` (server-side per-tool-call check).

## Running

Benchmarks are **excluded from the default pytest run** (see
`[tool.pytest.ini_options].addopts` in `pyproject.toml`). Invoke them
explicitly:

```bash
# One-off run
pytest tests/benchmarks/ --benchmark-only --no-cov

# Save a baseline (writes to .benchmarks/)
pytest tests/benchmarks/ --benchmark-only --no-cov --benchmark-save=baseline

# Compare against that baseline, fail CI on >15% mean regression
pytest tests/benchmarks/ --benchmark-only --no-cov \
    --benchmark-compare=0001_baseline --benchmark-compare-fail=mean:15%
```

`--no-cov` skips the main coverage gate, which is meaningless in isolated
benchmark mode (benchmarks don't exercise full code paths).

## Local baseline on your machine

Numbers are machine-dependent, so a baseline captured on a laptop won't be
comparable to one captured on CI. Re-baseline on each target platform.

## CI regression gate (manual follow-up)

Adding a benchmark-regression-gate job to `.github/workflows/ci.yml`
requires a maintainer with `workflow` scope. Suggested job:

```yaml
  benchmarks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -e ".[dev]"
      - name: Fetch saved baseline
        uses: actions/cache@v4
        with:
          path: .benchmarks
          key: benchmarks-${{ runner.os }}-py3.11
      - name: Run benchmarks (no gate on first run)
        run: |
          if ls .benchmarks/Linux-CPython-3.11-64bit/*.json >/dev/null 2>&1; then
            pytest tests/benchmarks/ --benchmark-only --no-cov \
              --benchmark-compare --benchmark-compare-fail=mean:15%
          else
            pytest tests/benchmarks/ --benchmark-only --no-cov \
              --benchmark-save=ci-baseline
          fi
```

Tune the `15%` gate if flakiness shows up on the runner; a pinned runner
type + `--benchmark-min-rounds=10` usually stabilises it.
