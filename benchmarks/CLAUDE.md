# Module: benchmarks

<!-- AUTO-MANAGED: module-description -->
## Purpose

Adversarial and comparative benchmark harnesses, one package each, run from the repo root as
`python -m benchmarks.<pkg>` (`benchmarks.<pkg>.run` for `agentdojo` and
`mcp_conformance`). None of it ships or is imported by `src/`. The pytest-benchmark latency
suite is a different thing: `tests/benchmarks/`, run by `make bench`.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: architecture -->
## Module Architecture

- **`blockrate/`** — policy + guard-chain block rate, with incumbents scope-claimed.
  `--write` re-measures into `RESULTS.md`; `render_comparison_section` also feeds
  `BENCHMARK.md`.
- **`toolprivbench/`** — least-privilege block rate; `subset_scenarios()` also seeds
  blockrate's corpus. `--write` drops the hand-kept `## Re-runs` table from `RESULTS.md`.
- **`agentdojo/run.py`** — a free deterministic bound and a paid `--model` pass, dated
  separately; `--out` appends the paid block below the `CROSS-MODEL-RUNS` marker and needs
  `--force` to repeat a heading.
- **`harness_injection/`** — matched-pair README injection against real agent CLIs; a dry
  run unless `--run`. `--write` renders `RESULTS.md`; `power.py` owns the statistics.
- **`vs_gateway/`** — airlock measured live against a gateway column replayed from
  `gateway_measurement.json`, which only `gateway_harness/regen.py` rewrites.
- **`mcp_conformance/run.py`** — runs the `mcp_spec.conformance` cases; exits 1 on a failure.
- **`scantools_mcptox/`** — `airlock scan-tools` coverage on MCPTox-style fixtures; it has
  no README row, so no date gate. It, `vs_gateway` and `mcp_conformance` keep hand-written
  `RESULTS.md` files.
- Nothing runs the top-level `bench_airlock.py` / `benchmark_*.py` (pytest collects only
  `test_*.py`).

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Module-Specific Conventions

- **A date names its run.** Move a README freshness marker (`_re-run_`, `_re-measured live_`,
  `last verified`) and its `docs/benchmarks/index.md` twin only after a real run. A replay
  or re-render is not one, so hand-fix a generated file rather than regenerate it under an
  old date.
- **Nothing is dropped.** Failed runs, did-not-run arms, wrong diagnoses and superseded runs
  stay beside their correction; unmeasured is "not measured" / `n=0`, never `0`; a null
  ships with its benign control and every denominator; incumbents that were not executed
  are scope-claimed.
- **Copies are hand-synced — grep the old figure repo-wide.** README, `docs/benchmarks/`,
  `SECURITY.md`, harness READMEs, and prose hard-coded in `scripts/generate_benchmark.py`
  (re-render with `make benchmark`) and `blockrate/report.py` all restate results.
- **`blockrate/report.py` emits absolute blob URLs**: its text renders at its own path, in
  the root `BENCHMARK.md`, and inside `docs/benchmarks/` pages (each of which must be in
  the nav).
- **Register a new README row** in `BENCHMARKS` (`scripts/check_benchmark_freshness.py`)
  under a string unique to its line, or its date goes unchecked.
- **Tests pin published figures** (`grep -rln 'from benchmarks' tests/`): move a pin and its
  `RESULTS.md` together, make run-dependent asserts conditional, and leave `power.Z_95`
  alone — the published intervals were computed with it.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: dependencies -->
## Key Dependencies

- **`[bench]` is just `agentdojo`, and no workflow installs it**, so the AgentDojo shim and
  smoke tests always skip in CI — and without it `python -m benchmarks.agentdojo.run`
  prints an install hint and exits 0.
- **Paid or host-touching runs — ask before starting one:** `agentdojo --model` (a provider
  key such as `OPENAI_API_KEY`; price the model id in `_MODEL_PRICES`), `harness_injection
  --run` (logged-in `claude` / `codex` / `cursor-agent` CLIs; its `--checkpoint` file is not
  gitignored) and `gateway_harness/regen.py` (Docker, the `docker mcp` plugin and the echo
  image; it writes into `~/.docker/mcp/catalogs/`).
- **Internal:** mostly the package root and `agent_airlock.policy`; recount with
  `grep -rhoE 'from agent_airlock[.a-z_]*' benchmarks/ --include='*.py' | sort -u`.
  `vs_gateway/__main__.py` imports `structlog` directly, so it needs `[logging]` or `[dev]`.
- **No lint, type or security gate covers this tree** (CI's ruff targets `src/ tests/`,
  mypy `src/`, and bandit excludes it). Only `tests/` and `generate_benchmark.py --check`
  execute its code in CI.

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Notes

Add module-specific notes here — this section is never auto-modified.

<!-- END MANUAL -->
