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
  `BENCHMARK.md`. Its `sandbox=True` arm names each policy stub after the item's tool
  and compares policy refusals only, and reports the agreements split into admitted and
  refused: a parity in which either side is zero says nothing (it was 200/200 refused
  until 0.10.23). It reports a backend as having run only when admitted calls came back
  from it, and E2B is the only one it looks for: `@Airlock(sandbox=True)` dispatches
  nowhere else (until 0.10.24 it counted a Docker daemon that answered a ping).
- **`toolprivbench/`** — least-privilege block rate; `subset_scenarios()` also seeds
  blockrate's corpus. `--write` drops the hand-kept `## Re-runs` table from `RESULTS.md`.
- **`agentdojo/run.py`** — a free deterministic bound and a paid `--model` pass (every paid
  run needs `--run`, `--budget-usd` and a new, empty `--logdir` outside the repo, because a
  reused one silently replays stale trajectories, and is metered through `_claude`'s ledger
  and budget guard), dated separately; `--out` appends
  the paid block below the `CROSS-MODEL-RUNS` marker and needs `--force` to repeat a heading
  (it appends another block; a dated block is never edited). **`agentdojo/replay_published.py`**
  replays AgentDojo's published Claude runs for free (`--fetch` is GitHub API calls plus
  thousands of raw downloads into the data dir; `--write` appends a dated block);
  `claude_patch.py` is the Anthropic LLM shim the model pass installs.
- **`harness_injection/`** — matched-pair README injection against real agent CLIs; a dry
  run unless `--run`. `--write` renders `RESULTS.md`; `power.py` owns the statistics.
  `--model HARNESS=MODEL` pins a CLI's model (recorded per cell and in the rendered
  command), because a CLI's configured default can change between runs; `--run` refuses a
  claude-code cell without one. A CLI that exits
  non-zero before any observable work is an `error` cell, never a non-action, and a resumed
  checkpoint re-runs every `error` cell and any cell recorded under a different model or
  auth method (`--allow-any-auth` widens the latter).
- **`vs_gateway/`** — airlock measured live against a gateway column replayed from
  `gateway_measurement.json`, which only `gateway_harness/regen.py` rewrites.
- **`mcp_conformance/run.py`** — runs the `mcp_spec.conformance` cases; exits 1 on a failure.
- **`scantools_mcptox/`** — `airlock scan-tools` coverage on MCPTox-style fixtures (always
  printed; CI pins it) and, with `--mcptox-data`, on the real corpus; `--write` rewrites
  only the dated section between the `SCANTOOLS-MCPTOX-REAL` markers of `RESULTS.md`, the
  rest is hand-written. It, `fix_hints` and `adaptive_redteam` have no README row, so no
  date gate. `vs_gateway`, `mcp_conformance` and `adaptive_redteam` keep wholly hand-written
  `RESULTS.md` files.
- **`adaptive_redteam/`** — sentinel-driven red-team campaign over the guards; no LLM judge,
  no paid API. Its own `CLAUDE.md` extends this file, and the stricter rule wins.
  `python -m benchmarks.adaptive_redteam` is `run_session.main` (`--guard`, `--seed`,
  `--candidates`, `--nohints`), resumable against an append-only ledger under
  `ledger/<guard>/`. Every `mcp_spec/*guard*.py` module must be in its adapter registry
  (`tests/test_adaptive_redteam_registry_parity.py`).
- **`mcptox/`** — `clean-view` prints only the clean side of each server (labels written
  from it are blind to attack outcomes); `replay` scores every recorded call under G0, G and
  LP for free, and `--write` rewrites the replay block of `RESULTS.md` plus
  `replay_summary.json`, refusing a non-Linux host unless `--non-canonical-host` and a
  filesystem gate that takes `~` literally unless `--allow-unexpanded-tilde` (both recorded
  in provenance); `fresh` is the paid pass, a dry run without `--run`, and `--score RUN_ID`
  re-scores stored outputs for free. Commit `replay_summary.json` (and `fresh`'s
  `fresh_summary.json`) with the block it rendered: `tests/test_mcptox_published.py`
  recomputes the summary on a host of the same OS with the data cached, and skips without
  one. The 2026-10-17 replay block and the 2026-10-16 fresh blocks shipped without theirs
  (noted in `RESULTS.md`), so that pin has never run against them.
- **`fix_hints/`** — `--round r1|r2`, `--pilot`, `--collect RUN_ID`, `--score RUN_ID`;
  nothing is sent without `--run`, which needs `--budget-usd`, a clean git tree and the key
  for that command only; raw results stay in the run store and `--write` appends a round
  block of aggregates to `RESULTS.md` and `summary.json`. Exit codes: 0 done, 1 a pilot
  request rejected, 2 bad arguments or environment, 3 a budget cap refused the job.
- **`_claude/`** — not a harness but the shared plumbing for credit-funded Claude API runs:
  an append-only, file-locked spend ledger; a budget guard that admits a job only if its
  worst case fits under both the per-command `--budget-usd` and the ledger's cumulative
  cap (`$AIRLOCK_BENCH_HARD_CAP_USD`); pricing by exact model id (an unknown id raises,
  never `$0`); an idempotent Batch client; a run store. The ledger and raw outputs live
  under `~/.cache/agent-airlock-bench/` (`$AIRLOCK_BENCH_DATA` moves it), never in git. `python -m benchmarks._claude ledger`
  prints spend with no network, while `python -m benchmarks._claude models --run` and
  `agentdojo.replay_published --fetch` touch the network without spending credit, as do
  `mcptox --fetch` and `scantools_mcptox --fetch` (a pinned file from raw.githubusercontent.com);
  `grep -rln 'from benchmarks\._claude' benchmarks scripts` lists its users.
- Nothing runs the top-level `bench_airlock.py` / `benchmark_*.py` (pytest's `testpaths` is
  `tests/`).

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Module-Specific Conventions

- **A date names its run.** Move a README freshness marker (`_re-run_`, `_re-measured live_`,
  `last verified`) and its `docs/benchmarks/index.md` twin only after a real run. A replay
  or re-render is not one, so hand-fix a generated file rather than regenerate it under an
  old date. Dates are UTC, the day `check_benchmark_freshness.py` reads; every harness that
  takes `--date` defaults it to the UTC day, so a run after midnight IST still stamps the
  day before.
- **Written to survive a hostile read.** `bench(...)` commits publish adversarial results
  under `benchmarks/`: a null result ships as a null result, a re-run that comes back
  weaker ships weaker, a broken harness is fixed before its output is quoted, an expiring
  row is re-measured rather than re-dated and a wrong diagnosis stays on the record beside
  its correction (#179), and the sample scope is stated inline rather than rounded up.
  Match this register when touching `benchmarks/` or `BENCHMARK.md`.
- **Nothing is dropped.** Failed runs, did-not-run arms, wrong diagnoses and superseded runs
  stay beside their correction; unmeasured is "not measured" / `n=0`, never `0`; a null
  ships with its benign control and every denominator; incumbents that were not executed
  are scope-claimed.
- **Copies are hand-synced — grep the old figure repo-wide.** README, `docs/benchmarks/`,
  `SECURITY.md`, `ROADMAP.md`, `demo/`, harness READMEs, and prose hard-coded in
  `scripts/generate_benchmark.py` (re-render with `make benchmark`) and `blockrate/report.py`
  all restate results.
- **Every file a `docs/benchmarks/` page snippet-includes emits absolute blob URLs**
  (`grep -rn -- '--8<--' docs/benchmarks/` lists them: `BENCHMARK.md` and the `RESULTS.md`
  of `blockrate`, `mcptox`, `fix_hints`, `adaptive_redteam`): each renders at its own path,
  in the tree, and inside a docs page that must be in the nav, so a relative link breaks in
  two of the three.
- **Register a new README row** in `BENCHMARKS` (`scripts/check_benchmark_freshness.py`)
  under a string unique to its line, or its date goes unchecked, and give it a twin row in
  `docs/benchmarks/index.md` whose bold first cell matches README's (case, `*`, backticks
  and hyphens ignored) with the same date: the default mode, run by CI's `docs` job, pairs
  rows by title and fails on a missing or mismatched twin.
- **Tests pin published figures** (`grep -rln 'from benchmarks' tests/`): move a pin and its
  `RESULTS.md` together, make run-dependent asserts conditional, and leave `power.Z_95`
  alone — the published intervals were computed with it.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: dependencies -->
## Key Dependencies

- **`[bench]` is just `agentdojo`, and no workflow installs it**, so most of the AgentDojo
  shim and the smoke tests skip in CI — and without it `python -m benchmarks.agentdojo.run`
  prints an install hint and exits 0. Exception: the shim's model-id routing (`_infer`,
  `_is_auto_registerable`) is plain string logic with no `agentdojo` import, so
  `tests/test_agentdojo_model_routing.py` pins it where CI runs.
- **Paid or host-touching runs — ask before starting one:** `agentdojo --model` (a provider
  key such as `OPENAI_API_KEY`; price the model id in `_MODEL_PRICES`), `harness_injection
  --run` (logged-in `claude` / `codex` / `cursor-agent` CLIs; its `--checkpoint` file is not
  gitignored, and every codex cell leaves a trusted-project entry for its temp dir in
  `~/.codex/config.toml`), `gateway_harness/regen.py` (Docker, the `docker mcp` plugin and the echo
  image; it writes into `~/.docker/mcp/catalogs/`) and plain `python -m benchmarks.blockrate`
  when `[sandbox]` is installed and `E2B_API_KEY` set (its sandbox arm sends the benign
  probes and every policy item the allow-list admits to E2B).
- **Runs through `_claude/` spend the Claude API credit — ask before starting one too:**
  `mcptox fresh --run`, `fix_hints --run`, `agentdojo --model <claude id> --run` and
  `scripts/smoke_frameworks.py --run` (each sends nothing without `--run`; `--run` needs
  `--budget-usd`). Read the key per command from Keychain, never export it:
  `ANTHROPIC_API_KEY="$(security find-generic-password -s anthropic-credits -w)"` before the
  command. An exported key overrides the Claude Code login, so every `claude -p` run would
  bill the credit.
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
