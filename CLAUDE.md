# agent-airlock

<!-- AUTO-MANAGED: project-description -->
## Overview

**agent-airlock** — an in-process, deny-by-default contract layer and type-checker for AI
agent tool calls. It intercepts calls into MCP (Model Context Protocol) servers and agent
frameworks, validates arguments strictly, applies policy, and sandboxes dangerous execution.

The wedge is argument validation at the call boundary; every other layer wraps it.

- Ghost-argument stripping/rejection (parameters the LLM invented)
- Pydantic V2 strict validation, no type coercion; self-healing errors carrying `fix_hints`
- Policy engine: RBAC, token-bucket rate limits, time windows, per-model-tier cost budgets,
  per-run resource-amplification budgets
- PII/secret detection and masking; Indic PII is opt-in (`pii_locales=["in"]`)
- Sandboxed execution via pluggable backends (E2B Firecracker, Modal, Docker, local, plus a
  beta, opt-in Anthropic Managed Agents backend)
- `mcp_spec/` guards mapped to specific named CVEs and MCP spec clauses — stdio injection,
  OAuth, DNS rebinding, SSRF, eval-RCE, WebSocket origin hijack, task lifecycle, handle trust
- Framework adapters: FastMCP, LangChain/LangGraph, Anthropic (Messages, Claude Agent SDK,
  Managed Agents), OpenAI, Gemini, PydanticAI, CrewAI, smolagents, Google ADK, Google Model
  Armor
- Fleet-wide kill switch (quorum-signed freeze) checked before any other gate
- `airlock` CLI — one dispatcher fronting every `cli/<name>.py`; the `_COMMANDS` table in
  `cli/__main__.py` (or `airlock --help`) is the authoritative subcommand list

**The installed core is Pydantic-only** (plus `tomli` on Python 3.10). Everything else —
structlog included — lives in an extra. `src/agent_airlock/_log.py` falls back to a
stdlib-logging shim when structlog is absent. `scripts/check_core_deps.py` enforces this as
an exhaustive allowlist; do not add a core dependency.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: build-commands -->
## Build & Development Commands

```bash
pip install -e ".[dev]"            # editable install with dev deps

# Optional extras — install only what you need. Full set:
#   logging bench sandbox modal mcp claude-agent model-armor console
#   redis crypto attested pydantic-ai crewai google-adk all dev docs
pip install -e ".[sandbox]"        # E2B Firecracker micro-VM execution
pip install -e ".[redis]"          # distributed rate limiter
pip install -e ".[all]"            # runtime extras EXCEPT modal, bench, attested (and dev/docs)

make test          # pytest tests/ -v --no-cov
make coverage      # pytest with coverage (floor enforced; see [tool.coverage.report])
make lint          # ruff check + ruff format --check + mypy src/
make format        # ruff format + ruff check --fix
make bench         # pytest-benchmark suite (tests/benchmarks/, --ignore'd by default addopts)
```

Repo-specific claim gates. `make help` lists every target, and
`tests/test_makefile_help.py` fails if a target is missing from it or from `.PHONY`:

```bash
make benchmark               # regenerate BENCHMARK.md (guard-suite block-rate corpus)
make test-badge              # regenerate the TEST-BADGE block in README.md
make egress-bench            # CVE egress walker over tests/cves/fixtures/
make verify-corpus           # verify wild_payload_corpus MANIFEST.sha256
make check-links             # dead relative links; docs/ pages must link inside docs/
make check-docs-api          # docs and example code use agent_airlock API that exists
make check-cve-catalog       # docs/cves/index.md matches the tests/cves/ suite
make check-docs              # mkdocs build --strict, built OUTSIDE the tree (see Architecture)
make check-changelog         # post-release drift: [Unreleased] must be empty after a release
make check-changelog-release # pre-tag: [Unreleased] must be NON-empty — red by design between releases
make check-benchmark-freshness          # dated README rows; every docs/benchmarks/ page in nav
make check-benchmark-freshness-release  # pre-tag: no benchmark claim older than 30 days
make check-registry-parity              # declared version must not outrun PyPI
make check-registry-parity-distance     # release-only: refuse to skip a version
```

What gates a merge — `ci.yml` jobs, on PRs and pushes to `main`:

- `test` (full Python matrix) — installs `.[dev,redis]`; ruff check, mypy, pytest with the
  coverage floor, `generate_benchmark.py --check`, and a pytest-benchmark smoke run that
  asserts the suite executes (deliberately not a latency threshold).
- `lint` — `ruff format --check` only.
- `docs` — `mkdocs build --strict`, `check_links.py`, `gen_cve_catalog.py --check`, and the
  **default** modes of `check_benchmark_freshness.py` and `check_changelog.py`.
- `bare-install` — `check_core_deps.py` against a no-extras install.
- `docker-sandbox` — builds the repo `Dockerfile`, runs `pytest -m docker`, and greps for an
  exact passed-count, so adding or removing a docker-marked test means editing that count.
- `security` — bandit (`-c pyproject.toml`) and a CycloneDX SBOM; `safety` runs with
  `continue-on-error`, so it is advisory only.
- `version-tag-guard` (pushes to `main` only) — `check_version_tagged.py`,
  `check_changelog_heading.py`, `check_registry_parity.py`.

`publish.yml` (on a published release) adds `check_benchmark_freshness.py --release`,
`check_registry_parity.py --distance-only`, a GitHub-description drift check and
`twine check`. That job installs only `build` and `twine`, so any script it runs must stay
stdlib-only. `make check-changelog-release` runs in no workflow: it is a manual pre-tag
check, and wiring it per-PR would fail every PR between releases.

`scripts/check_docs_api.py` imports the package, so it runs in `test` as
`tests/test_docs_api_gate.py` rather than in `docs`, which installs only mkdocs. It checks
names imported from `agent_airlock` in each Python fence and `examples/` script: the import
resolves, keywords match the signature, attributes exist.

`test` installs the `[redis]` extra because the redis-backed modules open with
`pytest.importorskip("fakeredis")`, and a skipped module reads like a passing one in the
summary line. If you add an `importorskip`, add its dependency to a CI job in the same PR.

Docker integration tests are **opt-in** — default `addopts` carries `-m 'not docker'`; run
them with `pytest -m docker`. `cve-watcher.yml` polls NVD on a schedule, diffs against the
ledger and files triage issues; it is not a merge gate.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: architecture -->
## Architecture

`src/` layout, single package, hatchling build. The `airlock` console script dispatches to
every `agent_airlock.cli.<name>:main(argv)` in space-form (`airlock scan-tools`), so flags
are identical to the `python -m agent_airlock.cli.<name>` long form. Three pre-dispatcher
scripts (`airlock-explain`, `airlock-conformance`, `airlock-scan-tools`) survive as stable
aliases. Subtree `CLAUDE.md` files live in `src/agent_airlock/mcp_spec/`,
`src/agent_airlock/integrations/`, `tests/cves/` and `benchmarks/`; they are excluded from
the sdist and wheel (`[tool.hatch.build.targets.*]`), so they never reach a user's
site-packages.

Repo-level directories outside the package: `tests/` (mostly mirrors the package's
subpackages; `tests/cves/` is the signed CVE regression suite), `benchmarks/` (agentdojo,
blockrate, harness_injection, mcp_conformance, scantools_mcptox, toolprivbench, vs_gateway),
`scripts/` (`check_*` claim gates, the generators behind `make benchmark` / `test-badge` /
`check-cve-catalog`, `smoke_*` end-to-end drivers, `cve_watcher.py`), `docs/` (mkdocs
source), `examples/`, `demo/` (runnable live demo), `presets/`, `schemas/`, `tools/`, and
`.claude-plugin/` (marketplace manifest).

**There is no committed `site/`.** The docs site is served from the `gh-pages` branch,
which `docs.yml` rebuilds with `mkdocs gh-deploy --force` on pushes to `main` that touch
`docs/`, `mkdocs.yml` or `src/`. `site/` is gitignored — do not add it back; stale
committed HTML once made project-classifying tooling read this library as a web app.
`make check-docs` builds to `$TMPDIR/agent-airlock-mkdocs-check` for the same reason.

Generated files stay where their generator writes them. `BENCHMARK.md` and
`benchmarks/blockrate/RESULTS.md` reach the site through `pymdownx.snippets` includes under
`docs/benchmarks/` (`check_paths` is on, so a moved file fails the strict build). Never copy
them into `docs/`, and keep cross-tree links inside them absolute.

```
src/agent_airlock/
├── core.py            @Airlock decorator — the entrypoint; sync + async
├── __init__.py        public API surface (large, explicit __all__)
├── config.py          ENV (AIRLOCK_*) > constructor > airlock.toml
├── exceptions.py      AirlockError base only; exception classes live where they're raised
├── testing.py         state-reset helpers for test isolation
├── _log.py            structlog-or-stdlib logging shim
│
├── VALIDATION   validator.py, unknown_args.py, safe_types.py, self_heal.py, handles.py
├── POLICY       policy.py, policy_presets.py, preset_loader.py, capabilities.py,
│                oversight.py, identity.py, redis_rate_limit.py, amplification.py,
│                capability_caps/, policy_compiler/, budget/
├── EXECUTION    sandbox.py, sandbox_backend.py, streaming.py, context.py,
│                conversation.py, runtime/; circuit_breaker.py and retry.py are
│                exported helpers, not part of the @Airlock call path
├── SANITIZE     sanitizer.py, audit.py, audit_otel.py, observability.py,
│                cost_tracking.py, trace_redaction.py
├── VACCINE      filesystem.py, network.py, honeypot.py, vaccine.py,
│                camouflage_resistant.py, ssrf_egress_guard.py, sequence_guard.py,
│                action_contradiction_gate.py, tool_output_trust_guard.py,
│                done_receipt_guard.py
├── mcp_spec/    per-CVE / per-spec-revision MCP guards — largest subpackage, own CLAUDE.md
├── mcp/         FastMCP integration (MCPAirlock, secure_tool, create_secure_mcp_server)
│                plus cimd.py — pinned CIMD trust anchor, denies on drift
├── kill_switch/ quorum-signed fleet freeze — registry, signer, quorum, broadcast, transports/
├── data/        dated snapshots (model pricing, advisory blast radius)
├── fixtures/    dated pattern files (redaction patterns)
├── ADVERSARIAL  anomaly.py, regression_corpus.py, sdk_provenance.py, a2a.py,
│                mcp_proxy_guard.py, negotiation_bench.py, corpus/wild_payload_corpus/
├── ATTEST       attest/, conformance/, baseline/, pack/, packs/, scan/, graph/, studio/,
│                owasp_agentic_coverage/
├── integrations/  every other framework adapter, plus adapters/ (commerce caps) and
│                  scanners/ (pluggable IDE-scanner protocol) — own CLAUDE.md
└── cli/           subcommands behind the unified dispatcher
```

**Call flow through `@Airlock`** — `_pre_execution` gates, then execute, then
`_post_execution`. Steps 0–6 match the `# Step N` comments in `core.py`:

0. Kill switch — a fleet freeze refuses before the arguments are even examined
1. Ghost arguments (BLOCK / STRIP_AND_LOG / STRIP_SILENT)
2. Resolve policy (static, or `Callable[[AirlockContext], SecurityPolicy]`) and check it
   against the caller's identity (the call's context object, else the one set around it)
   - 2.5 behavioral tool-call sequence guard
   - 2.6 action-time contradiction gate
   - 2.7 unsafe-deserialization content guard
   - 2.8 per-run resource-amplification budget — after the gates above, so a call that was
     going to be refused anyway is never charged to the run's ledger
3. Filesystem path validation
4. Capability requirements
5. Endpoint policy validation
6. Per-model-tier budget check — the tier, token count and model id come from context
   metadata (`_call_metadata`), never from the tool's arguments, which the model writes
7. Execute (unnumbered in code) — Pydantic strict validation, then run locally or in the
   sandbox, inside the network airgap when one is configured. Sandbox mode validates in
   the parent (`validate_sandbox_args`) before dispatch, so both paths fail the same way
8. `_post_execution` — sanitize output via `_sanitize_tool_output` (a string is masked and
   truncated; a dict, list, tuple or set is masked value by value and keeps its type; any
   other object is returned as-is and its detections reported as not masked) → audit log →
   mark untrusted output (when the policy sets `reauth_on_untrusted_reinvocation`) →
   reconcile actual vs estimated cost

Blocked calls return an `AirlockResponse`. Validation failures return structured JSON
carrying `fix_hints` for the model to retry against, rather than raising.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Code Conventions

- **Python 3.10+**, `from __future__ import annotations` first. Use `X | Y`, not `Optional`.
- **mypy strict** (`disallow_untyped_defs`, `warn_return_any`, pydantic plugin). Type every
  signature. `TypeVar` / `ParamSpec` / `@overload` for generics.
- **ruff**, line length 100, target `py310`. Selected: E, W, F, I, B, C4, UP, ARG, SIM;
  globally ignored: E501, SIM102, SIM103, B027. The `py310` target is deliberate — bumping
  it makes UP036/UP042 fire and emit code that breaks on 3.10. Do not raise it.
  Per-file `ARG` ignores exist for `integrations/`, `cli/`, `anomaly.py`, tests and examples —
  those unused args are callback-interface signatures, so do not "fix" them.
- **bandit** reads `[tool.bandit]` in `pyproject.toml` (CI passes `-c pyproject.toml`).
  B101 (`assert`) is deliberately not skipped — it caught narrowing asserts on a security
  path. Where an assert is genuinely fine, use a scoped `# nosec B101 - <reason>`.
- **Pydantic V2 strict mode** for validation. `@dataclass` with `field(default_factory=...)`
  for structured data; prefer it over plain dicts.
- **Enums** extend `str, Enum` so they serialize to JSON.
- **Logging** through `agent_airlock._log` (structlog when installed, stdlib shim otherwise):
  `from agent_airlock._log import structlog` then
  `logger = structlog.get_logger("agent-airlock.<dotted.module.path>")`. Never
  `import structlog` directly — the shim is the only module that does. Structured kwargs,
  never f-strings.
- **Imports** stdlib → third-party → first-party (`known-first-party = ["agent_airlock"]`).
- **Naming**: snake_case functions, PascalCase classes, UPPER_SNAKE constants, `_` private.
- **Docstrings** Google-style (Args / Returns / Raises).
- **Exceptions** live in the module that raises them, mostly subclassing
  `exceptions.AirlockError`; they store details as attributes and call `super().__init__()`.
- `TYPE_CHECKING` guards for type-only imports.
- **Tests**: `Test<Feature>` classes with `test_<scenario>` methods; keep each under ~5s.
- **Commits**: conventional — `feat:` `fix:` `docs:` `chore:` `ci:` `security:` `bench:`.
  Branches `feat/<short>` `fix/<short>` `chore/<short>`. Squash-merge into `main`, which
  stays tag-able at all times. The squash subject is the PR title, so write the PR title in
  conventional form too — prose PR titles are how unprefixed subjects reached `main`.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: patterns -->
## Detected Patterns

- **Decorator entrypoint** — `@Airlock()` wraps a function with the full layer stack, and
  preserves `__signature__` / `__annotations__` so framework introspection still works.
- **Defense-in-depth** — validation → policy → capability → filesystem → network → sandbox.
  Each layer exists because an earlier one proved insufficient for a specific CVE.
- **Guard + preset pairs** — `mcp_spec/` guards come in three shapes (see
  `mcp_spec/CLAUDE.md`); a guard's preset factory, usually `*_defaults()`, lives in
  `policy_presets.py`. Register it with `@preset` **and** list it in
  `policy_presets.__all__`, and any `policy_presets.<name>` named in README or `docs/` must
  resolve to a registered factory (`tests/presets/test_registry_parity.py`). An
  unregistered preset never shows up in `list_active()`. Many guards are re-exported from
  the package root (`agent_airlock.__all__`); `mcp_spec/__init__.py` exports none.
- **Lazy optional imports** — anything from an extra (`e2b`, `redis`, `cryptography`,
  `structlog`, framework SDKs) is imported inside the function that needs it, behind
  `try/except ImportError`, raising an error that names the extra to install. This is what
  keeps the `bare-install` job green.
- **Deny-by-default** — unknown tier, unregistered manifest, and unpinned spec revision all
  fail closed. New branches should preserve that direction.
- **Context propagation** — `contextvars`-backed `AirlockContext`; `get_current_context()`
  is available inside the wrapped tool, and a policy may be a callable over that context
  for per-tenant / per-workspace rules.
- **Declarative presets** — `presets/*.yaml` use a restricted YAML dialect
  (`schema_version: 1`) that `preset_loader` parses without PyYAML. Every `factory:`
  value, even on an `enabled: false` entry, must name a preset registered in
  `policy_presets.list_active()` — `tests/presets/test_ox_mcp_yaml.py` checks this
  against every file under `presets/`, not just the one it's named for.
- **Dated snapshots** — pricing tables, advisory blast-radius data and redaction patterns
  ship as dated files under `data/` and `fixtures/`; a refresh is a new dated file, not an
  edit to the old one.
- **Also by name** — `airlock attest` receipts (identity plus assume/guarantee
  `LayerContract`); `SandboxPool` warm pool hiding cold starts; `vaccinate()` monkeypatching
  third-party `@tool` decorators; honeypot deception returning plausible fake success.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: git-insights -->
## Git Insights

History is dominated by `feat:` and `fix:`, with steady `docs:`, `chore:` and `bench:`
work (`git log --format=%s | cut -d: -f1 | sort | uniq -c` recounts it). Three themes drive
most recent development:

1. **Per-CVE guards.** Most `feat:` commits add one guard for one named advisory
   (`mcp_spec/*_guard.py`), its preset defaults, and a regression fixture. Commit messages
   carry the primary-source URL. `cve-watcher.yml` files triage issues for argument-shaped
   CVEs; each gets a disposition from the vocabulary in `docs/cve-triage.md`
   (`in-scope-and-scheduled`, `in-scope-and-deferred-until-<DATE>`,
   `out-of-scope-because-<clause>`), and the queue closes with a fixture or a public,
   reasoned refusal (#177). An in-scope CVE that an existing guard already refuses lands as
   a second-defence fixture, not a new guard (#226).
2. **Claims integrity.** A distinct class of `fix(meta):` / `fix:` commits exists purely
   to stop the README/docs/registry over-claiming — "ten places the repo claimed something
   the code contradicted" (#175) is the archetype, and #215 extended it to the version
   `SECURITY.md` and `CITATION.cff` state. Machine-checked gates (`scripts/check_*.py`, the
   badge, changelog, version and README-shape tests) exist so this drift fails CI instead
   of shipping. The README was cut by roughly nine-tenths and its size gated
   (`tests/test_readme_shape.py`, #180); long-form material belongs in `docs/`.
3. **Benchmark honesty.** `bench(...)` commits publish adversarial results under
   `benchmarks/` and are written to survive a hostile read: a null result ships as a null
   result, a re-run that comes back weaker ships weaker, a broken harness is fixed before
   its output is quoted, an expiring row is re-measured rather than re-dated and a wrong
   diagnosis stays on the record beside its correction (#179), and the sample scope is
   stated inline rather than rounded up. Match this register when touching `benchmarks/`
   or `BENCHMARK.md`.

Practical consequence: **do not add a capability claim to README, docs, or a preset
description unless code and a test back it.** There is tooling that will fail the build on it.
A benchmark number is a claim too — report the run you actually got, including a zero.

The same rule applies to this file. Counts of modules, classes or commits rot on every
merge and are not gated by anything, so prefer the structural fact plus the command that
recounts it over a number pasted into prose.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: best-practices -->
## Best Practices

- Read `AGENTS.md` first — it holds the load-bearing contributor contract.
- Default safety posture:
  `@Airlock(policy=STRICT_POLICY, sandbox=True, sandbox_required=True)`.
  Anything weaker needs a one-line justification in the docstring. `STRICT_POLICY`
  requires an agent identity: a context object as the tool's first argument, or
  `with AirlockContext(agent_id=...)` around the call (`_caller_identity` in `core.py`).
- **Forbidden:** `subprocess.run(..., shell=True)` anywhere in `src/`; raw `eval()` /
  `exec()`; mocking fixtures in CVE regression tests. `mcp_spec/manifest_only_mode.py` is
  the only `subprocess` importer in `src/` and does not use `shell=True`; the `shell=True`
  grep hits in `capabilities.py` (a docstring) and `cli/doctor.py` (a detection regex) are
  text, not calls.
- **CVE fixtures are signed history.** Files under `corpus/wild_payload_corpus/` and
  `tests/cves/` require a primary-source URL in the commit message, and the same PR
  regenerates `docs/cves/index.md` with `python3 scripts/gen_cve_catalog.py` — it is built
  from the `tests/cves/` docstring headers, so never hand-edit it. Never remove a check
  without naming the CVE that motivated it.
- Every `feat:` needs at least one regression test.
- Run `make lint` and `pytest -m "not docker"` before committing.
- `bare-install` is the job that enforces the Pydantic-only core — if you add an import
  that is not in an extra, that job fails, not the test suite.
- **Version bumps** must move every surface a test pins — `pyproject.toml` + `__version__`,
  `.claude-plugin/plugin.json`, `CITATION.cff` (version plus that release's CHANGELOG
  date), the supported minor line in `SECURITY.md`, the README badge (`make test-badge`) —
  and need a conformant `## [X.Y.Z]` CHANGELOG heading. Tag `vX.Y.Z` within one commit of
  the bump, or `version-tag-guard` turns `main` red.
- `make test-badge` rewrites the README test count; the hand-written copies under
  `docs/distribution/` must match it in the same commit (`test_numeric_claim_parity.py`).
- A new page under `docs/benchmarks/` must be added to the `mkdocs.yml` nav, and the dates
  in `docs/benchmarks/index.md` must match the README's — `check_benchmark_freshness.py`
  fails on either gap.
- The README is gated on shape (`tests/test_readme_shape.py`: line and word ceilings, code
  in the first screenful, no table of contents) and on its framework and version-pin
  claims. Put new material in `docs/` and link it; do not grow the README.
- `scripts/smoke_*.py` are end-to-end drivers runnable outside pytest: one per guard whose
  behaviour a unit test alone does not show, plus `smoke_explain.py` for the installed
  `airlock-explain` CLI. Add one only when a unit test is not enough.
- New modules follow the layered structure: validation → policy → execution → sanitization.
- Keep security-relevant decisions observable via structured logging.

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Project Notes

### Phase 1: Core Validator
- [x] Ghost argument stripping
- [x] Pydantic strict validation
- [x] Self-healing responses
- [x] Configuration system

### Phase 2: E2B Sandbox
- [x] Warm sandbox pool (SandboxPool class)
- [x] Function serialization (cloudpickle)
- [x] E2B integration (execute_in_sandbox)
- [x] File mounting (`sandbox.mount_files()`)

### Phase 3: Policy Engine
- [x] SecurityPolicy class with allow/deny lists
- [x] Time-based restrictions (TimeWindow)
- [x] Rate limiting (token bucket algorithm)
- [x] Agent identity and role-based access control
- [x] Predefined policies (PERMISSIVE, STRICT, READ_ONLY, BUSINESS_HOURS)

### Phase 4: Output Sanitization
- [x] PII detection and masking (email, phone, SSN, credit card, IP)
- [x] Secret detection and masking (API keys, passwords, AWS keys, JWT, connection strings)
- [x] Token/character truncation with configurable limits
- [x] Masking strategies (FULL, PARTIAL, TYPE_ONLY, HASH)
- [x] Audit logging (JSON Lines format, thread-safe)

### Phase 5: FastMCP Integration
- [x] MCPAirlock decorator for MCP-specific features
- [x] secure_tool convenience decorator
- [x] create_secure_mcp_server factory function
- [x] MCP context extraction utilities
- [x] Progress reporting support
- [x] Comprehensive example (fastmcp_integration.py)

### Phase 0: Production Readiness (Added 2026-01-31)
- [x] Audit logging implementation (was config-only, now fully working)
- [x] Async function support (proper async/await wrapper)
- [x] Coverage verification (99%, enforced 80% in CI)
- [x] 647 tests total (includes context, streaming, audit, async, edge cases)

### Production Phase 1: Core Missing Features (Added 2026-01-31)
- [x] P1.1: Streaming/generator support (StreamingAirlock class)
  - Per-chunk PII/secret sanitization
  - Cumulative output truncation
  - Sync and async generator wrapping
- [x] P1.2: RunContext preservation (AirlockContext)
  - contextvars for request-scoped state
  - ContextExtractor for RunContextWrapper pattern
  - get_current_context() available inside tools
- [x] P1.3: Dynamic policy resolution
  - Policy can be SecurityPolicy or Callable[[AirlockContext], SecurityPolicy]
  - Enables workspace/tenant-specific policies
  - Context extracted from first arg with .context/.ctx attribute

### Phase 6: Launch
- [x] PyPI release v0.1.3, v0.1.4
- [x] README with manifesto-style copy
- [x] Security scan and fixes
- [ ] Outreach

### Framework Integrations (Tested 2026-02-01)
All major AI frameworks tested and working:
- [x] LangChain - `@tool` + `@Airlock()` pattern, `.invoke()` for tool calls
- [x] LangGraph - ToolNode integration, state graphs with security
- [x] PydanticAI - `output_type` param, RunContext preservation
- [x] OpenAI Agents SDK - `@function_tool` + `@Airlock()`, Agent.run()
- [x] Anthropic - `@Airlock()` with tool_use blocks, Messages API
- [x] AutoGen - FunctionTool with airlocked functions
- [x] CrewAI - `@tool` decorator pattern (Tool object wrapper)
- [x] LlamaIndex - FunctionTool.from_defaults(), ToolOutput.raw_output
- [x] smolagents - `@tool` + `@Airlock()` with proper Args docstrings

### Enterprise Production Roadmap (Added 2026-02-01)

The `PRODUCTION_ROADMAP.md` this line used to point at does not exist and is not in
git history. The live plan is [`ROADMAP.md`](ROADMAP.md); the checklist below is a
record of what shipped, not a tracker.

**Already Implemented (v0.1.5):**
- [x] Async function support (proper async/await)
- [x] Streaming support (StreamingAirlock)
- [x] Context propagation (AirlockContext)
- [x] Dynamic policy resolution (PolicyResolver callable)
- [x] Audit logging (JSON Lines, thread-safe)
- [x] Workspace PII config (per-tenant rules)
- [x] Conversation tracking (multi-turn state)

**V0.3.0 "Vaccine" Features (COMPLETED):**
- [x] Filesystem path validation (CVE-resistant)
- [x] Network egress control (socket monkeypatch)
- [x] Honeypot deception protocol
- [x] Framework vaccination (LangChain, OpenAI SDK auto-wrap)

**V0.4.0 "Enterprise" Features (COMPLETED):**
- [x] UnknownArgsMode (BLOCK/STRIP_AND_LOG/STRIP_SILENT)
- [x] SafePath/SafeURL safe types
- [x] Capability gating (@requires decorator)
- [x] Pluggable sandbox backends (E2B/Docker/Local)
- [x] OpenTelemetry observability
- [x] Circuit breaker pattern
- [x] Cost tracking with budget limits
- [x] Retry policies with exponential backoff
- [x] MCP Proxy Guard
- [x] India-specific PII (Aadhaar, PAN, UPI, IFSC)

**Future Roadmap:**
- [x] Redis-backed distributed rate limiting (`redis_rate_limit.py`, `[redis]` extra)
- [x] Performance benchmarks in CI (smoke run, not a latency gate — v0.8.80)
- [ ] Additional framework integrations

**Current Version:** see `pyproject.toml` / `agent_airlock.__version__` — this line is
not gated, so it is a pointer rather than a number that can rot (it read v0.5.0 while
the package was v0.8.79).

<!-- END MANUAL -->
