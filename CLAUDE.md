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
- PII/secret detection and masking (includes opt-in Indic PII)
- Sandboxed execution via pluggable backends (E2B Firecracker, Modal, Docker, local)
- `mcp_spec/` guards mapped to specific named CVEs and MCP spec clauses — stdio injection,
  OAuth, DNS rebinding, SSRF, eval-RCE, WebSocket origin hijack, task lifecycle, handle trust
- Framework adapters: FastMCP, LangChain/LangGraph, Anthropic (Messages, Claude Agent SDK,
  Managed Agents), OpenAI, Gemini, PydanticAI, CrewAI, smolagents, Google ADK, Google Model
  Armor
- Fleet-wide kill switch (quorum-signed freeze) checked before any other gate
- `airlock` CLI — one dispatcher fronting every `cli/<name>.py`; the `_COMMANDS` table in
  `cli/__main__.py` (or `airlock --help`) is the authoritative subcommand list

**The installed core is Pydantic-only.** Everything else — structlog included — lives in an
extra. `src/agent_airlock/_log.py` falls back to a stdlib-logging shim when structlog is
absent. `scripts/check_core_deps.py` enforces this; do not add a core dependency.

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

Repo-specific claim gates (`make help` lists every target):

```bash
make benchmark               # regenerate BENCHMARK.md (guard-suite block-rate corpus)
make test-badge              # regenerate the TEST-BADGE block in README.md
make egress-bench            # CVE egress walker over tests/cves/fixtures/
make verify-corpus           # verify wild_payload_corpus MANIFEST.sha256
make check-links             # dead relative-link gate (README + docs/)
make check-cve-catalog       # docs/cves/index.md matches the tests/cves/ suite
make check-docs              # mkdocs build --strict, built OUTSIDE the tree (see Architecture)
make check-changelog         # post-release drift: [Unreleased] must be empty after a release
make check-changelog-release # pre-tag: [Unreleased] must be NON-empty — red by design between releases
make check-benchmark-freshness          # every benchmark row carries a date marker
make check-benchmark-freshness-release  # pre-tag: no benchmark claim older than 30 days
make check-registry-parity              # declared version must not outrun PyPI
make check-registry-parity-distance     # release-only: refuse to skip a version
```

Which of those gate a merge (`ci.yml`): the `docs` job runs `mkdocs build --strict`,
`check_links.py`, `gen_cve_catalog.py --check`, and the **default** modes of
`check_changelog.py` and `check_benchmark_freshness.py`; `version-tag-guard` (pushes to
`main` only) runs `check_version_tagged.py`, `check_changelog_heading.py` and
`check_registry_parity.py`; `test` runs `generate_benchmark.py --check` plus a
pytest-benchmark smoke run (asserts it executes — deliberately not a latency threshold);
`bare-install` runs `check_core_deps.py` against a no-extras install. `publish.yml` adds
the `--release` and `--distance-only` forms; those are the only two that must NOT run
per-PR, because `check-changelog-release` fails outside a release window.

The `test` job installs `.[dev,redis]`, not `.[dev]`, and asserts the redis-backed
modules import. Both open with `pytest.importorskip("fakeredis")`, so while `[dev]` was
the only extra they were skipped in CI for their whole life — 30 tests that reported as
neither passed nor failed, which is why the v0.10.7 note in `CHANGELOG.md` exists. A
skipped module and a passing one look identical in the summary line; if you add an
`importorskip` to a module, add the dependency to a CI job in the same PR or the tests
below it are decoration. `bare-install` is unaffected: it still installs `-e .` alone,
so the Pydantic-only core is enforced exactly as before.

Docker integration tests are **opt-in**: default `addopts` carries `-m 'not docker'`.
Run them explicitly with `pytest -m docker`. `cve-watcher.yml` is a scheduled job that
diffs NVD against the ledger and files triage issues — not a merge gate.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: architecture -->
## Architecture

`src/` layout, single package, hatchling build. The `airlock` console script dispatches to
every `agent_airlock.cli.<name>:main(argv)` in space-form (`airlock scan-tools`), so flags
are identical to the `python -m agent_airlock.cli.<name>` long form. Three pre-dispatcher
scripts (`airlock-explain`, `airlock-conformance`, `airlock-scan-tools`) survive as stable
aliases. Subtree `CLAUDE.md` files are excluded from the sdist and wheel
(`[tool.hatch.build.targets.*]`), so they never reach a user's site-packages.

Repo-level directories outside the package: `tests/` (mirrors the package's subpackages;
`tests/cves/` is the signed CVE regression suite), `benchmarks/` (agentdojo, blockrate,
harness_injection, mcp_conformance, scantools_mcptox, toolprivbench, vs_gateway),
`scripts/` (the `check_*` claim gates, `smoke_*` guard drivers, `cve_watcher.py`), `docs/`
(mkdocs source), `examples/`, `demo/` (runnable live demo), `presets/`, `schemas/`,
`tools/`, and `.claude-plugin/` (marketplace manifest).

**There is no committed `site/`.** The docs site is served from the `gh-pages` branch,
which `docs.yml` rebuilds with `mkdocs gh-deploy --force` on pushes to `main` that touch
`docs/`, `mkdocs.yml` or `src/`. A bare `mkdocs build` writes `site/`, which is gitignored
— do not add it back. `make check-docs` builds to `$TMPDIR/agent-airlock-mkdocs-check` so
validating the docs leaves no HTML in the tree; a committed copy once drifted from `docs/`
and its stale HTML made project-classifying tooling read this Python library as a web app.

```
src/agent_airlock/
├── core.py            @Airlock decorator — the entrypoint; sync + async
├── __init__.py        public API surface (large, explicit __all__)
├── config.py          ENV (AIRLOCK_*) > constructor > airlock.toml
├── exceptions.py
├── testing.py         state-reset helpers for test isolation
│
├── VALIDATION   validator.py, unknown_args.py, safe_types.py, self_heal.py, handles.py
├── POLICY       policy.py, policy_presets.py, preset_loader.py, capabilities.py,
│                oversight.py, identity.py, redis_rate_limit.py, amplification.py,
│                capability_caps/, policy_compiler/, budget/
├── EXECUTION    sandbox.py, sandbox_backend.py, streaming.py, context.py,
│                conversation.py, circuit_breaker.py, retry.py, runtime/
├── SANITIZE     sanitizer.py, audit.py, audit_otel.py, observability.py,
│                cost_tracking.py, trace_redaction.py
├── VACCINE      filesystem.py, network.py, honeypot.py, vaccine.py,
│                camouflage_resistant.py, ssrf_egress_guard.py, sequence_guard.py,
│                action_contradiction_gate.py, tool_output_trust_guard.py,
│                done_receipt_guard.py
├── mcp_spec/    per-CVE / per-spec-revision MCP guards — largest subpackage, own CLAUDE.md
├── mcp/         cimd.py — pinned CIMD trust anchor, denies on drift
├── kill_switch/ quorum-signed fleet freeze — registry, signer, broadcast, transports/
├── data/        dated snapshots (model pricing, advisory blast radius)
├── fixtures/    dated pattern files (redaction patterns)
├── ADVERSARIAL  anomaly.py, regression_corpus.py, sdk_provenance.py, a2a.py,
│                mcp_proxy_guard.py, negotiation_bench.py, corpus/wild_payload_corpus/
├── ATTEST       attest/, conformance/, baseline/, pack/, packs/, scan/, graph/, studio/,
│                owasp_agentic_coverage/
├── integrations/  framework adapters, plus adapters/ (commerce caps) and scanners/
│                  (pluggable IDE-scanner protocol)
└── cli/           subcommands behind the unified dispatcher
```

**Call flow through `@Airlock`** — `_pre_execution` gates, then execute, then
`_post_execution`. Step numbers match the comments in `core.py`:

0. Kill switch — a fleet freeze refuses before the arguments are even examined
1. Ghost arguments (BLOCK / STRIP_AND_LOG / STRIP_SILENT)
2. Resolve policy (static, or `Callable[[AirlockContext], SecurityPolicy]`) and check it
   - 2.5 behavioral tool-call sequence guard
   - 2.6 action-time contradiction gate
   - 2.7 unsafe-deserialization content guard
   - 2.8 per-run resource-amplification budget — after the gates above, so a call that was
     going to be refused anyway is never charged to the run's ledger
3. Filesystem path validation
4. Capability requirements
5. Endpoint policy validation
6. Per-model-tier budget check
7. Pydantic strict validation → execute locally or in sandbox (circuit breaker + retry)
8. Sanitize output (PII/secrets, truncation) → audit log → mark untrusted output →
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
- **Exceptions** store details as attributes and call `super().__init__()`.
- `TYPE_CHECKING` guards for type-only imports.
- **Tests**: `Test<Feature>` classes with `test_<scenario>` methods; keep each under ~5s.
- **Commits**: conventional — `feat:` `fix:` `docs:` `chore:` `ci:` `security:` `bench:`.
  Branches `feat/<short>` `fix/<short>` `chore/<short>`. Squash-merge into `main`;
  `main` stays tag-able at all times.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: patterns -->
## Detected Patterns

- **Decorator entrypoint** — `@Airlock()` wraps a function with the full layer stack, and
  preserves `__signature__` / `__annotations__` so framework introspection still works.
- **Defense-in-depth** — validation → policy → capability → filesystem → network → sandbox.
  Each layer exists because an earlier one proved insufficient for a specific CVE.
- **Two guard shapes in `mcp_spec/`** — class-style triples (`<Name>Guard` +
  `@dataclass <Name>Decision` + `<Name>Verdict(str, Enum)`) and function-style validators
  (`validate_*` / `audit_*` / `check_*`). Either way the matching `*_defaults()` preset
  factory lives in `policy_presets.py`, `@preset`-registered; a guard with no registered
  preset never shows up in `list_active()`. Guards are **not** re-exported from
  `mcp_spec/__init__.py` — import each from its own module.
- **Lazy optional imports** — anything from an extra (`e2b`, `redis`, `cryptography`,
  `structlog`, framework SDKs) is imported inside the function that needs it, behind
  `try/except ImportError`, raising an error that names the extra to install. This is what
  keeps the `bare-install` job green.
- **Deny-by-default** — unknown tier, unregistered manifest, and unpinned spec revision all
  fail closed. New branches should preserve that direction.
- **Config priority** — `AIRLOCK_*` env > constructor > `airlock.toml`.
- **Self-healing** — `ValidationError` becomes structured JSON with `fix_hints`.
- **Context propagation** — `contextvars`-backed `AirlockContext`; `get_current_context()`
  is available inside the wrapped tool.
- **Policy resolver** — policy may be a callable taking `AirlockContext`, enabling
  per-tenant / per-workspace rules.
- **Preset registry** — explicit `@preset` registration so `list_active()` enumerates
  everything; versioned YAML/TOML bundles load through `preset_loader`.
- **Dated snapshots** — pricing tables, advisory blast-radius data and redaction patterns
  ship as dated files under `data/` and `fixtures/`; a refresh is a new dated file, not an
  edit to the old one.
- **Attestation receipts** — identity plus LayerContract (assume/guarantee) on
  `airlock attest`.
- **Warm pool** — `SandboxPool` keeps pre-created sandboxes to hide cold-start latency.
- **Framework vaccination** — `vaccinate()` monkeypatches third-party `@tool` decorators.
- **Honeypot deception** — return plausible fake success instead of an error.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: git-insights -->
## Git Insights

History is dominated by `fix:` and `feat:`, with steady `docs:`, `chore:` and `bench:`
work (`git log --format=%s | cut -d: -f1 | sort | uniq -c` recounts it). Three themes drive
most recent development:

1. **Per-CVE guards.** Most `feat:` commits add one guard for one named advisory
   (`mcp_spec/*_guard.py`), its preset defaults, and a regression fixture. Commit messages
   carry the primary-source URL. `cve-watcher.yml` feeds this: it polls NVD on a schedule
   and files triage issues for argument-shaped CVEs, and the queue is closed either with a
   fixture or with a public, reasoned refusal (#177).
2. **Claims integrity.** A distinct class of `fix(meta):` / `fix:` commits exists purely
   to stop the README/docs/registry over-claiming — "ten places the repo claimed something
   the code contradicted" (#175) is the archetype. Machine-checked gates (`scripts/check_*.py`,
   the badge, changelog and README-shape tests) were added so this drift fails CI instead
   of shipping. The README itself was cut by roughly nine-tenths and its size gated
   (`tests/test_readme_shape.py`, #180); long-form material belongs in `docs/`.
3. **Benchmark honesty.** `bench(...)` commits publish adversarial results under
   `benchmarks/` and are written to survive a hostile read: a null result ships as a null
   result, a broken harness is fixed before its output is quoted, a row that was about to
   expire gets re-dated only after re-running it (#179), and the sample scope is stated
   inline rather than rounded up. Match this register when touching `benchmarks/` or
   `BENCHMARK.md`.

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
  Anything weaker needs a one-line justification in the docstring.
- **Forbidden:** `subprocess.run(..., shell=True)` anywhere in `src/` (the only `subprocess`
  importer under `mcp_spec/` is `manifest_only_mode.py`, and even it does not use
  `shell=True`); raw `eval()` / `exec()`; mocking fixtures in CVE regression tests.
- **CVE fixtures are signed history.** Files under `corpus/wild_payload_corpus/` and
  `tests/cves/` require a primary-source URL in the commit message plus a matching
  `docs/cves/index.md` update in the same PR. Never remove a check without naming the CVE
  that motivated it.
- Every `feat:` needs at least one regression test.
- Run `make lint` and `pytest -m "not docker"` before committing.
- CI gates are `test`, `docker-sandbox`, `bare-install`, `lint`, `version-tag-guard`,
  `security`, `docs`. `bare-install` is the one that enforces the Pydantic-only core — if
  you add an import that is not in an extra, that job fails, not the test suite.
- The README is gated on shape (`tests/test_readme_shape.py`: line and word ceilings, first
  code block near the top) and on its framework and version-pin claims. Put new material in
  `docs/` and link it; do not grow the README.
- Six guards additionally carry a `scripts/smoke_*.py` end-to-end driver runnable outside
  pytest (sequence guard, action-contradiction gate, attested admission, capsule indirect
  injection, Flowise MCP stdio, explain). It is not required for every guard — add one
  when the guard's behaviour is hard to see from a unit test alone.
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
