# agent-airlock

<!-- AUTO-MANAGED: project-description -->
## Overview

**agent-airlock** — an in-process, deny-by-default contract layer and type-checker for AI
agent tool calls. It intercepts calls into MCP (Model Context Protocol) servers and agent
frameworks, validates arguments strictly, applies policy, and sandboxes dangerous execution.

The wedge is argument validation at the call boundary; every other layer wraps it.

- Ghost-argument stripping/rejection (parameters the LLM invented)
- Pydantic V2 strict validation, no type coercion; self-healing errors carrying `fix_hints`
- Policy engine: RBAC, token-bucket rate limits, time windows, per-model-tier cost budgets
- PII/secret detection and masking (includes opt-in Indic PII)
- Sandboxed execution via pluggable backends (E2B Firecracker, Modal, Docker, local)
- `mcp_spec/` guards mapped to specific named CVEs — stdio injection, OAuth, DNS rebinding,
  SSRF, eval-RCE, WebSocket origin hijack, task lifecycle
- Framework adapters: FastMCP, LangChain/LangGraph, Anthropic, OpenAI, Gemini, PydanticAI,
  CrewAI, smolagents
- `airlock` CLI: scan-tools, doctor, verify, attest, replay, corpus-bench, conformance

**The installed core is Pydantic-only.** Everything else — structlog included — lives in an
extra. `src/agent_airlock/_log.py` falls back to a stdlib-logging shim when structlog is
absent. `scripts/check_core_deps.py` enforces this; do not add a core dependency.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: build-commands -->
## Build & Development Commands

```bash
pip install -e ".[dev]"            # editable install with dev deps

# Optional extras — install only what you need
pip install -e ".[sandbox]"        # E2B Firecracker   ([modal] [mcp] [console] ...)
pip install -e ".[redis]"          # distributed rate limiter ([crypto] [attested] ...)
pip install -e ".[all]"            # everything

make test          # pytest tests/ -v --no-cov
make coverage      # pytest with coverage (floor enforced; see [tool.coverage.report])
make lint          # ruff check + ruff format --check + mypy src/
make format        # ruff format + ruff check --fix
make bench         # pytest-benchmark suite
```

Repo-specific gates (each also runs in CI):

```bash
make benchmark               # regenerate BENCHMARK.md (block-rate corpus)
make test-badge              # regenerate the TEST-BADGE block in README.md
make egress-bench            # CVE egress walker over tests/cves/fixtures/
make verify-corpus           # verify wild_payload_corpus MANIFEST.sha256
make check-changelog         # post-release drift gate
make check-changelog-release # pre-tag gate ([Unreleased] must be non-empty)
```

Docker integration tests are **opt-in**: default `addopts` carries `-m 'not docker'`.
Run them explicitly with `pytest -m docker`.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: architecture -->
## Architecture

`src/` layout, single package, hatchling build. The `airlock` console script dispatches to
every `agent_airlock.cli.<name>:main(argv)` in space-form (`airlock scan-tools`), so flags
are identical to the `python -m agent_airlock.cli.<name>` long form.

```
src/agent_airlock/
├── core.py            @Airlock decorator — the entrypoint; sync + async
├── __init__.py        public API surface (large, explicit __all__)
├── config.py          ENV (AIRLOCK_*) > constructor > airlock.toml
├── exceptions.py
│
├── VALIDATION   validator.py, unknown_args.py, safe_types.py, self_heal.py
├── POLICY       policy.py, policy_presets.py, preset_loader.py, capabilities.py,
│                oversight.py, identity.py, redis_rate_limit.py, capability_caps/,
│                policy_compiler/, budget/
├── EXECUTION    sandbox.py, sandbox_backend.py, streaming.py, context.py,
│                conversation.py, circuit_breaker.py, retry.py, runtime/
├── SANITIZE     sanitizer.py, audit.py, audit_otel.py, observability.py,
│                cost_tracking.py, trace_redaction.py
├── VACCINE      filesystem.py, network.py, honeypot.py, vaccine.py,
│                camouflage_resistant.py, ssrf_egress_guard.py, sequence_guard.py,
│                action_contradiction_gate.py, tool_output_trust_guard.py
├── mcp_spec/    per-CVE / per-spec-revision MCP guards (largest subpackage)
├── ADVERSARIAL  anomaly.py, regression_corpus.py, sdk_provenance.py, a2a.py,
│                mcp_proxy_guard.py, corpus/wild_payload_corpus/
├── ATTEST       attest/, conformance/, baseline/, pack/, packs/, kill_switch/,
│                scan/, graph/, studio/, owasp_agentic_coverage/
├── integrations/  framework adapters, plus adapters/ and scanners/
└── cli/           subcommands behind the unified dispatcher
```

**Call flow through `@Airlock`** — `_pre_execution` gates, then execute, then
`_post_execution`:

1. Ghost arguments (BLOCK / STRIP_AND_LOG / STRIP_SILENT)
2. Resolve policy (static, or `Callable[[AirlockContext], SecurityPolicy]`) and check it
   - 2.5 behavioral tool-call sequence guard
   - 2.6 action-time contradiction gate
   - 2.7 unsafe-deserialization content guard
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
- **ruff**, line length 100, target `py310`. Selected: E, W, F, I, B, C4, UP, ARG, SIM.
  Per-file `ARG` ignores exist for `integrations/`, `cli/`, `anomaly.py`, tests and examples —
  those unused args are callback-interface signatures, so do not "fix" them.
- **Pydantic V2 strict mode** for validation. `@dataclass` with `field(default_factory=...)`
  for structured data; prefer it over plain dicts.
- **Enums** extend `str, Enum` so they serialize to JSON.
- **Logging** through `agent_airlock._log` (structlog when installed, stdlib shim otherwise):
  `logger = get_logger("agent-airlock")`. Structured kwargs, never f-strings.
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
- **Guard triple** — new guards ship as `<Name>Guard` + `<Name>Decision` + `<Name>Verdict`
  with a `*_defaults()` factory re-exported from `__init__.py`. Follow this shape.
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
- **Attestation receipts** — identity plus LayerContract (assume/guarantee) on
  `airlock attest`.
- **Warm pool** — `SandboxPool` keeps pre-created sandboxes to hide cold-start latency.
- **Framework vaccination** — `vaccinate()` monkeypatches third-party `@tool` decorators.
- **Honeypot deception** — return plausible fake success instead of an error.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: git-insights -->
## Git Insights

History is dominated by `feat:` and `fix:`, with recurring `bench:` and `docs:` work.
Two themes drive most recent development:

1. **Per-CVE guards.** Most `feat:` commits add one guard for one named advisory
   (`mcp_spec/*_guard.py`), its preset defaults, and a regression fixture. Commit messages
   carry the primary-source URL.
2. **Claims integrity.** A distinct class of `fix(meta):` commits exists purely to stop the
   README/docs/registry over-claiming — reconciling coverage floors, test counts, CVE counts,
   spec-revision status, and dependency claims against what the code actually does.
   Machine-checked gates (`scripts/check_*.py`, badge and changelog tests) were added so this
   drift fails CI instead of shipping.

Practical consequence: **do not add a capability claim to README, docs, or a preset
description unless code and a test back it.** There is tooling that will fail the build on it.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: best-practices -->
## Best Practices

- Read `AGENTS.md` first — it holds the load-bearing contributor contract.
- Default safety posture:
  `@Airlock(policy=STRICT_POLICY, sandbox=True, sandbox_required=True)`.
  Anything weaker needs a one-line justification in the docstring.
- **Forbidden:** `subprocess.run(..., shell=True)` outside `mcp_spec/manifest_only_mode.py`;
  raw `eval()` / `exec()`; mocking fixtures in CVE regression tests.
- **CVE fixtures are signed history.** Files under `corpus/wild_payload_corpus/` and
  `tests/cves/` require a primary-source URL in the commit message plus a matching
  `docs/cves/index.md` update in the same PR. Never remove a check without naming the CVE
  that motivated it.
- Every `feat:` needs at least one regression test.
- Run `make lint` and `pytest -m "not docker"` before committing.
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
- [ ] File mounting (deferred to Phase 5)

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

See `PRODUCTION_ROADMAP.md` for full details.

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
- [ ] Redis-backed distributed rate limiting
- [ ] Performance benchmarks in CI
- [ ] Additional framework integrations

**Current Version:** v0.5.0 "April 2026"

<!-- END MANUAL -->
