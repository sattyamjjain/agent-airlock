# agent-airlock

<!-- AUTO-MANAGED: project-description -->
## Overview

**Agent-Airlock** is an open-source security middleware for MCP (Model Context Protocol) servers. It intercepts, validates, and sandboxes AI agent tool calls to prevent hallucinated arguments, type errors, and dangerous operations.

**Key Features:**
- Ghost argument stripping/rejection (LLM-invented parameters)
- Pydantic V2 strict schema validation (no type coercion)
- Self-healing error responses with fix_hints for LLM retry
- E2B Firecracker sandbox execution for dangerous code
- RBAC policy engine (rate limits, time windows, role-based access)
- PII/secret detection and masking (12 types including India PII)
- FastMCP integration with `@secure_tool` decorator
- Filesystem validation, network egress control, honeypot deception, framework vaccination ("Vaccine")
- Circuit breaker, cost tracking, retry policies, OpenTelemetry observability, capability gating ("Enterprise")
- Anomaly detection, human-oversight gating, identity/attestation, SDK provenance classification
- Curated security presets (`policy_presets.py` + `preset_loader.py`) and a regression corpus block-rate harness
- Redis-backed distributed rate limiting and per-model-tier cost budgets

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: build-commands -->
## Build & Development Commands

```bash
# Install dependencies
pip install -e ".[dev]"

# Install with optional features
pip install -e ".[sandbox]"   # E2B sandbox support
pip install -e ".[mcp]"       # FastMCP integration
pip install -e ".[all]"       # Everything

# Run tests
pytest tests/ -v

# Run tests with coverage
pytest tests/ -v --cov=agent_airlock --cov-report=html

# Type checking (strict mode)
mypy src/

# Linting
ruff check src/ tests/

# Format code
ruff format src/ tests/

# Run example MCP server
python examples/fastmcp_integration.py
```

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: architecture -->
## Architecture

```
src/agent_airlock/
├── __init__.py         # Public API exports
├── core.py             # @Airlock decorator — main entry point
│                       └─ Ghost args, validation, sandbox, policies, capabilities
│                       └─ Full async/await support, context propagation
├── config.py           # Config loading (env > constructor > airlock.toml)
├── exceptions.py       # Custom exception hierarchy
│
├── ── VALIDATION LAYER ──
├── validator.py        # Ghost argument detection + Pydantic strict validation
├── unknown_args.py     # BLOCK / STRIP_AND_LOG / STRIP_SILENT modes
├── safe_types.py       # SafePath, SafeURL with auto-validation
├── self_heal.py        # Self-healing error responses with fix_hints
│
├── ── POLICY LAYER ──
├── policy.py           # SecurityPolicy, RBAC, RateLimit (token bucket)
├── policy_presets.py   # Curated security presets (e.g. CAMOUFLAGE_RESISTANT,
│                       │   mobile_mcp_intent_guard, MCP_STDIO_INJECTION_GUARD)
├── preset_loader.py    # Loader for versioned YAML/TOML preset bundles
├── capabilities.py     # Capability gating (Flag enum, @requires decorator)
├── oversight.py        # @requires_human_oversight (Code-as-Harness anchor)
├── identity.py         # Agent identity + attestation receipts
├── redis_rate_limit.py # Redis-backed distributed rate limiting
│
├── ── EXECUTION LAYER ──
├── sandbox.py          # E2B Firecracker MicroVM integration
├── sandbox_backend.py  # Pluggable backends (E2B / Docker / Local)
├── streaming.py        # StreamingAirlock for generators (sync + async)
├── context.py          # AirlockContext with contextvars
├── conversation.py     # Multi-turn state + conversation constraints
├── circuit_breaker.py  # Fault tolerance (CLOSED / OPEN / HALF_OPEN)
├── retry.py            # Exponential backoff + jitter
│
├── ── SANITIZATION / OBSERVABILITY ──
├── sanitizer.py        # PII / secret detection + masking (incl. Indic PII)
├── audit.py            # JSON Lines audit log (thread-safe)
├── audit_otel.py       # OpenTelemetry audit exporter
├── observability.py    # OTel spans + metrics
├── cost_tracking.py    # Token usage + per-model-tier budget limits
│
├── ── "VACCINE" FEATURES ──
├── filesystem.py       # CVE-resistant path validation
├── network.py          # Egress control (socket monkeypatch, thread-local)
├── honeypot.py         # Deception protocol (fake-success responses)
├── vaccine.py          # Framework auto-wrap (LangChain / OpenAI @tool)
├── camouflage_resistant.py  # Debate-amplification + camouflage guard
│
├── ── ADVERSARIAL / CORPUS ──
├── anomaly.py          # Behavioral anomaly detection
├── regression_corpus.py # Block-rate regression corpus (Metis-inspired)
├── sdk_provenance.py   # Stainless SDK provenance classifier
├── a2a.py              # Agent-to-Agent protocol guard
├── mcp_proxy_guard.py  # Token-passthrough prevention
├── testing.py          # Test helpers / fixtures
│
├── mcp.py              # FastMCP @secure_tool integration
│
├── integrations/       # Framework adapters
│   ├── langchain.py, langgraph_toolnode_compat.py, lc_040_fixture_migration.py
│   ├── anthropic.py, anthropic_claude_agent_sdk.py
│   ├── claude_managed_agents.py, managed_agents_outcomes_guard.py
│   ├── claude_task_budget.py, claude_auto_memory.py
│   ├── openai_guardrails.py, gpt5_5_tool_shape_adapter.py
│   ├── gemini3_tool_shape_adapter.py, pydantic_ai.py
│   ├── crewai.py, smolagents_wrapper.py
│   ├── model_armor.py, model_tier.py, log_redaction.py
│   ├── agent_commerce_caps.py
│   ├── cisco_ide_scanner_bridge.py, cloudflare_mesh_probe.py
│
└── cli/                # `airlock <subcommand>` CLI surface
    ├── doctor.py, verify.py, console.py
    ├── attest.py, manifest.py, baseline.py, policy.py
    ├── pack.py, graph.py, replay.py, studio.py
    ├── corpus_bench.py, egress_bench.py, kill_switch.py
```

**Data Flow:**
1. LLM calls MCP tool with arguments
2. `@Airlock` intercepts → logs with sensitive param filtering
3. Ghost arguments handled (BLOCK/STRIP_AND_LOG/STRIP_SILENT)
4. Security policy checked (RBAC, rate limits, time restrictions)
5. Filesystem path validation (V0.3.0)
6. Capability gating (V0.4.0)
7. Pydantic validates types strictly (no coercion)
8. Network airgap applied if configured (V0.3.0)
9. Execute: local or E2B sandbox (with circuit breaker)
10. Output sanitized (PII/secrets masked, truncated)
11. Cost tracked, audit logged (with OTel export option)
12. Return result or self-healing error with `fix_hints`

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Code Conventions

- **Python:** 3.10+ with full type hints (`X | Y` unions, no `Optional`)
- **Validation:** Pydantic V2 strict mode
- **Logging:** structlog for structured JSON output (`logger = structlog.get_logger("agent-airlock")`)
- **Build:** src/ layout with hatch build system
- **Testing:** pytest with 80%+ coverage target, class-based `Test<Feature>` naming
- **Types:** mypy --strict (no untyped defs), `TypeVar`/`ParamSpec`/`overload` for generics
- **Lint/Format:** ruff check and ruff format
- **Imports:** `from __future__ import annotations` first, then stdlib → 3rd-party → first-party (agent_airlock)
- **Line length:** 100 characters
- **Docstrings:** Google-style (Args/Returns/Raises sections)
- **Naming:** snake_case (functions), PascalCase (classes), UPPER_SNAKE_CASE (constants), `_` prefix (private)
- **Enums:** Extend `str, Enum` for JSON serialization
- **Dataclasses:** `@dataclass` with `field(default_factory=...)` for mutable defaults
- **Commits:** Conventional commits (`feat:`, `fix:`, `docs:`, `chore:`, `ci:`, `security:`)

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: patterns -->
## Detected Patterns

- **Decorator Pattern:** `@Airlock()` wraps functions with validation/security
- **Defense-in-Depth:** 6 layers: validation → policy → capability → filesystem → network → sandbox
- **Response Objects:** `AirlockResponse` for consistent blocked/success format
- **Config Priority:** ENV vars (`AIRLOCK_*`) > constructor > `airlock.toml`
- **Self-Healing:** `ValidationError` → structured JSON with `fix_hints` for LLM retry
- **Token Bucket:** Rate limiting via `RateLimit` class with thread-safe refill
- **Warm Pool:** `SandboxPool` maintains pre-created E2B sandboxes (<200ms latency)
- **Predefined Policies:** `PERMISSIVE_POLICY`, `STRICT_POLICY`, `READ_ONLY_POLICY`, `BUSINESS_HOURS_POLICY`
- **Context Propagation:** `contextvars` for request-scoped state (AirlockContext)
- **Policy Resolver:** Dynamic policies via `Callable[[AirlockContext], SecurityPolicy]`
- **Streaming Sanitization:** Per-chunk validation with cumulative truncation
- **Conversation State:** Multi-turn tracking with budget management (ConversationConstraints)
- **Circuit Breaker:** CLOSED → OPEN → HALF_OPEN states for fault tolerance
- **Framework Vaccination:** Monkeypatch `@tool` decorators via `vaccinate()`
- **Honeypot Deception:** Return fake success data instead of errors
- **Signature Preservation:** Copy `__signature__`, `__annotations__` for framework introspection
- **Curated Presets:** CVE-targeted bundles loaded via `preset_loader` (e.g. `mobile_mcp_intent_guard_2026_05`)
- **Human Oversight Anchor:** `@requires_human_oversight` gates tool execution on out-of-band approval
- **Attestation Receipts:** Identity + LayerContract (assume/guarantee) receipts on `airlock attest`
- **Regression Corpus:** Block-rate harness with per-category coverage (`airlock corpus-bench`)
- **Tier-Aware Budgets:** Per-model-tier cost limits with deny-by-default fallback

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: git-insights -->
## Git Insights

Recent commits:
- `0be2e57` feat(sanitizer): opt-in Indic PII masking (Verhoeff + Devanagari) (#69)
- `d7be9ff` feat(presets): mobile_mcp_intent_guard_2026_05 for CVE-2026-35394 (#68)
- `e98f724` feat(policy): per-model-tier cost budgets with deny-by-default fallback (#67)
- `7c37e83` feat: CAMOUFLAGE_RESISTANT preset + debate-amplification guard
- `757f0d7` feat: opt-in LayerContract (assume/guarantee) block on attest receipts (#66)
- `0d26f98` feat: @requires_human_oversight decorator (Code-as-Harness anchor) (#65)
- `7a7c17b` feat: Stainless SDK provenance classifier + corpus per-category coverage (#64)
- `ac7cce2` feat: Metis-inspired corpus block-rate regression + `airlock corpus-bench` CLI (#63)
- `802f4f9` feat: OpenAPI Drift Guard (Hermes 2026-05-13) + MCP Calc-Server bundle preset (#62)
- `1c63eae` feat: Eval-RCE (CVE-2026-44717) + MCP Inspector runtime scan (CVE-2026-23744) (#61)

Key security additions:
- `sandbox_required=True` prevents unsafe local execution fallback
- Sensitive parameter names filtered from debug logs
- Path validation (CVE-resistant via `os.path.commonpath()`)
- Network egress control via socket monkeypatch with thread-local storage
- Capability gating with `@requires(Capability.*)` decorator
- `@requires_human_oversight` decorator as a Code-as-Harness anchor
- Circuit breaker for fault tolerance; MCP Proxy Guard for token passthrough
- OpenTelemetry observability + audit exporter
- Curated CVE-targeted presets (mobile MCP intent guard, MCP STDIO injection, OpenAPI drift, MCP Inspector runtime scan, Eval-RCE)
- Regression corpus block-rate harness (per-category coverage) via `airlock corpus-bench`
- LayerContract (assume/guarantee) attestation receipts
- Per-model-tier cost budgets with deny-by-default fallback
- Stainless SDK provenance classifier

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: best-practices -->
## Best Practices

- Always run `pytest tests/ -v` after code changes to verify nothing breaks
- Run `mypy src/` and `ruff check src/ tests/` before committing
- Use `python3 -m py_compile <file>` to verify syntax after writing Python
- Keep coverage above 80% (CI enforced via `--cov-fail-under=80`)
- New modules should follow the layered architecture pattern (validation → policy → execution → sanitization)
- Security-sensitive code must include structured logging via structlog
- Custom exceptions should store details as attributes and call `super().__init__()`
- Use `TYPE_CHECKING` guards for imports only needed by type checkers
- Prefer `@dataclass` over plain dicts for structured data
- Test classes should be named `Test<Feature>` with `test_<scenario>` methods

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
