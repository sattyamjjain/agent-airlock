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
- V0.3.0: Filesystem validation, network egress control, honeypot deception, framework vaccination
- V0.4.0: Circuit breaker, cost tracking, retry policies, OpenTelemetry observability, capability gating

**Stats:** ~25,900 lines of code | 1157 tests | 79%+ coverage (enforced in CI)
**Version:** 0.4.0 "Enterprise"

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
├── __init__.py         # Public API exports (200+ symbols)
├── core.py             # @Airlock decorator - main entry point (1003 lines)
│                       └─ Ghost args, validation, sandbox, policies, capabilities
│                       └─ Full async/await support, context propagation
│
├── ── VALIDATION LAYER ──
├── validator.py        # Ghost argument detection + Pydantic strict validation
├── unknown_args.py     # V0.4.0 BLOCK/STRIP_AND_LOG/STRIP_SILENT modes
├── safe_types.py       # SafePath, SafeURL with auto-validation
│
├── ── POLICY LAYER ──
├── policy.py           # SecurityPolicy, RBAC, RateLimit (token bucket)
├── capabilities.py     # V0.4.0 Capability gating (Flag enum)
│
├── ── EXECUTION LAYER ──
├── sandbox.py          # E2B Firecracker MicroVM integration
├── sandbox_backend.py  # V0.4.0 Pluggable backends (E2B/Docker/Local)
├── streaming.py        # StreamingAirlock for generators
├── context.py          # AirlockContext with contextvars
├── conversation.py     # Multi-turn state tracking
│
├── ── SANITIZATION LAYER ──
├── sanitizer.py        # PII/secret detection (12 types, 4 strategies)
│
├── ── V0.3.0 "VACCINE" FEATURES ──
├── filesystem.py       # Path validation (CVE-resistant)
├── network.py          # Egress control (socket monkeypatch)
├── honeypot.py         # Deception protocol (fake success data)
├── vaccine.py          # Framework injection (LangChain/OpenAI auto-wrap)
│
├── ── V0.4.0 "ENTERPRISE" FEATURES ──
├── circuit_breaker.py  # Fault tolerance pattern (CLOSED/OPEN/HALF_OPEN)
├── cost_tracking.py    # Token usage + budget limits
├── retry.py            # Exponential backoff + jitter
├── observability.py    # OpenTelemetry spans/metrics
├── audit_otel.py       # OTel audit export
├── mcp_proxy_guard.py  # Token passthrough prevention
│
├── ── INTEGRATIONS ──
├── integrations/
│   ├── langchain.py    # LangChain @tool wrapper
│   ├── anthropic.py    # Anthropic SDK ToolRegistry
│   └── openai_guardrails.py # OpenAI Agents SDK bridge
│
├── mcp.py              # FastMCP integration
│
└── cli/                # CLI tools
    ├── doctor.py       # airlock doctor command
    └── verify.py       # airlock verify command
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

- **Python:** 3.10+ with full type hints
- **Validation:** Pydantic V2 strict mode
- **Logging:** structlog for structured JSON output
- **Build:** src/ layout with hatch build system
- **Testing:** pytest with 80%+ coverage target
- **Types:** mypy --strict (no untyped defs)
- **Lint/Format:** ruff check and ruff format
- **Imports:** isort via ruff, first-party = agent_airlock
- **Line length:** 100 characters

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
- **Circuit Breaker:** CLOSED → OPEN → HALF_OPEN states for fault tolerance (V0.4.0)
- **Framework Vaccination:** Monkeypatch `@tool` decorators via `vaccinate()` (V0.3.0)
- **Honeypot Deception:** Return fake success data instead of errors (V0.3.0)
- **Signature Preservation:** Copy `__signature__`, `__annotations__` for framework introspection

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: git-insights -->
## Git Insights

Recent commits:
- `3f02298` fix: resolve additional mypy errors (jwt, langchain)
- `d754b28` fix: resolve all mypy type errors for CI
- `c253dd5` fix: resolve all ruff lint errors for CI
- `1c47174` fix: resolve CI failures - bandit security warnings and import sorting
- `8a3939e` feat: v0.4.0 "Enterprise" - Production-ready security platform
- `4b5fe16` feat: v0.2.0 - Security hardening and production roadmap

Key security additions:
- `sandbox_required=True` parameter prevents unsafe local execution fallback
- Sensitive parameter names filtered from debug logs
- Path validation (CVE-resistant using `os.path.commonpath()`)
- Network egress control via socket monkeypatch with thread-local storage
- Capability gating with `@requires(Capability.*)` decorator
- Circuit breaker for fault tolerance
- MCP Proxy Guard for token passthrough prevention
- OpenTelemetry observability integration

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

**Current Version:** v0.4.0 "Enterprise"

<!-- END MANUAL -->
