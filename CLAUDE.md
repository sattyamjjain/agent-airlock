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
- PII/secret detection and masking in outputs
- FastMCP integration with `@secure_tool` decorator

**Stats:** ~5,000 lines of code | 647 tests | 99% coverage (enforced 80% in CI)

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
├── __init__.py       # Public API exports (all decorators, configs, policies)
├── core.py           # @Airlock decorator - main entry point (726 lines)
│                     └─ Handles: ghost args, validation, sandbox, policies
│                     └─ Full async/await support, context propagation
│                     └─ Dynamic policy resolution via callables
├── audit.py          # JSON Lines audit logging (301 lines)
│                     └─ AuditLogger, AuditRecord, thread-safe writes
├── context.py        # Request-scoped context (318 lines)
│                     └─ AirlockContext, ContextExtractor, contextvars
│                     └─ RunContextWrapper pattern extraction
├── conversation.py   # Multi-turn conversation state (425 lines)
│                     └─ ConversationState, ConversationConstraints
│                     └─ Cross-call tracking, budget management
├── streaming.py      # Generator/streaming support (365 lines)
│                     └─ StreamingAirlock, per-chunk sanitization
│                     └─ Truncation across streamed output
├── validator.py      # Ghost argument detection + Pydantic strict validation
│                     └─ strip_ghost_arguments(), create_strict_validator()
├── self_heal.py      # LLM-friendly error responses
│                     └─ AirlockResponse with fix_hints for retry
├── config.py         # Configuration: env vars > constructor > TOML file
│                     └─ AirlockConfig dataclass (12 options)
├── policy.py         # RBAC engine (475 lines)
│                     └─ SecurityPolicy, RateLimit (token bucket), TimeWindow
├── sanitizer.py      # PII/secret detection + masking (705 lines)
│                     └─ 12 data types, 4 masking strategies
├── sandbox.py        # E2B integration with warm pool (518 lines)
│                     └─ SandboxPool, cloudpickle serialization
└── mcp.py            # FastMCP integration (344 lines)
                      └─ MCPAirlock, secure_tool, create_secure_mcp_server
```

**Data Flow:**
1. LLM calls MCP tool with arguments
2. `@Airlock` intercepts → logs with sensitive param filtering
3. Ghost arguments stripped/rejected based on `strict_mode`
4. Security policy checked (RBAC, rate limits, time restrictions)
5. Pydantic validates types strictly (no coercion)
6. If `sandbox=True`, serialize with cloudpickle → execute in E2B MicroVM
7. Output sanitized (PII/secrets masked, truncated if needed)
8. Return result or self-healing error with `fix_hints`

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
- **Defense-in-Depth:** 4 layers: validation → policy → sandbox → sanitization
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

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: git-insights -->
## Git Insights

Recent commits:
- `2630882` fix: skip cloudpickle tests when not installed
- `489b8d4` fix: resolve all ruff lint and format errors for CI
- `f138bb5` feat: v0.1.5 - Production-ready release with streaming, context, and 99% coverage
- `f859cfa` chore: bump version to 0.1.3
- `a18dacf` docs: upgrade README to top 1% 2026 standards

Key security additions:
- `sandbox_required=True` parameter prevents unsafe local execution fallback
- Sensitive parameter names filtered from debug logs
- Path validation to prevent directory traversal attacks
- Per-file-ignores for test patterns (ARG001, ARG005, SIM117)

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

### Framework Integrations (Tested 2026-01-31)
All major AI frameworks tested and working:
- [x] LangChain - `@tool` + `@Airlock()` pattern, `.invoke()` for tool calls
- [x] LangGraph - ToolNode integration, state graphs with security
- [x] PydanticAI - `output_type` param, RunContext preservation
- [x] OpenAI Agents SDK - `@function_tool` + `@Airlock()`, Agent.run()
- [ ] Anthropic, AutoGen, CrewAI, LlamaIndex, smolagents (deps not installed)

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

**P0 - Critical for Production (Week 1-2):**
- [ ] Redis-backed distributed rate limiting
- [ ] India-specific PII (Aadhaar, PAN, UPI, IFSC)
- [ ] Performance benchmarks with CI

**P1 - Enterprise Features (Week 3-4):**
- [ ] OpenAI Agents SDK Guardrails bridge
- [ ] Observability hooks (Datadog, OTEL, PostHog)
- [ ] Circuit breaker pattern

**P2 - Nice to Have (Week 5-6):**
- [ ] Cost tracking callbacks
- [ ] Anthropic SDK integration
- [ ] LangChain integration module
- [ ] Retry policies

**Target Versions:**
- v0.2.0: Redis rate limiting, India PII, Benchmarks
- v0.3.0: Guardrails bridge, Observability
- v1.0.0: Production certified, All integrations

<!-- END MANUAL -->
