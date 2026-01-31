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

**Stats:** 2,871 lines of code | 182 tests | 84% coverage

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
├── core.py           # @Airlock decorator - main entry point (396 lines)
│                     └─ Handles: ghost args, validation, sandbox, policies
├── validator.py      # Ghost argument detection + Pydantic strict validation
│                     └─ strip_ghost_arguments(), create_strict_validator()
├── self_heal.py      # LLM-friendly error responses
│                     └─ AirlockResponse with fix_hints for retry
├── config.py         # Configuration: env vars > constructor > TOML file
│                     └─ AirlockConfig dataclass (12 options)
├── policy.py         # RBAC engine (476 lines)
│                     └─ SecurityPolicy, RateLimit (token bucket), TimeWindow
├── sanitizer.py      # PII/secret detection + masking (430 lines)
│                     └─ 12 data types, 4 masking strategies
├── sandbox.py        # E2B integration with warm pool (509 lines)
│                     └─ SandboxPool, cloudpickle serialization
└── mcp.py            # FastMCP integration (335 lines)
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

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: git-insights -->
## Git Insights

Recent commits:
- `436b9e7` security: fix all vulnerabilities from security scan
- `6525b3a` ci: switch to API token auth for PyPI publish
- `f7070b9` docs: rewrite README as manifesto for viral launch
- `18a3e56` fix: resolve mypy unused-ignore error for tomli import
- `1c777c3` docs: complete Phase 6 launch preparation

Key security additions:
- `sandbox_required=True` parameter prevents unsafe local execution fallback
- Sensitive parameter names filtered from debug logs
- Path validation to prevent directory traversal attacks

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
- [ ] Audit logging (deferred)

### Phase 5: FastMCP Integration
- [x] MCPAirlock decorator for MCP-specific features
- [x] secure_tool convenience decorator
- [x] create_secure_mcp_server factory function
- [x] MCP context extraction utilities
- [x] Progress reporting support
- [x] Comprehensive example (fastmcp_integration.py)

### Phase 6: Launch
- [ ] PyPI release (requires PYPI_API_TOKEN secret in GitHub)
- [x] README with manifesto-style copy
- [x] Security scan and fixes
- [ ] Outreach

<!-- END MANUAL -->
