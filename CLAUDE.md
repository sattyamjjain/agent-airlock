# agent-airlock

<!-- AUTO-MANAGED: project-description -->
## Overview

**Agent-Airlock** is a security middleware for MCP (Model Context Protocol) servers. It intercepts, validates, and sandboxes AI agent tool calls to prevent hallucinated arguments, type errors, and dangerous operations.

Key features:
- Ghost argument stripping/rejection
- Pydantic V2 strict schema validation
- Self-healing error responses for LLMs
- E2B Firecracker sandbox execution (Phase 2)
- Policy engine with RBAC (Phase 3)

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: build-commands -->
## Build & Development Commands

```bash
# Install dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run tests with coverage
pytest tests/ -v --cov=agent_airlock --cov-report=html

# Type checking
mypy src/

# Linting
ruff check src/ tests/

# Format code
ruff format src/ tests/
```

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: architecture -->
## Architecture

```
src/agent_airlock/
├── __init__.py       # Public API exports
├── core.py           # @Airlock decorator (main entry point)
├── validator.py      # Ghost arg detection + Pydantic validation
├── self_heal.py      # LLM-friendly error responses
├── config.py         # Configuration (env vars, TOML, constructor)
├── sandbox.py        # E2B sandbox pool + execution (implemented)
├── policy.py         # RBAC policy engine (Phase 3)
├── sanitizer.py      # PII/secret masking (Phase 4)
└── logging.py        # Audit logging (Phase 4)
```

**Data Flow:**
1. LLM calls MCP tool with arguments
2. `@Airlock` intercepts the call
3. Ghost arguments stripped/rejected
4. Pydantic validates types strictly
5. If sandbox=True, execute in E2B MicroVM
6. Return result or self-healing error

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Code Conventions

- Python 3.10+ with full type hints
- Pydantic V2 for validation
- structlog for structured logging
- src/ layout with hatch build system
- pytest for testing with 80%+ coverage target
- mypy --strict for type checking
- ruff for linting and formatting

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: patterns -->
## Detected Patterns

- **Decorator Pattern**: `@Airlock()` wraps functions with validation
- **Response Objects**: `AirlockResponse` for consistent return format
- **Config Priority**: env vars > constructor > TOML file
- **Self-Healing**: ValidationError → structured JSON with fix_hints

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Project Notes

### Phase 1: Core Validator
- [x] Ghost argument stripping
- [x] Pydantic strict validation
- [x] Self-healing responses
- [x] Configuration system

### Phase 2 (Current): E2B Sandbox
- [x] Warm sandbox pool (SandboxPool class)
- [x] Function serialization (cloudpickle)
- [x] E2B integration (execute_in_sandbox)
- [ ] File mounting (deferred to Phase 5)

### Phase 3: Policy Engine
- [ ] RBAC for agents
- [ ] Time restrictions
- [ ] Rate limiting

### Phase 4: Output Sanitization
- [ ] PII masking
- [ ] Token truncation
- [ ] Audit logging

### Phase 5: FastMCP Integration
- [ ] MCP context awareness
- [ ] Decorator composition

### Phase 6: Launch
- [ ] PyPI release
- [ ] README with GIF demo
- [ ] Outreach

<!-- END MANUAL -->
