# Changelog

All notable changes to Agent-Airlock are documented here.

## [0.1.0] - 2026-01-31

### Added

#### Core Features
- **@Airlock decorator** - Main entry point for securing tool functions
- **Ghost argument detection** - Strips or rejects LLM-invented parameters
- **Pydantic V2 strict validation** - No silent type coercion
- **Self-healing responses** - Structured errors with fix_hints for LLM retry

#### Security Policy Engine
- **SecurityPolicy class** - RBAC with allow/deny lists
- **Rate limiting** - Token bucket algorithm with configurable limits
- **Time-based restrictions** - Control when tools can be called
- **Agent identity** - Per-agent access control and rate limits
- **Predefined policies** - PERMISSIVE, STRICT, READ_ONLY, BUSINESS_HOURS

#### Output Sanitization
- **PII detection and masking** - Email, phone, SSN, credit card, IP
- **Secret detection and masking** - API keys, passwords, AWS keys, JWT
- **Masking strategies** - FULL, PARTIAL, TYPE_ONLY, HASH
- **Token/character truncation** - Cost control circuit breaker
- **Workspace-specific rules** - Multi-tenant PII configuration

#### E2B Sandbox Integration
- **SandboxPool** - Warm pool of MicroVMs for low latency
- **Function serialization** - cloudpickle for safe transfer
- **Timeout control** - Configurable execution limits
- **sandbox_required** - Prevent unsafe local fallback

#### FastMCP Integration
- **secure_tool decorator** - Convenience wrapper for MCP tools
- **MCPAirlock class** - MCP-specific features
- **create_secure_mcp_server** - Factory for secured MCP servers
- **Progress reporting** - Support for MCP progress updates

#### Conversation Tracking
- **ConversationTracker** - Multi-agent session management
- **ConversationConstraints** - Cooldowns, quotas, sequences
- **Manual blocking** - Admin controls for suspicious sessions

#### Streaming Support
- **StreamingAirlock** - Per-chunk sanitization
- **Generator wrapping** - Sync and async generators
- **Truncation in streams** - Character limit enforcement

#### Developer Experience
- **AirlockConfig** - Centralized configuration
- **Environment variables** - AIRLOCK_* for all settings
- **airlock.toml** - File-based configuration
- **Error hooks** - on_validation_error, on_blocked, on_rate_limit
- **Framework compatibility** - OpenAI, Azure, LangChain

### Security
- Fixed potential ReDoS in regex patterns
- Added Bandit security scanning to CI
- Added Safety dependency checking
- SBOM generation with cyclonedx-bom
- Comprehensive SECURITY.md documentation

### Documentation
- Full API reference
- User guide with concepts, validation, policy, sanitization, sandbox
- 18 example files covering all features
- MkDocs configuration for documentation site

---

## Upgrade Guide

### From Pre-release to 0.1.0

This is the initial release. No migration needed.

### Configuration Priority

Configuration is loaded in this order (highest priority first):

1. Environment variables (`AIRLOCK_*`)
2. Constructor arguments
3. Configuration file (`airlock.toml`)
4. Default values

### Breaking Changes

None - this is the initial release.

---

## Roadmap

### 0.2.0 (Planned)
- FastMCP 3.x support
- File mounting for sandboxes
- Audit logging with structlog
- LangChain integration package

### 0.3.0 (Planned)
- Web dashboard for monitoring
- Prometheus metrics endpoint
- Redis-backed rate limiting
- Multi-region sandbox pools

---

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

Report issues at [GitHub Issues](https://github.com/attri-ai/agent-airlock/issues).
