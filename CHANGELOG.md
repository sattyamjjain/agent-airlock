# Changelog

All notable changes to Agent-Airlock are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- **Claude Agent SDK** (`claude-agent-sdk`) as an optional extra: install with `pip install "agent-airlock[claude-agent]"`. Renamed from Claude Code SDK in Sept 2025 ([anthropics/claude-agent-sdk-python](https://github.com/anthropics/claude-agent-sdk-python)). `examples/anthropic_integration.py` Example 7 already uses the new import path.
- **Google Cloud Model Armor adapter** (`agent_airlock.integrations.model_armor`): opt-in scanner that forwards prompts and model responses to [Model Armor](https://docs.cloud.google.com/model-armor/overview) and surfaces filter violations as structured `ModelArmorScanResult`s. Installed via `pip install "agent-airlock[model-armor]"`; enabled via `AIRLOCK_MODEL_ARMOR_ENABLED=1` + `AIRLOCK_MODEL_ARMOR_TEMPLATE=projects/P/locations/L/templates/T`. 14 tests against stub client. Several Google-side field names are flagged UNVERIFIED in the research log; the adapter uses `getattr` with safe fallbacks so schema drift degrades to "no detection" rather than crashing.
- **2026 policy presets** (`agent_airlock.policy_presets`): five incident- and standards-driven `SecurityPolicy` factories — `GTG_1002_DEFENSE` (Anthropic GTG-1002 disclosure), `MEX_GOV_2026` (Mexican-government breach, Feb 2026), `OWASP_MCP_TOP_10_2026` (OWASP MCP Top 10 beta), `EU_AI_ACT_ARTICLE_15` (applies Aug 2, 2026), `INDIA_DPDP_2023` (DPDP Act 2023 + India PII pack). Each preset is documented with primary-source citation and tested with canonical blocking + allowing scenarios (25 new tests).
- **Research log** (`docs/research-log.md`) tracking primary-source verifications that back every non-trivial change in the April 2026 roadmap (#6).

### Fixed
- **CI green on main** — removed an unused `# type: ignore[method-assign]` in `integrations/langchain.py` that began failing mypy 1.8+. Suppressed a bandit B104 false positive on the localhost blocklist check in `network.py`. Main had been red since Feb 6; PR #7 restored all three test matrix versions plus the `security` job.

### Documentation
- **April 2026 briefing pack** committed to tree: `ECOSYSTEM_STATE_2026-04.md`, `ROADMAP_2026.md`, `LAUNCH_PLAYBOOK_2026.md`, `DEEP_ANALYSIS.md`, `CROSS_PROJECT_SYNTHESIS.md`, `CLAUDE_PROMPT.md` (#8). Anchors the v0.5.0 roadmap in #6.

---

## [0.4.1] - 2026-03-15

### Added
- **Per-tool endpoint policies**: URL allowlisting per tool to prevent SSRF attacks (CVE-2026-26118 defense). New `EndpointPolicy` dataclass and `validate_endpoint()` function with wildcard matching, private IP blocking, and metadata URL blocking. Configurable via `[airlock.endpoints.<tool_name>]` in TOML.
- **Anomaly detection**: Real-time monitoring of tool call patterns with auto-blocking for anomalous sessions. New `AnomalyDetector` class detects call rate spikes, endpoint diversity spikes, high error rates, and consecutive blocked calls. Thread-safe with configurable sliding windows. Configurable via `[airlock.anomaly]` in TOML.
- **Credential scope declarations**: Per-tool minimum-privilege enforcement for MCP proxy credentials. New `CredentialScope` dataclass with scope validation, token age checks, freshness requirements, and audience verification. Configurable via `[airlock.credentials.<tool_name>]` in TOML.

### Security
- Direct mitigation for CVE-2026-26118 (Azure MCP Server SSRF) via endpoint allowlisting
- Defense against agent context-switching attacks (CVE-2026-12353) via anomaly detection
- Least-privilege enforcement via credential scope declarations

---

## [0.4.0] - 2026-02-01 — "Enterprise"

### ✨ New Features

- **Unknown Arguments Mode**: New `UnknownArgsMode` replaces boolean `strict_mode` with three explicit behaviors:
  - `BLOCK` - Reject calls with hallucinated arguments (production recommended)
  - `STRIP_AND_LOG` - Strip unknown args and log warnings (staging)
  - `STRIP_SILENT` - Silently strip unknown args (development)

- **Safe Types**: Built-in path and URL validation types that work with Pydantic:
  - `SafePath` - Validates file paths against traversal attacks
  - `SafePathStrict` - Stricter path validation with deny patterns
  - `SafeURL` - Validates URLs with protocol enforcement
  - `SafeURLAllowHttp` - Allows both HTTP and HTTPS

- **Capability Gating**: Fine-grained permission system for tool operations:
  - `@requires(Capability.FILESYSTEM_READ)` decorator
  - Predefined policies: `STRICT_CAPABILITY_POLICY`, `READ_ONLY_CAPABILITY_POLICY`
  - Flag-based capabilities: combine with `|` operator

- **Pluggable Sandbox Backends**: Choose your execution environment:
  - `E2BBackend` - E2B Firecracker MicroVMs (recommended)
  - `DockerBackend` - Docker containers (local development)
  - `LocalBackend` - Unsafe local execution (testing only)

- **Circuit Breaker**: Prevent cascading failures with fault tolerance:
  - `CircuitBreaker` with CLOSED/OPEN/HALF_OPEN states
  - Configurable failure thresholds and recovery timeouts
  - Predefined configs: `AGGRESSIVE_BREAKER`, `CONSERVATIVE_BREAKER`

- **Cost Tracking**: Monitor and limit API spending:
  - `CostTracker` with per-tool and aggregate tracking
  - `BudgetConfig` with hard/soft limits and alerts
  - `CostCallback` protocol for external system integration
  - `BudgetExceededError` when limits are reached

- **Retry Policies**: Intelligent retry with exponential backoff:
  - `RetryPolicy` with configurable attempts and delays
  - Jitter support to prevent thundering herd
  - Predefined policies: `FAST_RETRY`, `STANDARD_RETRY`, `PATIENT_RETRY`
  - Exception filtering with `NETWORK_EXCEPTIONS`

- **OpenTelemetry Observability**: Enterprise-grade monitoring:
  - `OpenTelemetryProvider` for distributed tracing
  - `observe()` context manager and decorator
  - Span attributes, events, and metrics
  - `OTelAuditExporter` for audit log integration

- **MCP Proxy Guard**: Enhanced MCP security:
  - `MCPProxyGuard` prevents token passthrough attacks
  - `MCPSession` binding for request authentication
  - Configurable with `STRICT_PROXY_CONFIG`, `PERMISSIVE_PROXY_CONFIG`

- **CLI Tools**: New command-line utilities:
  - `airlock doctor` - Diagnose configuration issues
  - `airlock verify` - Validate security setup

### 🔧 Improvements

- Enhanced audit logging with OpenTelemetry export support
- Better error messages for capability denials
- Improved thread safety in rate limiters and circuit breakers

---

## [0.3.0] - 2026-02-01 — "Vaccine"

### ✨ New Features

- **Filesystem Path Validation**: Bulletproof protection against directory traversal:
  - `FilesystemPolicy` with allowed roots and deny patterns
  - Uses `os.path.commonpath()` (CVE-resistant, not string prefix matching)
  - Symlink blocking to prevent escape attacks
  - Predefined: `RESTRICTIVE_FILESYSTEM_POLICY`, `SANDBOX_FILESYSTEM_POLICY`

- **Network Egress Control**: Block data exfiltration during tool execution:
  - `NetworkPolicy` with host/port allowlists
  - `network_airgap()` context manager blocks all outbound connections
  - Socket monkeypatching with thread-local storage for safety
  - Predefined: `NO_NETWORK_POLICY`, `INTERNAL_ONLY_POLICY`, `HTTPS_ONLY_POLICY`

- **Honeypot Deception Protocol**: Return fake success instead of errors:
  - `BlockStrategy.HONEYPOT` returns plausible fake data
  - Prevents agents from knowing access was blocked
  - `DefaultHoneypotGenerator` with sensible fake values
  - Example: Agent reads `.env` → gets `API_KEY=mickey_mouse_123`

- **Framework Vaccination**: One-line security for existing code:
  - `vaccinate("langchain")` automatically secures all `@tool` functions
  - Monkeypatches framework decorators to inject Airlock
  - Supports: LangChain, OpenAI Agents SDK, PydanticAI, CrewAI
  - `unvaccinate()` to restore original behavior

### 🔧 Improvements

- Path-like parameter detection with intelligent heuristics
- Callback hooks: `on_blocked`, `on_rate_limit`, `on_validation_error`

---

## [0.2.0] - 2026-02-01

### ✨ New Features

- **Security Hardening**: Comprehensive security review and fixes
- **Production Roadmap**: Clear path to enterprise readiness

### 🐛 Fixes

- Skip cloudpickle tests when package not installed
- Resolve all ruff lint and format errors for CI

---

## [0.1.5] - 2026-01-31

### ✨ New Features

- **Streaming Support**: `StreamingAirlock` for generator functions:
  - Per-chunk PII/secret sanitization
  - Cumulative output truncation across chunks
  - Sync and async generator support

- **Context Propagation**: `AirlockContext` with `contextvars`:
  - `get_current_context()` available inside tools
  - `ContextExtractor` for RunContextWrapper pattern
  - Request-scoped state management

- **Dynamic Policy Resolution**: Policies can now be functions:
  - `Callable[[AirlockContext], SecurityPolicy]` support
  - Enables workspace/tenant-specific policies
  - Context extracted from first arg with `.context` attribute

- **Conversation Tracking**: Multi-turn state management:
  - `ConversationTracker` tracks tool calls across turns
  - `ConversationConstraints` with budget management
  - Cross-call tracking for agent loops

### 🔧 Improvements

- 99% test coverage (enforced 80% in CI)
- 647 tests covering all features

---

## [0.1.3] - 2026-01-31

### ✨ New Features

- **Framework Compatibility**: Full support for major AI frameworks:
  - LangChain with `@tool` decorator
  - LangGraph with `ToolNode` and `StateGraph`
  - OpenAI Agents SDK with `@function_tool`
  - PydanticAI, CrewAI, AutoGen, LlamaIndex, smolagents

- **Signature Preservation**: Critical fix for framework introspection:
  - Copies `__signature__` and `__annotations__` to wrapper
  - Preserves Pydantic V2 attributes (`__pydantic_*`)
  - Enables LLMs to see correct function parameters

### 🔧 Improvements

- README upgraded to top 1% standards
- Comprehensive framework integration examples

### 🔒 Security

- Fixed all vulnerabilities from security scan
- Sensitive parameter names filtered from debug logs

---

## [0.1.2] - 2026-01-31

### 🔧 Improvements

- Switched to API token auth for PyPI publish
- README rewritten as manifesto for launch

### 🐛 Fixes

- Resolved mypy unused-ignore error for tomli import

---

## [0.1.1] - 2026-01-31

### ✨ New Features

- **Policy Engine**: RBAC for AI agents:
  - `SecurityPolicy` with allow/deny tool lists
  - `RateLimit` with token bucket algorithm
  - `TimeWindow` for time-based restrictions
  - Predefined: `PERMISSIVE_POLICY`, `STRICT_POLICY`, `READ_ONLY_POLICY`, `BUSINESS_HOURS_POLICY`

- **Output Sanitization**: PII and secret masking:
  - 12 data types: email, phone, SSN, credit card, API keys, etc.
  - India-specific: Aadhaar, PAN, UPI ID, IFSC
  - 4 masking strategies: FULL, PARTIAL, TYPE_ONLY, HASH
  - Token/character truncation with configurable limits

- **FastMCP Integration**: MCP-native security:
  - `@secure_tool(mcp)` decorator
  - `MCPAirlock` for MCP-specific features
  - `create_secure_mcp_server()` factory function

- **Audit Logging**: JSON Lines format:
  - `AuditLogger` with thread-safe writes
  - Configurable log path
  - Full call tracing with args/results

### 📝 Documentation

- Complete Phase 6 launch preparation
- Security best practices guide

---

## [0.1.0] - 2026-01-31

### ✨ New Features

- **Core Validator**: The `@Airlock` decorator:
  - Ghost argument detection and stripping
  - Pydantic V2 strict validation (no type coercion)
  - Self-healing error responses with `fix_hints`

- **E2B Sandbox Integration**: Isolated execution:
  - `SandboxPool` with warm pool management
  - Function serialization via cloudpickle
  - `sandbox_required=True` prevents local fallback

- **Configuration System**: Flexible config priority:
  - Environment variables (`AIRLOCK_*`)
  - Constructor parameters
  - TOML config files (`airlock.toml`)

### 🔧 Improvements

- Full async/await support
- Comprehensive type hints throughout

---

## Links

- [Documentation](https://github.com/sattyamjjain/agent-airlock#readme)
- [PyPI Package](https://pypi.org/project/agent-airlock/)
- [Issue Tracker](https://github.com/sattyamjjain/agent-airlock/issues)
