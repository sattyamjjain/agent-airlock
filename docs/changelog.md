# Changelog

For the complete changelog with all versions and detailed release notes, see the [CHANGELOG.md](../CHANGELOG.md) file in the project root.

## Quick Version Summary

| Version | Codename | Highlights |
|---------|----------|------------|
| **0.4.0** | "Enterprise" | UnknownArgsMode, Safe Types, Capability Gating, Circuit Breaker, Cost Tracking, Retry Policies, OpenTelemetry, MCP Proxy Guard |
| **0.3.0** | "Vaccine" | Filesystem path validation, Network egress control, Honeypot deception, Framework vaccination |
| **0.2.0** | - | Security hardening, Production roadmap |
| **0.1.5** | - | Streaming support, Context propagation, Dynamic policy resolution, Conversation tracking |
| **0.1.3** | - | Framework compatibility (LangChain, OpenAI SDK, PydanticAI, etc.), Signature preservation |
| **0.1.1** | - | Policy engine, Output sanitization, FastMCP integration, Audit logging |
| **0.1.0** | - | Core validator, E2B sandbox integration, Configuration system |

---

## Latest Release: V0.4.0 "Enterprise"

### ✨ New Features

- **UnknownArgsMode**: Explicit `BLOCK`, `STRIP_AND_LOG`, `STRIP_SILENT` modes (replaces `strict_mode`)
- **Safe Types**: `SafePath`, `SafePathStrict`, `SafeURL`, `SafeURLAllowHttp`
- **Capability Gating**: `@requires(Capability.FILESYSTEM_READ)` decorator
- **Pluggable Sandbox Backends**: E2B, Docker, Local
- **Circuit Breaker**: Prevent cascading failures with CLOSED/OPEN/HALF_OPEN states
- **Cost Tracking**: Budget limits with soft/hard thresholds and alerts
- **Retry Policies**: Exponential backoff with jitter support
- **OpenTelemetry**: Distributed tracing with span attributes and metrics
- **MCP Proxy Guard**: Token passthrough prevention, session binding
- **CLI Tools**: `airlock doctor`, `airlock verify`

### 🔧 Improvements

- Enhanced audit logging with OpenTelemetry export support
- Better error messages for capability denials
- Improved thread safety in rate limiters and circuit breakers

---

## V0.3.0 "Vaccine"

### ✨ New Features

- **Filesystem Path Validation**: `os.path.commonpath()` (CVE-resistant)
- **Network Egress Control**: `network_airgap()` context manager
- **Honeypot Deception**: Return fake data instead of errors
- **Framework Vaccination**: `vaccinate("langchain")` automatic security

---

## Upgrade Guide

### From V0.3.0 to V0.4.0

**UnknownArgsMode migration:**
```python
# Old (deprecated)
@Airlock(config=AirlockConfig(strict_mode=True))

# New (V0.4.0)
from agent_airlock import UnknownArgsMode
@Airlock(unknown_args_mode=UnknownArgsMode.BLOCK)
```

### From V0.1.x to V0.3.0

No breaking changes - all V0.3.0 features are opt-in.

---

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.

Report issues at [GitHub Issues](https://github.com/sattyamjjain/agent-airlock/issues).

---

[View full changelog →](../CHANGELOG.md)
