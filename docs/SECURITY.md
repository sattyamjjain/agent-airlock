# Security Best Practices for Agent-Airlock

This document provides security guidelines for using Agent-Airlock in production MCP servers.

## Table of Contents

- [Threat Model](#threat-model)
- [Defense-in-Depth](#defense-in-depth)
- [Configuration Guidelines](#configuration-guidelines)
- [Policy Engine](#policy-engine)
- [Sandbox Execution](#sandbox-execution)
- [Output Sanitization](#output-sanitization)
- [Audit Logging](#audit-logging)
- [Reporting Vulnerabilities](#reporting-vulnerabilities)

---

## Threat Model

Agent-Airlock protects against these AI agent attack vectors:

### 1. Hallucinated Arguments
**Threat**: LLMs invent parameters that don't exist in tool signatures.

**Example**:
```python
# Tool expects: read_file(path: str)
# LLM sends: read_file(path="data.txt", force=True, admin=True)
```

**Mitigation**: Ghost argument stripping (permissive) or rejection (strict mode).

### 2. Type Coercion Attacks
**Threat**: LLMs send wrong types expecting implicit conversion.

**Example**:
```python
# Tool expects: delete_records(limit: int)
# LLM sends: delete_records(limit="999999999")
```

**Mitigation**: Pydantic V2 strict mode - no type coercion allowed.

### 3. Prompt Injection via Tool Arguments
**Threat**: Malicious content in tool arguments designed to manipulate subsequent LLM behavior.

**Example**:
```python
# LLM sends: write_file(content="Ignore all previous instructions...")
```

**Mitigation**: Output sanitization + policy-based content filtering.

### 4. Resource Exhaustion
**Threat**: Tools that consume excessive compute, memory, or API calls.

**Example**:
```python
# LLM sends: process_file(path="/dev/zero")  # Infinite read
```

**Mitigation**: Rate limiting, output truncation, and sandbox resource limits.

### 5. Privilege Escalation
**Threat**: Agents attempting to access tools beyond their authorization level.

**Example**:
```python
# Read-only agent tries: delete_database(confirm=True)
```

**Mitigation**: RBAC policy engine with role-based tool access.

### 6. Data Exfiltration
**Threat**: Sensitive data leaking through tool outputs back to the LLM.

**Example**:
```python
# Tool returns: {"api_key": "sk-live-xxxxx", "user_ssn": "123-45-6789"}
```

**Mitigation**: PII/secret detection and masking in output sanitization.

---

## Defense-in-Depth

Agent-Airlock implements multiple security layers:

```
┌─────────────────────────────────────────────────────────────┐
│ Layer 1: Input Validation                                   │
│   • Ghost argument detection                                │
│   • Pydantic strict schema validation                       │
│   • Type checking with no coercion                          │
├─────────────────────────────────────────────────────────────┤
│ Layer 2: Policy Enforcement                                 │
│   • Tool allow/deny lists                                   │
│   • Rate limiting (token bucket)                            │
│   • Time-based restrictions                                 │
│   • Agent role verification                                 │
├─────────────────────────────────────────────────────────────┤
│ Layer 3: Execution Isolation                                │
│   • Local execution (trusted tools)                         │
│   • E2B Firecracker MicroVM (untrusted code)               │
│   • Resource limits (CPU, memory, network)                  │
├─────────────────────────────────────────────────────────────┤
│ Layer 4: Output Protection                                  │
│   • PII detection and masking                               │
│   • Secret/API key removal                                  │
│   • Output size truncation                                  │
│   • Audit logging                                           │
└─────────────────────────────────────────────────────────────┘
```

---

## Configuration Guidelines

### Recommended Production Configuration

```python
from agent_airlock import Airlock, AirlockConfig, STRICT_POLICY

config = AirlockConfig(
    strict_mode=True,          # Reject unknown arguments
    mask_pii=True,             # Mask SSN, credit cards, etc.
    mask_secrets=True,         # Mask API keys, passwords
    max_output_chars=10000,    # Prevent token explosion
    sanitize_output=True,      # Enable all output protection
)

@Airlock(config=config, policy=STRICT_POLICY)
def my_secure_tool(args: MyArgs) -> dict:
    ...
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AIRLOCK_STRICT_MODE` | Reject unknown arguments | `false` |
| `AIRLOCK_MASK_PII` | Enable PII masking | `true` |
| `AIRLOCK_MASK_SECRETS` | Enable secret masking | `true` |
| `E2B_API_KEY` | E2B sandbox API key | None |

### Strict Mode vs Permissive Mode

| Mode | Behavior | Use Case |
|------|----------|----------|
| **Permissive** (default) | Strip unknown args, log warning | Development, backward compatibility |
| **Strict** | Reject call, return error | Production, high-security environments |

---

## Policy Engine

### Predefined Policies

```python
from agent_airlock import (
    PERMISSIVE_POLICY,    # No restrictions
    STRICT_POLICY,        # Requires agent ID
    READ_ONLY_POLICY,     # Blocks write/delete/modify tools
    BUSINESS_HOURS_POLICY # 9 AM - 5 PM only
)
```

### Custom Policies

```python
from agent_airlock import SecurityPolicy

PRODUCTION_POLICY = SecurityPolicy(
    # Tool access control
    allowed_tools=["read_*", "query_*", "get_*"],
    denied_tools=["delete_*", "drop_*", "truncate_*"],

    # Agent identity requirements
    require_agent_id=True,
    allowed_roles=["analyst", "developer"],

    # Rate limiting
    rate_limits={
        "query_*": "100/minute",
        "*": "1000/hour",
    },

    # Time restrictions
    time_restrictions={
        "write_*": "09:00-17:00",  # Business hours only
    },
)
```

### Rate Limit Patterns

```python
rate_limits={
    "expensive_api": "10/minute",    # Specific tool
    "query_*": "100/minute",          # Wildcard pattern
    "*": "1000/hour",                 # Global fallback
}
```

---

## Sandbox Execution

### When to Use Sandbox

Use `sandbox=True` for tools that:
- Execute user-provided code
- Process untrusted file content
- Make network requests to arbitrary URLs
- Perform filesystem operations

```python
@Airlock(sandbox=True)
def execute_code(code: str) -> str:
    """Runs in isolated E2B MicroVM."""
    exec(code)
    return "executed"
```

### Sandbox Limitations

- Cold start: ~500ms (warm pool reduces to ~100ms)
- Max execution time: 60 seconds (configurable)
- No persistent state between calls
- Network access is sandboxed

### E2B API Key Security

```bash
# Store in environment (recommended)
export E2B_API_KEY="your-key-here"

# Or in config file (less secure)
# airlock.toml
[sandbox]
e2b_api_key = "your-key-here"  # Ensure file permissions are restricted
```

---

## Output Sanitization

### PII Detection

Automatically detects and masks:
- Social Security Numbers (XXX-XX-XXXX)
- Credit Card Numbers (4XXX-XXXX-XXXX-XXXX)
- Email Addresses
- Phone Numbers
- IP Addresses

### Secret Detection

Automatically detects and masks:
- API Keys (`sk-live-`, `api_key=`, etc.)
- AWS Access Keys (`AKIA...`)
- JWT Tokens (`eyJ...`)
- Connection Strings (`postgres://`, `mongodb://`)
- Generic Passwords

### Masking Strategies

```python
from agent_airlock import SanitizationConfig, MaskingStrategy

config = SanitizationConfig(
    pii_strategy=MaskingStrategy.PARTIAL,   # Show last 4 chars
    secret_strategy=MaskingStrategy.FULL,   # Complete redaction
)
```

| Strategy | Example |
|----------|---------|
| `FULL` | `***REDACTED***` |
| `PARTIAL` | `***-**-6789` |
| `TYPE_ONLY` | `[SSN REDACTED]` |
| `HASH` | `[SSN:a1b2c3d4]` |

---

## Audit Logging

### Log Format

All tool calls are logged as structured JSON:

```json
{
  "timestamp": "2026-01-31T10:30:00Z",
  "tool": "delete_records",
  "agent_id": "agent-123",
  "args": {"table": "users", "where": "id=1"},
  "result": "blocked",
  "reason": "tool_denied",
  "policy": "STRICT_POLICY"
}
```

### Log Destinations

```python
import structlog

# Configure logging backend
structlog.configure(
    processors=[
        structlog.processors.JSONRenderer()
    ],
    logger_factory=structlog.PrintLoggerFactory(),
)
```

---

## Reporting Vulnerabilities

If you discover a security vulnerability in Agent-Airlock:

1. **Do NOT** open a public GitHub issue
2. Email: security@example.com (replace with actual contact)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We aim to respond within 48 hours and provide a fix within 7 days for critical issues.

---

## Security Checklist

Before deploying to production:

- [ ] Enable `strict_mode=True`
- [ ] Configure appropriate `SecurityPolicy`
- [ ] Enable PII and secret masking
- [ ] Set reasonable `max_output_chars` limit
- [ ] Use `sandbox=True` for code execution tools
- [ ] Store E2B API key in environment variable
- [ ] Configure audit logging
- [ ] Review and test rate limits
- [ ] Test with adversarial inputs

---

## References

- [OWASP AI Agent Security Top 10 (2026)](https://owasp.org/www-project-ai-security/)
- [MCP Security Guidelines](https://modelcontextprotocol.io/specification)
- [E2B Security Model](https://e2b.dev/docs/security)
- [Pydantic Strict Mode](https://docs.pydantic.dev/latest/concepts/strict_mode/)
