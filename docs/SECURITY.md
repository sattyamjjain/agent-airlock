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

**Mitigation**: Ghost argument stripping (the default) or rejection (`UnknownArgsMode.BLOCK`).

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
from agent_airlock import Airlock, AirlockConfig, STRICT_POLICY, UnknownArgsMode

config = AirlockConfig(
    unknown_args=UnknownArgsMode.BLOCK,  # Reject unknown arguments
    mask_pii=True,             # Mask SSN, credit cards, etc.
    mask_secrets=True,         # Mask API keys, passwords
    max_output_chars=10000,    # Prevent token explosion
    sanitize_output=True,      # Enable all output protection
)

# STRICT_POLICY refuses any call that carries no agent identity
@Airlock(config=config, policy=STRICT_POLICY)
def my_secure_tool(args: MyArgs) -> dict:
    ...
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AIRLOCK_UNKNOWN_ARGS` | `block` rejects unknown arguments; also `strip_and_log`, `strip_silent` | `strip_and_log` |
| `AIRLOCK_STRICT_MODE` | Deprecated; `true` maps to `block`, any other value to `strip_and_log` (and wins over `AIRLOCK_UNKNOWN_ARGS`) | unset |
| `E2B_API_KEY` | E2B sandbox API key, used when none is set in code | None |

PII and secret masking have no environment variable. Both are on by default
(`mask_pii=True`, `mask_secrets=True`); turn them off in code.

### Unknown-Argument Modes

Set with `AirlockConfig(unknown_args=...)`. `strict_mode=True` is the deprecated spelling
of `BLOCK`.

| Mode | Behavior | Use Case |
|------|----------|----------|
| `STRIP_AND_LOG` (default) | Strip unknown args, log warning | Development, backward compatibility |
| `BLOCK` | Reject call, return error | Production, high-security environments |
| `STRIP_SILENT` | Strip unknown args, no warning | Isolated development only |

---

## Policy Engine

### Predefined Policies

```python
from agent_airlock import (
    PERMISSIVE_POLICY,    # No restrictions
    STRICT_POLICY,        # Requires agent ID
    READ_ONLY_POLICY,     # Blocks write/delete/modify tools
    BUSINESS_HOURS_POLICY # delete_*, drop_*, *_production only 9 AM - 5 PM
)
```

### Custom Policies

```python
from agent_airlock import SecurityPolicy

PRODUCTION_POLICY = SecurityPolicy(
    # Tool access control
    allowed_tools=["read_*", "query_*", "get_*"],
    denied_tools=["delete_*", "drop_*", "truncate_*"],

    # Agent identity requirements; how a call carries one: guide/policy.md#agent-identity
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

### CRITICAL: Use sandbox_required=True for Dangerous Operations

When E2B is not installed or configured, a `sandbox=True` call is refused with a blocked
response. `sandbox=True` alone still leaves one local fallback: if `agent_airlock.sandbox`
itself fails to import, the function runs in your process. `sandbox_required=True` refuses
that case too, so it is the setting for tools that execute arbitrary code.

```python
# Refused when E2B is unavailable, but runs locally if agent_airlock.sandbox
# cannot be imported
@Airlock(sandbox=True)
def execute_code(code: str) -> str:
    exec(code)
    return "executed"

# SECURE: never runs in your process
@Airlock(sandbox=True, sandbox_required=True)
def execute_code(code: str) -> str:
    """Runs in an isolated E2B micro-VM, or not at all."""
    exec(code)
    return "executed"
```

**Always use `sandbox_required=True` for**:
- Code execution (exec(), eval())
- Shell command execution
- Any operation that could compromise the host system

### Sandbox Limitations

- Cold start: E2B reports about 125ms for its Firecracker micro-VMs; not measured by this
  project. A warmed pool (`get_sandbox_pool(config).warm_up()`) creates sandboxes before the
  first call.
- Sandbox lifetime: `sandbox_timeout` seconds, 60 by default, passed to E2B when each sandbox
  is created. There is no per-call time limit.
- **Sandboxes are reused.** The pool hands a sandbox back for later calls in the same process,
  so anything one call leaves in it, such as files, can be seen by the next. Do not rely on
  isolation between calls.
- Network access is sandboxed
- 24-hour session cap (E2B limitation)

### E2B API Key Security

```bash
# Store in environment (recommended)
export E2B_API_KEY="your-key-here"

# Or in config file (less secure), loaded with AirlockConfig.from_toml("airlock.toml")
# airlock.toml
[airlock]
e2b_api_key = "your-key-here"  # Ensure file permissions are restricted
```

A key set in code or in the file takes precedence; `E2B_API_KEY` is used only when neither
sets one.

### Pickle Serialization Security

Agent-Airlock uses `cloudpickle` to serialize functions and arguments for
sandbox execution. This is inherently risky because pickle can execute
arbitrary code during deserialization.

**Why this is acceptable**:
1. Deserialization occurs INSIDE the E2B sandbox (isolated MicroVM)
2. Even if malicious code executes, it's contained in the sandbox
3. The sandbox has no access to your host filesystem or network

**For high-security environments**, consider:
- Adding HMAC signing to verify payload integrity before sending to sandbox
- Implementing a restricted unpickler that validates types
- Using JSON serialization for simple argument types

**Risk assessment**:
- If an attacker can modify the pickle payload in transit → RCE in sandbox only
- Sandbox isolation prevents host compromise
- This is defense-in-depth: validation + isolation + sanitization

### Rate Limit State Persistence

**Note**: Rate limit state is stored in memory and resets on process restart.
In distributed deployments, consider:
- Using external storage (Redis) for rate limit state
- Accepting per-instance rate limiting as a temporary measure
- Documenting this limitation in your deployment guide

---

## Output Sanitization

### PII Detection

Automatically detects and masks:
- Social Security Numbers (XXX-XX-XXXX)
- Credit Card Numbers (an unbroken run of digits; `4111-1111-1111-1111` is not detected)
- Email Addresses
- Phone Numbers
- IP Addresses

With `pii_locales=["in"]`, also Aadhaar, PAN, UPI IDs, IFSC codes, Devanagari names and
Indian mobile numbers.

### Secret Detection

Automatically detects and masks:
- API Keys of known shapes: `sk-` keys with 20+ characters after the prefix (OpenAI,
  Anthropic), Google `AIza...`, GitHub `ghp_`/`gho_`/`github_pat_`, Slack `xox*`.
  Others, such as `sk-live-...` or `api_key=...`, are not detected.
- AWS Access Keys (`AKIA...`)
- JWT Tokens (`eyJ...`)
- Connection Strings (`postgres://`, `mongodb://`)
- Generic Passwords (8+ characters after `password=`, `pwd=`, `secret=`, `token=`, etc.)

A string, dict, list, tuple or set result is masked. Any other object (a Pydantic model, a
dataclass) is returned as it is, and what was found in it is logged as not masked; what a
generator yields is not masked either. See [PII & Secret Masking](guide/sanitization.md).

### Masking Strategies

`@Airlock` masks each type with its default strategy: `FULL` for SSN, passwords, private
keys and connection strings, `TYPE_ONLY` for IFSC, `PARTIAL` for the rest. `AirlockConfig`
has no strategy setting. To choose one, run the standalone sanitizer with a `mask_config`
mapping; a type left out of the mapping is masked `FULL`:

```python
from agent_airlock import MaskingStrategy, SensitiveDataType, sanitize_output

result = sanitize_output(
    text,
    mask_config={
        SensitiveDataType.SSN: MaskingStrategy.PARTIAL,   # First and last 3 chars
        SensitiveDataType.API_KEY: MaskingStrategy.FULL,  # Complete redaction
    },
)
```

| Strategy | Example (SSN `123-45-6789`) |
|----------|---------|
| `FULL` | `[REDACTED]` |
| `PARTIAL` | `123***789` |
| `TYPE_ONLY` | `[SSN]` |
| `HASH` | `[SHA256:01a54629...]` |

---

## Audit Logging

### Log Format

Calls through `@Airlock` are appended to a JSON Lines file, one record per line:
`airlock_audit.json` by default (`audit_log_path`; `enable_audit_log=False` turns it off).
A call to `delete_records` refused by a `denied_tools=["delete_*"]` policy:

```json
{
  "timestamp": "2026-01-31T10:30:00.123456+00:00",
  "tool_name": "delete_records",
  "blocked": true,
  "block_reason": "policy_violation",
  "duration_ms": 0.11,
  "sanitized_count": 0,
  "truncated": false,
  "args_preview": {"table": "'users'", "where": "'id=1'"},
  "result_type": "None",
  "result_preview": "BLOCKED",
  "error": "AIRLOCK_BLOCK: Policy violation for 'delete_records'. Tool 'delete_records' is denied by policy (matches 'delete_*')"
}
```

Fields with no value are left out. `agent_id` and `session_id` are recorded only from a
context carried by the tool's first argument; an identity set around the call with
`with AirlockContext(...)` does not reach the record. Argument values whose names look
sensitive (`password`, `token`, `api_key`, ...) are written as `[REDACTED]`.

### Log Destinations

The library's own log lines (not the audit file) go through structlog when the
`[logging]` extra is installed, and through the stdlib `logging` module otherwise:

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
2. Report it privately via [GitHub Security Advisories](https://github.com/sattyamjjain/agent-airlock/security/advisories/new), or email sattyamjjain@gmail.com
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We aim to respond within 48 hours and provide a fix within 7 days for critical issues.

---

## Security Checklist

Before deploying to production:

- [ ] Set `unknown_args=UnknownArgsMode.BLOCK`
- [ ] Configure appropriate `SecurityPolicy`
- [ ] Enable PII and secret masking
- [ ] Set reasonable `max_output_chars` limit
- [ ] Use `sandbox=True` for code execution tools
- [ ] **Use `sandbox_required=True` for exec()/eval() tools**
- [ ] Store E2B API key in environment variable
- [ ] Configure audit logging
- [ ] Review and test rate limits
- [ ] **Validate file paths to prevent directory traversal**
- [ ] Test with adversarial inputs

---

## OWASP LLM Top 10 Mapping (2025)

Agent-Airlock provides mitigations for these OWASP LLM Application Security risks:

| OWASP Risk | Agent-Airlock Mitigation |
|------------|--------------------------|
| **LLM01: Prompt Injection** | Strict type validation rejects malformed inputs; no implicit type coercion |
| **LLM05: Improper Output Handling** | PII/secret detection + masking sanitizes string and container (dict, list, tuple, set) tool outputs |
| **LLM06: Excessive Agency** | Rate limiting, time restrictions, and RBAC policies constrain agent actions |
| **LLM09: Misinformation** | Ghost argument rejection prevents hallucinated parameters from executing |
| **LLM10: Unbounded Consumption** | Output truncation limits token usage; rate limiting prevents API abuse |

---

## References

- [OWASP Top 10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP Top 10 for LLMs v2025 PDF](https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf)
- [LLM01: Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [MCP Security Guidelines](https://modelcontextprotocol.io/specification)
- [E2B Security Model](https://e2b.dev/docs/security)
- [E2B Firecracker Performance](https://e2b.dev/blog/firecracker-vs-qemu) - E2B's own cold-start figure
- [Pydantic Strict Mode](https://docs.pydantic.dev/latest/concepts/strict_mode/)
