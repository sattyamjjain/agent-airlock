# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in Agent-Airlock, please report it responsibly:

1. **Do NOT create a public GitHub issue**
2. Email security concerns to: sattyamjain@example.com
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We aim to respond within 48 hours and will work with you to understand and address the issue.

---

## Security Audit Results

Last audit: 2026-01-31

### Static Analysis (Bandit)

| Finding | Severity | Status | Notes |
|---------|----------|--------|-------|
| B110: try_except_pass (4x) | Low | Acknowledged | Intentional - ignoring MCP progress reporting errors |
| B105: hardcoded_password_string | Low | False Positive | Enum value name, not actual password |

### Dependency Scan (Safety)

**Result:** 0 vulnerabilities found in 73 scanned packages

### ReDoS Analysis

All regex patterns have been reviewed for Regular Expression Denial of Service vulnerabilities:

| Pattern | Risk | Mitigation |
|---------|------|------------|
| EMAIL | Low | Word boundaries limit backtracking |
| PHONE | Safe | Fixed-width numeric patterns |
| SSN | Safe | Fixed-width pattern |
| CREDIT_CARD | Safe | Fixed-width pattern |
| IP_ADDRESS | Safe | Bounded repetition `{3}` |
| API_KEY | Safe | Specific prefixes, bounded lengths |
| AWS_KEY | Safe | Fixed pattern |
| PASSWORD | Low | Prefix anchors limit search space |
| PRIVATE_KEY | Safe | Fixed pattern |
| JWT | Low | Bounded by prefix and dot separators |
| CONNECTION_STRING | Low | Protocol prefixes limit matching |

**Recommendation:** For untrusted input, consider setting `max_output_chars` to limit regex processing time.

---

## Security Architecture

### Defense-in-Depth Layers

```
┌─────────────────────────────────────────────────────────────┐
│ Layer 1: Input Validation (Ghost Argument Stripping)        │
│   - Removes LLM-hallucinated parameters                     │
│   - Strict mode rejects unknown arguments                   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ Layer 2: Schema Validation (Pydantic V2 Strict Mode)        │
│   - No type coercion ("100" → int fails)                    │
│   - Self-healing error responses with fix_hints             │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ Layer 3: Policy Enforcement (RBAC)                          │
│   - Tool allow/deny lists                                   │
│   - Rate limiting (token bucket algorithm)                  │
│   - Time-based restrictions                                 │
│   - Agent identity verification                             │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ Layer 4: Execution Isolation (E2B Sandbox)                  │
│   - Firecracker MicroVM isolation                           │
│   - Network isolation                                       │
│   - Resource limits                                         │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│ Layer 5: Output Sanitization                                │
│   - PII detection and masking                               │
│   - Secret detection and masking                            │
│   - Output truncation (cost control)                        │
└─────────────────────────────────────────────────────────────┘
```

---

## Security Considerations

### 1. Cloudpickle Serialization (Sandbox Only)

When using `sandbox=True`, functions are serialized using cloudpickle for execution in E2B sandboxes.

**Risk:** Pickle deserialization can execute arbitrary code.

**Mitigation:**
- Deserialization only occurs inside the isolated E2B MicroVM
- The MicroVM is destroyed after execution
- Network access is restricted in the sandbox
- Never deserialize untrusted pickled data on the host

**Best Practice:**
```python
# SECURE: sandbox_required=True prevents local fallback
@Airlock(sandbox=True, sandbox_required=True)
def dangerous_operation(code: str) -> str:
    exec(code)  # Only runs in MicroVM
    return "done"
```

### 2. Rate Limiter Timing

The token bucket rate limiter uses floating-point time comparisons.

**Risk:** Potential timing attacks to probe rate limit state.

**Mitigation:**
- Rate limit responses include consistent timing
- No early exits that could leak state information
- Reset times are rounded to avoid precision-based attacks

### 3. Sensitive Parameter Logging

Debug logs could potentially leak sensitive information.

**Mitigation:**
- Parameter names are filtered against a blocklist before logging
- Sensitive parameter values are never logged
- Audit logs redact sensitive fields automatically

**Filtered parameter names:**
- password, passwd, pwd, secret, token
- key, api_key, apikey, auth, authorization
- credential, credentials, private_key, privatekey
- access_token, refresh_token, session, cookie
- ssn, credit_card, card_number

### 4. PII Detection Limitations

Regex-based PII detection has inherent limitations:

**Known Limitations:**
- May not detect obfuscated PII (e.g., "john at example dot com")
- Language-specific patterns (non-US phone formats)
- Context-dependent sensitivity (public vs private IP addresses)

**Recommendations:**
- Use workspace-specific PII configs for custom patterns
- Combine with application-level data classification
- Regular review of masking effectiveness

### 5. Audit Log Security

Audit logs contain tool call metadata.

**Best Practices:**
- Store audit logs in a secure, access-controlled location
- Implement log rotation and retention policies
- Encrypt logs at rest for sensitive environments
- Consider log forwarding to a SIEM system

---

## Secure Configuration

### Production Hardening Checklist

```python
from agent_airlock import Airlock, AirlockConfig, SecurityPolicy

# 1. Enable strict mode to reject unknown arguments
config = AirlockConfig(
    strict_mode=True,           # Reject ghost arguments
    sanitize_output=True,       # Enable output sanitization
    mask_pii=True,              # Mask PII in output
    mask_secrets=True,          # Mask secrets in output
    max_output_chars=20000,     # Limit output size
    enable_audit_log=True,      # Enable audit logging
)

# 2. Define restrictive policy
policy = SecurityPolicy(
    allowed_tools=["read_file", "search"],  # Allowlist, not blocklist
    denied_tools=["delete_*", "drop_*"],    # Extra protection
    rate_limits={"*": "100/minute"},        # Global rate limit
)

# 3. Use sandbox for dangerous operations
@Airlock(
    config=config,
    policy=policy,
    sandbox=True,               # Execute in isolation
    sandbox_required=True,      # Never fall back to local
)
def execute_code(code: str) -> str:
    ...
```

### Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `E2B_API_KEY` | E2B sandbox authentication | None |
| `AIRLOCK_STRICT_MODE` | Force strict mode globally | false |
| `AIRLOCK_MAX_OUTPUT_TOKENS` | Override max output tokens | 5000 |

---

## Compliance Considerations

### GDPR (General Data Protection Regulation)

Agent-Airlock helps with GDPR compliance through:

1. **Data Minimization** (Article 5)
   - Output truncation limits data exposure
   - Ghost argument stripping prevents over-collection

2. **Purpose Limitation** (Article 5)
   - Policy engine restricts tool access by purpose
   - Audit logs track data access

3. **Data Protection by Design** (Article 25)
   - PII detection and masking enabled by default
   - Defense-in-depth architecture

**Your Responsibilities:**
- Configure PII masking appropriate for your data categories
- Implement appropriate audit log retention (default: no automatic deletion)
- Ensure lawful basis for processing data through AI agents
- Document AI agent data processing in your privacy policy

### CCPA (California Consumer Privacy Act)

Agent-Airlock supports CCPA compliance through:

1. **Right to Know**
   - Audit logs record all tool calls and data access
   - Configure log retention for compliance window

2. **Right to Delete**
   - Implement session/conversation clearing in your application
   - Audit logs can be purged per retention policy

3. **Security Requirements**
   - Multiple security layers protect personal information
   - Encryption recommended for audit logs at rest

### HIPAA (Health Insurance Portability and Accountability Act)

For healthcare applications:

1. **Technical Safeguards**
   - Enable all PII masking features
   - Use E2B sandbox for PHI processing
   - Configure workspace-specific PII patterns for PHI

2. **Audit Controls**
   - Enable audit logging with extended retention
   - Forward logs to secure SIEM system
   - Implement access monitoring

3. **Access Controls**
   - Use strict policy with role-based tool access
   - Implement agent identity verification

**Note:** Agent-Airlock is not HIPAA-certified. Consult healthcare compliance experts for your specific use case.

### SOC 2

Agent-Airlock supports SOC 2 compliance through:

| Trust Principle | Support |
|-----------------|---------|
| Security | Policy engine, sandbox isolation, input validation |
| Availability | Rate limiting, resource controls |
| Processing Integrity | Schema validation, audit logging |
| Confidentiality | PII/secret masking, output sanitization |
| Privacy | GDPR/CCPA features above |

---

## Data Handling

### What Agent-Airlock Collects

| Data Type | Purpose | Storage |
|-----------|---------|---------|
| Function signatures | Schema generation | In-memory only |
| Call arguments | Validation, audit | Audit log (if enabled) |
| Tool outputs | Sanitization | Audit log (sanitized) |
| Timestamps | Rate limiting, audit | In-memory + audit log |
| Agent IDs | Policy enforcement | Audit log |

### Data Retention

Default behavior:
- In-memory data: Cleared when process exits
- Audit logs: Append-only, no automatic deletion
- Conversation state: TTL-based cleanup (default: 1 hour)

**Recommendation:** Implement application-level log rotation and retention policies.

### Data Flow

```
LLM Request → Airlock Validation → [Audit Log] → Execution → Sanitization → Response
                     │                                              │
                     ▼                                              ▼
              Sensitive params                               PII/secrets
              filtered from logs                             masked in output
```

---

## Incident Response

If you believe Agent-Airlock security has been compromised:

1. **Isolate** - Stop affected AI agents
2. **Collect** - Preserve audit logs for analysis
3. **Report** - Contact security@example.com
4. **Remediate** - Apply patches when available
5. **Review** - Assess policy and configuration

---

## Security Updates

Subscribe to security advisories:
- Watch this repository for releases
- Check the [CHANGELOG](CHANGELOG.md) for security fixes
- Follow [@sattyamjain](https://twitter.com/sattyamjain) for announcements

---

## Third-Party Security

### E2B Sandbox

Agent-Airlock uses [E2B](https://e2b.dev) for sandboxed execution:
- Firecracker MicroVM technology
- SOC 2 Type II certified
- See: https://e2b.dev/security

### Pydantic

Input validation uses [Pydantic V2](https://docs.pydantic.dev):
- Strict mode prevents type coercion attacks
- Regular security updates
- See: https://github.com/pydantic/pydantic/security

---

*Last updated: 2026-01-31*
