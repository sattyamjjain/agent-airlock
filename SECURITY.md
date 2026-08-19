# Security Policy

## Supported Versions

Agent-Airlock is pre-1.0. Security fixes land only on the current `0.8.x` line;
older versions are unsupported — upgrade to the latest `0.8.x` release.

| Version | Supported          |
| ------- | ------------------ |
| 0.8.x   | :white_check_mark: |
| < 0.8.0 | :x:                |

### Fixed security issues

| Fixed in | Issue |
| --- | --- |
| v0.8.74 | [`SecurityPolicy.freeze()` silently dropped five security fields](docs/security/freeze-dropped-security-fields.md) (affects v0.5.7–v0.8.73, only when `freeze()` is called) |

### Published measurements

| Result | What it is |
| --- | --- |
| [Matched-pair multi-harness prompt injection](docs/benchmarks/injection-multi-harness.md) | **A null result, published as one.** `claude-code` 2.1.233 and `codex` 0.147.0 both ignored a planted README script convention entirely — 0/6 injected and 0/6 on the benign control. Explicitly **not** an injection-resistance finding: the benign twin was ignored identically. Includes the two earlier inconclusive runs and why they were inconclusive. |

## What the free containment layers cover, and what they leave open

Process-level containment for agents is being given away now. NVIDIA's **OpenShell** and
Cisco's **DefenseClaw** both ship deny-by-default sandboxing around the process an agent's
tools run in, and Amazon's **Cedar** gives away the policy language for expressing who may do
what. None of these is a competitor airlock is trying to argue with, and the honest starting
point is that **if you are not running one of them, do that before you reach for this.** They
close a larger and more commonly exploited class of problem than argument validation does.

**What they solve.** They bound *what a process can reach*. A contained tool process cannot
open a socket to an attacker's host, read `~/.aws/credentials`, or write outside its
workspace, regardless of what the model asked it to do or how the request was phrased. That
is containment in the operating-system sense, and it holds even when every layer above it has
been fooled — which is the property that makes it valuable and the reason it belongs at the
bottom of any agent stack. Cedar covers the adjacent question: given an authenticated
principal and a resource, is this action permitted at all.

**What they do not solve.** They bound the blast radius of a call; they do not check whether
the call is the one the contract allows. A sandbox has no opinion about
`transfer(amount=-1)`, about an `account_id` the model invented that happens to be a valid
string, about a `session` handle minted for another tenant, or about six extra parameters
that were never in the tool's signature. Every one of those is a well-formed, in-policy,
fully-contained call that does the wrong thing with the authority it legitimately has. Cedar
is the sharpest illustration: it answers *may this principal call this action on this
resource*, and answers it well — but the arguments are the part it does not model, and an
authorized principal calling an authorized action with fabricated arguments passes.

That gap is the whole of airlock's wedge, and it is deliberately narrow: **a deny-by-default
type-checker and contract layer for the arguments themselves, in-process, at the call
boundary.** The two compose in the obvious direction — containment bounds what a call can do,
airlock refuses the call before it is made — and they are complementary rather than
overlapping. Note the ordering that follows from that: airlock validates in the *calling*
process, before dispatch. Under `sandbox=True` with a real backend, `@Airlock` serialises the
undecorated function into the micro-VM, so `Annotated` validators (`SafePath`, `SafeURL`,
`HandleField`) do not run on that path; validate in the parent process, or keep validated
tools out of the sandbox.

### Where agent-airlock is the wrong tool

Stated plainly, because a security library that cannot say where it does not help is not one
worth trusting on where it does:

- **You need containment, not validation.** If the risk you are managing is "this tool could
  exfiltrate data or touch the host", a sandbox is the answer and airlock is not a substitute
  for one. `sandbox=True` delegates to E2B, Modal, or Docker precisely because airlock does
  not implement isolation itself.
- **You cannot run code in the agent's process.** airlock is a decorator. If the tools are
  behind someone else's server and you can only intervene on the wire, you need a proxy or a
  gateway; see the MCP-gateway comparison in the README.
- **The open question is who may authorize an action.** That is an authorization model —
  Cedar, or the propose-versus-authorize architectures. airlock's escalation verdict routes
  to an approver you supply; it does not decide policy for your organisation. The full
  comparison is in the README's
  [propose-versus-authorize section](README.md#propose-versus-authorize-agent-safe-pipeline-and-toolpermit)
  and is not repeated here.
- **You want a human-approval UI.** airlock's approver is a callable. There is no prompt, no
  pending-request queue, and no approval store.
- **Your tools take no structured arguments.** A single free-text `query` string has almost no
  contract to check. The value of argument validation scales with how much structure the
  arguments have.

## Reporting a Vulnerability

If you discover a security vulnerability in Agent-Airlock, please report it responsibly:

1. **Do NOT create a public GitHub issue**
2. Report it privately via [**GitHub Security Advisories**](https://github.com/sattyamjjain/agent-airlock/security/advisories/new) ("Report a vulnerability" on the repo's Security tab), or email **sattyamjjain@gmail.com**
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
3. **Report** - Report privately via [GitHub Security Advisories](https://github.com/sattyamjjain/agent-airlock/security/advisories/new) or email sattyamjjain@gmail.com
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
