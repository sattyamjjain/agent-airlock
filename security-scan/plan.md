# Security Scan Report: Agent-Airlock

**Scan Date:** 2026-01-31
**Project:** agent-airlock (MCP security middleware)

---

## Summary

| Severity | Count | Fixed |
|----------|-------|-------|
| Critical | 1 | ⬜ |
| High | 1 | ⬜ |
| Medium | 3 | ⬜ |
| Low | 3 | ⬜ |
| **Total** | **8** | **0** |

---

## Findings

### 1. [CRITICAL] Unsafe Pickle Deserialization in Sandbox

- **File:** `src/agent_airlock/sandbox.py:150-153`
- **Status:** ⬜ Pending
- **Description:** `cloudpickle.loads()` deserializes arbitrary payloads. While execution occurs in E2B sandbox (isolated), payload manipulation before transmission could enable RCE within sandbox.
- **Exploitation:** Attacker intercepts/manipulates base64 pickle payload → injects malicious pickle objects → code execution in sandbox
- **Fix:**
  1. Add HMAC signing for payload integrity verification
  2. Document risk in SECURITY.md
  3. Consider restricted unpickler

---

### 2. [HIGH] Unsafe exec() Fallback Without Warning

- **Files:**
  - `examples/e2b_sandbox.py:56`
  - `examples/fastmcp_integration.py:203`
- **Status:** ⬜ Pending
- **Description:** Examples use `exec(code)` with `sandbox=True`. When E2B unavailable, silently falls back to local execution. Users may copy this expecting protection.
- **Exploitation:** E2B not configured → fallback to local → attacker code runs on host
- **Fix:**
  1. Add `sandbox_required=True` option that fails instead of fallback
  2. Add prominent warnings in examples
  3. Log warning → raise exception when sandbox unavailable

---

### 3. [MEDIUM] Path Traversal in Example File Operations

- **Files:**
  - `examples/basic_usage.py:17-20`
  - `examples/e2b_sandbox.py:68-74`
  - `examples/fastmcp_integration.py:104-118`
- **Status:** ⬜ Pending
- **Description:** File operations lack path validation. `read_file("../../etc/passwd")` would succeed.
- **Fix:** Add path sanitization examples using `Path.resolve()` + allowlist

---

### 4. [MEDIUM] Sensitive Parameter Names in Logs

- **File:** `src/agent_airlock/core.py:119-124`
- **Status:** ⬜ Pending
- **Description:** Debug logs include `kwargs_keys` which may reveal sensitive parameter names like `password`, `api_key`
- **Fix:** Filter sensitive parameter names from debug output

---

### 5. [MEDIUM] Missing TOML Schema Validation

- **File:** `src/agent_airlock/config.py:66-88`
- **Status:** ⬜ Pending
- **Description:** Unknown TOML config keys silently ignored. Typos go unnoticed.
- **Fix:** Add warning for unknown configuration keys

---

### 6. [LOW] In-Memory Rate Limit State

- **File:** `src/agent_airlock/policy.py:116-201`
- **Status:** ⬜ Pending
- **Description:** Rate limits reset on process restart. Not effective in distributed systems.
- **Fix:** Document limitation clearly

---

### 7. [LOW] Example Test Credentials

- **File:** `tests/test_config.py:39`
- **Status:** ⬜ Pending
- **Description:** Uses `test-api-key-123` - should use clearer fake format
- **Fix:** Use `FAKE-KEY-DO-NOT-USE` pattern

---

### 8. [LOW] Missing Input Edge Case Tests

- **File:** `src/agent_airlock/policy.py:64-93`
- **Status:** ⬜ Pending
- **Description:** TimeWindow/RateLimit parsing could be more robust
- **Fix:** Add edge case tests

---

## Positive Findings

✅ Defense in depth (validation → policy → sandbox → sanitization)
✅ Pydantic strict mode prevents type coercion
✅ Comprehensive PII/secret regex patterns
✅ Ghost argument detection
✅ Token bucket rate limiting
✅ RBAC implementation
✅ Output sanitization with masking strategies
✅ Security documentation exists

---

## Remediation Priority

1. **Immediate:** #2 (sandbox fallback) - user-facing security issue
2. **Short-term:** #1 (pickle signing), #3 (path traversal examples)
3. **Long-term:** #4-8 (documentation and hardening)

---

## Next Steps

Run `/security-scan resume` to begin remediation.
