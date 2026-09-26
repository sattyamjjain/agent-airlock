# Agent-Airlock

**A deny-by-default contract layer for AI agent tool calls**

[![PyPI version](https://img.shields.io/pypi/v/agent-airlock?logo=pypi&logoColor=white&color=3775A9)](https://pypi.org/project/agent-airlock/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-3776AB?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-green)](https://opensource.org/licenses/Apache-2.0)

## What is Agent-Airlock?

An LLM decides which tool to call and what arguments to pass it. Agent-Airlock is the
contract at that boundary: strict argument validation with no type coercion, stripping of
parameters the model invented, and structured `fix_hints` the model can retry against.

It runs **in-process** — not a proxy, gateway or sidecar — because the process executing
the tool is the only place the real Python arguments exist. The installed core depends on
Pydantic and nothing else.

```python
from agent_airlock import Airlock, AirlockConfig, UnknownArgsMode

@Airlock(config=AirlockConfig(unknown_args=UnknownArgsMode.BLOCK))
def delete_user(user_id: int) -> dict:
    """Delete a user - protected by Airlock."""
    return {"deleted": user_id}

# LLM tries: delete_user(user_id="123", admin_override=True)
# Refused: unknown argument 'admin_override'. Retried without it, refused again:
# 'user_id' must be an integer, not str. Neither call reaches the function.
```

## Key Features

### Ghost Argument Protection
LLMs hallucinate parameters that don't exist. Airlock catches them.

```python
from agent_airlock import Airlock, AirlockConfig, UnknownArgsMode

# BLOCK - reject calls with unknown args
# STRIP_AND_LOG (the default) - strip them and log a warning
# STRIP_SILENT - strip them silently

@Airlock(config=AirlockConfig(unknown_args=UnknownArgsMode.BLOCK))
def delete_file(path: str) -> bool: ...

# LLM invents "force=True" - Airlock blocks it
result = delete_file(path="/data/users.db", force=True)  # Blocked!
```

### Strict Type Validation
No silent type coercion. `"123"` is not `123`.

```python
# LLM sends string instead of int - Airlock returns helpful error
result = get_user(user_id="123")  # Returns fix_hint, not crash
```

### Self-Healing Responses
When validation fails, Airlock returns structured errors the LLM can understand and retry.

```python
{
    "success": False,
    "status": "blocked",
    "error": "AIRLOCK_BLOCK: Tool 'get_user' validation failed. user_id: Input should be a valid integer",
    "block_reason": "validation_error",
    "fix_hints": ["'user_id' must be an integer, not str"],
    "metadata": {...},  # the function name and each field error
}
```

### Safe Types (V0.4.0)
Built-in types that validate paths and URLs automatically:

```python
from agent_airlock import SafePath, SafeURL

def read_file(path: SafePath) -> str:
    """Path is automatically validated against traversal attacks."""
    return open(path).read()

def fetch_data(url: SafeURL) -> dict:
    """URL is validated for HTTPS protocol."""
    return requests.get(url).json()
```

### Capability Gating (V0.4.0)
Fine-grained permission system for tool operations:

```python
from agent_airlock import Airlock, Capability, requires

@Airlock()
@requires(Capability.FILESYSTEM_READ | Capability.NETWORK_HTTP)
def fetch_and_save(url: str, path: str) -> bool:
    """Tool requires both filesystem and network capabilities."""
    ...
```

`@requires` declares what a tool needs; it is enforced against a `CapabilityPolicy` set as
`SecurityPolicy(capability_policy=...)` or `AirlockConfig(capability_policy=...)`. With
neither set, nothing is checked.

### Policy Engine
RBAC, rate limiting, and time-based restrictions.

```python
from agent_airlock import SecurityPolicy

policy = SecurityPolicy(
    allowed_tools=["read_*"],
    denied_tools=["delete_*", "drop_*"],
    rate_limits={"*": "100/hour"},
)
```

### Circuit Breaker (V0.4.0)
Prevent cascading failures with fault tolerance:

```python
from agent_airlock import AGGRESSIVE_BREAKER, Airlock, CircuitBreaker

breaker = CircuitBreaker("search-api", AGGRESSIVE_BREAKER)

@Airlock()
@breaker  # inside @Airlock, so it sees the tool's exceptions
def external_api_call(query: str) -> dict:
    """After 3 failures the circuit opens and calls fail fast."""
    ...
```

### PII/Secret Masking
Detect and mask sensitive data in outputs. India-specific types (Aadhaar, PAN, UPI) are
opt-in with `AirlockConfig(pii_locales=["in"])`.

```python
# Output: "User email: j***@example.com"
# Instead of: "User email: john@example.com"
```

### E2B Sandbox Execution
Run dangerous code in isolated Firecracker MicroVMs.

```python
@Airlock(sandbox=True, sandbox_required=True)
def run_user_code(code: str) -> str:
    exec(code)  # Runs in an E2B micro-VM, not on your server
    return "ok"
```

When E2B is not installed or configured, the call is refused with a blocked response; it is
not run on your server instead.

### OpenTelemetry Observability (V0.4.0)
Enterprise-grade distributed tracing:

```python
from agent_airlock import configure_observability, OpenTelemetryProvider

configure_observability(OpenTelemetryProvider(service_name="my-agent"))
```

## Quick Start

```bash
pip install agent-airlock
```

```python
from agent_airlock import Airlock

@Airlock()
def my_tool(query: str, limit: int = 10) -> list:
    return ["result1", "result2"]

# That's it! Your tool is now protected.
```

## Why Agent-Airlock?

| Feature | Enterprise Solutions | Agent-Airlock |
|---------|---------------------|---------------|
| Pricing | $$$$ | **Free & Open Source** |
| Integration | Proxy/Gateway | **Native Decorator** |
| Self-Healing | No | **Yes** |
| E2B Native | No | **Yes** |
| Developer UX | Dashboard | **Pythonic API** |
| Defense Layers | 2-3 | **6 Layers** |

## Defense Layers (V0.4.0)

1. **Validation** - Ghost argument detection, strict type checking
2. **Policy** - RBAC, rate limits, time restrictions
3. **Capability** - Fine-grained permission gating
4. **Filesystem** - Path traversal prevention
5. **Network** - Egress control, data exfiltration prevention
6. **Sandbox** - E2B Firecracker MicroVM isolation

## Next Steps

- [Installation Guide](getting-started/installation.md)
- [Quick Start Tutorial](getting-started/quickstart.md)
- [Configuration Reference](getting-started/configuration.md)
- [API Reference](api/airlock.md)
- [Examples](examples/basic.md)
