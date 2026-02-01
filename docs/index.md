# Agent-Airlock

**Security middleware for MCP servers - Intercept, validate, and sandbox AI agent tool calls**

[![PyPI version](https://badge.fury.io/py/agent-airlock.svg)](https://badge.fury.io/py/agent-airlock)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## What is Agent-Airlock?

Agent-Airlock is the **open-source, developer-first alternative** to enterprise MCP security solutions. It provides a simple decorator-based API to secure your AI agent tool calls with **6 layers of defense-in-depth**.

```python
from agent_airlock import Airlock, UnknownArgsMode

@Airlock(unknown_args_mode=UnknownArgsMode.BLOCK)
def delete_user(user_id: int) -> dict:
    """Delete a user - protected by Airlock."""
    return {"deleted": user_id}

# LLM tries: delete_user(user_id="123", admin_override=True)
# Airlock blocks: ghost argument 'admin_override', wrong type for 'user_id'
```

## Key Features

### Ghost Argument Protection
LLMs hallucinate parameters that don't exist. Airlock catches them.

```python
from agent_airlock import UnknownArgsMode

# BLOCK mode (production) - reject calls with unknown args
# STRIP_AND_LOG mode (staging) - strip and log warnings
# STRIP_SILENT mode (development) - silently strip

@Airlock(unknown_args_mode=UnknownArgsMode.BLOCK)
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
    "status": "blocked",
    "error": "Validation failed",
    "fix_hints": [
        "user_id: Expected int, got str. Try: user_id=123"
    ]
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
from agent_airlock import CircuitBreaker, AGGRESSIVE_BREAKER

@Airlock(circuit_breaker=AGGRESSIVE_BREAKER)
def external_api_call(query: str) -> dict:
    """Auto-fails fast if external service is down."""
    ...
```

### PII/Secret Masking
Detect and mask sensitive data in outputs (including India-specific: Aadhaar, PAN, UPI).

```python
# Output: "User email: [EMAIL REDACTED]"
# Instead of: "User email: john@example.com"
```

### E2B Sandbox Execution
Run dangerous code in isolated Firecracker MicroVMs.

```python
@Airlock(sandbox=True)
def run_user_code(code: str) -> str:
    return exec(code)  # Executes in E2B sandbox, not your server
```

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
