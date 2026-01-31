# Agent-Airlock

**Security middleware for MCP servers - Intercept, validate, and sandbox AI agent tool calls**

[![PyPI version](https://badge.fury.io/py/agent-airlock.svg)](https://badge.fury.io/py/agent-airlock)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## What is Agent-Airlock?

Agent-Airlock is the **open-source, developer-first alternative** to enterprise MCP security solutions. It provides a simple decorator-based API to secure your AI agent tool calls.

```python
from agent_airlock import Airlock, AirlockConfig

@Airlock(config=AirlockConfig(strict_mode=True))
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
# LLM invents "force=True" - Airlock strips or rejects it
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

### Policy Engine
RBAC, rate limiting, and time-based restrictions.

```python
policy = SecurityPolicy(
    allowed_tools=["read_*"],
    denied_tools=["delete_*", "drop_*"],
    rate_limits={"*": "100/hour"},
)
```

### PII/Secret Masking
Detect and mask sensitive data in outputs.

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

## Next Steps

- [Installation Guide](getting-started/installation.md)
- [Quick Start Tutorial](getting-started/quickstart.md)
- [API Reference](api/airlock.md)
- [Examples](examples/basic.md)
