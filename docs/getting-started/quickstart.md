# Quick Start

This guide will get you up and running with Agent-Airlock in under 5 minutes.

## Your First Protected Tool

```python
from agent_airlock import Airlock

@Airlock()
def search_users(query: str, limit: int = 10) -> list[dict]:
    """Search for users by name."""
    # Your implementation here
    return [{"name": f"User matching '{query}'", "id": i} for i in range(limit)]
```

That's it! Your tool is now protected against:

- Ghost arguments (LLM-invented parameters)
- Type errors (string where int expected)
- Invalid values

## Handling Validation Errors

When the LLM sends invalid arguments, Airlock returns a self-healing response:

```python
# LLM tries: search_users(query=123, limit="ten")
result = search_users(query=123, limit="ten")

# Result is NOT a crash, but a helpful response:
# {
#     "status": "blocked",
#     "error": "Validation failed",
#     "fix_hints": [
#         "query: Expected str, got int. Try: query='123'",
#         "limit: Expected int, got str. Try: limit=10"
#     ]
# }
```

## Strict Mode

By default, Airlock strips unknown arguments. Enable strict mode to reject them:

```python
from agent_airlock import Airlock, AirlockConfig

config = AirlockConfig(strict_mode=True)

@Airlock(config=config)
def delete_user(user_id: int) -> dict:
    return {"deleted": user_id}

# LLM tries: delete_user(user_id=123, force=True)
# Blocked! "force" is not a valid parameter
```

## Adding Security Policies

Control who can call what:

```python
from agent_airlock import Airlock, SecurityPolicy

policy = SecurityPolicy(
    allowed_tools=["search_*", "get_*"],
    denied_tools=["delete_*", "drop_*"],
    rate_limits={"*": "100/hour"},
)

@Airlock(policy=policy)
def search_products(query: str) -> list:
    return [...]
```

## PII Masking

Prevent sensitive data from leaking to the LLM:

```python
from agent_airlock import Airlock, AirlockConfig

config = AirlockConfig(
    sanitize_output=True,
    mask_pii=True,
    mask_secrets=True,
)

@Airlock(config=config)
def get_user_profile(user_id: int) -> dict:
    return {
        "name": "John Doe",
        "email": "john@example.com",  # Masked!
        "ssn": "123-45-6789",         # Masked!
    }

# Output to LLM:
# {
#     "name": "John Doe",
#     "email": "[EMAIL REDACTED]",
#     "ssn": "[SSN REDACTED]"
# }
```

## Sandbox Execution

Run dangerous code in isolated environments:

```python
from agent_airlock import Airlock

@Airlock(sandbox=True)
def execute_code(code: str) -> str:
    """Execute arbitrary Python code safely."""
    return eval(code)  # Runs in E2B MicroVM, not your server!
```

!!! warning "E2B API Key Required"
    Sandbox execution requires an E2B API key. Set `E2B_API_KEY` environment variable.

## FastMCP Integration

Use with FastMCP servers:

```python
from fastmcp import FastMCP
from agent_airlock import secure_tool

mcp = FastMCP("My Secure Server")

@mcp.tool
@secure_tool()
def my_tool(x: int) -> int:
    return x * 2
```

## Next Steps

- [Configuration Options](configuration.md) - All configuration options
- [Policy Engine](../guide/policy.md) - RBAC and rate limiting
- [PII Masking](../guide/sanitization.md) - Data protection
- [Examples](../examples/basic.md) - More code examples
