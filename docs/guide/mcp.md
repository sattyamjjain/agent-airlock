# FastMCP Integration

Seamless integration with FastMCP servers.

## Quick Start

```python
from fastmcp import FastMCP
from agent_airlock import secure_tool

mcp = FastMCP("My Secure Server")

@mcp.tool
@secure_tool()
def search_users(query: str, limit: int = 10) -> list:
    """Search for users by name."""
    return [{"name": f"User {i}"} for i in range(limit)]

if __name__ == "__main__":
    mcp.run()
```

## Installation

```bash
pip install agent-airlock[mcp]
```

This installs:
- `mcp>=1.0` - MCP SDK
- `fastmcp>=2.0,<3.0` - FastMCP framework

## Decorators

### @secure_tool

Convenience decorator combining `@mcp.tool` and `@Airlock`:

```python
from agent_airlock import secure_tool

@mcp.tool
@secure_tool()
def my_tool(x: int) -> int:
    return x * 2
```

Equivalent to:

```python
from agent_airlock import Airlock

@mcp.tool
@Airlock()
def my_tool(x: int) -> int:
    return x * 2
```

### Configuration

```python
from agent_airlock import secure_tool, AirlockConfig, SecurityPolicy

config = AirlockConfig(strict_mode=True, mask_pii=True)
policy = SecurityPolicy(rate_limits={"*": "100/hour"})

@mcp.tool
@secure_tool(config=config, policy=policy)
def protected_tool(query: str) -> list:
    return []
```

## MCPAirlock

For more control, use `MCPAirlock`:

```python
from agent_airlock import MCPAirlock, AirlockConfig

config = AirlockConfig(
    strict_mode=True,
    sanitize_output=True,
    mask_pii=True,
)

mcp_airlock = MCPAirlock(config=config)

@mcp.tool
@mcp_airlock
def my_tool(x: int) -> int:
    return x * 2
```

## Server Factory

Create a fully secured MCP server:

```python
from agent_airlock import create_secure_mcp_server, SecurityPolicy

policy = SecurityPolicy(
    allowed_tools=["search_*", "get_*"],
    denied_tools=["delete_*"],
    rate_limits={"*": "100/hour"},
)

mcp = create_secure_mcp_server(
    name="Secure API",
    policy=policy,
    strict_mode=True,
    mask_pii=True,
)

@mcp.tool
def search_products(query: str) -> list:
    return []

if __name__ == "__main__":
    mcp.run()
```

## MCP Context

Access MCP context within tools:

```python
from fastmcp import Context
from agent_airlock import secure_tool

@mcp.tool
@secure_tool()
def my_tool(query: str, ctx: Context) -> list:
    # Access MCP context
    client_id = ctx.client_id

    # Report progress
    ctx.report_progress(0.5, "Processing...")

    return []
```

## Progress Reporting

Airlock supports MCP progress reporting during sandbox execution:

```python
@mcp.tool
@secure_tool(sandbox=True)
async def long_task(data: str, ctx: Context) -> dict:
    ctx.report_progress(0.1, "Starting...")
    result = process(data)
    ctx.report_progress(0.9, "Almost done...")
    return result
```

## Error Handling

MCP-compatible error responses:

```python
@mcp.tool
@secure_tool(strict_mode=True)
def my_tool(user_id: int) -> dict:
    return {"id": user_id}

# When validation fails, returns MCP-compatible error:
# {
#     "status": "blocked",
#     "error": "Validation failed",
#     "fix_hints": ["user_id: Expected int, got str"]
# }
```

## Example: Complete Server

```python
"""Secure MCP Server Example."""
from fastmcp import FastMCP
from agent_airlock import (
    secure_tool,
    AirlockConfig,
    SecurityPolicy,
    create_secure_mcp_server,
)

# Create server with security defaults
mcp = create_secure_mcp_server(
    name="Customer API",
    strict_mode=True,
    mask_pii=True,
)

# Read-only tool
@mcp.tool
@secure_tool()
def get_customer(customer_id: int) -> dict:
    """Get customer by ID."""
    return {
        "id": customer_id,
        "name": "John Doe",
        "email": "john@example.com",  # Masked in output
    }

# Rate-limited tool
rate_policy = SecurityPolicy(rate_limits={"search_customers": "50/minute"})

@mcp.tool
@secure_tool(policy=rate_policy)
def search_customers(query: str, limit: int = 10) -> list:
    """Search for customers."""
    return [{"name": f"Customer {i}"} for i in range(limit)]

# Sandboxed tool for dangerous operations
@mcp.tool
@secure_tool(sandbox=True, sandbox_required=True)
def analyze_data(code: str, data: list) -> dict:
    """Run analysis code on data."""
    # Executes in E2B sandbox
    result = exec(code)
    return {"result": result}

# Resources
@mcp.resource("customers://{customer_id}")
def get_customer_resource(customer_id: int) -> str:
    return f"Customer {customer_id}"

if __name__ == "__main__":
    mcp.run()
```

## Testing

Test your secured MCP server:

```python
import pytest
from my_server import mcp

@pytest.fixture
def client():
    return mcp.test_client()

def test_valid_call(client):
    result = client.call_tool("get_customer", customer_id=123)
    assert result["id"] == 123

def test_invalid_type(client):
    result = client.call_tool("get_customer", customer_id="invalid")
    assert result["status"] == "blocked"
    assert "fix_hints" in result

def test_ghost_argument(client):
    result = client.call_tool("get_customer", customer_id=123, admin=True)
    assert result["status"] == "blocked"
    assert "admin" in str(result["fix_hints"])
```

## Compatibility

Agent-Airlock works with:

| Framework | Supported |
|-----------|-----------|
| FastMCP 2.x | ✅ |
| FastMCP 3.x | 🚧 (planned) |
| MCP SDK | ✅ |
| Claude Desktop | ✅ |
| Claude Code | ✅ |
