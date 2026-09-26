# FastMCP Integration

Seamless integration with FastMCP servers.

## Quick Start

```python
from fastmcp import FastMCP
from agent_airlock.mcp import secure_tool

mcp = FastMCP("My Secure Server")

@secure_tool(mcp)
def search_users(query: str, limit: int = 10) -> list:
    """Search for users by name."""
    return [{"name": f"User {i}"} for i in range(limit)]

if __name__ == "__main__":
    mcp.run()
```

`secure_tool(mcp)` wraps the function in Airlock and registers it with the server, so it
takes the place of `@mcp.tool` rather than sitting under it.

## Installation

```bash
pip install agent-airlock[mcp]
```

This installs:
- `mcp>=1.0` - MCP SDK
- `fastmcp>=2.0,<5.0` - FastMCP framework

The integration lives in `agent_airlock.mcp`: import `secure_tool`, `MCPAirlock` and
`create_secure_mcp_server` from there. The package root does not export `secure_tool` or
`MCPAirlock`.

## Decorators

### @secure_tool

Convenience decorator combining `@mcp.tool` and `MCPAirlock`. Its first argument is the
server:

```python
from agent_airlock.mcp import secure_tool

@secure_tool(mcp)
def my_tool(x: int) -> int:
    return x * 2
```

Equivalent to:

```python
from agent_airlock.mcp import MCPAirlock

@mcp.tool
@MCPAirlock(report_progress=True)
def my_tool(x: int) -> int:
    return x * 2
```

`name=` and `description=` are passed through to `mcp.tool()`.

### Configuration

```python
from agent_airlock import AirlockConfig, SecurityPolicy
from agent_airlock.mcp import secure_tool

config = AirlockConfig(mask_pii=True)
policy = SecurityPolicy(rate_limits={"*": "100/hour"})

@secure_tool(mcp, config=config, policy=policy)
def protected_tool(query: str) -> list:
    return []
```

`sandbox=True` runs the tool in the E2B sandbox. There is no `sandbox_required` parameter;
the complete server below shows a tool that must never run outside the sandbox.

## MCPAirlock

For more control, use `MCPAirlock`, the wrapper `secure_tool` applies. You register the
tool yourself, and one instance can wrap several tools:

```python
from agent_airlock import AirlockConfig
from agent_airlock.mcp import MCPAirlock

config = AirlockConfig(
    sanitize_output=True,
    mask_pii=True,
)

mcp_airlock = MCPAirlock(config=config)

@mcp.tool
@mcp_airlock
def my_tool(x: int) -> int:
    return x * 2
```

It takes `sandbox`, `config`, `policy` and `report_progress` (default `False`).

## Server Factory

`create_secure_mcp_server` creates the FastMCP server and returns it with a decorator that
applies `secure_tool` using the server's defaults:

```python
from agent_airlock import AirlockConfig, SecurityPolicy
from agent_airlock.mcp import create_secure_mcp_server

policy = SecurityPolicy(
    allowed_tools=["search_*", "get_*"],
    denied_tools=["delete_*"],
    rate_limits={"*": "100/hour"},
)

mcp, secure = create_secure_mcp_server(
    "Secure API",
    config=AirlockConfig(mask_pii=True),
    default_policy=policy,
)

@secure
def search_products(query: str) -> list:
    return []

if __name__ == "__main__":
    mcp.run()
```

The decorator also takes per-tool overrides: `@secure(sandbox=True)`, `policy=` (replaces
`default_policy` for that tool), `tool_name=` and `tool_description=`. Only tools registered
through it are guarded. The factory installs nothing on the server itself, so a tool added
with a plain `@mcp.tool` runs without Airlock.

## MCP Context

A secured tool can still take FastMCP's `Context`. FastMCP injects it and keeps it out of
the tool's input schema, and Airlock passes it through unchanged:

```python
from fastmcp import Context
from agent_airlock.mcp import secure_tool

@secure_tool(mcp)
def my_tool(query: str, ctx: Context) -> list:
    # Access MCP context
    client_id = ctx.client_id
    return []
```

## Progress Reporting

Airlock does not send progress notifications itself. `MCPAirlock(report_progress=True)`,
which `secure_tool` turns on, calls `ctx.report_progress()` before and after the call when
the tool receives a keyword argument named `ctx`. FastMCP's `Context.report_progress` is a
coroutine and the wrapper does not await it, so nothing reaches the client. To report
progress, make the tool `async` and await FastMCP's method yourself:

```python
from fastmcp import Context
from agent_airlock.mcp import secure_tool

@secure_tool(mcp)
async def long_task(data: str, ctx: Context) -> dict:
    await ctx.report_progress(progress=10, total=100, message="Starting...")
    result = {"length": len(data)}
    await ctx.report_progress(progress=90, total=100, message="Almost done...")
    return result
```

## Error Handling

FastMCP validates the arguments against the tool's signature before the tool runs, and
coerces where it can: `"5"` reaches an `int` parameter as `5`. A value it cannot coerce, or
an argument the tool does not declare, is rejected with FastMCP's own validation error.
Those calls never reach Airlock, so on an MCP server Airlock's strict type check and
ghost-argument handling see only what FastMCP passes on.

When Airlock blocks a call that FastMCP let through, such as a policy denial or an exhausted
rate limit, `MCPAirlock` returns the reason and the fix hints as the tool's result, so the
model can read them:

```python
from agent_airlock import SecurityPolicy
from agent_airlock.mcp import secure_tool

@secure_tool(mcp, policy=SecurityPolicy(denied_tools=["delete_*"]))
def delete_user(user_id: int) -> str:
    return f"deleted {user_id}"

# A call returns this text, and the function body never runs:
# Error: AIRLOCK_BLOCK: Policy violation for 'delete_user'. Tool 'delete_user' is denied by policy (matches 'delete_*')
#
# Suggested fixes:
# - This operation is not permitted by the current security policy
# - Contact the administrator if you believe this is an error
```

The text is an ordinary result, not an MCP error (`isError` is false), and it takes the
place of the return value, so FastMCP checks it against the tool's output schema:

- `-> str` accepts it.
- `-> dict` rejects it: the client gets a FastMCP error whose message contains the Airlock
  text.
- A typed scalar such as `-> int` is accepted by FastMCP 2.14.7, but on 3.4.7 and 4.0
  `fastmcp.Client` raises on the result.

An `async def` tool, and a plain `@Airlock()` under `@mcp.tool`, skip the conversion: a
blocked call returns Airlock's response dict (`"success": False`, `"status": "blocked"`,
`error`, `block_reason`, `fix_hints`), and the same output-schema check applies to it. A
`-> dict` tool accepts it.

## Example: Complete Server

```python
"""Secure MCP Server Example."""
from agent_airlock import Airlock, SecurityPolicy
from agent_airlock.mcp import create_secure_mcp_server

# Create server with security defaults
mcp, secure = create_secure_mcp_server("Customer API")

# Read-only tool
@secure
def get_customer(customer_id: int) -> dict:
    """Get customer by ID."""
    return {
        "id": customer_id,
        "name": "John Doe",
        "email": "john@example.com",  # Masked in output
    }

# Rate-limited tool
rate_policy = SecurityPolicy(rate_limits={"search_customers": "50/minute"})

@secure(policy=rate_policy)
def search_customers(query: str, limit: int = 10) -> list:
    """Search for customers."""
    return [{"name": f"Customer {i}"} for i in range(limit)]

# Sandboxed tool for dangerous operations. The factory's decorator has no
# sandbox_required, so use Airlock directly: without an E2B sandbox the call
# is refused instead of running locally.
@mcp.tool
@Airlock(sandbox=True, sandbox_required=True)
def analyze_data(code: str, data: list) -> dict:
    """Run analysis code on data."""
    namespace = {"data": data}
    exec(code, namespace)  # runs inside the E2B sandbox
    return {"result": namespace.get("result")}

# Resources are plain FastMCP: Airlock guards only the tools wrapped above
@mcp.resource("customers://{customer_id}")
def get_customer_resource(customer_id: int) -> str:
    return f"Customer {customer_id}"

if __name__ == "__main__":
    mcp.run()
```

## Testing

Test your secured MCP server in memory with FastMCP's `Client`, with no network or
subprocess:

```python
import asyncio

from fastmcp import Client

from my_server import mcp


def call(name: str, arguments: dict):
    async def run():
        async with Client(mcp) as client:
            return await client.call_tool(name, arguments, raise_on_error=False)

    return asyncio.run(run())


def test_valid_call():
    result = call("get_customer", {"customer_id": 123})
    assert result.data["id"] == 123
    assert result.data["email"] != "john@example.com"  # masked by Airlock


def test_invalid_type():
    result = call("get_customer", {"customer_id": "invalid"})
    assert result.is_error  # rejected by FastMCP before Airlock runs


def test_ghost_argument():
    result = call("get_customer", {"customer_id": 123, "admin": True})
    assert result.is_error
    assert "admin" in result.content[0].text
```

## Compatibility

The `mcp` extra pins `fastmcp>=2.0,<5.0`.

| Component | Supported |
|-----------|-----------|
| FastMCP 2.x | ✅ (tests recorded on 2.14.7) |
| FastMCP 3.x | Allowed by the pin; no recorded test run |
| FastMCP 4.x | ✅ (tests recorded on 4.0.3) |
| MCP clients (Claude Desktop, Claude Code, ...) | Airlock runs inside the tool function, so clients see an ordinary FastMCP server |
