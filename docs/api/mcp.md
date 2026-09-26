# MCP Integration API

FastMCP integration for MCP servers. The names on this page live in `agent_airlock.mcp`;
FastMCP itself comes from the `mcp` extra (`pip install agent-airlock[mcp]`).

The package root does not export `secure_tool`, `MCPAirlock` or `MCPContextExtractor`. It
has its own `create_secure_mcp_server` (same parameters, delegating to the one below) and
two accessors: `get_secure_tool()` returns `secure_tool`, and `get_mcp_airlock()` returns
the `MCPAirlock` class.

## secure_tool

```python
from agent_airlock.mcp import secure_tool
```

### Signature

```python
def secure_tool(
    mcp: Any,
    *,
    sandbox: bool = False,
    config: AirlockConfig | None = None,
    policy: SecurityPolicy | None = None,
    name: str | None = None,
    description: str | None = None,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """
    Convenience decorator that combines @mcp.tool and @MCPAirlock.

    Args:
        mcp: FastMCP instance
        sandbox: Execute in E2B sandbox
        config: Airlock configuration
        policy: Security policy
        name: Tool name (defaults to the function name)
        description: Tool description (defaults to the docstring)

    Returns:
        Decorator that wraps the function and registers it with the server
    """
```

The decorator wraps the function in `MCPAirlock(report_progress=True)`, registers it with
`mcp.tool()`, and returns what `mcp.tool()` returns: a `FunctionTool` on FastMCP 2.x, the
wrapped function on 4.x. There is no `sandbox_required` parameter.

### Example

```python
from fastmcp import FastMCP
from agent_airlock.mcp import secure_tool

mcp = FastMCP("My Server")

@secure_tool(mcp)
def my_tool(x: int) -> int:
    return x * 2
```

## MCPAirlock

```python
from agent_airlock.mcp import MCPAirlock
```

### Signature

```python
class MCPAirlock:
    def __init__(
        self,
        *,
        sandbox: bool = False,
        config: AirlockConfig | None = None,
        policy: SecurityPolicy | None = None,
        report_progress: bool = False,
    ) -> None:
        """
        MCP-specific Airlock decorator.

        Args:
            sandbox: Execute in E2B sandbox
            config: Airlock configuration
            policy: Security policy
            report_progress: Call ctx.report_progress() before and after the
                call (see report_progress below)
        """

    def __call__(self, func: Callable[P, R]) -> Callable[P, R]:
        """Apply Airlock to function."""
```

It wraps the function in `Airlock(sandbox=..., config=..., policy=...)`. On a sync tool, a
blocked call comes back as text rather than Airlock's response dict (see
[Error Responses](#error-responses)). The wrapper keeps the function's signature, so FastMCP
builds the same input schema.

### Example

```python
from agent_airlock import AirlockConfig
from agent_airlock.mcp import MCPAirlock

config = AirlockConfig(mask_pii=True)
mcp_airlock = MCPAirlock(config=config)

@mcp.tool
@mcp_airlock
def my_tool(x: int) -> int:
    return x * 2
```

## create_secure_mcp_server

```python
from agent_airlock.mcp import create_secure_mcp_server
```

### Signature

```python
def create_secure_mcp_server(
    name: str,
    *,
    config: AirlockConfig | None = None,
    default_policy: SecurityPolicy | None = None,
) -> tuple[Any, Callable[..., Any]]:
    """
    Create a FastMCP server with pre-configured Airlock security.

    Args:
        name: Server name
        config: Default Airlock configuration
        default_policy: Default security policy for all tools

    Returns:
        Tuple of (FastMCP instance, secure_tool decorator)

    Raises:
        ImportError: If FastMCP is not installed
    """
```

The returned decorator applies `secure_tool` with the server, `config` and `default_policy`.
Use it bare (`@secure`) or with keyword overrides: `sandbox`, `policy` (replaces
`default_policy` for that tool), `tool_name` and `tool_description`. Only tools registered
through it are guarded; the factory installs nothing server-wide, so a plain `@mcp.tool`
on the returned server runs without Airlock.

### Example

```python
from agent_airlock import SecurityPolicy
from agent_airlock.mcp import create_secure_mcp_server

policy = SecurityPolicy(
    allowed_tools=["search_*", "get_*"],
    rate_limits={"*": "100/hour"},
)

mcp, secure = create_secure_mcp_server("Secure API", default_policy=policy)

@secure
def search_users(query: str) -> list:
    return []

if __name__ == "__main__":
    mcp.run()
```

## Context Utilities

### FastMCP Context

A secured tool can take FastMCP's `Context`. FastMCP injects it and Airlock passes it
through:

```python
from fastmcp import Context
from agent_airlock.mcp import secure_tool

@secure_tool(mcp)
def my_tool(query: str, ctx: Context) -> list:
    # Context automatically passed
    client_id = ctx.client_id
    return []
```

### MCPContextExtractor

```python
from agent_airlock.mcp import MCPContextExtractor
```

Static helpers for building an agent identity from an MCP context. Airlock does not call
them itself.

- `extract_agent_id(ctx) -> str | None`: `str(ctx.client_id)` if the context has a
  `client_id` attribute, else `session_id`, else `request_id`, else `None`.
- `extract_metadata(ctx) -> dict[str, Any]`: `client_info` and `protocol_version`, for
  whichever of the two the context has.

On a FastMCP `Context` they return less than their names suggest. `Context` always has a
`client_id` attribute, so `extract_agent_id` never falls back to `session_id` and returns
the string `"None"` when the client sent no client ID. `Context` has neither `client_info`
nor `protocol_version`, so `extract_metadata` returns `{}`. For a per-session identity, read
`ctx.session_id` directly.

### report_progress

`MCPAirlock(report_progress=True)`, and so `secure_tool`, calls `ctx.report_progress()`
before and after the call when the tool receives a keyword argument named `ctx`. FastMCP's
`Context.report_progress` is a coroutine and the wrapper does not await it, so no
notification reaches the client. Report progress from an `async` tool instead, awaiting
FastMCP's method:

```python
from fastmcp import Context
from agent_airlock.mcp import secure_tool

@secure_tool(mcp)
async def long_task(data: str, ctx: Context) -> dict:
    await ctx.report_progress(progress=0, total=100, message="Starting...")
    # Process...
    await ctx.report_progress(progress=50, total=100, message="Halfway...")
    # More processing...
    await ctx.report_progress(progress=100, total=100, message="Complete")
    return {"status": "done"}
```

## Error Responses

On a sync tool, `MCPAirlock` returns a blocked call as text:

```text
Error: AIRLOCK_BLOCK: Policy violation for 'delete_user'. Tool 'delete_user' is denied by policy (matches 'delete_*')

Suggested fixes:
- This operation is not permitted by the current security policy
- Contact the administrator if you believe this is an error
```

The LLM can read the suggested fixes and adjust its next call. The text replaces the tool's
return value, so it has to fit the tool's output schema: a `-> str` tool accepts it, a
`-> dict` tool does not. [FastMCP Integration](../guide/mcp.md) covers the other return
types.

An `async def` tool, or a tool wrapped in plain `@Airlock()`, returns Airlock's response
dict instead:

```python
{
    "success": False,
    "status": "blocked",
    "error": "AIRLOCK_BLOCK: Policy violation for 'delete_user'. Tool 'delete_user' is denied by policy (matches 'delete_*')",
    "block_reason": "policy_violation",
    "fix_hints": [
        "This operation is not permitted by the current security policy",
        "Contact the administrator if you believe this is an error",
    ],
    "metadata": {
        "function": "delete_user",
        "policy": "SecurityPolicy",
        "violation_reason": "Tool 'delete_user' is denied by policy (matches 'delete_*')",
    },
}
```

Arguments FastMCP rejects never reach Airlock: a value it cannot coerce to the parameter's
type, or an argument the tool does not declare, gets FastMCP's own validation error.

## Async Support

`secure_tool` and `MCPAirlock` accept `async def` tools:

```python
import asyncio

from agent_airlock.mcp import secure_tool

@secure_tool(mcp)
async def async_tool(x: int) -> int:
    await asyncio.sleep(0.1)
    return x * 2
```

A blocked call on an async tool returns the response dict above, not the text.

## Testing

Test secured MCP tools in memory with FastMCP's `Client`:

```python
import asyncio

from fastmcp import Client

from my_server import mcp


def call(name: str, arguments: dict):
    async def run():
        async with Client(mcp) as client:
            return await client.call_tool(name, arguments, raise_on_error=False)

    return asyncio.run(run())


def test_tool_call():
    assert call("my_tool", {"x": 5}).data == 10


def test_validation_error():
    result = call("my_tool", {"x": "invalid"})
    assert result.is_error  # rejected by FastMCP before Airlock runs
```

## Compatibility

The `mcp` extra pins `fastmcp>=2.0,<5.0`.

| MCP Component | Supported |
|---------------|-----------|
| FastMCP 2.x | ✅ (tests recorded on 2.14.7) |
| FastMCP 3.x | Allowed by the pin; no recorded test run |
| FastMCP 4.x | ✅ (tests recorded on 4.0.3) |
| MCP clients (Claude Desktop, Claude Code, ...) | Airlock runs inside the tool function, so clients see an ordinary FastMCP server |

Other frameworks do not go through this module: they use the
[Airlock decorator](airlock.md) or an adapter in `agent_airlock.integrations`.
