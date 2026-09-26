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
            report_progress: Send a progress notification before and after
                the call (see report_progress below)
        """

    def __call__(self, func: Callable[P, R]) -> Callable[P, R]:
        """Apply Airlock to function."""
```

It wraps the function in `Airlock(sandbox=..., config=..., policy=...)`. A blocked call
raises FastMCP's `ToolError` carrying the refusal, on sync and async tools alike (see
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

- `extract_agent_id(ctx) -> str | None`: the first of `client_id`, `session_id` and
  `request_id` that has a value, as a string; `None` when none has one, or when reading one
  raises.
- `extract_metadata(ctx) -> dict[str, Any]`: `client_info` and `protocol_version`, for
  whichever of the two the context has.

On a FastMCP `Context`, `client_id` is `None` unless the client sends one, so
`extract_agent_id` usually returns the session ID. Until 0.10.18 it returned the string
`"None"` instead. `client_id` is whatever the client chooses to send, so do not base access
checks on it. `Context` has neither `client_info` nor `protocol_version`, so
`extract_metadata` returns `{}`.

### report_progress

`MCPAirlock(report_progress=True)`, and so `secure_tool`, sends two notifications through
the tool's FastMCP `Context`, whatever its parameter is called: `(0, 100, "Starting
<tool>...")` before the call and `(100, 100, "Completed <tool>")` after it, as
`(progress, total, message)`. A client receives them only when it asked for progress. An
async tool always sends them; a sync tool sends them on FastMCP 3.x and later, which run it
in a worker thread, and none on 2.x, which runs it on the event loop's own thread. Until
0.10.18 none was ever sent: the coroutine was not awaited, and the message was passed where
FastMCP expects `total`.

For progress in between, await FastMCP's method from an `async` tool:

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

`MCPAirlock` raises a blocked call as FastMCP's `ToolError` with this text, and FastMCP
sends the client an error result (`isError` true) carrying it:

```text
Error: AIRLOCK_BLOCK: Policy violation for 'delete_user'. Tool 'delete_user' is denied by policy (matches 'delete_*')

Suggested fixes:
- This operation is not permitted by the current security policy
- Contact the administrator if you believe this is an error
```

The LLM can read the suggested fixes and adjust its next call. Being an error result, it
does not have to fit the tool's output schema, so it reaches the client the same way for a
`-> str`, `-> dict` or `-> int` tool. Until 0.10.18 the text was returned in place of the
tool's result, and only a `-> str` tool passed it on intact. Without FastMCP installed, the
wrapper returns the text instead of raising.

A tool wrapped in plain `@Airlock()` returns Airlock's response dict instead:

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

A blocked call on an async tool raises the same `ToolError` as on a sync one. Until 0.10.18
it returned the response dict above.

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
| FastMCP 2.x | ✅ (MCP tests pass on 2.14.7) |
| FastMCP 3.x | ✅ (MCP tests pass on 3.4.7) |
| FastMCP 4.x | ✅ (MCP tests pass on 4.0.10; CI's `test` job runs them on the newest release the pin allows) |
| MCP clients (Claude Desktop, Claude Code, ...) | Airlock runs inside the tool function, so clients see an ordinary FastMCP server |

Other frameworks do not go through this module: they use the
[Airlock decorator](airlock.md) or an adapter in `agent_airlock.integrations`.
