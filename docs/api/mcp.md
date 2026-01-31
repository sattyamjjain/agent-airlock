# MCP Integration API

FastMCP integration for MCP servers.

## secure_tool

```python
from agent_airlock import secure_tool
```

### Signature

```python
def secure_tool(
    config: AirlockConfig | None = None,
    policy: SecurityPolicy | None = None,
    sandbox: bool = False,
    sandbox_required: bool = False,
) -> Callable[[F], F]:
    """
    Convenience decorator for securing MCP tools.

    Args:
        config: Airlock configuration
        policy: Security policy
        sandbox: Execute in E2B sandbox
        sandbox_required: Fail if sandbox unavailable

    Returns:
        Decorated function
    """
```

### Example

```python
from fastmcp import FastMCP
from agent_airlock import secure_tool

mcp = FastMCP("My Server")

@mcp.tool
@secure_tool()
def my_tool(x: int) -> int:
    return x * 2
```

## MCPAirlock

```python
from agent_airlock import MCPAirlock
```

### Signature

```python
class MCPAirlock:
    def __init__(
        self,
        config: AirlockConfig | None = None,
        policy: SecurityPolicy | None = None,
    ):
        """
        MCP-specific Airlock decorator.

        Args:
            config: Airlock configuration
            policy: Security policy
        """

    def __call__(self, func: F) -> F:
        """Apply Airlock to function."""
```

### Example

```python
from agent_airlock import MCPAirlock, AirlockConfig

config = AirlockConfig(strict_mode=True, mask_pii=True)
mcp_airlock = MCPAirlock(config=config)

@mcp.tool
@mcp_airlock
def my_tool(x: int) -> int:
    return x * 2
```

## create_secure_mcp_server

```python
from agent_airlock import create_secure_mcp_server
```

### Signature

```python
def create_secure_mcp_server(
    name: str,
    policy: SecurityPolicy | None = None,
    strict_mode: bool = False,
    mask_pii: bool = False,
    mask_secrets: bool = False,
    sandbox_default: bool = False,
) -> FastMCP:
    """
    Create a FastMCP server with security defaults.

    Args:
        name: Server name
        policy: Security policy for all tools
        strict_mode: Reject ghost arguments
        mask_pii: Mask PII in outputs
        mask_secrets: Mask secrets in outputs
        sandbox_default: Default sandbox setting

    Returns:
        Configured FastMCP instance
    """
```

### Example

```python
from agent_airlock import create_secure_mcp_server, SecurityPolicy

policy = SecurityPolicy(
    allowed_tools=["search_*", "get_*"],
    rate_limits={"*": "100/hour"},
)

mcp = create_secure_mcp_server(
    name="Secure API",
    policy=policy,
    strict_mode=True,
    mask_pii=True,
)

@mcp.tool
def search_users(query: str) -> list:
    return []

if __name__ == "__main__":
    mcp.run()
```

## Context Utilities

### get_mcp_context

```python
from agent_airlock.mcp import get_mcp_context
```

Extract MCP context from function call:

```python
from fastmcp import Context

@mcp.tool
@secure_tool()
def my_tool(query: str, ctx: Context) -> list:
    # Context automatically passed
    client_id = ctx.client_id
    return []
```

### report_progress

Report progress during execution:

```python
from fastmcp import Context

@mcp.tool
@secure_tool()
async def long_task(data: str, ctx: Context) -> dict:
    ctx.report_progress(0.0, "Starting...")
    # Process...
    ctx.report_progress(0.5, "Halfway...")
    # More processing...
    ctx.report_progress(1.0, "Complete")
    return {"status": "done"}
```

## Error Responses

MCP-compatible error format:

```python
{
    "status": "blocked",
    "error": "Validation failed",
    "fix_hints": [
        "user_id: Expected int, got str"
    ],
    "tool_name": "get_user"
}
```

The LLM can read `fix_hints` and retry with corrected arguments.

## Async Support

All MCP tools support async:

```python
@mcp.tool
@secure_tool()
async def async_tool(x: int) -> int:
    await asyncio.sleep(0.1)
    return x * 2
```

## Testing

Test secured MCP tools:

```python
import pytest
from my_server import mcp

@pytest.fixture
def client():
    return mcp.test_client()

def test_tool_call(client):
    result = client.call_tool("my_tool", x=5)
    assert result == 10

def test_validation_error(client):
    result = client.call_tool("my_tool", x="invalid")
    assert result["status"] == "blocked"
```

## Compatibility

| MCP Component | Supported |
|---------------|-----------|
| FastMCP 2.x | ✅ |
| FastMCP 3.x | 🚧 Planned |
| MCP SDK | ✅ |
| Claude Desktop | ✅ |
| Claude Code | ✅ |
| OpenAI Function Calling | ✅ |
| Azure OpenAI | ✅ |
| LangChain | ✅ |
