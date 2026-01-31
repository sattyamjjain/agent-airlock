# Airlock Decorator

The main entry point for Agent-Airlock.

## Airlock

```python
from agent_airlock import Airlock
```

### Signature

```python
def Airlock(
    config: AirlockConfig | None = None,
    policy: SecurityPolicy | None = None,
    sandbox: bool = False,
    sandbox_required: bool = False,
    agent_id: str | None = None,
) -> Callable[[F], F]:
    """
    Decorator that wraps a function with security validation.

    Args:
        config: Configuration options (strict mode, sanitization, etc.)
        policy: Security policy (RBAC, rate limits, time restrictions)
        sandbox: If True, execute in E2B sandbox
        sandbox_required: If True, fail if sandbox unavailable
        agent_id: Identifier for the calling agent

    Returns:
        Decorated function with security wrapper
    """
```

### Basic Usage

```python
@Airlock()
def my_tool(x: int) -> int:
    return x * 2
```

### With Configuration

```python
from agent_airlock import Airlock, AirlockConfig

config = AirlockConfig(
    strict_mode=True,
    sanitize_output=True,
    mask_pii=True,
)

@Airlock(config=config)
def my_tool(x: int) -> int:
    return x * 2
```

### With Policy

```python
from agent_airlock import Airlock, SecurityPolicy

policy = SecurityPolicy(
    rate_limits={"*": "100/hour"},
)

@Airlock(policy=policy)
def my_tool(x: int) -> int:
    return x * 2
```

### With Sandbox

```python
@Airlock(sandbox=True)
def dangerous_tool(code: str) -> str:
    return eval(code)
```

### Async Support

```python
@Airlock()
async def async_tool(x: int) -> int:
    await asyncio.sleep(0.1)
    return x * 2
```

## AirlockResponse

Response object for blocked calls.

```python
from agent_airlock import AirlockResponse
```

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `status` | `str` | "blocked" or "success" |
| `error` | `str \| None` | Error message |
| `fix_hints` | `list[str]` | Corrective suggestions for LLM |
| `blocked_args` | `list[str]` | Arguments that were rejected |
| `tool_name` | `str` | Name of the tool |
| `validation_errors` | `list[dict]` | Detailed validation errors |

### Example

```python
@Airlock(config=AirlockConfig(strict_mode=True))
def my_tool(x: int) -> int:
    return x * 2

result = my_tool(x="invalid", ghost=True)
# result is AirlockResponse:
# {
#     "status": "blocked",
#     "error": "Validation failed",
#     "fix_hints": [
#         "x: Expected int, got str. Try: x=0",
#         "Remove unknown parameters: ghost"
#     ],
#     "blocked_args": ["ghost"],
#     "tool_name": "my_tool"
# }
```

## Utility Functions

### is_sandboxed

Check if code is running in a sandbox:

```python
from agent_airlock import is_sandboxed

if is_sandboxed():
    print("Running in E2B sandbox")
else:
    print("Running locally")
```

### get_airlock_version

Get the installed version:

```python
from agent_airlock import get_airlock_version

print(get_airlock_version())  # "0.1.0"
```

## Type Hints

```python
from agent_airlock import Airlock
from typing import TypeVar, Callable

F = TypeVar('F', bound=Callable[..., Any])

# Airlock preserves function signatures
@Airlock()
def my_tool(x: int, y: str = "default") -> dict:
    return {"x": x, "y": y}

# Type hints work correctly
result: dict = my_tool(x=5)
```
