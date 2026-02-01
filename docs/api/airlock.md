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
    policy: SecurityPolicy | Callable[[AirlockContext], SecurityPolicy] | None = None,
    sandbox: bool = False,
    sandbox_required: bool = False,
    agent_id: str | None = None,
    # V0.4.0 additions
    unknown_args_mode: UnknownArgsMode | None = None,
    capability_policy: CapabilityPolicy | None = None,
    circuit_breaker: CircuitBreaker | None = None,
    cost_tracker: CostTracker | None = None,
    retry_policy: RetryPolicy | None = None,
    return_dict: bool = False,
) -> Callable[[F], F]:
    """
    Decorator that wraps a function with security validation.

    Args:
        config: Configuration options (sanitization, output limits, etc.)
        policy: Security policy (RBAC, rate limits, time restrictions)
               Can be a callable for dynamic resolution.
        sandbox: If True, execute in E2B sandbox
        sandbox_required: If True, fail if sandbox unavailable
        agent_id: Identifier for the calling agent
        unknown_args_mode: How to handle unknown arguments (V0.4.0)
        capability_policy: Fine-grained capability gating (V0.4.0)
        circuit_breaker: Fault tolerance configuration (V0.4.0)
        cost_tracker: Cost monitoring and budget limits (V0.4.0)
        retry_policy: Automatic retry with backoff (V0.4.0)
        return_dict: If True, always return dict instead of AirlockResponse

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

### With UnknownArgsMode (V0.4.0)

```python
from agent_airlock import Airlock, UnknownArgsMode

# Production - reject unknown arguments
@Airlock(unknown_args_mode=UnknownArgsMode.BLOCK)
def prod_tool(x: int) -> int:
    return x * 2

# Staging - strip and log
@Airlock(unknown_args_mode=UnknownArgsMode.STRIP_AND_LOG)
def staging_tool(x: int) -> int:
    return x * 2

# Development - silently strip
@Airlock(unknown_args_mode=UnknownArgsMode.STRIP_SILENT)
def dev_tool(x: int) -> int:
    return x * 2
```

### With Configuration

```python
from agent_airlock import Airlock, AirlockConfig

config = AirlockConfig(
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

### With Dynamic Policy (V0.1.5+)

```python
from agent_airlock import Airlock, SecurityPolicy, AirlockContext

def resolve_policy(ctx: AirlockContext) -> SecurityPolicy:
    """Resolve policy based on context."""
    if ctx.workspace_id == "enterprise":
        return SecurityPolicy(rate_limits={"*": "10000/hour"})
    return SecurityPolicy(rate_limits={"*": "100/hour"})

@Airlock(policy=resolve_policy)
def my_tool(x: int) -> int:
    return x * 2
```

### With Sandbox

```python
@Airlock(sandbox=True)
def dangerous_tool(code: str) -> str:
    return eval(code)
```

### With Capability Gating (V0.4.0)

```python
from agent_airlock import Airlock, Capability, requires

@Airlock()
@requires(Capability.FILESYSTEM_READ)
def read_tool(path: str) -> str:
    return open(path).read()

@Airlock()
@requires(Capability.FILESYSTEM_READ | Capability.NETWORK_HTTP)
def fetch_and_save(url: str, path: str) -> bool:
    data = requests.get(url).text
    open(path, "w").write(data)
    return True
```

### With Circuit Breaker (V0.4.0)

```python
from agent_airlock import Airlock, AGGRESSIVE_BREAKER

@Airlock(circuit_breaker=AGGRESSIVE_BREAKER)
def external_api_call(query: str) -> dict:
    return requests.get(f"https://api.example.com?q={query}").json()
```

### With Cost Tracking (V0.4.0)

```python
from agent_airlock import Airlock, CostTracker, BudgetConfig

tracker = CostTracker(budget=BudgetConfig(hard_limit=100.0))

@Airlock(cost_tracker=tracker)
def expensive_tool(query: str) -> str:
    return call_expensive_api(query)
```

### With Retry Policy (V0.4.0)

```python
from agent_airlock import Airlock, STANDARD_RETRY

@Airlock(retry_policy=STANDARD_RETRY)
def flaky_tool(query: str) -> dict:
    return requests.get(f"https://flaky-api.com?q={query}").json()
```

### Async Support

```python
@Airlock()
async def async_tool(x: int) -> int:
    await asyncio.sleep(0.1)
    return x * 2
```

### Streaming Support (V0.1.5+)

```python
from agent_airlock import StreamingAirlock

@StreamingAirlock()
def stream_tool(query: str):
    for chunk in generate_chunks(query):
        yield chunk

@StreamingAirlock()
async def async_stream_tool(query: str):
    async for chunk in generate_async_chunks(query):
        yield chunk
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
from agent_airlock import Airlock, UnknownArgsMode

@Airlock(unknown_args_mode=UnknownArgsMode.BLOCK)
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

## Safe Types (V0.4.0)

### SafePath

```python
from agent_airlock import SafePath, SafePathStrict, SafePathInTmp

def read_file(path: SafePath) -> str:
    """Path validated against traversal attacks."""
    return open(path).read()

def write_temp(path: SafePathInTmp) -> bool:
    """Path must be in /tmp."""
    ...
```

### SafeURL

```python
from agent_airlock import SafeURL, SafeURLAllowHttp

def fetch_api(url: SafeURL) -> dict:
    """URL must be HTTPS."""
    return requests.get(url).json()

def fetch_legacy(url: SafeURLAllowHttp) -> dict:
    """URL can be HTTP or HTTPS."""
    return requests.get(url).json()
```

## Capability (V0.4.0)

```python
from agent_airlock import Capability

# Available capabilities (Flag enum, can combine with |)
Capability.FILESYSTEM_READ
Capability.FILESYSTEM_WRITE
Capability.NETWORK_HTTP
Capability.NETWORK_SOCKET
Capability.PROCESS_SPAWN
Capability.DATABASE_READ
Capability.DATABASE_WRITE
```

## CircuitBreaker (V0.4.0)

```python
from agent_airlock import CircuitBreaker, CircuitState

breaker = CircuitBreaker(...)

# Check state
breaker.state  # CircuitState.CLOSED, OPEN, or HALF_OPEN

# Get stats
stats = breaker.stats  # CircuitStats with failure_count, success_count, etc.
```

## Predefined Constants

### Policies

```python
from agent_airlock import (
    PERMISSIVE_POLICY,
    STRICT_POLICY,
    READ_ONLY_POLICY,
    BUSINESS_HOURS_POLICY,
)
```

### Capability Policies (V0.4.0)

```python
from agent_airlock import (
    PERMISSIVE_CAPABILITY_POLICY,
    STRICT_CAPABILITY_POLICY,
    READ_ONLY_CAPABILITY_POLICY,
    NO_NETWORK_CAPABILITY_POLICY,
)
```

### Circuit Breakers (V0.4.0)

```python
from agent_airlock import (
    AGGRESSIVE_BREAKER,
    CONSERVATIVE_BREAKER,
    DEFAULT_BREAKER,
)
```

### Retry Policies (V0.4.0)

```python
from agent_airlock import (
    NO_RETRY,
    FAST_RETRY,
    STANDARD_RETRY,
    AGGRESSIVE_RETRY,
    PATIENT_RETRY,
)
```

### Unknown Args Modes (V0.4.0)

```python
from agent_airlock import (
    PRODUCTION_MODE,   # UnknownArgsMode.BLOCK
    STAGING_MODE,      # UnknownArgsMode.STRIP_AND_LOG
    DEVELOPMENT_MODE,  # UnknownArgsMode.STRIP_SILENT
)
```

## Utility Functions

### get_current_context

Get the current Airlock context (available inside tools):

```python
from agent_airlock import get_current_context

@Airlock()
def my_tool(x: int) -> int:
    ctx = get_current_context()
    print(f"Workspace: {ctx.workspace_id}")
    return x * 2
```

### observe (V0.4.0)

Context manager/decorator for observability:

```python
from agent_airlock import observe

@observe("my_operation")
def my_function():
    ...

with observe("my_operation", tool_name="my_tool") as span:
    span.set_attribute("key", "value")
    ...
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
