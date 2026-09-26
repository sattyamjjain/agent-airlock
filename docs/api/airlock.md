# Airlock Decorator

The main entry point for Agent-Airlock.

## Airlock

```python
from agent_airlock import Airlock
```

### Signature

```python
class Airlock:
    def __init__(
        self,
        *,
        sandbox: bool = False,
        sandbox_required: bool = False,
        config: AirlockConfig | None = None,
        policy: SecurityPolicy | Callable[[AirlockContext], SecurityPolicy | None] | None = None,
        return_dict: bool = False,
    ) -> None:
        """
        Args:
            sandbox: If True, execute the function in an E2B sandbox.
            sandbox_required: If True and sandbox=True, refuse the call instead of
                falling back to local execution when E2B is unavailable.
            config: Configuration options. Uses DEFAULT_CONFIG if not provided.
            policy: Security policy (RBAC, rate limits, time restrictions), or a
                callable that takes an AirlockContext and returns one.
            return_dict: If True, a successful call returns the AirlockResponse dict
                too; if False (default), it returns the raw result.
        """
```

These five are the only constructor arguments. All are keyword-only, and the decorator is
always called: `@Airlock()`, not `@Airlock`. Unknown-argument handling, output sanitization
and capability policy live on `AirlockConfig` (passed as `config=`) or on the
`SecurityPolicy`. Circuit breakers, retries and cost tracking are separate helpers, shown
below.

### Basic Usage

```python
@Airlock()
def my_tool(x: int) -> int:
    return x * 2
```

### With UnknownArgsMode (V0.4.0)

The mode is a config field, `AirlockConfig(unknown_args=...)`. The default is
`STRIP_AND_LOG`.

```python
from agent_airlock import Airlock, AirlockConfig, UnknownArgsMode

# Production - reject unknown arguments
@Airlock(config=AirlockConfig(unknown_args=UnknownArgsMode.BLOCK))
def prod_tool(x: int) -> int:
    return x * 2

# Staging - strip and log
@Airlock(config=AirlockConfig(unknown_args=UnknownArgsMode.STRIP_AND_LOG))
def staging_tool(x: int) -> int:
    return x * 2

# Development - silently strip
@Airlock(config=AirlockConfig(unknown_args=UnknownArgsMode.STRIP_SILENT))
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

The resolver receives the context read from the tool's first argument (an object with a
`context`, `ctx`, `request_context` or `session_context` attribute, such as an agent
framework's run context). When that carries no agent id, the identity, roles and workspace
of a context set around the call (`with AirlockContext(...)`) are used. For a tool with
neither, like `my_tool` here, the context is empty (`workspace_id` is `None`), so
`resolve_policy` returns the 100/hour policy.

### With Sandbox

```python
# When E2B is not installed or configured, the call is refused with a blocked
# response. sandbox_required=True also rules out the one local fallback: running the
# function here if agent_airlock.sandbox itself fails to import.
@Airlock(sandbox=True, sandbox_required=True)
def dangerous_tool(code: str) -> str:
    return eval(code)
```

### With Capability Gating (V0.4.0)

`@requires` only declares what a tool needs. `@Airlock` checks the declaration against the
`capability_policy` of the `SecurityPolicy` passed as `policy=`, or, when that has none,
the one on `AirlockConfig`. With neither set, nothing is checked.

```python
from agent_airlock import (
    Airlock, AirlockConfig, Capability, requires, READ_ONLY_CAPABILITY_POLICY,
)

config = AirlockConfig(capability_policy=READ_ONLY_CAPABILITY_POLICY)

@Airlock(config=config)
@requires(Capability.FILESYSTEM_READ)
def read_tool(path: str) -> str:  # runs: FILESYSTEM_READ is granted
    return open(path).read()

@Airlock(config=config)
@requires(Capability.FILESYSTEM_READ | Capability.NETWORK_HTTP)
def fetch_and_save(url: str, path: str) -> bool:  # blocked: NETWORK_HTTP is not granted
    data = requests.get(url).text
    open(path, "w").write(data)
    return True
```

### With Circuit Breaker (V0.4.0)

`Airlock` takes no circuit-breaker argument. `CircuitBreaker` is its own decorator: stack
it under `@Airlock`, so it sees the tool's exceptions. Airlock turns an exception into a
blocked response, so a breaker stacked above it would never count a failure. While the
circuit is open the tool body does not run, and the call returns the same blocked response
Airlock gives for any exception the tool raises.

```python
from agent_airlock import Airlock, CircuitBreaker, AGGRESSIVE_BREAKER

breaker = CircuitBreaker("external-api", AGGRESSIVE_BREAKER)  # opens after 3 failures

@Airlock()
@breaker
def external_api_call(query: str) -> dict:
    return requests.get("https://api.example.com", params={"q": query}).json()
```

### With Cost Tracking (V0.4.0)

`Airlock` takes no cost-tracker argument. `CostTracker` is standalone: record each call's
token usage with `track()`. When a recorded call breaks a `BudgetConfig` limit (per call
or per session), `BudgetExceededError` is raised. Amounts are `Decimal`.

```python
from decimal import Decimal
from agent_airlock import CostTracker, BudgetConfig

tracker = CostTracker(budget=BudgetConfig(max_cost_per_session=Decimal("100")))

with tracker.track("expensive_tool") as call:
    result = call_expensive_api(query)
    call.set_tokens(input_tokens=1200, output_tokens=300)
```

The budget `@Airlock` itself enforces before a call runs is the per-model-tier one,
`SecurityPolicy(model_tier_budget=...)`. A call is tagged with its tier through
`AirlockContext` metadata (`airlock_tier`, `input_tokens`), never through tool arguments.
See the [Policy API](policy.md).

### With Retry Policy (V0.4.0)

`Airlock` takes no retry argument. `RetryPolicy` is its own decorator: stack it under
`@Airlock`, so it retries the tool body. Arguments are validated before the body runs, so
a call Airlock rejects is never retried. When the retries run out, `RetryExhaustedError` is
raised and Airlock returns it as a blocked response.

```python
from agent_airlock import Airlock, RetryPolicy, STANDARD_RETRY

@Airlock()
@RetryPolicy(STANDARD_RETRY)
def flaky_tool(query: str) -> dict:
    return requests.get("https://flaky-api.com", params={"q": query}).json()
```

### Async Support

```python
@Airlock()
async def async_tool(x: int) -> int:
    await asyncio.sleep(0.1)
    return x * 2
```

### Streaming Support (V0.1.5+)

`StreamingAirlock` is not a decorator, and `@Airlock` does not sanitize what a generator
yields. Decorate a generator function with `create_streaming_wrapper`, which masks each
string chunk and applies `max_output_chars` to the stream as a whole:

```python
from agent_airlock import create_streaming_wrapper

@create_streaming_wrapper
def stream_tool(query: str):
    for chunk in generate_chunks(query):
        yield chunk

@create_streaming_wrapper
async def async_stream_tool(query: str):
    async for chunk in generate_async_chunks(query):
        yield chunk
```

Used as a bare decorator it applies the default `AirlockConfig()`. To pass a config, call
it as `create_streaming_wrapper(stream_tool, config)`, or wrap a generator yourself with
`StreamingAirlock(config).wrap_generator(gen)` (`wrap_async_generator` for an async one).

## AirlockResponse

The shape of a blocked call's return value. The wrapper returns
`AirlockResponse.to_dict()`, a plain `dict`, not the object; keys with no value are left
out.

```python
from agent_airlock import AirlockResponse
```

### Keys

| Key | Type | Description |
|-----|------|-------------|
| `success` | `bool` | `False` for a blocked call |
| `status` | `str` | `"blocked"`, or `"completed"` for a success under `return_dict=True` |
| `error` | `str` | Error message |
| `block_reason` | `str` | Why it was blocked, e.g. `"ghost_arguments"`, `"validation_error"` |
| `fix_hints` | `list[str]` | Corrective suggestions for the LLM |
| `metadata` | `dict` | Details, e.g. the function name and the offending arguments |
| `result` | `Any` | The tool's result (successes under `return_dict=True`) |
| `warnings` | `list[str]` | E.g. how many values were masked |

### Example

```python
from agent_airlock import Airlock, AirlockConfig, UnknownArgsMode

@Airlock(config=AirlockConfig(unknown_args=UnknownArgsMode.BLOCK))
def my_tool(x: int) -> int:
    return x * 2

result = my_tool(x="invalid", ghost=True)
# The unknown argument is caught before type validation runs:
# {
#     "success": False,
#     "status": "blocked",
#     "error": "AIRLOCK_BLOCK: Unknown arguments detected: ghost",
#     "block_reason": "ghost_arguments",
#     "fix_hints": [
#         "Remove these unknown arguments: ghost",
#         "Check the function signature for valid parameter names"
#     ],
#     "metadata": {"function": "my_tool", "ghost_arguments": ["ghost"]}
# }

result = my_tool(x="invalid")
# {
#     "success": False,
#     "status": "blocked",
#     "error": "AIRLOCK_BLOCK: Tool 'my_tool' validation failed. x: Input should be a valid integer",
#     "block_reason": "validation_error",
#     "fix_hints": ["'x' must be an integer, not str"],
#     "metadata": {"function": "my_tool", "error_count": 1, "errors": [...]}
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
    """Path must be under /tmp/airlock."""
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
Capability.FILESYSTEM_DELETE
Capability.NETWORK_HTTP
Capability.NETWORK_HTTPS
Capability.NETWORK_ARBITRARY   # raw sockets
Capability.PROCESS_EXEC        # external processes, no shell
Capability.PROCESS_SHELL
Capability.DATA_PII
Capability.DATA_SECRETS
Capability.DATABASE_READ
Capability.DATABASE_WRITE
```

Named combinations: `FILESYSTEM_ALL` (read, write, delete), `NETWORK_ALL` (HTTP, HTTPS,
arbitrary), `DANGEROUS` (`PROCESS_SHELL | FILESYSTEM_DELETE | NETWORK_ARBITRARY`) and
`SAFE_READ` (`FILESYSTEM_READ | DATABASE_READ | NETWORK_HTTPS`).

## CircuitBreaker (V0.4.0)

```python
from agent_airlock import CircuitBreaker, CircuitState, AGGRESSIVE_BREAKER

breaker = CircuitBreaker("external-api", AGGRESSIVE_BREAKER)  # name, CircuitBreakerConfig

# Check state
breaker.state  # CircuitState.CLOSED, OPEN, or HALF_OPEN

# Get stats
stats = breaker.stats  # CircuitStats: total_failures, consecutive_failures, times_opened, ...

# Close the circuit and clear the stats
breaker.reset()
```

Used directly (`with breaker:`), an open circuit raises `CircuitBreakerError`, whose
`retry_after` is the seconds left until a trial call is allowed.

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

`CircuitBreakerConfig` presets, passed to `CircuitBreaker(name, config)`:

```python
from agent_airlock import (
    AGGRESSIVE_BREAKER,    # opens after 3 failures, trial call after 10s
    CONSERVATIVE_BREAKER,  # opens after 10 failures, trial call after 60s
    DEFAULT_BREAKER,       # opens after 5 failures, trial call after 30s
)
```

### Retry Policies (V0.4.0)

`RetryConfig` presets, passed to `RetryPolicy(config)`:

```python
from agent_airlock import (
    NO_RETRY,          # 0 retries
    FAST_RETRY,        # 3 retries, 0.1s base delay, 1s cap
    STANDARD_RETRY,    # 3 retries, 1s base delay, 30s cap
    AGGRESSIVE_RETRY,  # 5 retries, 0.5s base delay, 60s cap
    PATIENT_RETRY,     # 10 retries, 2s base delay, 300s cap
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
from typing import Any, TypeVar, Callable

F = TypeVar('F', bound=Callable[..., Any])

# Airlock preserves function signatures
@Airlock()
def my_tool(x: int, y: str = "default") -> dict:
    return {"x": x, "y": y}

# Type hints work correctly
result: dict = my_tool(x=5)
```
