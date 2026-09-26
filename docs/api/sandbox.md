# Sandbox API

E2B sandbox execution for untrusted code.

## SandboxPool

```python
from agent_airlock.sandbox import SandboxPool
```

### Signature

```python
class SandboxPool:
    def __init__(
        self,
        pool_size: int = 2,
        api_key: str | None = None,
        timeout: int = 60,
    ) -> None:
        """
        Pool of warm E2B sandboxes for low-latency execution.

        Args:
            pool_size: Warm sandboxes to keep; one released into a full pool is killed
            api_key: E2B API key (falls back to E2B_API_KEY env var)
            timeout: Passed to E2B's Sandbox.create() for each new sandbox: how many
                seconds that sandbox lives
        """
```

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `warm_up(count=None)` | `None` | Create up to `count` sandboxes (default `pool_size`) without overfilling the pool; a failed creation is logged, not raised |
| `acquire()` | E2B `Sandbox` | Take a pooled sandbox, or create one if the pool is empty |
| `release(sandbox)` | `None` | Return a sandbox to the pool; kill it if the pool is full or shut down |
| `sandbox()` | context manager | `acquire()` on entry, `release()` on exit |
| `shutdown()` | `None` | Kill the pooled sandboxes; later releases kill instead of pooling |

`warm_up()` and `acquire()` raise `SandboxNotAvailableError` when `e2b-code-interpreter` is not
installed. The pool does not cap concurrency (an empty pool creates another sandbox), keeps no
statistics, and does not run Python functions itself: `execute_in_sandbox` does that, on the
process-wide pool that `get_sandbox_pool()` returns.

`get_sandbox_pool(config=None)`, also importable from `agent_airlock`, creates that pool on its
first call from `config.sandbox_pool_size`, `config.e2b_api_key` and `config.sandbox_timeout`
(`DEFAULT_CONFIG` when `config` is `None`). Every later call, including the ones
`execute_in_sandbox` makes, returns the same pool and ignores its `config`.

### Example

```python
from agent_airlock import AirlockConfig
from agent_airlock.sandbox import execute_in_sandbox, get_sandbox_pool

config = AirlockConfig(sandbox_pool_size=2)

pool = get_sandbox_pool(config)  # the pool execute_in_sandbox() and @Airlock(sandbox=True) use
pool.warm_up()  # create the sandboxes now instead of on the first call

def my_function(x: int) -> int:
    return x * 2

result = execute_in_sandbox(my_function, args=(5,), config=config)
print(result.result)  # 10, executed in an E2B sandbox

pool.shutdown()
```

## execute_in_sandbox

```python
from agent_airlock.sandbox import execute_in_sandbox
```

### Signature

```python
def execute_in_sandbox(
    func: Callable[..., R],
    args: tuple[Any, ...] = (),
    kwargs: dict[str, Any] | None = None,
    config: AirlockConfig | None = None,
) -> SandboxResult:
    """
    Execute a function in an E2B sandbox.

    Args:
        func: Function to execute
        args: Positional arguments
        kwargs: Keyword arguments
        config: Airlock configuration (DEFAULT_CONFIG when None). Only used to
            create the process-wide pool, so it has no effect once that pool exists.

    Returns:
        SandboxResult with the execution outcome. Failures are returned, not raised.
    """
```

`execute_in_sandbox_async` takes the same arguments and runs this call in a worker thread, so it
can be awaited without blocking the event loop. Neither takes a per-call timeout; see
`sandbox_timeout` under [Configuration](#configuration).

### SandboxResult

| Field | Type | Description |
|-------|------|-------------|
| `success` | `bool` | `True` when `func` returned without raising |
| `result` | `Any` | The return value, after a JSON round trip (see [Serialization](#serialization)) |
| `error` | `str \| None` | `"ExceptionType: message"` when `func` raised, otherwise what failed around it |
| `stdout`, `stderr` | `str` | Output captured from the sandbox |
| `execution_time_ms` | `float` | Time since the call started, including getting a sandbox |
| `sandbox_id` | `str \| None` | E2B id of the sandbox that ran the call |

`to_dict()` returns these fields as a dict. `agent_airlock.SandboxResult`, exported at the
package root, is the `sandbox_backend` variant, which adds a `backend` field.

### Example

```python
from agent_airlock.sandbox import execute_in_sandbox

def risky_code(code: str) -> str:
    return str(eval(code))

result = execute_in_sandbox(risky_code, args=("2 + 2",))
if result.success:
    print(result.result)  # 4
else:
    print(result.error)
```

## Exceptions

A failed sandbox call is returned, not raised, by both `execute_in_sandbox` and the decorator.

`execute_in_sandbox` returns `SandboxResult(success=False, error=...)` for every failure: the
E2B SDK or `cloudpickle` missing, a serialization error, an E2B error (a missing API key
included), or an exception raised by `func` inside the sandbox:

```python
from agent_airlock.sandbox import execute_in_sandbox

def divide(a: int, b: int) -> float:
    return a / b

result = execute_in_sandbox(divide, args=(1, 0))
print(result.success)  # False
print(result.error)  # ZeroDivisionError: division by zero
```

A tool decorated with `@Airlock(sandbox=True)` returns a blocked response instead of its value
when sandbox execution fails. The underlying error is logged as the `unexpected_error` event,
not returned:

```python
{
    "success": False,
    "status": "blocked",
    "error": "AIRLOCK_BLOCK: Unexpected error in 'my_tool'",
    "block_reason": "validation_error",
    "fix_hints": ["An internal error occurred. Please try again."],
}
```

The sandbox exception classes that exist:

| Exception | Import from | Raised by |
|-----------|-------------|-----------|
| `SandboxError` | `agent_airlock.sandbox` | Base class; `mount_files()`, `mount_directory()` and `download_file()` raise it |
| `SandboxNotAvailableError` | `agent_airlock.sandbox` | `SandboxPool.warm_up()` and `acquire()` without `e2b-code-interpreter`; `serialize_function_call()` without `cloudpickle` |
| `SandboxExecutionError` | `agent_airlock` | The decorator, internally, when the sandbox reports a failure; it becomes the blocked response above |
| `SandboxUnavailableError` | `agent_airlock` | The decorator, internally, when `sandbox_required=True` and `agent_airlock.sandbox` fails to import; it becomes the blocked response above |

`agent_airlock.sandbox` defines a second `SandboxExecutionError` (a `SandboxError` subclass),
but nothing in the package raises it.

## Where a Call Ran

There is no `is_sandboxed()` function. `SandboxResult.sandbox_id` names the E2B sandbox that
ran a call, and the decorator logs it on the `sandbox_execution_success` event. A tool with
`@Airlock(sandbox=True)` does not quietly run on your machine when E2B is unavailable: it
returns the blocked response above. The decorator's local fallback is reached only when
`sandbox_required=False` and importing `agent_airlock.sandbox` itself fails.

## Serialization

Agent-Airlock uses `cloudpickle` to send the call and JSON to bring the result back:

```python
import base64
import json

import cloudpickle

# Serialize: pickle the call with protocol 4, then base64-encode it
payload = base64.b64encode(
    cloudpickle.dumps({"func": func, "args": args, "kwargs": kwargs}, protocol=4)
).decode("utf-8")

# Deserialize in sandbox, call, and print the outcome as JSON
call = cloudpickle.loads(base64.b64decode(payload))
result = call["func"](*call["args"], **call["kwargs"])
print(json.dumps({"success": True, "result": result, "error": None}, default=str))
```

### Serializable Types

For the function and its arguments:

| Type | Supported |
|------|-----------|
| Basic types (int, str, list, dict) | ✅ |
| Pydantic models | ✅ |
| Dataclasses | ✅ |
| Lambda functions | ✅ |
| Classes with __dict__ | ✅ |
| Open file handles | ❌ |
| Database connections | ❌ |
| Thread locks | ❌ |
| Network sockets | ❌ |

cloudpickle sends a function defined in `__main__` by value. A function it can import by name
from a module is sent by reference instead, so that module must also be importable inside the
sandbox.

The return value comes back as JSON: a tuple arrives as a list, and a value JSON cannot encode
(a set, a Pydantic model, a dataclass) arrives as its `str()`.

## Configuration

### Environment Variables

| Variable | Description |
|----------|-------------|
| `E2B_API_KEY` | E2B API key, used when `e2b_api_key` is not set |

There is no environment variable for the sandbox timeout: set `sandbox_timeout` on
`AirlockConfig`, directly or through `AirlockConfig.from_toml()`.

### AirlockConfig

```python
from agent_airlock import Airlock, AirlockConfig

config = AirlockConfig(
    e2b_api_key="...",     # Override env var
    sandbox_timeout=60,    # Seconds each pooled sandbox lives (E2B's sandbox timeout)
    sandbox_pool_size=2,   # Warm sandboxes to keep
)

@Airlock(sandbox=True, config=config)
def my_tool():
    pass
```

These three settings are read once, when the process-wide pool is created, so give every
sandboxed tool the same values. `sandbox_timeout` is not a per-call limit: agent-airlock passes
no timeout for the call itself.

The decorator always runs sandboxed tools through E2B. For the pluggable `SandboxBackend`
classes (Docker, Local, Modal), which you call directly, see
[DockerBackend](../sandbox/docker.md).
