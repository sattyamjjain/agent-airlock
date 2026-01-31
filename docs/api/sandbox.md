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
        api_key: str | None = None,
        min_size: int = 2,
        max_size: int = 10,
        idle_timeout: int = 300,
    ):
        """
        Pool of warm E2B sandboxes for low-latency execution.

        Args:
            api_key: E2B API key (falls back to E2B_API_KEY env var)
            min_size: Minimum warm sandboxes to maintain
            max_size: Maximum concurrent sandboxes
            idle_timeout: Seconds before cleaning up idle sandbox
        """
```

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `execute(func, args, kwargs)` | `Any` | Execute function in sandbox |
| `stats()` | `dict` | Pool statistics |
| `cleanup()` | `None` | Clean up all sandboxes |

### Example

```python
from agent_airlock.sandbox import SandboxPool

pool = SandboxPool(min_size=2, max_size=5)

def my_function(x: int) -> int:
    return x * 2

result = pool.execute(my_function, args=(5,), kwargs={})
# result = 10, executed in E2B sandbox

stats = pool.stats()
print(f"Active: {stats['active']}")
print(f"Avg latency: {stats['avg_latency_ms']}ms")

pool.cleanup()
```

## execute_in_sandbox

```python
from agent_airlock.sandbox import execute_in_sandbox
```

### Signature

```python
def execute_in_sandbox(
    func: Callable[..., T],
    args: tuple = (),
    kwargs: dict | None = None,
    timeout: int = 30,
    api_key: str | None = None,
) -> T:
    """
    Execute a function in an E2B sandbox.

    Args:
        func: Function to execute
        args: Positional arguments
        kwargs: Keyword arguments
        timeout: Execution timeout in seconds
        api_key: E2B API key

    Returns:
        Function result

    Raises:
        SandboxExecutionError: If execution fails
        SandboxTimeoutError: If execution times out
    """
```

### Example

```python
from agent_airlock.sandbox import execute_in_sandbox

def risky_code(code: str) -> str:
    return eval(code)

result = execute_in_sandbox(
    risky_code,
    args=("2 + 2",),
    timeout=10,
)
# result = 4
```

## Exceptions

### SandboxExecutionError

```python
from agent_airlock.sandbox import SandboxExecutionError
```

Raised when sandbox execution fails:

```python
try:
    result = execute_in_sandbox(my_func, args)
except SandboxExecutionError as e:
    print(f"Execution failed: {e}")
    print(f"Error type: {e.error_type}")
    print(f"Traceback: {e.traceback}")
```

### SandboxTimeoutError

```python
from agent_airlock.sandbox import SandboxTimeoutError
```

Raised when execution exceeds timeout:

```python
try:
    result = execute_in_sandbox(slow_func, timeout=5)
except SandboxTimeoutError as e:
    print(f"Timed out after {e.timeout}s")
```

### SandboxUnavailableError

```python
from agent_airlock.sandbox import SandboxUnavailableError
```

Raised when E2B is unavailable (and `sandbox_required=True`):

```python
try:
    result = my_sandboxed_tool()
except SandboxUnavailableError:
    print("E2B not available and sandbox_required=True")
```

## is_sandboxed

```python
from agent_airlock import is_sandboxed
```

### Signature

```python
def is_sandboxed() -> bool:
    """
    Check if current code is running in a sandbox.

    Returns:
        True if running in E2B sandbox, False otherwise
    """
```

### Example

```python
from agent_airlock import is_sandboxed

@Airlock(sandbox=True)
def my_tool() -> str:
    if is_sandboxed():
        return "Running safely in sandbox"
    else:
        return "Running locally (fallback)"
```

## Serialization

Agent-Airlock uses `cloudpickle` for function serialization:

```python
import cloudpickle

# Serialize
serialized = cloudpickle.dumps((func, args, kwargs))

# Deserialize in sandbox
func, args, kwargs = cloudpickle.loads(serialized)
result = func(*args, **kwargs)
```

### Serializable Types

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

## Configuration

### Environment Variables

| Variable | Description |
|----------|-------------|
| `E2B_API_KEY` | E2B API key |
| `AIRLOCK_SANDBOX_TIMEOUT` | Default timeout in seconds |

### AirlockConfig

```python
from agent_airlock import AirlockConfig

config = AirlockConfig(
    e2b_api_key="...",     # Override env var
    sandbox_timeout=60,     # Seconds
)

@Airlock(sandbox=True, config=config)
def my_tool():
    pass
```
