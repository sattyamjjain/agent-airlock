# E2B Sandbox Execution

Execute untrusted code in isolated Firecracker MicroVMs.

## Why Sandbox?

Some tools execute arbitrary code:
- Code interpreters
- File processors
- Data transformers
- Plugin systems

Running this code on your server is dangerous. E2B sandboxes provide:
- Complete isolation (Firecracker MicroVMs)
- A filesystem and processes separate from your server
- Resource limits
- Automatic cleanup

## Quick Start

```python
from agent_airlock import Airlock

@Airlock(sandbox=True)
def run_code(code: str) -> str:
    """Execute Python code safely."""
    return eval(code)

result = run_code(code="2 + 2")
# Executes in E2B sandbox, returns: 4
```

## Setup

### Install Dependencies

```bash
pip install agent-airlock[sandbox]
```

### Configure API Key

Get an API key from [e2b.dev](https://e2b.dev) and set it:

```bash
export E2B_API_KEY="your-key-here"
```

Or configure in code:

```python
from agent_airlock import AirlockConfig

config = AirlockConfig(e2b_api_key="your-key-here")
```

## Sandbox Options

### Timeout

```python
from agent_airlock import Airlock, AirlockConfig

config = AirlockConfig(sandbox_timeout=60)  # 60 seconds

@Airlock(sandbox=True, config=config)
def long_running_task(data: str) -> str:
    # Process data...
    return data.upper()
```

`sandbox_timeout` (default 60) is passed to E2B as each sandbox's timeout: how many seconds the
sandbox lives after the pool creates it. It is not a per-call limit, and it is read once:
every sandboxed call in the process shares one pool, built from the config of the first
sandboxed call, so a later config with a different value does not change it.

### Required Sandbox

Prevent fallback to local execution:

```python
@Airlock(sandbox=True, sandbox_required=True)
def dangerous_operation(code: str) -> str:
    return eval(code)

# If E2B is unavailable, returns a blocked response instead of running locally
```

With `sandbox_required=True` the function never runs on your machine. The default,
`sandbox_required=False`, allows a local fallback only when importing `agent_airlock.sandbox`
fails. A missing E2B SDK or API key is reported as a failed sandbox call, so in that case both
settings return the blocked response shown under [Error Handling](#error-handling).

## How It Works

1. **Serialization**: Function and arguments serialized with `cloudpickle`
2. **Transfer**: Serialized data sent to E2B
3. **Execution**: Code runs in isolated MicroVM
4. **Return**: The sandbox prints the outcome as JSON, which Airlock parses

```
┌─────────────────┐     ┌─────────────────┐
│   Your Server   │     │  E2B MicroVM    │
│                 │     │                 │
│ @Airlock(       │     │ - Python 3.11   │
│   sandbox=True  │────▶│ - Isolated      │
│ )               │     │ - Own files     │
│                 │◀────│ - Auto-cleanup  │
└─────────────────┘     └─────────────────┘
     serialize            deserialize
     cloudpickle          cloudpickle
```

## Sandbox Pool

For low latency, Airlock keeps a pool of E2B sandboxes and reuses them across calls. Every
sandboxed call in the process shares it:

```python
from agent_airlock import AirlockConfig
from agent_airlock.sandbox import get_sandbox_pool

# Default pool configuration
pool = get_sandbox_pool(AirlockConfig(sandbox_pool_size=2))

# Create the warm sandboxes before the first call
pool.warm_up()
```

### Pool Behavior

| When | The pool |
|------|----------|
| It is empty (first call, or every sandbox in use) | Creates an E2B sandbox and installs `cloudpickle` in it |
| A call finishes | Takes the sandbox back for the next call |
| It already holds `sandbox_pool_size` sandboxes | Kills the returned sandbox instead |
| `pool.shutdown()` is called | Kills the pooled sandboxes |

The pool does not cap concurrent calls and has no idle timeout: a sandbox ends when its
`sandbox_timeout` expires or the pool kills it.

## File Handling

The decorator does not mount files. The function runs against the sandbox's own filesystem,
which does not contain your server's files, so pass the contents as an argument; they are
serialized with the call:

```python
@Airlock(sandbox=True)
def process_file(content: str) -> dict:
    """Process file contents in sandbox."""
    return {"lines": len(content.split("\n"))}

with open("/data/input.txt") as f:
    result = process_file(content=f.read())
```

## Limitations

### Serialization Requirements

Only serializable objects work:
- ✅ Basic types (int, str, list, dict)
- ✅ Pydantic models
- ✅ Dataclasses
- ❌ Open file handles
- ❌ Database connections
- ❌ Thread locks

That list covers arguments. The return value comes back as JSON: a tuple arrives as a list,
and a value JSON cannot encode (a set, a Pydantic model, a dataclass) arrives as its `str()`.

### Network Access

Airlock does not restrict the sandbox's network. The pool creates each sandbox with
`Sandbox.create(timeout=...)` and no network setting, so outbound access is E2B's default,
which allows internet access:

```python
@Airlock(sandbox=True)
def fetch_url(url: str) -> str:
    import requests
    return requests.get(url).text  # Not blocked by Airlock
```

For a function that must have no network, `DockerBackend` runs it with `network_mode="none"`
by default; see [DockerBackend](../sandbox/docker.md).

### Size Limits

Airlock sets no payload or result size limit of its own, and no per-call execution timeout:
`sandbox_timeout` (default 60 seconds) is how long each pooled sandbox lives; see
[Timeout](#timeout).

## Error Handling

```python
from agent_airlock import Airlock

@Airlock(sandbox=True)
def risky_code(code: str) -> str:
    return eval(code)

result = risky_code(code="1/0")
if isinstance(result, dict) and result.get("status") == "blocked":
    print(f"Sandbox error: {result['error']}")
    # Error is contained - your server is safe
```

A failure does not raise. The call returns a blocked response (`"success": False`,
`"status": "blocked"`), and the underlying error, such as
`ZeroDivisionError: division by zero`, is logged as the `unexpected_error` event. To get the
sandbox's error text back, call `execute_in_sandbox` instead, which returns it in
`SandboxResult.error`; see the [Sandbox API](../api/sandbox.md#exceptions).

## Monitoring

The pool keeps no statistics. Each `SandboxResult` from `execute_in_sandbox` reports its own
call:

```python
from agent_airlock.sandbox import execute_in_sandbox

def square(x: int) -> int:
    return x * x

result = execute_in_sandbox(square, args=(4,))
print(f"Sandbox: {result.sandbox_id}")
print(f"Latency: {result.execution_time_ms}ms")
```

The pool logs `sandbox_created` (with `elapsed_ms`) each time it creates a sandbox, and the
decorator logs `sandbox_execution_success` (with `sandbox_id` and `execution_time_ms`) for each
sandboxed call.

## Best Practices

### 1. Use for Untrusted Code Only

```python
# ✅ Good - external/untrusted code
@Airlock(sandbox=True)
def run_user_script(script: str) -> str:
    return exec(script)

# ❌ Overkill - trusted internal code
@Airlock(sandbox=True)  # Not needed
def add_numbers(a: int, b: int) -> int:
    return a + b
```

### 2. Set the Timeout Once

All sandboxed calls share one pool, built from the first sandboxed call's config, and each
sandbox lives `sandbox_timeout` seconds from its creation. Give every sandboxed tool the same
config:

```python
config = AirlockConfig(sandbox_timeout=300)

@Airlock(sandbox=True, config=config)
def quick_calc(expr: str) -> float:
    return eval(expr)

@Airlock(sandbox=True, config=config)
def train_model(data: list) -> dict:
    # Long-running ML task
    return {"accuracy": 0.95}
```

### 3. Handle Failures Gracefully

```python
@Airlock(sandbox=True, sandbox_required=True)
def run_user_code(code: str) -> str:
    return str(eval(code))

result = run_user_code(code="2 + 2")
if isinstance(result, dict) and result.get("status") == "blocked":
    print("Sandbox failed or unavailable; nothing ran locally")
```

There is no `is_sandboxed()` check: a sandboxed tool returns either its result or the blocked
response.
