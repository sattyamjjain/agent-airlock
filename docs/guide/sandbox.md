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
- No network access (configurable)
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
    return result
```

### Required Sandbox

Prevent fallback to local execution:

```python
@Airlock(sandbox=True, sandbox_required=True)
def dangerous_operation(code: str) -> str:
    return eval(code)

# If E2B is unavailable, raises error instead of running locally
```

## How It Works

1. **Serialization**: Function and arguments serialized with `cloudpickle`
2. **Transfer**: Serialized data sent to E2B
3. **Execution**: Code runs in isolated MicroVM
4. **Return**: Results serialized back

```
┌─────────────────┐     ┌─────────────────┐
│   Your Server   │     │  E2B MicroVM    │
│                 │     │                 │
│ @Airlock(       │     │ - Python 3.11   │
│   sandbox=True  │────▶│ - Isolated      │
│ )               │     │ - No network    │
│                 │◀────│ - Auto-cleanup  │
└─────────────────┘     └─────────────────┘
     serialize            deserialize
     cloudpickle          cloudpickle
```

## Sandbox Pool

For low latency, Airlock maintains a warm pool of sandboxes:

```python
from agent_airlock.sandbox import SandboxPool

# Default pool configuration
pool = SandboxPool(
    min_size=2,       # Minimum warm sandboxes
    max_size=10,      # Maximum concurrent sandboxes
    idle_timeout=300, # Cleanup idle after 5 minutes
)

# Use pool for execution
result = pool.execute(my_function, args, kwargs)
```

### Pool Benefits

| Without Pool | With Pool |
|--------------|-----------|
| ~2-5s cold start | ~200ms warm start |
| New VM per call | Reuse existing VMs |
| Higher costs | Lower costs |

## File Handling

Mount files into sandbox:

```python
@Airlock(sandbox=True)
def process_file(file_path: str) -> dict:
    """Process a file in sandbox."""
    with open(file_path) as f:
        content = f.read()
    return {"lines": len(content.split("\n"))}

# File is automatically mounted into sandbox
result = process_file(file_path="/data/input.txt")
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

### Network Access

By default, sandboxes have no network access:

```python
@Airlock(sandbox=True)
def fetch_url(url: str) -> str:
    import requests
    return requests.get(url).text  # Will fail - no network
```

### Size Limits

- Maximum payload: 10MB
- Maximum result: 10MB
- Execution timeout: 5 minutes (configurable)

## Error Handling

```python
from agent_airlock import Airlock
from agent_airlock.sandbox import SandboxExecutionError

@Airlock(sandbox=True)
def risky_code(code: str) -> str:
    return eval(code)

try:
    result = risky_code(code="import os; os.system('rm -rf /')")
except SandboxExecutionError as e:
    print(f"Sandbox error: {e}")
    # Error is contained - your server is safe
```

## Monitoring

Track sandbox usage:

```python
from agent_airlock.sandbox import SandboxPool

pool = SandboxPool()

# Get statistics
stats = pool.stats()
print(f"Active: {stats['active']}")
print(f"Idle: {stats['idle']}")
print(f"Total executions: {stats['total_executions']}")
print(f"Average latency: {stats['avg_latency_ms']}ms")
```

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

### 2. Set Appropriate Timeouts

```python
# Short timeout for simple operations
@Airlock(sandbox=True, config=AirlockConfig(sandbox_timeout=10))
def quick_calc(expr: str) -> float:
    return eval(expr)

# Longer timeout for complex operations
@Airlock(sandbox=True, config=AirlockConfig(sandbox_timeout=300))
def train_model(data: list) -> dict:
    # Long-running ML task
    return {"accuracy": 0.95}
```

### 3. Handle Failures Gracefully

```python
@Airlock(sandbox=True, sandbox_required=False)
def optional_sandbox(code: str) -> str:
    """Falls back to local if E2B unavailable."""
    return eval(code)

# Check if sandboxed
from agent_airlock import is_sandboxed
if is_sandboxed():
    print("Running in sandbox")
```
