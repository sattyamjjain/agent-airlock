# Sandbox Execution Examples

## Basic Sandbox Usage

```python
from agent_airlock import Airlock

@Airlock(sandbox=True)
def run_code(code: str) -> str:
    """Execute arbitrary Python code safely."""
    result = eval(code)
    return str(result)

# Executes in E2B sandbox, not your server
result = run_code(code="2 + 2")
print(result)  # "4"

# Even dangerous code is safe
result = run_code(code="__import__('os').getcwd()")
# Returns sandbox directory, not your server's
```

## Required Sandbox

```python
from agent_airlock import Airlock

@Airlock(sandbox=True, sandbox_required=True)
def dangerous_operation(code: str) -> str:
    """This MUST run in sandbox - no fallback."""
    return exec(code)

# If E2B is unavailable, raises error instead of running locally
try:
    result = dangerous_operation(code="import os; os.listdir('/')")
except Exception as e:
    print(f"Sandbox unavailable: {e}")
```

## Sandbox Timeout

```python
from agent_airlock import Airlock, AirlockConfig

# Short timeout for quick operations
fast_config = AirlockConfig(sandbox_timeout=5)

@Airlock(sandbox=True, config=fast_config)
def quick_calc(expr: str) -> float:
    return eval(expr)

# Long timeout for complex operations
slow_config = AirlockConfig(sandbox_timeout=300)

@Airlock(sandbox=True, config=slow_config)
def train_model(data: list) -> dict:
    # Long-running ML task
    import time
    time.sleep(60)  # Simulate training
    return {"accuracy": 0.95}
```

## Sandbox Pool Management

```python
from agent_airlock.sandbox import SandboxPool

# Create pool with custom settings
pool = SandboxPool(
    min_size=2,        # Keep 2 warm sandboxes
    max_size=10,       # Max 10 concurrent
    idle_timeout=300,  # Clean up after 5 min idle
)

def process_code(code: str) -> str:
    return eval(code)

# Execute using pool
result = pool.execute(process_code, args=("2 + 2",), kwargs={})
print(result)  # 4

# Check pool stats
stats = pool.stats()
print(f"Active sandboxes: {stats['active']}")
print(f"Idle sandboxes: {stats['idle']}")
print(f"Average latency: {stats['avg_latency_ms']}ms")

# Cleanup when done
pool.cleanup()
```

## Error Handling

```python
from agent_airlock import Airlock
from agent_airlock.sandbox import (
    SandboxExecutionError,
    SandboxTimeoutError,
    SandboxUnavailableError,
)

@Airlock(sandbox=True)
def risky_code(code: str) -> str:
    return eval(code)

try:
    result = risky_code(code="1/0")  # Division by zero
except SandboxExecutionError as e:
    print(f"Execution error: {e}")
    print(f"Error type: {e.error_type}")

try:
    result = risky_code(code="while True: pass")  # Infinite loop
except SandboxTimeoutError as e:
    print(f"Timeout after {e.timeout}s")

# Check if running in sandbox
from agent_airlock import is_sandboxed

@Airlock(sandbox=True)
def check_environment() -> str:
    if is_sandboxed():
        return "Running in E2B sandbox"
    else:
        return "Running locally (fallback)"
```

## Data Processing in Sandbox

```python
from agent_airlock import Airlock

@Airlock(sandbox=True)
def process_data(data: list[dict]) -> dict:
    """Process user-provided data safely."""
    total = sum(item.get("value", 0) for item in data)
    count = len(data)
    return {
        "total": total,
        "count": count,
        "average": total / count if count > 0 else 0,
    }

data = [
    {"value": 10},
    {"value": 20},
    {"value": 30},
]

result = process_data(data=data)
print(result)
# {"total": 60, "count": 3, "average": 20.0}
```

## Combining Sandbox with Other Features

```python
from agent_airlock import Airlock, AirlockConfig, SecurityPolicy

config = AirlockConfig(
    strict_mode=True,
    sanitize_output=True,
    mask_secrets=True,
    sandbox_timeout=30,
)

policy = SecurityPolicy(
    rate_limits={"execute_*": "10/minute"},
)

@Airlock(sandbox=True, config=config, policy=policy)
def execute_script(script: str) -> dict:
    """
    Execute script with all protections:
    - Strict mode (no ghost args)
    - Sandbox execution (isolated)
    - Output sanitization (no secrets leaked)
    - Rate limiting (prevent abuse)
    """
    result = exec(script)
    return {"result": str(result)}
```

## Direct Sandbox Execution

```python
from agent_airlock.sandbox import execute_in_sandbox

def my_function(x: int, y: int) -> int:
    return x + y

# Execute directly without decorator
result = execute_in_sandbox(
    my_function,
    args=(5, 3),
    kwargs={},
    timeout=10,
)
print(result)  # 8
```

## Async Sandbox Execution

```python
import asyncio
from agent_airlock import Airlock

@Airlock(sandbox=True)
async def async_process(data: str) -> dict:
    """Async function in sandbox."""
    await asyncio.sleep(0.1)
    return {"processed": data.upper()}

async def main():
    result = await async_process(data="hello")
    print(result)  # {"processed": "HELLO"}

asyncio.run(main())
```

## Monitoring Sandbox Usage

```python
from agent_airlock.sandbox import SandboxPool

pool = SandboxPool()

# After running several operations...
stats = pool.stats()

print(f"Total executions: {stats['total_executions']}")
print(f"Success rate: {stats['success_rate']:.1%}")
print(f"Average latency: {stats['avg_latency_ms']:.0f}ms")
print(f"Active sandboxes: {stats['active']}")
print(f"Idle sandboxes: {stats['idle']}")
print(f"Total created: {stats['total_created']}")
print(f"Total cleaned: {stats['total_cleaned']}")
```
