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

# If E2B is unavailable, the call returns a blocked response instead of running locally
result = dangerous_operation(code="import os; os.listdir('/')")
if isinstance(result, dict) and result.get("status") == "blocked":
    print(f"Sandbox unavailable: {result['error']}")
```

## Sandbox Timeout

`sandbox_timeout` is how long each E2B sandbox lives, not a per-call limit, and every
sandboxed call in the process shares one pool, built from the first sandboxed call's config.
Set it once and give every sandboxed tool the same config (see the
[E2B Sandbox guide](../guide/sandbox.md#timeout)):

```python
from agent_airlock import Airlock, AirlockConfig

# Each pooled sandbox lives 300 seconds from its creation
config = AirlockConfig(sandbox_timeout=300)

@Airlock(sandbox=True, config=config)
def quick_calc(expr: str) -> float:
    return eval(expr)

@Airlock(sandbox=True, config=config)
def train_model(data: list) -> dict:
    # Long-running ML task
    import time
    time.sleep(60)  # Simulate training
    return {"accuracy": 0.95}
```

## Sandbox Pool Management

```python
from agent_airlock import AirlockConfig
from agent_airlock.sandbox import execute_in_sandbox, get_sandbox_pool

config = AirlockConfig(sandbox_pool_size=2)  # warm_up() creates 2 sandboxes

# The pool execute_in_sandbox() and @Airlock(sandbox=True, config=config) use for this config
pool = get_sandbox_pool(config)
pool.warm_up()  # Create them now instead of on the first two calls

def process_code(code: str) -> str:
    return str(eval(code))

# Execute using pool
result = execute_in_sandbox(process_code, args=("2 + 2",), config=config)
print(result.result)  # 4

# Cleanup when done
pool.shutdown()
```

Each sandbox runs one call and is killed after it, so the two warm sandboxes cover the first
two calls; later calls create their own until `warm_up()` runs again. The pool does not cap
concurrency (an empty pool creates another sandbox) and keeps no statistics; see
[Monitoring Sandbox Usage](#monitoring-sandbox-usage).

## Error Handling

```python
from agent_airlock import Airlock

@Airlock(sandbox=True, return_dict=True)
def risky_code(code: str) -> str:
    return str(eval(code))

result = risky_code(code="1/0")  # Division by zero, inside the sandbox
if not result["success"]:
    print(result["status"])  # "blocked"
    print(result["error"])  # "AIRLOCK_BLOCK: Unexpected error in 'risky_code'"
```

A decorated tool never raises for a sandbox failure. An exception inside the sandbox returns
this blocked response, the same one the tool returns when it raises outside a sandbox, and the
underlying error is logged as the `unexpected_error` event. A missing E2B SDK or API key, or
an E2B error, returns `"block_reason": "sandbox_error"` with
`"AIRLOCK_BLOCK: 'risky_code' could not run in its sandbox"`, logged as the `sandbox_failed`
event. `execute_in_sandbox` returns the sandbox's own error text:

```python
from agent_airlock.sandbox import execute_in_sandbox

def risky_code(code: str) -> str:
    return str(eval(code))

result = execute_in_sandbox(risky_code, args=("1/0",))
print(result.success)  # False
print(result.error)  # "ZeroDivisionError: division by zero"
```

There is no timeout exception and no `is_sandboxed()` helper: a tool with `sandbox=True`
returns either its sandboxed result or the blocked response (see
[Required Sandbox](../guide/sandbox.md#required-sandbox) for the one local-fallback case).

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
)
print(result.result)  # 8
```

`execute_in_sandbox` returns a `SandboxResult`, not the bare value: check `result.success`
before reading `result.result`. It takes no timeout argument.

## Async Sandbox Execution

An `async def` tool can take `sandbox=True`. Its coroutine is awaited inside the sandbox, and
awaiting the decorated tool returns what it returned:

```python
import asyncio
from agent_airlock import Airlock

@Airlock(sandbox=True)
async def count_words(text: str) -> int:
    await asyncio.sleep(0)  # runs on an event loop inside the sandbox
    return len(text.split())

print(asyncio.run(count_words(text="one two three")))  # 3
```

Until 0.10.17 the sandbox never awaited the coroutine, and the tool returned the string form
of a coroutine object (`'<coroutine object ...>'`).

Without the decorator, await `execute_in_sandbox_async`, which runs the sandbox call in a
worker thread:

```python
import asyncio
from agent_airlock.sandbox import execute_in_sandbox_async

def process(data: str) -> dict:
    """Runs in the sandbox."""
    return {"processed": data.upper()}

async def main():
    result = await execute_in_sandbox_async(process, args=("hello",))
    print(result.result)  # {'processed': 'HELLO'}

asyncio.run(main())
```

## Monitoring Sandbox Usage

The pool keeps no statistics. Each `SandboxResult` from `execute_in_sandbox` carries
`success`, `execution_time_ms` and `sandbox_id`, so aggregate those:

```python
from agent_airlock.sandbox import execute_in_sandbox

def square(x: int) -> int:
    return x * x

results = [execute_in_sandbox(square, args=(n,)) for n in range(5)]
ok = [r for r in results if r.success]

print(f"Total executions: {len(results)}")
print(f"Success rate: {len(ok) / len(results):.1%}")
if ok:
    print(f"Average latency: {sum(r.execution_time_ms for r in ok) / len(ok):.0f}ms")
    print(f"Sandboxes used: {len({r.sandbox_id for r in ok})}")
```

The pool also logs `sandbox_created` (with `elapsed_ms`) each time it creates a sandbox, and
the decorator logs `sandbox_execution_success` (with `sandbox_id` and `execution_time_ms`) for
each sandboxed call.
