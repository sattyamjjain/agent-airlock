# Basic Usage Examples

## Simple Tool Protection

```python
from agent_airlock import Airlock

@Airlock()
def calculate(x: int, y: int, operation: str = "add") -> int:
    """Perform a calculation."""
    if operation == "add":
        return x + y
    elif operation == "multiply":
        return x * y
    else:
        raise ValueError(f"Unknown operation: {operation}")

# Valid call
result = calculate(x=5, y=3, operation="add")
print(result)  # 8

# Invalid type - returns error response
result = calculate(x="five", y=3)
# {"status": "blocked", "fix_hints": ["x: Expected int, got str"]}
```

## Strict Mode

```python
from agent_airlock import Airlock, AirlockConfig

config = AirlockConfig(strict_mode=True)

@Airlock(config=config)
def delete_file(path: str) -> dict:
    """Delete a file."""
    # In real code: os.remove(path)
    return {"deleted": path}

# Valid call
result = delete_file(path="/tmp/test.txt")

# Ghost argument - blocked in strict mode
result = delete_file(path="/tmp/test.txt", force=True)
# {"status": "blocked", "fix_hints": ["Remove unknown parameters: force"]}
```

## Output Sanitization

```python
from agent_airlock import Airlock, AirlockConfig

config = AirlockConfig(
    sanitize_output=True,
    mask_pii=True,
    mask_secrets=True,
)

@Airlock(config=config)
def get_user_details(user_id: int) -> dict:
    """Get user details."""
    return {
        "id": user_id,
        "name": "John Doe",
        "email": "john@example.com",
        "ssn": "123-45-6789",
        "api_key": "sk-1234567890abcdef",
    }

result = get_user_details(user_id=123)
# {
#     "id": 123,
#     "name": "John Doe",
#     "email": "[EMAIL REDACTED]",
#     "ssn": "[SSN REDACTED]",
#     "api_key": "[API_KEY REDACTED]"
# }
```

## Async Functions

```python
import asyncio
from agent_airlock import Airlock

@Airlock()
async def fetch_data(url: str) -> dict:
    """Fetch data from URL."""
    await asyncio.sleep(0.1)  # Simulate network call
    return {"url": url, "status": "fetched"}

# Usage
async def main():
    result = await fetch_data(url="https://api.example.com/data")
    print(result)

asyncio.run(main())
```

## Error Handling

```python
from agent_airlock import Airlock, AirlockResponse

@Airlock()
def process_data(data: list[int]) -> dict:
    """Process a list of integers."""
    return {"sum": sum(data), "count": len(data)}

result = process_data(data="not a list")

# Check if blocked
if isinstance(result, dict) and result.get("status") == "blocked":
    print("Blocked!")
    print(f"Error: {result['error']}")
    for hint in result.get("fix_hints", []):
        print(f"  Hint: {hint}")
else:
    print(f"Success: {result}")
```

## Combining Features

```python
from agent_airlock import Airlock, AirlockConfig, SecurityPolicy

config = AirlockConfig(
    strict_mode=True,
    sanitize_output=True,
    mask_pii=True,
)

policy = SecurityPolicy(
    rate_limits={"search_*": "100/hour"},
)

@Airlock(config=config, policy=policy)
def search_customers(query: str, limit: int = 10) -> list:
    """Search for customers."""
    return [
        {"name": "Customer 1", "email": "c1@example.com"},
        {"name": "Customer 2", "email": "c2@example.com"},
    ]

# All protections apply:
# - Strict mode (no ghost args)
# - Rate limiting (100/hour)
# - PII masking (emails hidden)
result = search_customers(query="test")
```

## Decorator Stacking

```python
from functools import wraps
from agent_airlock import Airlock

def log_calls(func):
    """Log function calls."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        print(f"Calling {func.__name__}")
        return func(*args, **kwargs)
    return wrapper

@log_calls
@Airlock()
def my_tool(x: int) -> int:
    return x * 2

result = my_tool(x=5)
# Prints: "Calling my_tool"
# Returns: 10
```
