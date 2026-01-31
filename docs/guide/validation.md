# Validation

Agent-Airlock provides strict argument validation to prevent LLM-related bugs.

## Ghost Argument Detection

"Ghost arguments" are parameters the LLM invents that don't exist in your function signature.

### The Problem

```python
def delete_user(user_id: int) -> dict:
    return {"deleted": user_id}

# LLM calls with invented parameters
delete_user(user_id=123, force=True, bypass_audit=True)
```

Without Airlock, `force` and `bypass_audit` are silently ignored by `**kwargs` or cause a `TypeError`.

### The Solution

```python
from agent_airlock import Airlock, AirlockConfig

# Permissive mode: strip ghost arguments
@Airlock(config=AirlockConfig(strict_mode=False))
def delete_user(user_id: int) -> dict:
    return {"deleted": user_id}

# Strict mode: reject ghost arguments
@Airlock(config=AirlockConfig(strict_mode=True))
def delete_user_strict(user_id: int) -> dict:
    return {"deleted": user_id}
```

### Permissive Mode (Default)

Ghost arguments are stripped and logged:

```python
result = delete_user(user_id=123, force=True)
# Logs: WARNING - Stripped ghost arguments: ['force']
# Returns: {"deleted": 123}
```

### Strict Mode

Ghost arguments cause rejection:

```python
result = delete_user_strict(user_id=123, force=True)
# Returns: AirlockResponse(
#     status="blocked",
#     error="Ghost arguments not allowed",
#     fix_hints=["Remove unknown parameters: force"],
#     blocked_args=["force"]
# )
```

## Type Validation

Airlock uses Pydantic V2 strict mode - no type coercion allowed.

### The Problem

Standard Pydantic allows coercion:

```python
# Without strict mode
def get_user(user_id: int) -> dict: ...

get_user(user_id="123")  # Works! "123" coerced to 123
get_user(user_id="abc")  # Crashes at runtime
```

### The Solution

Airlock enforces exact types:

```python
from agent_airlock import Airlock

@Airlock()
def get_user(user_id: int) -> dict:
    return {"id": user_id}

result = get_user(user_id="123")
# Returns: AirlockResponse(
#     status="blocked",
#     error="Type validation failed",
#     fix_hints=["user_id: Expected int, got str. Try: user_id=123"]
# )
```

## Supported Types

Airlock validates all standard Python types:

| Type | Valid | Invalid |
|------|-------|---------|
| `int` | `123` | `"123"`, `123.0` |
| `float` | `3.14`, `3` | `"3.14"` |
| `str` | `"hello"` | `123`, `None` |
| `bool` | `True`, `False` | `1`, `0`, `"true"` |
| `list[int]` | `[1, 2, 3]` | `[1, "2", 3]` |
| `dict[str, int]` | `{"a": 1}` | `{"a": "1"}` |
| `Optional[int]` | `123`, `None` | `"123"` |

## Complex Types

Airlock supports Pydantic models:

```python
from pydantic import BaseModel
from agent_airlock import Airlock

class UserCreate(BaseModel):
    name: str
    email: str
    age: int

@Airlock()
def create_user(user: UserCreate) -> dict:
    return {"created": user.name}

# Valid
result = create_user(user={"name": "John", "email": "j@x.com", "age": 30})

# Invalid - age is string
result = create_user(user={"name": "John", "email": "j@x.com", "age": "30"})
# Blocked with fix_hints
```

## Self-Healing Responses

When validation fails, Airlock returns actionable hints:

```python
@Airlock()
def search(query: str, limit: int = 10, offset: int = 0) -> list:
    return []

result = search(query=123, limit="ten", extra_param=True)
# Returns:
# {
#     "status": "blocked",
#     "error": "Validation failed",
#     "fix_hints": [
#         "query: Expected str, got int. Try: query='123'",
#         "limit: Expected int, got str. Try: limit=10",
#         "Remove unknown parameters: extra_param"
#     ]
# }
```

The LLM can read these hints and retry with corrected arguments.

## Validation Hooks

Monitor validation errors:

```python
from agent_airlock import Airlock, AirlockConfig
from pydantic import ValidationError

def on_validation_error(tool_name: str, error: ValidationError):
    # Log to monitoring system
    print(f"Validation error in {tool_name}: {error.error_count()} issues")

config = AirlockConfig(on_validation_error=on_validation_error)

@Airlock(config=config)
def my_tool(x: int) -> int:
    return x
```

## Framework Compatibility

Airlock preserves function signatures for framework compatibility:

```python
import inspect
from agent_airlock import Airlock

@Airlock()
def my_tool(query: str, limit: int = 10) -> list:
    return []

# Signature is preserved
sig = inspect.signature(my_tool)
assert "query" in sig.parameters
assert sig.parameters["limit"].default == 10
```

This ensures compatibility with:
- OpenAI Function Calling
- Azure OpenAI
- LangChain
- FastMCP
- Any framework that inspects function signatures
