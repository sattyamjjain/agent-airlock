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
from agent_airlock import Airlock, AirlockConfig, UnknownArgsMode

# Default (STRIP_AND_LOG): strip ghost arguments and log them
@Airlock()
def delete_user(user_id: int) -> dict:
    return {"deleted": user_id}

# BLOCK: reject a call that carries ghost arguments
@Airlock(config=AirlockConfig(unknown_args=UnknownArgsMode.BLOCK))
def delete_user_strict(user_id: int) -> dict:
    return {"deleted": user_id}
```

`STRIP_SILENT` strips them without logging.

### Stripping (Default)

Ghost arguments are stripped and logged:

```python
result = delete_user(user_id=123, force=True)
# Logs a warning: ghost_arguments_stripped  stripped_args=['force']
# Returns: {"deleted": 123}
```

### Blocking

Ghost arguments cause rejection:

```python
result = delete_user_strict(user_id=123, force=True)
# Returns:
# {
#     "success": False,
#     "status": "blocked",
#     "error": "AIRLOCK_BLOCK: Unknown arguments detected: force",
#     "block_reason": "ghost_arguments",
#     "fix_hints": [
#         "Remove these unknown arguments: force",
#         "Check the function signature for valid parameter names",
#     ],
#     "metadata": {...},
# }
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
# Returns:
# {
#     "success": False,
#     "status": "blocked",
#     "error": "AIRLOCK_BLOCK: Tool 'get_user' validation failed. user_id: Input should
#               be a valid integer",
#     "block_reason": "validation_error",
#     "fix_hints": ["'user_id' must be an integer, not str"],
#     "metadata": {...},
# }
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

Airlock supports Pydantic models, passed as a dict or an instance, and strict mode reaches
inside them:

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
# Blocked, with fix_hints: ["'user.age' must be an integer, not str"]
```

The same holds for a list of models (`'users.1.age'`), a TypedDict, and an optional model.
Until 0.10.16 a model was validated with its own config, lax by default, so `"30"` was
coerced to `30` and the call ran.

## Self-Healing Responses

When validation fails, Airlock returns actionable hints:

```python
@Airlock()
def search(query: str, limit: int = 10, offset: int = 0) -> list:
    return []

result = search(query=123, limit="ten", extra_param=True)
# extra_param is stripped (the default mode), then both type errors are reported:
# {
#     "success": False,
#     "status": "blocked",
#     "error": "AIRLOCK_BLOCK: Tool 'search' validation failed. query: Input should be a
#               valid string; limit: Input should be a valid integer",
#     "block_reason": "validation_error",
#     "fix_hints": [
#         "'query' must be a string, not int",
#         "'limit' must be an integer, not str"
#     ],
#     "metadata": {...},
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
