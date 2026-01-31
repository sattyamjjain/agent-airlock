# Policy API

Security policy engine for RBAC, rate limiting, and time restrictions.

## SecurityPolicy

```python
from agent_airlock import SecurityPolicy
```

### Signature

```python
@dataclass
class SecurityPolicy:
    # Tool access control
    allowed_tools: list[str] = field(default_factory=list)
    denied_tools: list[str] = field(default_factory=list)

    # Rate limiting
    rate_limits: dict[str, str] = field(default_factory=dict)

    # Time restrictions
    time_restrictions: dict[str, str] = field(default_factory=dict)

    # Agent identity
    allowed_agents: list[str] = field(default_factory=list)
    denied_agents: list[str] = field(default_factory=list)
    agent_rate_limits: dict[str, str] = field(default_factory=dict)
```

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `allowed_tools` | `list[str]` | Allowlist of tool patterns |
| `denied_tools` | `list[str]` | Denylist of tool patterns |
| `rate_limits` | `dict[str, str]` | Rate limits per tool pattern |
| `time_restrictions` | `dict[str, str]` | Time windows per tool pattern |
| `allowed_agents` | `list[str]` | Allowed agent IDs |
| `denied_agents` | `list[str]` | Denied agent IDs |
| `agent_rate_limits` | `dict[str, str]` | Rate limits per agent |

### Pattern Matching

Tool patterns support glob-style matching:

| Pattern | Matches |
|---------|---------|
| `read_*` | `read_file`, `read_config`, etc. |
| `*_user` | `get_user`, `delete_user`, etc. |
| `*` | Everything |
| `search_*` | `search_users`, `search_products` |

### Example

```python
from agent_airlock import SecurityPolicy

policy = SecurityPolicy(
    allowed_tools=["read_*", "search_*", "get_*"],
    denied_tools=["delete_*", "drop_*"],
    rate_limits={
        "*": "100/hour",
        "search_*": "1000/hour",
        "delete_*": "10/day",
    },
    time_restrictions={
        "delete_*": "09:00-17:00",
    },
)
```

## Predefined Policies

### PERMISSIVE_POLICY

```python
from agent_airlock import PERMISSIVE_POLICY
```

Minimal restrictions - allows everything with basic rate limiting.

### STRICT_POLICY

```python
from agent_airlock import STRICT_POLICY
```

Maximum restrictions - requires explicit allowlist.

### READ_ONLY_POLICY

```python
from agent_airlock import READ_ONLY_POLICY
```

Only allows read operations (`read_*`, `get_*`, `list_*`, `search_*`).

### BUSINESS_HOURS_POLICY

```python
from agent_airlock import BUSINESS_HOURS_POLICY
```

All operations restricted to business hours (09:00-17:00).

## RateLimit

```python
from agent_airlock.policy import RateLimit
```

### Signature

```python
class RateLimit:
    def __init__(
        self,
        calls: int,
        period_seconds: int,
    ):
        """
        Token bucket rate limiter.

        Args:
            calls: Maximum calls allowed
            period_seconds: Time period in seconds
        """
```

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `is_allowed()` | `bool` | Check if call is allowed |
| `consume()` | `bool` | Consume a token, return success |
| `retry_after()` | `int` | Seconds until next token available |
| `reset()` | `None` | Reset the rate limiter |

### Example

```python
from agent_airlock.policy import RateLimit

rate_limit = RateLimit(calls=100, period_seconds=3600)

if rate_limit.is_allowed():
    rate_limit.consume()
    # Proceed with call
else:
    wait = rate_limit.retry_after()
    print(f"Rate limited, retry in {wait}s")
```

## TimeWindow

```python
from agent_airlock.policy import TimeWindow
```

### Signature

```python
class TimeWindow:
    def __init__(
        self,
        start: str,
        end: str,
        timezone: str = "UTC",
    ):
        """
        Time-based access window.

        Args:
            start: Start time (HH:MM)
            end: End time (HH:MM)
            timezone: Timezone name
        """
```

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `is_active()` | `bool` | Check if currently in window |
| `next_start()` | `datetime` | Next time window opens |
| `next_end()` | `datetime` | Next time window closes |

### Example

```python
from agent_airlock.policy import TimeWindow

window = TimeWindow(
    start="09:00",
    end="17:00",
    timezone="America/New_York",
)

if window.is_active():
    # Within business hours
    pass
else:
    # Outside business hours
    next_open = window.next_start()
```

## Policy Composition

### merge()

Combine two policies:

```python
base = SecurityPolicy(denied_tools=["delete_*"])
strict = SecurityPolicy(rate_limits={"*": "10/hour"})

combined = base.merge(strict)
# Combined has both denied_tools and rate_limits
```

### override()

Override specific settings:

```python
base = SecurityPolicy(rate_limits={"*": "100/hour"})
override = SecurityPolicy(rate_limits={"*": "1000/hour"})

final = base.override(override)
# rate_limits is now {"*": "1000/hour"}
```
