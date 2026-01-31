# Policy Engine

Agent-Airlock's policy engine provides RBAC, rate limiting, and time-based restrictions.

## Security Policies

Define what tools can be called, when, and how often:

```python
from agent_airlock import Airlock, SecurityPolicy

policy = SecurityPolicy(
    allowed_tools=["search_*", "get_*"],
    denied_tools=["delete_*", "drop_*"],
    rate_limits={"*": "100/hour"},
    time_restrictions={"delete_*": "09:00-17:00"},
)

@Airlock(policy=policy)
def search_users(query: str) -> list:
    return []
```

## Tool Allow/Deny Lists

### Allowlist (Whitelist)

Only specified tools can be called:

```python
policy = SecurityPolicy(
    allowed_tools=["read_file", "list_files", "search_*"],
)
```

Supports glob patterns:
- `read_*` - Matches `read_file`, `read_config`, etc.
- `*_user` - Matches `get_user`, `delete_user`, etc.
- `*` - Matches everything

### Denylist (Blacklist)

Specified tools are blocked:

```python
policy = SecurityPolicy(
    denied_tools=["delete_*", "drop_*", "truncate_*"],
)
```

### Priority

Deny takes precedence over allow:

```python
policy = SecurityPolicy(
    allowed_tools=["*"],  # Allow everything
    denied_tools=["delete_*"],  # Except deletions
)
```

## Rate Limiting

Prevent abuse with rate limits:

```python
policy = SecurityPolicy(
    rate_limits={
        "*": "100/hour",           # Default for all tools
        "search_*": "1000/hour",   # Higher limit for searches
        "delete_*": "10/day",      # Low limit for deletions
    },
)
```

### Rate Limit Formats

| Format | Meaning |
|--------|---------|
| `10/minute` | 10 calls per minute |
| `100/hour` | 100 calls per hour |
| `1000/day` | 1000 calls per day |

### Token Bucket Algorithm

Rate limiting uses a token bucket algorithm:
- Tokens refill over time
- Burst capacity equals the rate limit
- Smooth rate limiting, not hard cutoffs

```python
from agent_airlock.policy import RateLimit

rate_limit = RateLimit(calls=100, period_seconds=3600)

# Check if allowed
if rate_limit.is_allowed():
    # Proceed with call
    rate_limit.consume()
else:
    # Rate limited
    retry_after = rate_limit.retry_after()
```

## Time-Based Restrictions

Restrict when tools can be called:

```python
policy = SecurityPolicy(
    time_restrictions={
        "delete_*": "09:00-17:00",  # Business hours only
        "backup_*": "02:00-05:00",  # Night maintenance window
    },
)
```

### Time Window Format

```python
from agent_airlock.policy import TimeWindow

# Single window
window = TimeWindow(start="09:00", end="17:00")

# With timezone
window = TimeWindow(start="09:00", end="17:00", timezone="America/New_York")

# Check if currently allowed
if window.is_active():
    # Within allowed window
    pass
```

## Agent Identity

Track and control per-agent access:

```python
from agent_airlock import Airlock, SecurityPolicy

policy = SecurityPolicy(
    allowed_agents=["agent-1", "agent-2"],
    denied_agents=["suspicious-agent"],
    agent_rate_limits={
        "agent-1": "1000/hour",
        "agent-2": "100/hour",
    },
)

@Airlock(policy=policy, agent_id="agent-1")
def my_tool(x: int) -> int:
    return x
```

## Predefined Policies

Agent-Airlock includes common policy presets:

### PERMISSIVE_POLICY

Minimal restrictions:

```python
from agent_airlock import PERMISSIVE_POLICY

@Airlock(policy=PERMISSIVE_POLICY)
def my_tool(x: int) -> int:
    return x
```

### STRICT_POLICY

Maximum restrictions:

```python
from agent_airlock import STRICT_POLICY

@Airlock(policy=STRICT_POLICY)
def my_tool(x: int) -> int:
    return x
```

### READ_ONLY_POLICY

Only read operations allowed:

```python
from agent_airlock import READ_ONLY_POLICY

@Airlock(policy=READ_ONLY_POLICY)
def read_file(path: str) -> str:
    return open(path).read()
```

### BUSINESS_HOURS_POLICY

Operations restricted to business hours:

```python
from agent_airlock import BUSINESS_HOURS_POLICY

@Airlock(policy=BUSINESS_HOURS_POLICY)
def send_email(to: str, subject: str) -> dict:
    return {"sent": True}
```

## Policy Composition

Combine policies:

```python
from agent_airlock import SecurityPolicy

base_policy = SecurityPolicy(
    denied_tools=["delete_*"],
    rate_limits={"*": "100/hour"},
)

strict_policy = SecurityPolicy(
    allowed_tools=["read_*"],
    rate_limits={"*": "10/hour"},
)

# Merge policies (stricter wins)
combined = base_policy.merge(strict_policy)
```

## Monitoring Blocked Calls

Register callbacks for policy violations:

```python
from agent_airlock import AirlockConfig

def on_blocked(tool_name: str, reason: str, context: dict):
    print(f"Blocked {tool_name}: {reason}")
    # Alert security team, log to SIEM, etc.

def on_rate_limit(tool_name: str, retry_after: int):
    print(f"Rate limited {tool_name}, retry in {retry_after}s")

config = AirlockConfig(
    on_blocked=on_blocked,
    on_rate_limit=on_rate_limit,
)
```
