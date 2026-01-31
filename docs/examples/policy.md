# Policy Examples

## Allow/Deny Lists

```python
from agent_airlock import Airlock, SecurityPolicy

# Allow only read operations
read_only = SecurityPolicy(
    allowed_tools=["read_*", "get_*", "list_*", "search_*"],
)

# Deny dangerous operations
no_delete = SecurityPolicy(
    denied_tools=["delete_*", "drop_*", "truncate_*", "remove_*"],
)

@Airlock(policy=read_only)
def read_file(path: str) -> str:
    return open(path).read()

@Airlock(policy=no_delete)
def delete_user(user_id: int) -> dict:
    # This will be blocked by policy
    return {"deleted": user_id}
```

## Rate Limiting

```python
from agent_airlock import Airlock, SecurityPolicy

policy = SecurityPolicy(
    rate_limits={
        "*": "1000/hour",            # Default limit
        "search_*": "100/minute",    # Higher for searches
        "delete_*": "10/day",        # Very low for deletions
        "send_email": "50/hour",     # Specific tool limit
    },
)

@Airlock(policy=policy)
def search_users(query: str) -> list:
    return []

@Airlock(policy=policy)
def delete_user(user_id: int) -> dict:
    return {"deleted": user_id}

# Rate limit monitoring
from agent_airlock import AirlockConfig

def on_rate_limit(tool_name: str, retry_after: int):
    print(f"Rate limited: {tool_name}, retry in {retry_after}s")

config = AirlockConfig(on_rate_limit=on_rate_limit)
```

## Time Restrictions

```python
from agent_airlock import Airlock, SecurityPolicy

policy = SecurityPolicy(
    time_restrictions={
        "delete_*": "09:00-17:00",     # Business hours only
        "send_notification": "08:00-22:00",  # Daytime only
        "backup_*": "02:00-05:00",     # Night maintenance window
    },
)

@Airlock(policy=policy)
def delete_database(name: str) -> dict:
    """Only allowed during business hours."""
    return {"deleted": name}
```

## Agent-Based Access

```python
from agent_airlock import Airlock, SecurityPolicy

policy = SecurityPolicy(
    allowed_agents=["agent-alpha", "agent-beta"],
    denied_agents=["suspicious-agent"],
    agent_rate_limits={
        "agent-alpha": "10000/hour",  # High limit for trusted agent
        "agent-beta": "1000/hour",    # Lower limit
    },
)

@Airlock(policy=policy, agent_id="agent-alpha")
def admin_operation() -> dict:
    return {"status": "ok"}
```

## Predefined Policies

```python
from agent_airlock import (
    Airlock,
    PERMISSIVE_POLICY,
    STRICT_POLICY,
    READ_ONLY_POLICY,
    BUSINESS_HOURS_POLICY,
)

# Minimal restrictions
@Airlock(policy=PERMISSIVE_POLICY)
def any_tool(x: int) -> int:
    return x

# Maximum restrictions
@Airlock(policy=STRICT_POLICY)
def strict_tool(x: int) -> int:
    return x

# Read-only operations
@Airlock(policy=READ_ONLY_POLICY)
def read_data(id: int) -> dict:
    return {"id": id}

# Business hours only
@Airlock(policy=BUSINESS_HOURS_POLICY)
def business_tool() -> dict:
    return {"status": "ok"}
```

## Policy Composition

```python
from agent_airlock import SecurityPolicy

# Base policy
base = SecurityPolicy(
    denied_tools=["delete_*"],
    rate_limits={"*": "100/hour"},
)

# Production overrides
production = SecurityPolicy(
    rate_limits={"*": "1000/hour"},  # Higher limits
    time_restrictions={"*": "09:00-17:00"},  # Business hours
)

# Development overrides
development = SecurityPolicy(
    rate_limits={"*": "10000/hour"},  # Very high limits
)

# Combine policies
prod_policy = base.merge(production)
dev_policy = base.merge(development)
```

## Role-Based Access Control

```python
from agent_airlock import Airlock, SecurityPolicy

# Define role policies
ADMIN_POLICY = SecurityPolicy(
    allowed_tools=["*"],
    rate_limits={"*": "10000/hour"},
)

USER_POLICY = SecurityPolicy(
    allowed_tools=["read_*", "search_*"],
    denied_tools=["delete_*", "admin_*"],
    rate_limits={"*": "100/hour"},
)

GUEST_POLICY = SecurityPolicy(
    allowed_tools=["search_*"],
    rate_limits={"*": "10/hour"},
)

def get_policy_for_role(role: str) -> SecurityPolicy:
    policies = {
        "admin": ADMIN_POLICY,
        "user": USER_POLICY,
        "guest": GUEST_POLICY,
    }
    return policies.get(role, GUEST_POLICY)

# Usage
@Airlock(policy=get_policy_for_role("user"))
def user_search(query: str) -> list:
    return []
```

## Monitoring Policy Violations

```python
from agent_airlock import Airlock, AirlockConfig, SecurityPolicy

violations = []

def on_blocked(tool_name: str, reason: str, context: dict):
    violations.append({
        "tool": tool_name,
        "reason": reason,
        "context": context,
    })
    print(f"BLOCKED: {tool_name} - {reason}")

config = AirlockConfig(on_blocked=on_blocked)
policy = SecurityPolicy(denied_tools=["delete_*"])

@Airlock(config=config, policy=policy)
def delete_user(user_id: int) -> dict:
    return {"deleted": user_id}

# After attempting blocked calls
print(f"Total violations: {len(violations)}")
```
