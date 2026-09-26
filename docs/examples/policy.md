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

A policy can require a caller identity and a role. Airlock reads both from the call's
context: a context object as the tool's first argument, or one set around the call.

```python
from agent_airlock import Airlock, AirlockContext, SecurityPolicy

policy = SecurityPolicy(require_agent_id=True, allowed_roles=["admin"])

@Airlock(policy=policy)
def admin_operation(ctx) -> dict:
    return {"status": "ok"}

@Airlock(policy=policy)
def rotate_keys() -> dict:
    return {"status": "rotated"}

# A framework context object: ctx.context carries agent_id and roles
admin_operation(framework_ctx)

# No context argument: set one around the call
with AirlockContext(agent_id="agent-alpha", roles=["admin"]):
    rotate_keys()
```

A call with no identity, or whose roles include none of `allowed_roles`, is refused.

## Predefined Policies

```python
from agent_airlock import (
    Airlock,
    PERMISSIVE_POLICY,
    STRICT_POLICY,
    READ_ONLY_POLICY,
    BUSINESS_HOURS_POLICY,
)

# No restrictions
@Airlock(policy=PERMISSIVE_POLICY)
def any_tool(x: int) -> int:
    return x

# Requires an agent identity (see Agent-Based Access), 100 calls an hour,
# and a capability policy
@Airlock(policy=STRICT_POLICY)
def strict_tool(x: int) -> int:
    return x

# Read-only operations
@Airlock(policy=READ_ONLY_POLICY)
def read_data(id: int) -> dict:
    return {"id": id}

# delete_*, drop_* and *_production tools only run 09:00-17:00
@Airlock(policy=BUSINESS_HOURS_POLICY)
def drop_table(name: str) -> dict:
    return {"dropped": name}
```

## Policy per Environment

There is no policy merge. Build each policy whole, sharing settings through plain Python:

```python
import os

from agent_airlock import SecurityPolicy

DENIED = ["delete_*"]

production = SecurityPolicy(
    denied_tools=DENIED,
    rate_limits={"*": "1000/hour"},
    time_restrictions={"*": "09:00-17:00"},  # Business hours
)

development = SecurityPolicy(
    denied_tools=DENIED,
    rate_limits={"*": "10000/hour"},  # Very high limits
)

policy = production if os.environ.get("ENV") == "production" else development
```

## Role-Based Access Control

```python
from agent_airlock import Airlock, AirlockContext, SecurityPolicy

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

def policy_for_caller(context: AirlockContext) -> SecurityPolicy:
    # The caller's first role, from the context object passed as the tool's first argument
    return get_policy_for_role(context.roles[0] if context.roles else "guest")

# The policy is chosen on every call, from the caller's roles:
# admin and user may read, guest may only search
@Airlock(policy=policy_for_caller)
def read_report(ctx, report_id: int) -> dict:
    return {"id": report_id}
```

To restrict a tool to roles without a policy per role, set
`SecurityPolicy(allowed_roles=[...])` (see Agent-Based Access).

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
