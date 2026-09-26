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

rate_limit = RateLimit.parse("100/hour")

if rate_limit.acquire():
    ...  # a token was taken: proceed with the call
else:
    ...  # rate limited; rate_limit.remaining() is 0
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

window = TimeWindow.parse("09:00-17:00")
overnight = TimeWindow.parse("22:00-06:00")  # a window may cross midnight

if window.is_within():  # pass dt=... to check another moment
    ...
```

Windows are checked against the local clock (`datetime.now()`); there is no timezone
argument.

## Agent Identity

`require_agent_id=True` refuses a call that carries no agent identity, and
`allowed_roles` refuses one whose agent holds none of the listed roles. An anonymous call
holds no role, so it is refused too:

```python
from agent_airlock import Airlock, SecurityPolicy

policy = SecurityPolicy(require_agent_id=True, allowed_roles=["admin", "operator"])

@Airlock(policy=policy)
def delete_records(ctx, table: str) -> str:
    ...
```

Airlock reads the identity from the call's context object, the tool's first argument, in
the shape frameworks pass one: an attribute named `context`, `ctx`, `request_context` or
`session_context` whose object has an `agent_id` (or `agent`, `assistant_id`) and `roles`
(or `permissions`, `scopes`). An OpenAI Agents SDK `RunContextWrapper` fits when the
`context` object you give it carries those fields.

When a framework passes the tool no context object, set one around the call. `async with`
works the same way, and a context object on the call itself comes first:

```python
from agent_airlock.context import AirlockContext

@Airlock(policy=policy)
def export_report(name: str) -> str:
    ...

with AirlockContext(agent_id="support-bot", roles=["operator"]):
    export_report(name="q3")
```

Until 0.10.13 `@Airlock` passed no identity to the policy: `require_agent_id` refused
every call, however the caller identified itself, and `allowed_roles` was never
enforced.

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

Requires an agent identity (see [Agent Identity](#agent-identity)), limits every tool to
100 calls an hour, and applies a strict capability policy:

```python
from agent_airlock import STRICT_POLICY
from agent_airlock.context import AirlockContext

@Airlock(policy=STRICT_POLICY)
def my_tool(x: int) -> int:
    return x

with AirlockContext(agent_id="agent-1"):
    my_tool(x=1)  # refused without an identity
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

## Choosing a Policy per Call

`policy` can also be a function that takes the call's `AirlockContext` and returns the
policy to apply, for per-tenant or per-workspace rules. There is no policy merge; build
each policy whole:

```python
from agent_airlock import Airlock, SecurityPolicy
from agent_airlock.context import AirlockContext

production = SecurityPolicy(allowed_tools=["read_*"])
default = SecurityPolicy(denied_tools=["delete_*"])

def pick(context: AirlockContext) -> SecurityPolicy:
    return production if context.workspace_id == "prod" else default

@Airlock(policy=pick)
def write_note(ctx, text: str) -> str:
    ...
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
