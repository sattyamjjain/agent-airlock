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
    default_deny: bool = False

    # Rate limiting and time windows
    rate_limits: dict[str, str] = field(default_factory=dict)
    time_restrictions: dict[str, str] = field(default_factory=dict)

    # Agent identity
    require_agent_id: bool = False
    allowed_roles: list[str] = field(default_factory=list)

    # Capabilities
    capability_policy: CapabilityPolicy | None = None

    # Escalation to a human approver
    escalate_tools: dict[str, str] = field(default_factory=dict)
    approver: Approver | None = None
    escalation_channel: str = "default"
    escalation_timeout_seconds: float = 300.0

    # Budgets and guards, all off by default
    model_tier_budget: ModelTierBudget | None = None
    amplification_budget: AmplificationBudget | None = None
    sequence_guard: SequenceGuard | None = None
    action_contradiction_gate: ActionContradictionGate | None = None
    deserialization_guard: UnsafeDeserializationGuard | None = None
    trace_redaction: TraceRedactionPolicy | None = None
    reauth_on_untrusted_reinvocation: bool = False
    untrusted_reinvocation_threshold: int = 1
    stdio_mode: Literal["allowlist", "manifest_only", "disabled"] = "allowlist"
```

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `allowed_tools` | `list[str]` | Allowlist of tool patterns. Empty allows every tool not denied |
| `denied_tools` | `list[str]` | Denylist of tool patterns. Takes precedence over the allowlist |
| `default_deny` | `bool` | With `True`, an empty allowlist denies every tool |
| `rate_limits` | `dict[str, str]` | Rate limits per tool pattern (`"100/hour"`). The most specific pattern applies |
| `time_restrictions` | `dict[str, str]` | Time windows per tool pattern (`"09:00-17:00"`) |
| `require_agent_id` | `bool` | Refuse a call that carries no agent identity |
| `allowed_roles` | `list[str]` | Refuse a call whose agent holds none of these roles; an anonymous call holds none |
| `capability_policy` | `CapabilityPolicy \| None` | Checked against what a tool declares with `@requires(...)` |
| `escalate_tools` | `dict[str, str]` | Tool patterns that need a human's approval, with the reason the approver sees |
| `approver` | `Approver \| None` | Transport that asks the human. A matched escalation with no approver is refused |
| `model_tier_budget` | `ModelTierBudget \| None` | Per-model-tier cost caps, checked before the tool runs |
| `amplification_budget` | `AmplificationBudget \| None` | Per-run call budget against a declared baseline |
| `sequence_guard`, `action_contradiction_gate`, `deserialization_guard` | | Optional guards run after the policy check |
| `trace_redaction` | `TraceRedactionPolicy \| None` | Redacts traces sent to a non-local sink |
| `stdio_mode` | `str` | How STDIO subprocess launches are allowed: `"allowlist"`, `"manifest_only"` or `"disabled"` |

How a call carries its identity for `require_agent_id` and `allowed_roles` is described in
[Agent Identity](../guide/policy.md#agent-identity).

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

An empty `SecurityPolicy()`: allows every tool, with no rate limit.

### STRICT_POLICY

```python
from agent_airlock import STRICT_POLICY
```

Requires an agent identity, limits every tool to 100 calls an hour, and applies a
capability policy that grants `FILESYSTEM_READ`, `NETWORK_HTTPS` and `DATABASE_READ` and
denies `PROCESS_SHELL` and `FILESYSTEM_DELETE`. It also turns on trace redaction.

### READ_ONLY_POLICY

```python
from agent_airlock import READ_ONLY_POLICY
```

Allows `read_*`, `get_*`, `list_*` and `search_*`, denies `write_*`, `delete_*`, `update_*`
and `create_*`, and applies a capability policy that denies write and delete capabilities.

### BUSINESS_HOURS_POLICY

```python
from agent_airlock import BUSINESS_HOURS_POLICY
```

Restricts `delete_*`, `drop_*` and `*_production` to 09:00-17:00. Other tools are not
restricted.

## RateLimit

```python
from agent_airlock.policy import RateLimit
```

A token bucket. `SecurityPolicy.rate_limits` builds one per pattern; you rarely construct
one yourself.

### Signature

```python
@dataclass
class RateLimit:
    max_tokens: int
    refill_period_seconds: float

    @classmethod
    def parse(cls, limit_str: str) -> RateLimit:
        """Parse "count/period", where period is second, minute, hour or day."""
```

The bucket starts full.

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `parse(limit_str)` | `RateLimit` | Build one from `"100/hour"`; raises `ValueError` on a bad format |
| `acquire(tokens=1)` | `bool` | Take tokens if available; `False` when rate limited |
| `remaining()` | `int` | Tokens left after refilling for elapsed time |

### Example

```python
from agent_airlock.policy import RateLimit

rate_limit = RateLimit.parse("100/hour")

if rate_limit.acquire():
    ...  # proceed with the call
else:
    print(f"Rate limited, {rate_limit.remaining()} tokens left")
```

## TimeWindow

```python
from agent_airlock.policy import TimeWindow
```

### Signature

```python
@dataclass
class TimeWindow:
    start_hour: int
    start_minute: int
    end_hour: int
    end_minute: int

    @classmethod
    def parse(cls, window_str: str) -> TimeWindow:
        """Parse "HH:MM-HH:MM"."""
```

### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `parse(window_str)` | `TimeWindow` | Build one from `"09:00-17:00"` |
| `is_within(dt=None)` | `bool` | Whether `dt` (default: now) falls in the window |

Windows are checked against the local clock (`datetime.now()`); there is no timezone
argument. A window may cross midnight (`"22:00-06:00"`).

### Example

```python
from agent_airlock.policy import TimeWindow

window = TimeWindow.parse("09:00-17:00")

if window.is_within():
    ...  # within business hours
else:
    ...  # outside business hours
```

## Choosing a Policy per Call

There is no policy merge or override; build each policy whole. To apply different policies
to different calls, pass `Airlock` a function that takes the call's `AirlockContext` and
returns the policy:

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
