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
    rate_limit_mode: Literal["most_specific", "all"] = "most_specific"
    rate_limit_scope: Literal["policy", "agent"] = "policy"
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
    standing_grants: list[StandingGrant] = field(default_factory=list)
    approval_ledger: ApprovalLedger | None = None
    effect_guard: EffectGuard | None = None

    # Budgets and guards, all off by default
    model_tier_budget: ModelTierBudget | None = None
    amplification_budget: AmplificationBudget | None = None
    sequence_guard: SequenceGuard | None = None
    action_contradiction_gate: ActionContradictionGate | None = None
    deserialization_guard: UnsafeDeserializationGuard | None = None
    tool_arg_sink_guard: ToolArgSinkGuard | None = None
    data_flow_policy: DataFlowPolicy | None = None  # V0.10.29
    run_guard: RunGuard | None = None  # V0.10.29
    shell_command_policy: ShellCommandPolicy | None = None  # V0.10.29
    trace_redaction: TraceRedactionPolicy | None = None
    reauth_on_untrusted_reinvocation: bool = False
    untrusted_reinvocation_threshold: int = 1
    stdio_mode: Literal["allowlist", "manifest_only", "disabled"] = "allowlist"
```

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `allowed_tools` | `list[str]` | Allowlist of tool patterns. Empty allows every tool not denied. A value that is not a list or tuple of str (`None`, a bare string) raises `TypeError` |
| `denied_tools` | `list[str]` | Denylist of tool patterns. Takes precedence over the allowlist. Same type check |
| `default_deny` | `bool` | With `True`, an empty allowlist denies every tool, refused as `empty_allowlist` and logged as `policy_indeterminate` |
| `rate_limits` | `dict[str, str]` | Rate limits per tool pattern (`"100/hour"`). The most specific pattern applies, or every matching one under `rate_limit_mode="all"`. A call refused after it took its token (by a later gate or the approver), or replayed by an effect guard, gives the token back |
| `rate_limit_mode` | `str` | `"most_specific"` (default) or `"all"`: with `{"*": "3/hour", "search_*": "100/hour"}`, `"all"` admits 3 searches an hour, the default 100. Under `"all"` a call takes a token from every matching bucket or from none |
| `rate_limit_scope` | `str` | `"policy"` (default): one bucket per pattern for every agent the policy serves. `"agent"`: one per pattern per agent id, and one shared bucket for calls with none |
| `time_restrictions` | `dict[str, str]` | Time windows per tool pattern (`"09:00-17:00"`) |
| `require_agent_id` | `bool` | Refuse a call that carries no agent identity |
| `allowed_roles` | `list[str]` | Refuse a call whose agent holds none of these roles; an anonymous call holds none |
| `capability_policy` | `CapabilityPolicy \| None` | Checked against what a tool declares with `@requires(...)` |
| `escalate_tools` | `dict[str, str]` | Tool patterns that need a human's approval, with the reason the approver sees |
| `approver` | `Approver \| None` | Transport that asks the human. A matched escalation with no approver is refused. It runs in a worker thread and must answer within `escalation_timeout_seconds` (default 300): no answer in time is refused as `escalation_timeout`, and a later answer is dropped, so an approver must not act after its deadline. An answer that is not an `OversightResponse` with an `OversightVerdict` verdict (the string `"grant"`, `None`, an exception) is refused as `policy_indeterminate`. On an async tool the event loop keeps running while it decides, and an `async` approver is awaited |
| `standing_grants` | `list[StandingGrant]` | The operator's standing approvals of one exact tool called with exact target arguments: such a call runs without asking, and its audit record names the grant. Revoke one with `revoke_standing_grant(grant_id)` |
| `approval_ledger` | `ApprovalLedger \| None` | Approvals recorded ahead of a call, each claimed by exactly one call, before the approver is asked. See [Approvals bound to the call](../guide/bound-approvals.md) |
| `effect_guard` | `EffectGuard \| None` | Runs each call to a tool that is not `@reversibility("reversible")` at most once, keyed on the `tool_call_id` the host puts on the call's context: a replay of a committed call returns the stored value, one of a pending or unknown call is refused (`effect_status_unknown`). See [At-most-once dispatch](../guide/effect-guard.md) |
| `model_tier_budget` | `ModelTierBudget \| None` | Per-model-tier cost caps, checked before the tool runs |
| `amplification_budget` | `AmplificationBudget \| None` | Per-run call budget against a declared baseline. Its `max_wall_seconds` caps how long a run may keep calling tools, from its first call |
| `sequence_guard`, `action_contradiction_gate`, `deserialization_guard` | | Optional guards run after the policy check |
| `tool_arg_sink_guard` | `ToolArgSinkGuard \| None` | Refuses shell syntax in named (or all) string arguments, anything but a bare version in installer arguments, and a function name its allowlist (or the default denylist) does not admit in dispatch arguments (step 2.75). See [Shell and installer arguments](../guide/shell-and-installer-arguments.md) and [Dispatch arguments](../guide/dispatch-arguments.md) |
| `reauth_on_untrusted_reinvocation`, `untrusted_reinvocation_threshold` | `bool`, `int` | Once a tool's output has flowed back into the model `threshold` times in a run, the next call to it needs `authorize_once(tool)` on the run's `AirlockContext`. The count lives on that context, so a call that belongs to no run is refused: one with no `AirlockContext` passed in and none set around it, or whose surrounding context names a different agent |
| `data_flow_policy` | `DataFlowPolicy \| None` | Refuses (`deny`, the default) or escalates (`escalate`) a call of an `@sink` tool made after an `@source(trust="untrusted")` call completed in the same run, until the host calls `clear_taint()` on the run's context (step 2.4). A sink called outside any run is refused. See [Sources and sinks](../guide/data-flow.md) |
| `run_guard` | `RunGuard \| None` | Halts the run after a hard stop (a refusal in `halt_on`, or of an `irreversible_tools` match), so every later call is refused as `run_halted` (step 0.7); and refuses the call that completes a repeated block of calls, then halts on the next repeat (step 2.3). See [Halting a run, and loops](../guide/run-guard.md) |
| `shell_command_policy` | `ShellCommandPolicy \| None` | Allows, escalates (rule `shell_command`) or refuses an agent shell tool's command by rule, following wrappers (`env`, `xargs`, `find -exec`, `sudo`, `sh -c`, ...) to the command they launch (step 2.77). See [Shell commands](../guide/shell-commands.md) |
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

### Narrowing a policy

Since 0.10.29, for a delegated agent:

| Method | |
| --- | --- |
| `narrow(*, allowed_tools=None, denied_tools=(), rate_limits=None, amplification_budget=None)` | A copy that can only admit less: the allowlist intersected, deny patterns added, rate limits and the call budget lowered. Raises `ValueError` when a value would admit more |
| `is_subset_of(parent)` | Whether this policy admits no call `parent` refuses. False also when the policies' shape cannot prove it; `agent_airlock.delegation.subset_problems(child, parent)` says why |

See [Delegation](../guide/delegation.md).

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
