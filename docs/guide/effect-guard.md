# At-most-once dispatch

A tool call whose response is lost after the tool took effect looks, to the caller, like a
call that failed: it times out, and the retry runs the tool again. With
`SecurityPolicy(effect_guard=EffectGuard())` (0.10.29) each side-effecting call runs at
most once.

```python
from agent_airlock import Airlock, AirlockContext, SecurityPolicy
from agent_airlock.effect_guard import EffectGuard, reversibility

policy = SecurityPolicy(allowed_tools=["charge", "read_balance"], effect_guard=EffectGuard())


@Airlock(policy=policy)
def charge(account: str, cents: int) -> dict:
    ...


@reversibility("reversible")
@Airlock(policy=policy)
def read_balance(account: str) -> int:
    ...


# The host or adapter carries the model's tool call id onto the call's context.
with AirlockContext(agent_id="agent-1", metadata={"tool_call_id": tool_call.id}):
    charge(account="acct_1", cents=500)
```

## How a call is recorded

The guard keys each call on the `tool_call_id` in the call's context metadata. Only the
host or an adapter sets it: an argument of that name is the model's, and is never read.

1. Before the tool runs, the call is recorded `pending`. This is the last step before
   execution, after every other gate.
2. When the tool returns, the call is `committed`, with the value it returned.
3. When the tool raises an error that leaves its effect in doubt, the call is `unknown`.
   By default that is `TimeoutError`, `ConnectionResetError`, `ConnectionAbortedError`,
   `BrokenPipeError` and `EffectOutcomeUnknown`, which a tool raises to say it cannot
   tell (`EffectGuard(ambiguous_errors=...)` changes the list). Any other error releases
   the record, so the call may run again.

A tool that returns a generator or another deferred result takes effect as it is consumed,
after the call returns, so its call is recorded `unknown`.

## What a replay gets

A call whose `tool_call_id` the guard has seen:

| Earlier attempt | The replay |
| --- | --- |
| `committed` | returns the stored value without running, audited with `effect: "replayed"` |
| `pending` or `unknown`, tool not reversible | refused as `effect_status_unknown`: do not retry, ask the backend about the idempotency key |
| `pending` or `unknown`, tool `@reversibility("reversible")` | runs again |
| any, with other arguments or another tool | refused as a policy violation |

Every gate runs again on a replay, the policy and an escalation included: a policy that
now denies the tool refuses the replay, and the first attempt's approval is never reused.

## Reversibility

`@reversibility("reversible" | "costly" | "irreversible")` is static metadata on the tool,
read through the `__wrapped__` chain like `@requires`, above or below `@Airlock`. The
strictest tag found wins, and an untagged tool is irreversible to the guard. It is separate
from the capability a tool needs: a refusal from either stands.

## The idempotency key

Every guarded call gets `get_current_context().idempotency_key`: the sha256 of the tool's
name and its canonical arguments (`agent_airlock.effect_guard.idempotency_key`). It is the
same for the same business input whatever the `tool_call_id`, so a tool can send it to its
backend, which can then refuse a duplicate the guard never saw.

## Options

| Option | Default | What it does |
| --- | --- | --- |
| `store` | `InMemoryEffectStore()` | Where statuses live. The default holds one process's; pass a shared `EffectStore` to cover replicas |
| `require_tool_call_id` | `True` | Refuse a call to a tool that is not reversible when its context carries no `tool_call_id` (a non-empty string), since it cannot be run at most once |
| `require_approval_for_irreversible` | `False` | Escalate every call to an irreversible tool to the policy's approver, whatever `escalate_tools` says |
| `target_args` | `()` | When set, a call to an irreversible tool must pass at least one of these arguments with a value, the way a destructive command should name its `--project` |
| `ambiguous_errors` | see above | The errors that record a call `unknown` |

## What it does not do

- The shipped store is in memory: two processes do not see each other's calls. A store
  shared between replicas (implement `EffectStore`, whose `begin` must be atomic) has to
  serialise the stored results itself.
- The guard cannot tell a lost response from a tool that crashed mid-effect: both are
  `unknown`, and only a reversible tool runs again.
- No adapter sets `tool_call_id` yet; the host does, as above.
