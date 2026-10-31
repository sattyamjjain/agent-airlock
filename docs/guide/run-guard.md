# Halting a run, and catching loops

Since 0.10.29 a `RunGuard` can halt a run after a hard stop, and catch a run that keeps
repeating the same calls. Until then there was no halt latch: after a fleet freeze or an
approval nobody could read, the model's next call was judged as if nothing had happened.
`AmplificationBudget` capped how many calls a run made, but nothing noticed the same calls
coming back.

```python
from agent_airlock import Airlock, AirlockContext, RunGuard, SecurityPolicy

policy = SecurityPolicy(run_guard=RunGuard(irreversible_tools=("wire_*", "delete_*")))


@Airlock(policy=policy)
def wire_money(account: str, amount: int) -> str:
    ...


with AirlockContext(agent_id="assistant") as run:
    ...
    if run.halted:
        print("stopped:", run.halt_reason)
```

## What a single call can bound, and what needs the run

`@Airlock` judges one call at a time. By itself it bounds that call: its arguments, its
tool's rate limit, its cost, its approval. Some failures only show across a run's calls,
so they need the run's `AirlockContext`, the one a run wrapper carries or the one set
around the calls. `_share_run_state` hands it to every call of the run.

| Bounded per call | Needs the run's context |
| --- | --- |
| argument validation and the value gates | the halt latch (this page) |
| policy: allow, deny, escalate, roles, time windows | loop detection (this page) |
| rate limits (per tool, or per agent) | `reauth_on_untrusted_reinvocation` counts |
| the per-model-tier cost budget | the amplification budget (keyed by session) |
| sandboxing and the network airgap | the source-to-sink taint ([Sources and sinks](data-flow.md)) |

A call under a `RunGuard` that belongs to no run is refused as `run_guard_outside_run`,
since the guard keeps its state on the run. A thread started without the caller's context
(a bare `threading.Thread`) is outside the run; `asyncio.to_thread` and a run wrapper
carry it.

## Hard stops

A refusal halts the run when:

- its block reason is in `halt_on`, which is `kill_switch` and `policy_indeterminate` by
  default: a fleet freeze, and an approval answer nobody could read as consent or refusal;
- or the refused call's tool matches one of `irreversible_tools`, whatever the reason.

From then on, every call in the run is refused as `run_halted`, whatever the call and
whatever its own policy, even a tool with no `RunGuard` at all. The halt latch is step
0.7, before any gate reads the arguments. It is checked again at the end of the gates, so
a call that was waiting on an approver, or in a `serialize_batch` wait, when the run halted
is refused too. A call already running when the run halts finishes.

The refusal's metadata names the halt reason. `run.halted` and `run.halt_reason` say the
same to the host, and `run.halt(reason)` halts a run from host code. A halted run stays
halted: start a new run to go on.

## Loops

With `detect_loops` (on by default), step 2.3 keeps the run's recent calls as
`(tool, arguments digest)`, the same canonical digest approvals bind to. When a block of 1
to `max_loop_period` calls (5 by default) has just repeated `loop_repeats` times in a row
(5 by default):

- the call that completes it is refused with `violation_type` `loop_detected`, and its
  fix hints tell the model to change approach, since one more repeat ends the run;
- the next call that completes a loop halts the run, and is refused as `run_halted`.

So a single call made five times trips on the fifth, as does a three-call sequence on its
fifteenth call. The same tool called with different arguments never trips. Only calls the
policy admitted at step 2 are counted, and only those whose policy carries the `RunGuard`.

## Settings

| Setting | Default | |
| --- | --- | --- |
| `halt_on` | `{"kill_switch", "policy_indeterminate"}` | block reasons (or `BlockReason` members) whose refusal halts the run |
| `irreversible_tools` | `()` | tool-name globs: any refusal of a matching call halts the run |
| `detect_loops` | `True` | look for repeated blocks of calls |
| `loop_repeats` | `5` | repeats that make a loop, 2 to 100 |
| `max_loop_period` | `5` | the longest block looked for, 1 to 10 |

The policy digest covers the guard, so dropping it after `freeze()` is detected.

The decision record names the steps: `0.7:run_halted` for a halted run and
`2.3:run_loop` for a loop refusal.
