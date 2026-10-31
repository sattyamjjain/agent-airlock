# Delegation

Since 0.10.29 a host that hands part of a task to another agent can give that agent a
policy no wider than its own, prove it, and hold the child's calls to it. Until then a
child given a wider policy than its parent got it, nothing tied a tool argument to the
lease its caller held, and a parent run with `max_turns=2` could let each nested agent take
its framework's default of 10.

Raised in openai/codex#36381, modelcontextprotocol/modelcontextprotocol#3354 and
openai/openai-agents-python#5453.

## Narrow a policy

`SecurityPolicy.narrow()` returns a copy that can only admit less:

```python
from agent_airlock import SecurityPolicy
from agent_airlock.amplification import AmplificationBudget

planner = SecurityPolicy(
    allowed_tools=["read_*", "write_file", "spawn_agent"],
    rate_limits={"*": "100/hour"},
)
researcher = planner.narrow(
    allowed_tools=["read_*", "search"],  # "search" is not the planner's: dropped
    denied_tools=["read_secrets"],
    rate_limits={"*": "20/hour"},
    amplification_budget=AmplificationBudget(max_calls_per_run=30),
)
assert researcher.is_subset_of(planner)
```

| | |
| --- | --- |
| `allowed_tools` | intersected with the parent's; an intersection that comes out empty admits no tool |
| `denied_tools` | added to the parent's |
| `rate_limits` | added, or put in place of the parent's for a pattern; each must be lower than every parent limit it could stand in for: no bigger burst, no faster refill (`10/minute` is not lower than `100/hour`) |
| `amplification_budget` | no looser than the parent's |

Every other field is the parent's own object. A request that would widen the policy
raises `ValueError` naming what widens it.

`is_subset_of(parent)` checks any policy, not only one `narrow()` built. It is sound, not
complete: it says False also when it cannot prove the subset from the policies' shape, such
as a glob that may overlap another. `agent_airlock.delegation.subset_problems(child,
parent)` says what it could not prove. The rules:

| Field | The child is within the parent when |
| --- | --- |
| allowlist | each child pattern is within a parent pattern, or the parent admits every tool |
| deny list | each parent pattern is within a child pattern |
| time windows, rate limits | every parent pattern is kept, no looser; a pattern the child adds is no looser than any of the parent's |
| `require_agent_id`, `allowed_roles` | on if the parent's is; the child's roles are among the parent's |
| re-authorization | on if the parent's is, at a threshold no higher |
| escalations | every parent rule is kept; the child's approver, channel and ledger are the parent's or none; no standing grant admits what the parent's do not |
| call budget | no looser than the parent's |
| every other field | the parent's own object |

A field added to `SecurityPolicy` later fails the check until the rules compare it.

## Delegate

`AirlockContext.delegate(child_policy)` refuses a child that is not within its parent and
otherwise issues a `DelegationLease`. Entering the lease starts the child's run:

```python
from agent_airlock import AirlockContext, SecurityPolicy

planner = SecurityPolicy(allowed_tools=["read_*", "write_file", "spawn_agent"])
run = AirlockContext(agent_id="planner")
lease = run.delegate(
    planner.narrow(allowed_tools=["read_*"]),
    parent_policy=planner,  # a delegated run's parent is its own ceiling instead
    agent_id="researcher",
    max_depth=0,  # the researcher may not delegate further
)
with lease as child:
    ...  # the researcher's tool calls
```

Every call in the child's run must pass the policies of its delegation chain, outermost
first, as well as its tool's own: the parent's (so siblings share its rate limits and call
budget) and the child's. That check is step 2.1, layer `2.1:delegation_ceiling` in the
decision record; a refusal there names the policy `DelegationCeiling`. An escalation on a
ceiling goes to that policy's approver.

The ceiling applies the policy's tool lists, identity, time windows, rate limits,
escalations, re-authorization and call budget. Its other fields (shell commands, data flow,
capabilities, the guards) must be the parent's, and the tool's own policy applies them as
before.

The lease is single-use. Entering it spends it, whatever comes of the entry, and checks
again that the child is within the parent. A second entry is refused, and so is an entry
from another run or another level of delegation. The child's context shares the run's
taint, halt latch and untrusted-output counts, so a halted run cannot carry on through a
child; the parent's `authorize_once` grants stay the parent's. The lease keeps a frozen copy
of the child's policy, so changing the policy object afterwards changes nothing.

`delegate()` refuses with `DelegationRefused`, whose `problems` say what made the child
wider.

## Leases on arguments

`@lease_scoped` binds an argument to the capability lease its caller holds in a
`CapabilityCapEngine`:

```python
from agent_airlock import Airlock, lease_scoped
from agent_airlock.capability_caps import (
    Capability,
    CapabilityCapEngine,
    CapabilityRulesConfig,
    Lease,
)

engine = CapabilityCapEngine(CapabilityRulesConfig())
engine.grant_lease(
    "writer",
    Lease(lease_id="docs", capability="write_file", categories=frozenset(), target="/repo/docs/*"),
)


@Airlock()
@lease_scoped(arg="path", capability=Capability.WRITE_FILE, engine=engine)
def write_file(path: str, text: str) -> str:
    ...
```

Before the tool runs (step 4.5), the call's `path` must fall within the target glob of a
lease its agent holds whose `capability` label is the capability's value (`"write_file"`),
however well it fits the tool's schema. The use is then metered through
`engine.check_and_use`, whose caps can still refuse it. A refusal is `capability_denied`
with `violation_type` `lease_scope`, and it never shows the lease's target.

The value is matched as written, with `fnmatchcase`, so `*` crosses `/`. A value with a
`..` segment or a NUL is refused, a call that names no agent holds no lease, and an
argument the call leaves out is checked at its default. Symlinks are the filesystem
guard's to resolve (step 3).

`delegate(..., engine=engine, leases=[...])` grants a child leases for its run, each within
one its parent holds (the same capability, a target the parent's covers, no category the
parent's lacks), under the child's own `agent_id`, and revokes them when the run ends. With
an engine, entering the lease also meters the parent's `delegate_to_agent` capability, so a
cap there bounds how many children it starts.

## Nested-run budget

An agent that runs another agent as a tool starts a new run, and each run counts its own
turns. `run_budget()` sets the budget of the whole tree at its root, and each
`nested_run()` below it takes one level of depth and draws its turns from what is left. A
share it names (`max_turns`) is reserved, and what it did not spend goes back when it ends;
with none, it spends from what is left as it goes, so concurrent siblings draw on the same
turns:

```python
from agent_airlock import Airlock, nested_run, run_budget, spend_turn


@Airlock()
def ask_researcher(question: str) -> str:
    with nested_run(max_turns=10) as budget:
        # budget.turns_left is at most what the tree has left: pass it as the
        # framework's own max_turns, and count each turn the nested agent takes.
        spend_turn()
        return "answer"


with run_budget(max_depth=1, max_turns=6):
    ...  # the root agent's run
```

| | |
| --- | --- |
| `max_depth` | levels of nested run below this one; `1` lets the root's agent run agents as tools, not those agents run more |
| `max_turns` | the turns the whole tree may take; a nested run's share is at most what is left |
| `hard_stop` | the root's choice: raise out of the run instead |

Running out raises `RunBudgetExhausted` before the nested run starts, and `@Airlock` hands
it to the agent that called the tool as a failed tool result (`run_budget_exhausted`), so
that agent can finish with what it has: the calls before it have already run. With
`hard_stop=True` at the root, the exception goes up through every `@Airlock` instead and
ends the run. A budget inside another can only tighten it, and may not set `hard_stop`.

A `DelegationLease` takes a level too, with its own `max_depth` and `max_turns`. The budget
rides a ContextVar: tasks and `asyncio.to_thread` calls started inside a scope inherit it,
a bare `threading.Thread` does not.

## What it does not do

- It counts turns only when told: a framework adapter, or the host, calls `spend_turn()`
  for each turn.
- It does not prove a child's task needs what it is given, only that it is given no more
  than its parent has.
- Glob coverage is decided from the patterns' shape, so `is_subset_of()` refuses some true
  subsets it cannot prove: `ba*` within `*a*` (a pattern with two `*`), or anything with a
  character class. And `narrow()` drops an intersection the patterns cannot express:
  narrowing `read_*` to `*_file` admits no tool, though both match `read_file`. Name
  `read_file` to keep it.
