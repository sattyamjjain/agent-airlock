# OpenAI Agents SDK

`agent_airlock.integrations.openai_agents` covers three things the OpenAI Agents SDK
leaves to the host: approving a paused run's tool calls, budgeting agents that run as
tools, and ending a run Airlock halted. Each tool is still guarded by its own `@Airlock`
(`@function_tool` over `@Airlock`, as in [Compatibility](../COMPATIBILITY.md)). It was
read against openai-agents v0.24.0, and imports the SDK only when you call it.

## Approvals from the state being resumed

An escalated tool runs only once a human approved that exact call. In the SDK a run that
pauses for approval hands back interruptions, and the host approves them on the run's
state. `InterruptionApprovals` does that approval and records it for Airlock:

```python
from agents import Runner

from agent_airlock.approvals import SQLiteApprovalLedger
from agent_airlock.integrations.openai_agents import InterruptionApprovals
from agent_airlock.policy import SecurityPolicy

policy = SecurityPolicy(
    escalate_tools={"delete_file": "deletes a file"},
    approval_ledger=SQLiteApprovalLedger("approvals.db"),
)
approvals = InterruptionApprovals(policy, ttl_seconds=60.0)

result = await Runner.run(agent, prompt)
while result.interruptions:
    state = result.to_state()
    for item in state.get_interruptions():
        if human_says_yes(item):
            approvals.approve(state, item)
        else:
            approvals.reject(state, item, message="Not approved.")
    result = await Runner.run(agent, state)
```

Give the tool `needs_approval=True` in `@function_tool(...)`, so the SDK pauses before it
runs.

- Only an item of the state being resumed is approved (openai/openai-agents-python#5413):
  one from another run, or the same call id with other arguments, raises `ValueError` and
  approves nothing.
- Each call id is approved once. A second approval of it, in this state or another run's,
  raises `ValueError`.
- The approval goes into the policy's `approval_ledger` for the arguments the SDK will call
  the tool with: its own preparation of them, defaults filled in, bound to the tool's
  signature. The resumed call claims it at step 2, once, so it still spends its rate-limit
  token. A tool whose arguments the SDK cannot prepare without running the tool's own
  validators is recorded for the JSON the model sent; if the SDK then changes them, the
  call is refused at step 2.
- The recorded approval admits one call of that tool with exactly those arguments within
  `ttl_seconds`. Keep the ledger to the runs that one approver answers for.

## Agents as tools

The SDK gives each nested agent run its own `max_turns`, 10 unless set, whatever the
parent run has left (openai/openai-agents-python#5453). `airlock_agent_tool` is the SDK's
`Agent.as_tool` with every call run inside the run tree's budget
([Delegation](../guide/delegation.md)):

```python
from agents import Agent, Runner

from agent_airlock.integrations.openai_agents import airlock_agent_tool, airlock_turn_hooks
from agent_airlock.nested_runs import run_budget

research = airlock_agent_tool(
    researcher,
    tool_name="research",
    tool_description="Look a question up.",
    max_turns=4,
)
orchestrator = Agent(name="orchestrator", instructions="Answer with help.", tools=[research])

with run_budget(max_depth=1, max_turns=12):
    result = await Runner.run(orchestrator, prompt, hooks=airlock_turn_hooks())
```

- Each call of the tool is one nested run: it takes a level of `max_depth`, and each of its
  model calls takes a turn of what the tree has left, so neither the nested run nor its
  concurrent siblings take more than the root allowed. `max_turns` reserves that share of
  the tree's turns for each call and gives back what it does not spend; it is also the
  SDK's own cap for the run.
- `airlock_turn_hooks()` counts the root run's own model calls against the same budget.
  When the root run has no turn left, `RunBudgetExhausted` is raised out of it.
- A nested run the budget has no depth or turn for, or one that spends its turns, is the
  calling agent's failed tool result (`run_budget_exhausted`), and the run goes on. With
  `run_budget(hard_stop=True)` the exception is raised out of the run instead.
- Everything else is `as_tool`'s own: nested approvals, streaming, structured input. Your
  `hooks` are still called, after the count. `failure_error_function` answers the tool's
  other errors (the SDK's `default_tool_error_function` unless you pass one; `None` raises
  them), and `RunConfig.tool_error_formatter` does not apply to them.

## Hard and soft refusals

A `RunGuard` hard stop, or `context.halt()`, halts a run: every later call in it is refused
as `run_halted` (openai/openai-agents-python#5351). `airlock_tool_input_guardrail` gives
the SDK that verdict before the tool runs:

```python
from agents import function_tool

from agent_airlock import Airlock
from agent_airlock.integrations.openai_agents import airlock_tool_input_guardrail
from agent_airlock.policy import SecurityPolicy

policy = SecurityPolicy(denied_tools=["drop_*"])


@function_tool(tool_input_guardrails=[airlock_tool_input_guardrail(policy)])
@Airlock(policy=policy)
def read_file(path: str) -> str:
    return open(path).read()
```

- A call in a halted run gets `raise_exception`: the SDK raises
  `ToolInputGuardrailTripwireTriggered` and the run ends.
- A call the policy refuses by name or time window gets `reject_content` with the refusal's
  text, so the model reads it and the run goes on.
- Anything else is `allow`, and the tool's own `Airlock` makes the rest of its checks as it
  runs. The guardrail spends no rate-limit token.

The run is the `AirlockContext` passed as the run's `context`
(`Runner.run(agent, prompt, context=run)`), or the one set around the call.
