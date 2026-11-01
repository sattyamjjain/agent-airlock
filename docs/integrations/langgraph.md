# LangGraph

`agent_airlock.integrations.langgraph` puts Airlock in LangGraph's `ToolNode`, where the
graph runs each tool call. The model picks the tool, so the check belongs where the graph
dispatches it rather than on each `@tool` function (langchain-ai/langgraph#8817, #8818).

```python
from langgraph.prebuilt import ToolNode

from agent_airlock.integrations.langgraph import (
    airlock_awrap_tool_call,
    airlock_wrap_tool_call,
)
from agent_airlock.policy import SecurityPolicy

policy = SecurityPolicy(denied_tools=["drop_*"])
node = ToolNode(
    tools,
    wrap_tool_call=airlock_wrap_tool_call(policy),
    awrap_tool_call=airlock_awrap_tool_call(policy),
)
```

## What runs

Each call goes through an `Airlock` built once per tool from what the model fills in
(`tool.tool_call_schema`, which leaves out the state, store and runtime LangGraph injects):
the policy and every other gate, then the node's own `execute` with the arguments Airlock
admitted, ghost arguments stripped, then masking of the result's content.

- A refusal is a `ToolMessage` with `status="error"`, the call's `tool_call_id` and the
  refusal's text and hints, and `execute` never runs.
- A call of a tool the node does not have (`request.tool is None`) is refused the same way.
- A `Command` a tool returns is passed on as it is; its messages are not masked.
- Each call spends one rate-limit token, the call's.

`airlock_middleware(policy)` is the same check as a `create_agent` middleware
(`create_agent(model, tools, middleware=[airlock_middleware(policy)])`), and
`filter_tools(tools, policy)` drops what the policy refuses outright before
`model.bind_tools(...)`, so the model is never offered it. A tool the policy escalates is
kept: a human can approve it.

## Approvals across an interrupt

With no more, a call the policy escalates goes to the policy's `approver`, and with none it
is refused. `InterruptApprovals` puts it to a human with LangGraph's `interrupt()` instead:

```python
from agent_airlock.approvals import SQLiteApprovalLedger
from agent_airlock.integrations.langgraph import InterruptApprovals, airlock_wrap_tool_call
from agent_airlock.policy import SecurityPolicy

ledger = SQLiteApprovalLedger("approvals.db")  # not the checkpoint store
policy = SecurityPolicy(escalate_tools={"delete_file": "deletes a file"}, approval_ledger=ledger)
approvals = InterruptApprovals(key, ledger)  # key: 16+ bytes, kept outside the checkpoints
wrap = airlock_wrap_tool_call(policy, approvals=approvals)
```

The graph pauses with `{"airlock_approval": {"tool", "rule", "reason", "arguments",
"binding", "seal"}}` as the interrupt's value. On a yes, resume with
`Command(resume=approvals.approve(value))`; on a no, with anything else.

The approval is bound to the call that asked: its thread, the checkpoint its task belongs to
(`checkpoint_ns` and `checkpoint_map`), the tool call id, the tool and a digest of its
arguments, by an HMAC whose key the checkpoint store never holds. When the task runs again
on resume, the wrapper derives that binding again and admits the call only when the
approval's token matches it, once, from the ledger. The checkpoint is read as untrusted
input (langchain-ai/langgraph#8938):

- a resume value forged into the checkpoint store, without the key, admits nothing;
- a request altered in the store is not signed: `approve()` checks the seal first;
- an approval replayed (the same resume again, or time travel to the interrupted
  checkpoint) admits nothing, since the ledger spends it once;
- a resume from an older checkpoint, the head row deleted, admits nothing: its binding is
  another.

An admitted call is recorded in the policy's `approval_ledger` and claimed at step 2, so it
still spends its rate-limit token. `InterruptApprovals` needs a policy with an
`approval_ledger`, and a graph with a checkpointer, which `interrupt()` needs.

On resume LangGraph runs the whole task again: in a `ToolNode` that ran several calls in
one task, the calls before the interrupted one run again too. `create_agent` sends each
tool call as its own task, so only the interrupted call runs again there.

## Install

`langgraph` (for `ToolNode` and `interrupt`) and, for the middleware, `langchain`. Neither
is imported until used, so the module imports without them.
