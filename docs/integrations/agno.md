# agno

agno calls a tool's function with the model's arguments as keywords. Put Airlock on the
function itself, or in one of agno's `tool_hooks`. Not in a `pre_hook`: agno logs what a
`pre_hook` raises and runs the tool anyway.

Read against agno v3.1.12 (2026-10-29). There is no agno adapter module: the decorator and
the hook below are all it takes.

## Guard the function

```python
from agno.agent import Agent
from agno.tools import tool

from agent_airlock import Airlock
from agent_airlock.policy import SecurityPolicy

policy = SecurityPolicy(denied_tools=["drop_*"], rate_limits={"*": "100/hour"})


@tool
@Airlock(policy=policy)
def delete_records(table: str) -> str:
    return f"deleted {table}"


agent = Agent(tools=[delete_records])
```

`@tool` goes on top. agno reads the tool's parameters from the signature `@Airlock` keeps,
and calls it with the model's arguments as keywords, so every check runs: the policy, ghost
arguments, strict types, paths and endpoints, then masking of the result. A refusal comes
back as the tool's result, a dict with `success: False`, `block_reason` and `fix_hints` for
the model to read, and the function does not run.

## A policy check in a tool hook

For tools you cannot decorate, such as a toolkit's methods, use `tool_hooks`
(`Agent(tool_hooks=[...])` covers every tool the agent has). A hook gets the tool's
`function_name`, a `function_call` and the `arguments`, and the tool runs only if the hook
calls `function_call(**arguments)`:

```python
from typing import Any, Callable

from agno.agent import Agent

from agent_airlock.policy import PolicyViolation, SecurityPolicy

policy = SecurityPolicy(allowed_tools=["search_*", "get_*"])


def airlock_policy(
    function_name: str, function_call: Callable[..., Any], arguments: dict[str, Any]
) -> Any:
    try:
        policy.check(function_name)
    except PolicyViolation as refused:
        return f"AIRLOCK_BLOCK: {refused.message}"
    return function_call(**arguments)


agent = Agent(tools=[...], tool_hooks=[airlock_policy])
```

This checks the policy by tool name: the lists, time windows and rate limits. A tool the
policy escalates is refused, since no approver is asked here. The hook does not check the
arguments' types or values; decorate the function for that.

## Not a pre_hook

agno runs a `pre_hook` before the tool and catches what it raises. It re-raises only its
own `AgentRunException` (`StopAgentRun`, `RetryAgentRun`) and `RunCancelledException`,
which stop or retry the whole run. Anything else, a `PermissionError` included, is logged as
`Error in pre-hook callback` and the tool runs anyway (agno-agi/agno#11404, open;
`FunctionCall._handle_pre_hook` in v3.1.12). A permission check written there the ordinary
Python way does not stop the call.
