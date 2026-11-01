# Claude Code permission prompts

In a headless `claude -p` run nobody is there to answer a permission prompt, so Claude
Code denies the call unless something approves it. `--permission-prompt-tool` points that
decision at an MCP tool (anthropics/claude-code#99813).
`agent_airlock.mcp.permission_prompt` is a FastMCP server with one such tool that answers
from a `SecurityPolicy`.

## Set it up

Write the server with your policy:

```python
# airlock_prompt.py
from agent_airlock.mcp.permission_prompt import permission_prompt_server
from agent_airlock.oversight import OversightRequest, OversightResponse, OversightVerdict
from agent_airlock.policy import SecurityPolicy


def ask_on_call(request: OversightRequest) -> OversightResponse:
    # Your transport: Slack, PagerDuty, a ticket. Answer this request_id.
    return OversightResponse(request_id=request.request_id, verdict=OversightVerdict.DENY)


policy = SecurityPolicy(
    denied_tools=["WebFetch"],
    rate_limits={"Bash": "60/hour"},
    escalate_tools={"Bash": "runs shell commands"},
    approver=ask_on_call,
    escalation_timeout_seconds=120,
)

if __name__ == "__main__":
    permission_prompt_server(policy, name="airlock").run()
```

Name it in an MCP config:

```json
{
  "mcpServers": {
    "airlock": {"type": "stdio", "command": "python", "args": ["airlock_prompt.py"]}
  }
}
```

Then run:

```bash
claude -p --mcp-config airlock.json \
  --permission-prompt-tool mcp__airlock__permission_prompt \
  "Run the test suite and fix the failures"
```

The tool's full name is `mcp__<server name>__permission_prompt`. Install the extra with
`pip install "agent-airlock[mcp]"`.

## What it decides

Claude Code asks only about calls that nothing else approved: an allow rule, an
`--allowedTools` entry or the permission mode settle the rest before the tool is asked.
For those it does see, in order:

1. **The kill switch.** While the fleet is frozen, every request is denied with
   `interrupt`, which ends the run.
2. **A malformed request** (no tool name, an input that is not an object) is denied.
3. **The policy**, by tool name, as for `@Airlock`: the deny list and allowlist, time
   windows and rate limits, where each prompt spends a token (an escalation the approver
   then denies gives it back). A request from Claude Code
   names no agent, so an identity the policy requires (`require_agent_id`,
   `allowed_roles`) is the server's own: pass `agent=AgentIdentity(...)`.
4. **An escalation** goes to the policy's `approver`. Its request is bound to the input
   as `@Airlock`'s are: the input's `args_digest`, a masked `args_preview` (never the raw
   input) and the `tool_use_id`. Only a `GRANT` that echoes the request's `request_id`
   within `escalation_timeout_seconds`, and names this `args_digest` or none, allows. No
   approver, a denial, a timeout, an approver that raises or answers anything else:
   denied. Standing grants and the approval ledger are not consulted here.
5. **Anything else** is allowed with its input unchanged.

A denial's message is Airlock's refusal text, which the model reads, and the run goes on
unless the kill switch ended it. The input is shown to the approver masked but not
screened here: Claude Code's own tools are not Airlock-guarded functions, and the policy decides by
tool name. Keep `@Airlock` on your own tools.

## The contract

Read off Claude Code 2.1.316 by running it against a probe server:

- The tool is called with `{"tool_name": "Bash", "input": {...}, "tool_use_id": "toolu_..."}`.
- It answers with one text block holding JSON: `{"behavior": "allow", "updatedInput": {...}}`
  or `{"behavior": "deny", "message": "..."}`. `"interrupt": true` on a denial ends the
  run.
- An answer that also carries `structuredContent` is refused as invalid ("Expected a
  single text block param"), and the call does not run. FastMCP adds it to a typed return
  by default, so the tool is registered with no output schema.
- An `allow` for an MCP tool marked `_meta["anthropic/requiresUserInteraction"]` is turned
  into a denial by Claude Code (v2.1.199 and later): that tool needs a person.
