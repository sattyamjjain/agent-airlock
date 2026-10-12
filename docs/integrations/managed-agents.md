# Claude Managed Agents approval gate (v0.10.25)

**Module:** `agent_airlock.integrations.claude_managed_agents`
**Preset:** `agent_airlock.policy_presets.claude_managed_agents_safe_defaults`

## Where a client can stop a tool call

[Claude Managed Agents](https://platform.claude.com/docs/en/managed-agents/overview)
runs the agent loop on Anthropic's orchestration layer and the built-in
tools in a container your process never touches. The toolset
`agent_toolset_20260401` has eight tools: `bash`, `read`, `write`,
`edit`, `glob`, `grep`, `web_fetch` and `web_search`.

Each tool has a permission policy, and the toolset's default is
`always_allow`: the call runs and your client only hears about it
afterwards. Under `auto` the server decides, and a call it judges safe
also runs without waiting. Only `always_ask` makes the server stop
before the call: it emits an `agent.tool_use` event with
`evaluated_permission: "ask"`, the session goes idle with
`stop_reason: requires_action`, and nothing runs until you send a
`user.tool_confirmation` that names the event's `id`.

That confirmation is the one point where a client can refuse a built-in
tool call, and `ManagedAgentToolGate` puts Airlock's checks there.

Until 0.10.25 this module audited a request dict with a `"tool"` key for
tools named `read_file`, `web_browse` and `code_execute`. No Managed
Agents request has that shape and the API has none of those tools, so it
never gated a real call. `audit_managed_agent_invocation` still runs and
now emits a `FutureWarning`; it goes in v1.0.0.

## Quick start

```python
from agent_airlock import ManagedAgentToolGate, RemotePathPolicy
from agent_airlock.integrations.claude_managed_agents import check_agent_toolset

gate = ManagedAgentToolGate(
    {"read", "glob"},
    path_policy=RemotePathPolicy(allowed_roots=("/workspace",)),
)

agent = client.beta.agents.create(
    name="Repo reader",
    model="claude-opus-5-5",
    tools=[gate.agent_toolset()],  # every tool listed; read and glob on, all always_ask
)
check_agent_toolset(agent.tools, allowed_tools=gate.allowed_tools)

with client.beta.sessions.events.stream(session_id=session.id) as stream:
    client.beta.sessions.events.send(
        session_id=session.id,
        events=[{"type": "user.message", "content": [{"type": "text", "text": "..."}]}],
    )
    for event in stream:
        if event.type in ("agent.tool_use", "agent.mcp_tool_use"):
            decision = gate.review(event, session_id=session.id)
            if decision.confirmation is not None:
                client.beta.sessions.events.send(
                    session_id=session.id, events=[decision.confirmation]
                )
            elif not decision.enforced:
                # The server ran this call without waiting; stop the session.
                client.beta.sessions.events.send(
                    session_id=session.id, events=[{"type": "user.interrupt"}]
                )
        elif event.type == "session.status_idle":
            if event.stop_reason.type != "requires_action":
                break
        elif event.type == "session.status_terminated":
            break
```

`check_agent_toolset` reads the agent's tools as the server echoes them
back and raises `ManagedAgentToolsetError`, listing every problem, when a
call could run without reaching the gate: an enabled tool under
`always_allow` or `auto`, a toolset of another version, an MCP toolset
tool not under `always_ask`, or an entry it cannot place.

## What `review` checks

In order, stopping at the first refusal:

1. **Kill switch.** A frozen fleet refuses every call.
2. **The tool is known.** A built-in tool must be one of the eight; an
   `agent.mcp_tool_use` must name a `(server, tool)` pair in
   `allowed_mcp_tools`.
3. **The tool is allowed** in this gate's `allowed_tools`.
4. **Its input.**
   - `read`, `write`, `edit`: a `file_path` is required, and it and every
     other path-named key must pass the `RemotePathPolicy`
     (`write_path_policy`, when set, for `write` and `edit`).
   - `glob`: its `path` (or the policy's `workdir`) and the literal start
     of its `pattern` must fall inside the roots; `..`, a leading `~` and
     a `$` component are refused, and so is a pattern whose literal parts
     match a deny pattern (`**/*.env`).
   - `grep`: its `path` (or the `workdir`). The `pattern` is a regex over
     file contents, not a path.
   - `web_fetch`: the `url` must be `http` or `https` and pass the
     `EndpointPolicy` (allowlist, private and metadata addresses).
   - `bash`: refused unless you pass a `command_check`, which gets the
     command and must return `True` to allow it.
   - `web_search`: the name is all there is to check.
5. **`policy.check`**, last, under the built-in tool's name or
   `mcp__<server>__<tool>`.

A check that raises refuses the call; the error is logged without the
input. The decision is a `ToolUseDecision`: `allowed`, `checks` (the
last one is the one that refused), `refusal` (Airlock's refusal dict),
`needs_confirmation`, `enforced`, `deny_message` and `confirmation`.

## Construction is explicit

```python
from agent_airlock import ManagedAgentToolGate, RemotePathPolicy
from agent_airlock.network import EndpointPolicy

gate = ManagedAgentToolGate(
    {"read", "write", "web_fetch", "bash"},
    path_policy=RemotePathPolicy(allowed_roots=("/workspace",)),
    write_path_policy=RemotePathPolicy(allowed_roots=("/workspace/out",)),
    endpoint_policy=EndpointPolicy(allowed_endpoints=["docs.example.com"]),
    command_check=lambda command: command in ("ls", "pytest -q"),
    allowed_mcp_tools=[("github", "list_issues")],
)
```

The gate refuses to be built with an unknown tool name, a path tool
without a path policy, or `web_fetch` without an endpoint policy. A gate
with no tools refuses everything, and that is what the preset returns.

`RemotePathPolicy` denies `*.env`, `.env*`, `*.pem`, `*.key`, `*.p12`,
`*.pfx`, `**/.ssh/**`, `**/.aws/**`, `**/credentials/**` and
`**/secrets/**` by default, case-insensitively. Its `workdir` defaults to
`/workspace`, the container's working directory.

## Honest scope

- **Path checks are lexical.** `posixpath.normpath` and `commonpath` on
  the path the model wrote, never `realpath`: the container is remote, so
  a symlink inside it is invisible to the gate.
- **`bash` is not parsed.** The gate cannot tell what a shell command
  touches, so it refuses every `bash` call unless your `command_check`
  allows it, and what that check accepts is your decision.
- **`grep` and `glob` read or list a whole directory.** The deny patterns
  apply to the directory and to a glob's literal parts, not to each file
  `grep` searches. Leave `grep` out of `allowed_tools` when the workdir
  holds secrets.
- **A call the server allows on its own cannot be stopped.** Under
  `always_allow`, or `auto` deciding to run it, the call is already
  running when its event arrives. The gate reviews it for the record and
  reports `enforced=False` when it would have refused; the only response
  left is `user.interrupt`. This is why every tool the gate covers has to
  be `always_ask`, and why `check_agent_toolset` exists.
- **`deny_message` is visible to the model.** It is delivered as the
  rejected tool's result, so it carries the refusal's error and fix hints
  (`refusal_text`), cut to 4,000 characters, and never its metadata.
- **Custom tools are yours to run.** An `agent.custom_tool_use` event is
  answered with `user.custom_tool_result`, not a confirmation; `review`
  raises `UnreviewableEventError` for it. Run custom tools through
  `@Airlock`.

## Session budgets, not task budgets

A Managed Agents session is not a Messages API request, so the
`task_budget` builders in `claude_task_budget` do not apply to it (this
page used to say they compose; they do not). Cap a session's spend with
its own budget, set when the session is created:

```python
session = client.beta.sessions.create(
    agent={"type": "agent", "id": agent.id, "version": agent.version},
    environment_id=environment.id,
    budget={"type": "limit", "max_list_cost": {"amount": "2500", "currency": "USD"}},
)
```

`amount` is in cents (`"2500"` is $25.00). The platform checks it
before every model request and pauses the session at the cap
(`stop_reason: budget_reached`). A task budget is advisory and
token-denominated, for one agentic loop you drive through
`client.beta.messages.create`.

## Preset

```python
from agent_airlock.policy_presets import claude_managed_agents_safe_defaults

cfg = claude_managed_agents_safe_defaults()
cfg["gate"]            # a ManagedAgentToolGate that allows no tool
cfg["agent_toolset"]   # all eight tools listed, disabled, always_ask
cfg["toolset_tools"]   # the eight names (also under "harness_tools")
```

It also carries `beta_header`, `toolset_version`, `source` and the
deprecated `audit_config`.

## Logging

Every review logs `managed_agent_tool_reviewed` with the tool, event id,
session id, the server's permission, the verdict and the last check, and
never the input. A refusal the server did not wait for logs
`managed_agent_tool_not_enforced` as a warning. `redact_sse_event` masks
bearer tokens, JWTs and API-key shapes in any frame you log yourself.

## Primary sources

- [Managed Agents tools and permission policies](https://platform.claude.com/docs/en/managed-agents/tools)
- [Managed Agents events](https://platform.claude.com/docs/en/managed-agents/events)
- [Managed Agents overview](https://platform.claude.com/docs/en/managed-agents/overview)
