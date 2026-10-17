# Live API contract tests

These tests send real requests to the Anthropic API, so they **spend API
credit**. A full run costs well under $1: every request is on Claude
Haiku 5.5, the Agent SDK run is capped at $0.50 (`max_budget_usd`), and the
Managed Agents session carries a hard $25.00 list-cost budget as a backstop
it is not expected to come near.

They check what only live traffic can show: that the request and response
shapes airlock builds and reads are the ones the API uses.

| Module | What it checks |
|---|---|
| `test_live_messages.py` | A refusal from `process_message_tools` is an `is_error` tool result the API accepts back, and names the allowed root; the generated schema makes the model send an integer as an integer; `output_config.task_budget` is accepted and the pre-0.10.25 shape is a 400 |
| `test_live_agent_sdk.py` | Under the Claude Agent SDK, a tool `wrap_tools` refuses never runs, and the model gets `ToolResultBlock.is_error` with `AIRLOCK_BLOCK` |
| `test_live_managed_agents.py` | In a Managed Agents session, `always_ask` reads arrive as `agent.tool_use` with `evaluated_permission: "ask"`, the gate's confirmations are accepted, an allowed read succeeds, and a refused read's `deny_message` reaches the agent as an error |

## Running

The default test run never collects this directory (`addopts` carries
`--ignore=tests/live`), and each test also skips unless both
`AIRLOCK_LIVE=1` and `ANTHROPIC_API_KEY` are set.

```bash
python3 -m venv .venv-live
.venv-live/bin/pip install -e ".[dev,claude-agent]" "anthropic>=1.13"
ANTHROPIC_API_KEY="$(security find-generic-password -s anthropic-credits -w)" \
  PATH="$PWD/.venv-live/bin:$PATH" make test-live
```

Read the key per command, as above, rather than exporting it. To run one
module, `-k managed` (or `-k messages`, `-k agent_sdk`) on the same
`pytest tests/live -o addopts="" -m live` command `make test-live` runs.

For the whole session the fixtures remove every other `ANTHROPIC_*`
variable, `CLAUDE_CODE_*` (the subscription login included), `CLAUDECODE`
and the other Claude Code session variables, and the client gets the key
explicitly, so nothing but the API key authenticates a request. No
sampling parameter is sent.

## Records

Each run appends to `tests/live/.results/<UTC date>.json` (gitignored):
package versions, the model requested and observed, token usage, list
cost, the field names of the events seen, the gate's decisions and the
cleanup outcome. Free text goes through `redact_sse_event` and the API key
is replaced wherever it appears; a record never holds a credential.

## Cleanup

The Managed Agents test deletes its session and environment and archives
its agent (agents cannot be deleted) in `finally`. If a run is killed
before that, list and remove what it left; everything it creates is named
`airlock-live-<8 hex>`:

```bash
ant beta:sessions list --transform '{id,title,status}' --format jsonl
ant beta:sessions delete --session-id "$SID"
ant beta:environments delete --environment-id "$ENV_ID"
ant beta:agents archive --agent-id "$AGENT_ID"
```

The same through the Python SDK: `client.beta.sessions.delete(session_id=...)`,
`client.beta.environments.delete(environment_id=...)` and
`client.beta.agents.archive(agent_id=...)`.

## Last verified

| Date (UTC) | anthropic | claude-agent-sdk | Model | Result |
|---|---|---|---|---|
| not yet run | 1.13.0 | 0.2.165 | claude-haiku-5-5 | written against the SDK types; the first live run fills this row |
