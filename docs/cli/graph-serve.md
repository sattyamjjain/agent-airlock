# `airlock graph serve` — live agent → tool → server topology

**Landed in v0.5.9.** Implementation `src/agent_airlock/graph/`; CLI
`src/agent_airlock/cli/graph.py`.

Builds a picture of the agent → tool → MCP-server topology recorded in an airlock
audit log and serves it locally, so an operator can show someone in thirty seconds
what their agents are actually calling.

Pure stdlib: `http.server` plus vanilla HTML/JS/CSS, so it adds **zero runtime
dependencies** and needs no extra.

## Usage

```console
$ airlock graph serve --audit-log ./airlock_audit.jsonl
$ airlock graph serve --audit-log ./airlock_audit.jsonl --host 0.0.0.0 --port 9000
```

| flag | default | meaning |
|---|---|---|
| `--audit-log PATH` | — | JSON-Lines audit file to build the graph from |
| `--host HOST` | `127.0.0.1` | bind address |
| `--port PORT` | `8765` | bind port |

## `graph dump` — the same snapshot, as JSON

```console
$ airlock graph dump --audit-log ./airlock_audit.jsonl
```

`--audit-log` is required here. Use this when you want the topology in a pipeline
rather than a browser: it prints the `GraphSnapshot` — nodes, edges, and the policy
overlay — and exits.

## Honest scope

- **Live updates are a 5-second client poll**, not a push. A WebSocket transport was
  queued for v0.5.10 and has not landed; the poll is what ships.
- The graph is built **from the audit log**, so it shows calls that reached
  `@Airlock`. A tool invoked outside the decorator leaves no record and does not
  appear — the picture is of what airlock saw, not of everything that happened.
- `--host 0.0.0.0` binds publicly and the server has **no authentication**. It is a
  local operator tool. Binding it to a routable interface exposes your audit log;
  if you need it remote, put it behind something that authenticates.

## See also

- [`airlock console`](console.md) — verdict stream and preset rehearsal over the same log
- [Sanitization and audit](../guide/sanitization.md)
