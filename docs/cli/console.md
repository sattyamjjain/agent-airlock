# `airlock console` — interactive policy-rehearsal TUI

**Landed in v0.6.0.** Implementation `src/agent_airlock/cli/console.py`.

A three-pane [Textual](https://textual.textualize.io/) app for rehearsing a preset
chain against a verdict stream before it gates anything real.

| pane | shows |
|---|---|
| left | live verdict stream, newest at the top |
| top-right | the active preset chain, each entry toggleable |
| bottom-right | the last 50 verdicts **re-evaluated** against the chain as you edit it |

The bottom-right pane is the point: toggling a preset off does not just change what
happens next, it replays recent history through the edited chain so you can see what
that preset was actually catching before you drop it.

## Install

```bash
pip install "agent-airlock[console]"
```

Textual is behind the extra so the base install stays Pydantic-only. Running the
command without it prints an install hint rather than a traceback.

## Usage

```console
$ airlock console --audit-log ./airlock_audit.jsonl
```

| flag | meaning |
|---|---|
| `--audit-log PATH` | JSON-Lines audit log to stream verdicts from |
| `--no-tui` | emit a single JSON snapshot to stdout and exit |

## `--no-tui` for CI

`--no-tui` skips Textual entirely and prints one JSON object, which is what you want
in a pipeline or when you just need the current state:

```console
$ airlock console --no-tui
{
  "active_presets": [],
  "verdicts": []
}
```

Empty output like that is the honest answer for a process with no presets registered
and no audit log — not an error. Point `--audit-log` at a real file to get content.

## Honest scope

- It is a **rehearsal** surface. Toggling a preset in the console changes what the
  console replays; it does not reconfigure a running agent. Nothing here writes
  policy.
- Verdicts come from an audit log, so the console shows what `@Airlock` already
  decided. It is not an interceptor and cannot show a call that was never made.
- `--no-tui` does not need the `[console]` extra to produce its snapshot, but the
  interactive path does.

## See also

- [`airlock graph serve`](graph-serve.md) — the topology view over the same audit log
- [`airlock studio`](studio.md) — paste-a-transcript rehearsal in a browser
