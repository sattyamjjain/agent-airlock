# `airlock studio` — paste-a-transcript rehearsal sandbox

**Landed in v0.6.0.** Implementation `src/agent_airlock/studio/`; CLI
`src/agent_airlock/cli/studio.py`.

A local HTTP sandbox for rehearsing a policy bundle against an agent transcript. Paste
a transcript into the form, and each line is evaluated against the loaded bundle with
inline verdicts plus a diff against the previous run — so you can change a policy and
see exactly which lines changed verdict.

Stdlib `http.server` renders it, so the default path needs **no extra**.

## Usage

```console
$ airlock studio
$ airlock studio --host 0.0.0.0 --port 9001
```

| flag | default |
|---|---|
| `--host HOST` | `127.0.0.1` |
| `--port PORT` | `8010` |

## Why it exists

Reading a policy and knowing what it will do to a real transcript are different
skills. The diff-against-previous-run is the part that matters: tightening a rule
usually changes more verdicts than the author expects, and this shows which.

Positioning anchor: Microsoft's
[Agent Governance Toolkit](https://opensource.microsoft.com/blog/2026/04/02/introducing-the-agent-governance-toolkit-open-source-runtime-security-for-ai-agents/).

## Honest scope

- **Rehearsal only.** Studio evaluates a transcript you paste. It does not sit in a
  request path, does not gate a live agent, and writes no policy.
- The transcript is **text you supply**, so fidelity is your responsibility — a
  hand-written transcript rehearses the policy against what you imagine an agent
  sends, not against what it sends.
- `--host 0.0.0.0` binds publicly with **no authentication**, and the form accepts
  whatever is pasted into it. Keep it on loopback unless you have put something in
  front of it.
- FastAPI is gated behind an extra; the stdlib server is the always-available default
  and is what these instructions describe.

## See also

- [`airlock console`](console.md) — the terminal equivalent, over an audit log
- [`airlock policy compile / explain`](policy-compile-explain.md) — authoring the bundle
