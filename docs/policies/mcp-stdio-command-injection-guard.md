# MCP STDIO command-injection guard (v0.7.6+, carried from 2026-05-11)

`agent_airlock.mcp_spec.stdio_command_injection_guard.StdioCommandInjectionGuard`
is the runtime gate for shell metachars and path traversal in MCP
STDIO argv vectors.

## Why

Per [Help Net Security 2026-05-05][hns] citing Snyk ToxicSkills:

> "1 in 4 MCP servers opens AI agent security to code execution
> risk."

MCP STDIO transport accepts an argv vector that often arrives via
the model's tool-call payload. A shell metachar in any element opens
an injection path. The guard denies on:

1. **Shell metachars in any element** of `command` or `args`:
   `;`, `&&`, `||`, `|`, newline, carriage return, backtick, `$(`.
2. **Path traversal** (`../` resolving outside an operator-supplied
   `cwd_allowlist`). The traversal check is **opt-in** — empty
   allowlist disables it.
3. **A stop-parsing token** (`--%`) as a whole element of `command` or
   `args` (CVE-2026-19591).

`command` and `args` may each be a single string or a list of strings,
and both shapes are checked. A single string is a shell-form command
line, so the stop-parsing and traversal checks look at its tokens. Until
v0.10.21 a list `command` and a string `args` were skipped entirely.

[hns]: https://www.helpnetsecurity.com/2026/05/05/ai-agent-security-skills-blind-spots/

## Install

Core. No optional extra. The `mcp` package is **not** loaded — the
guard is a regex / string-set match over the argv.

## Quickstart

```python
from agent_airlock import StdioCommandInjectionGuard, StdioCommandInjectionVerdict

# Default: metachar block-list active; traversal check opt-in.
guard = StdioCommandInjectionGuard(cwd_allowlist=("/srv/app",))

decision = guard.evaluate({"command": "bash", "args": ["-c", "echo hi; rm -rf /"]})
# decision.allowed is False
# decision.verdict == StdioCommandInjectionVerdict.DENY_SHELL_METACHAR
# decision.matched_metachar == ";"
```

## Companion preset

`agent_airlock.policy_presets.mcp_stdio_command_injection_preset_defaults()`
returns the recommended config dict (preset_id, severity,
default_action, advisory_url, cwd_allowlist, extra_metachars).

## Decision shape

`evaluate(args)` returns `StdioCommandInjectionDecision`. The
`allowed: bool` field intentionally mirrors the v0.6.1 –v0.7.5
family for chain-friendly composition.

| Verdict | When |
|---|---|
| `ALLOW` | no metachar in argv; traversal check disabled or path inside allowlist |
| `DENY_SHELL_METACHAR` | any default or operator-extended metachar found |
| `DENY_PATH_TRAVERSAL` | path-shaped argv element resolves outside `cwd_allowlist` |
| `DENY_STOP_PARSING_TOKEN` | an argv element is a stop-parsing token (`--%`), so the argv no longer describes what would run |

## Extending the metachar set

```python
guard = StdioCommandInjectionGuard(
    cwd_allowlist=("/srv/app",),
    extra_metachars=frozenset({"#"}),  # treat `#` as a metachar too
)
```

## Honest scope

- The default metachar set captures the disclosed exploitation
  primitives. Determined attackers can sometimes shell-quote around
  individual metachars in narrow contexts.
- Operators with a fixed-binary policy should ALSO use
  [`enforce_allowlist`](../mcp/manifest-only-mode.md) /
  `AllowlistVerdict` as a second layer — the runtime allowlist gate
  refuses anything outside a signed manifest, regardless of metachar
  shape.
- The traversal check is **opt-in** because operators who don't
  route their MCP servers through a fixed cwd would see false
  positives. Pass a non-empty `cwd_allowlist` to enable it.

## Primary source

- [Help Net Security — 1 in 4 MCP servers opens AI agent security to code execution risk (2026-05-05)][hns]
