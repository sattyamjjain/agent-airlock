# Shell and installer arguments

Added in 0.10.28. `ToolArgSinkGuard` reads a call's string arguments for shell syntax, and
its installer arguments for anything but a bare version. `@Airlock` runs it as step 2.75,
right after the deserialization guard. It is off until a policy sets it, and a policy
without it behaves exactly as before:

| Field | Default | What it does |
|---|---|---|
| `shell_args` | `frozenset()` | argument names screened for shell syntax |
| `screen_all_str_args` | `False` | screen every argument, except `free_text_args` |
| `free_text_args` | `frozenset()` | arguments `screen_all_str_args` leaves alone: messages, prompts, file bodies |
| `installer_args` | `frozenset()` | arguments that must be a bare version |
| `extra_metachars` | `frozenset()` | tokens refused on top of the default set |
| `mode` | `"deny"` | `"deny"` refuses a finding, `"warn"` logs it and runs the call |
| `dispatch_args` | `{}` | arguments that name a function the tool calls, each with the names it may hold: see [Dispatch arguments](dispatch-arguments.md) |

Each name collection takes a set, list or tuple of strings and is stored as a `frozenset`.
A config that could not mean what it says raises when the guard is built: a lone string
(`shell_args="repo"` would otherwise be split into letters), a mode other than `"deny"` or
`"warn"`, an argument named both free text and screened, `free_text_args` without
`screen_all_str_args`, or a guard that screens nothing.

## The CVEs

Nine MCP server CVEs published on 27 and 28 October 2026 share one shape: a string
argument of an ordinary tool, written by the model, reaches a shell or a package installer
on the server. A prompt-injected agent only has to write `x; id` or `file:../evil` into it.

| CVE | Server | Argument | Reaches | CVSS 3.1 |
|---|---|---|---|---|
| [CVE-2026-117558](https://nvd.nist.gov/vuln/detail/CVE-2026-117558) | ai-sdlc plugin MCP server through 0.31.2 | `repo` | `gh issue view` / `gh pr view` through `execSync` | 7.8 |
| [CVE-2026-117559](https://nvd.nist.gov/vuln/detail/CVE-2026-117559) | DroidMind through 0.4.0 | `command`, `path` | `Device.run_shell()`, past its allowlist with `$(...)` or backticks | 7.8 |
| [CVE-2026-117560](https://nvd.nist.gov/vuln/detail/CVE-2026-117560) | ATXP Gemini CLI extension through 1.0.0 | `message_id`, `subject`, `query` | `runAtxp()` | 7.8 |
| [CVE-2026-117561](https://nvd.nist.gov/vuln/detail/CVE-2026-117561) | sf-mcp through 1.3.2 | Salesforce CLI flag values | `execSync` in `executeSfCommand` | 7.8 |
| [CVE-2026-117567](https://nvd.nist.gov/vuln/detail/CVE-2026-117567) | esp-mcp through 28afddf | `target`, `port`, `project_path`, `project_name` | `asyncio.create_subprocess_shell` | 7.8 |
| [CVE-2026-117568](https://nvd.nist.gov/vuln/detail/CVE-2026-117568) | mcp-ffmpeg through 1.0.5 | `videoPath`, `outputDir` | `child_process.exec` | 7.0 |
| [CVE-2026-117569](https://nvd.nist.gov/vuln/detail/CVE-2026-117569) | Kali-GPT through a608c74 | `target`, `ports`, `domain`, `wordlist`, `url` | `subprocess.run(shell=True)` | 7.8 |
| [CVE-2026-117573](https://nvd.nist.gov/vuln/detail/CVE-2026-117573) | hagent through 761eec6 | `args` | `arduino-cli` and `idf.py` under `subprocess.run(shell=True)` | 7.8 |
| [CVE-2026-59176](https://nvd.nist.gov/vuln/detail/CVE-2026-59176) | functype-mcp-server before 1.4.4 | `version` | `pnpm add functype@<version>`, then imported (CWE-829) | 7.8 |

NVD names no argument for DroidMind or sf-mcp; the names above are the servers' own
(`android-shell`'s `command`, `list_directory`'s `path`; sf-mcp's tools take the CLI's flag
names, such as `target-org` and `query`, and build `--<flag>=<value>`).

Until 0.10.28 the call path screened shell syntax only in a stdio spawn's argv
(`StdioCommandInjectionGuard`) and in a `SafeURL` argument, so a guarded tool whose
`repo: str` received `x; id` passed every gate. Any tool `@Airlock` guards is now screened
when its policy carries the guard, whether the tool builds the command line itself or
forwards its arguments to an MCP server that does.

## Shell arguments

Name the arguments a server splices into a command line:

```python
from agent_airlock import Airlock, SecurityPolicy, ToolArgSinkGuard

policy = SecurityPolicy(tool_arg_sink_guard=ToolArgSinkGuard(shell_args={"repo"}))


@Airlock(policy=policy)
def check_issue(repo: str, number: int) -> str:
    return f"checked {repo}#{number}"


check_issue(repo="owner/name", number=7)  # runs
check_issue(repo="owner/name; id", number=7)  # refused: block_reason "tool_arg_sink"
```

Shell syntax is the stdio guard's own default set, `DEFAULT_SHELL_METACHARS` (the guard
imports it, it does not keep a copy): `;`, `&`, `&&`, `||`, `|`, a newline, a carriage
return, a backtick, `$(`, `<(` and `>(`. Bare `<` and `>` are left out because
`pkg>=1.0` is benign; add them, or quotes, through `extra_metachars`.

### What is read

- **Names are the tool's parameter names**, or `**kwargs` keys. A positional argument is
  read under its parameter's name, and `*args` items under the `*args` name. A positional
  argument the call cannot bind to a parameter is screened whatever the names say, since
  which parameter it is cannot be known.
- **Everything an argument holds** is screened with it: strings nested in lists, tuples,
  sets and mappings, mapping keys included, and in the tool's own pydantic models and
  dataclasses, through the walk the other value gates use. A value counts by the argument
  it sits in, not by the nearest key: with `shell_args={"repo"}`, a `repo` key inside
  another argument is that argument's content.
- **Text in any shape**: `str` (a subclass is read as the characters it holds, whatever
  its `__str__` or `__contains__` says), bytes and memoryviews, a `UserString`, and path
  and URL objects. A number, a bool or `None` carries no text and passes. An object the
  host passed (a framework's run context) is not walked, as at the other value gates.
- **Input nested deeper than 32 levels, or a container that contains itself**, is refused
  as `deny_uninspectable` rather than skipped.

## Every string argument

`screen_all_str_args=True` screens every argument and opts free text out by name:

```python
from agent_airlock import Airlock, SecurityPolicy, ToolArgSinkGuard

guard = ToolArgSinkGuard(screen_all_str_args=True, free_text_args={"body"})


@Airlock(policy=SecurityPolicy(tool_arg_sink_guard=guard))
def comment_on_issue(repo: str, body: str) -> str:
    return f"commented on {repo}"


comment_on_issue(repo="owner/name", body="Looks good; merging.")  # runs
```

In this mode a `**kwargs` key is screened too: a server that turns keyword arguments into
`--name=value` flags puts the name on the command line (sf-mcp builds `--${key}=...`).
The refusal does not repeat the name.

Host-injected arguments are arguments like any other: a LangGraph state or a run config
passed to the tool is screened unless you name it in `free_text_args`.

## Installer arguments

An installer argument must be a bare version. Two patterns decide it, matched against the
whole value, ASCII only:

- **PEP 440**: the regular expression of PEP 440's Appendix B (`packaging`'s
  `VERSION_PATTERN`), case-insensitive. `1.4.4`, `2.0.0rc1`, `1!2.0.post1`, `1.0+local.7`.
  No specifier operator: `>=1.0` is a range, and `>` is redirection to a shell.
- **npm semver**: the expression semver.org suggests for SemVer 2.0.0, after an optional
  `^`, `~` or `=` and an optional `v`. `^1.30.0`, `~2.1.0-beta.1`. No `<` / `>` ranges,
  `x` wildcards or dist-tags (`latest`): resolve those on the host.

`None` passes, since no version reaches the installer. Anything else is refused, and the
refusal says which kind of thing it found:

| Value | Refused as |
|---|---|
| `1.4.4; touch x` | shell syntax (`;`) |
| `https://files.example.test/pkg-1.0-py3-none-any.whl` | a URL or package protocol (`https:`) |
| `git+https://github.com/example/pkg` | a VCS reference (`git+`) |
| `file:../evil`, `npm:evil-pkg@1.0.0` | a URL or package protocol (`file:`, `npm:`) |
| `../p`, `C:\pkgs\evil` | a path |
| `@scope/evil` | a package@version or scoped package name (`@`) |
| `1.0 other` | whitespace, which separates a second argument or package |
| `pkg[extra]` | package extras (`[`) |
| `evil-pkg`, `latest` | a package name or tag, not a version |
| `2` | not a string |

```python
from agent_airlock import Airlock, SecurityPolicy, ToolArgSinkGuard

guard = ToolArgSinkGuard(installer_args={"version"})


@Airlock(policy=SecurityPolicy(tool_arg_sink_guard=guard))
def set_functype_version(version: str) -> str:
    return f"installing functype@{version}"


set_functype_version(version="1.4.4")  # runs
set_functype_version(version="file:../evil")  # refused: not a bare version
```

## Modes and the refusal

In `deny` mode a finding is the usual blocked response: `block_reason` `"tool_arg_sink"`,
an `error`, `fix_hints` saying what to send instead, and `metadata` with the `argument`
(`"repo"`, `"repo[1]"`, `"target.repo"`), the `token` that tripped it and the `verdict`
(`deny_shell_metachar`, `deny_not_a_version` or `deny_uninspectable`). It names the
argument and the token, never the whole value; a mapping key is reported as "a mapping
key in argument 'repo'", since its path would spell it out. `on_blocked` hears it with
`violation_type` `"tool_arg_sink"`, and the log has `airlock_tool_arg_sink_block`.

In `warn` mode the finding is logged as `airlock_tool_arg_sink_warn_only` (function,
argument, token, verdict) and the call runs.

## Preset

`policy_presets.tool_arg_sink_defaults()` screens every string argument in `warn` mode,
so adopting it cannot break a host on day one:

```python
from agent_airlock import Airlock
from agent_airlock.policy_presets import tool_arg_sink_defaults

preset = tool_arg_sink_defaults(free_text_args={"body"}, installer_args={"version"})


@Airlock(policy=preset["policy"])
def comment_on_issue(repo: str, body: str) -> str:
    return f"commented on {repo}"
```

Read the log, name the free-text arguments it flags, then pass `mode="deny"`. To keep a
policy of your own, pass `preset["guard"]` as its `tool_arg_sink_guard`. The preset lists
the nine CVEs under `"cves"` and maps to OWASP MCP05, CWE-78 and CWE-829.

## Honest scope

- **It screens text, not how a server quotes it.** A server that passes argv without a
  shell is not exposed to these characters, and a value refused there was harmless. That
  is the reason for `warn` first and for `free_text_args`.
- **The default set leaves out quotes**, bare `<` and `>`, `$VAR` expansion and globs. A
  quote that only closes the server's own quoting injects arguments rather than commands:
  mcp-ffmpeg (CVE-2026-117568) took a closing double quote as well as `$()` and backticks,
  and the guard refuses those two by default but the quote only with
  `extra_metachars={'"'}`.
- **Option injection passes.** A value starting with `-` (CWE-88) is not shell syntax.
- **Only text is read.** A number or an object the host passed carries no text the model
  wrote.
