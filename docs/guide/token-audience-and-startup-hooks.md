# Token audience and startup hooks

Two checks added in 0.10.27. Both run before `@Airlock` reads any argument, right after
the kill switch. The token-audience check changes nothing for a config that does not set
an audience; the startup-hook check is on by default as `"warn"` since 0.10.36:

| Setting | Default | What it checks |
|---|---|---|
| `expected_token_audience` | `None`, nothing checked | the `aud` claim of the OAuth access token behind each guarded call |
| `token_audience_mode` | `"warn"` | what a wrong or missing audience does once an audience is set |
| `startup_hook_check` | `"warn"` (`"off"` before 0.10.36) | executable `.pth` lines and `sitecustomize` / `usercustomize` in the running interpreter |
| `startup_hook_allowlist` | `{}` | `{file name: sha256}` of the startup hooks you know |

A mode is `"off"`, `"warn"` or `"deny"`; anything else raises `ValueError` when the config
is built, so a typo never reads as the default.

## Token audience

[CVE-2026-115413](https://github.com/awslabs/mcp/security/advisories/GHSA-4prq-p2x5-w9fh)
(High, CVSS 3.1 7.8, CWE-346): the AWS API MCP Server before 1.6.0, in OAuth mode, did
not validate the access token's audience. A token the same identity provider issued to
another application ran AWS operations with the server's own credentials. The fix in
1.6.0 also has the operator configure the expected audience. One identity provider
serving several applications is the ordinary case, which is why a token being valid is not
enough: it has to be valid *for this server*.

`agent_airlock.mcp_spec.oauth.validate_access_token_audience` has shipped for releases,
but until 0.10.27 nothing on the call path called it. Set the server's canonical resource
URI and every guarded call checks the token behind it:

```python
from agent_airlock import Airlock, AirlockConfig, AirlockContext

config = AirlockConfig(
    expected_token_audience="https://mcp.example.test",
    token_audience_mode="deny",
)


@Airlock(config=config)
def list_buckets() -> list[str]:
    return []


# The claims your server decoded from the bearer token after verifying its signature,
# expiry and issuer. Placeholder values.
claims = {"sub": "placeholder-subject", "aud": "https://mcp.example.test"}

with AirlockContext(metadata={"access_token_claims": claims}):
    list_buckets()  # runs; a token for any other audience is refused
```

### Where the claims come from

The host puts the decoded claims on the call's `AirlockContext` metadata under
`access_token_claims` (`agent_airlock.core.ACCESS_TOKEN_CLAIMS_KEY`): with
`with AirlockContext(metadata=...)` around the call, or on the context of the run wrapper
a framework passes as the tool's first positional argument. A run wrapper is an object
model JSON cannot have built: a framework's own object that is not a pydantic model, an
object whose context is an `AirlockContext`, or an instance of a plain host class (see
[Agent Identity](policy.md#agent-identity)). That is the channel the per-model-tier
budget reads its tags from, and the model cannot write it. Until 0.10.28 a tool's own
model or dataclass with a `context` field, passed first, was read as a run wrapper, so its
JSON could supply the claims. A tool argument named
`access_token_claims` is the model's, and is never read for this check: the call is judged
on the host's claims or, with none, refused under `deny` as carrying no claims.

The check reads the audience and nothing else. Verifying the token's signature, expiry and
issuer is the host's job, done before it hands the claims over; the check trusts the
mapping it is given.

### What matches

`aud` may be a string or a list of strings, and both sides are canonicalised
(`canonicalize_resource_uri`): scheme and host lowercased, a trailing slash dropped, and a
bare host with or without its root `/` treated as one resource (RFC 3986 §6.2.3). The
comparison also reads a scheme's default port (`:443` for https, `:80` for http) as no
port. An IPv6 literal keeps its brackets, so `https://[::1]:80` and `https://[::1:80]`
stay two resources. So a token for `["https://mcp.example.test/"]` or for
`https://mcp.example.test:443` matches `https://mcp.example.test`. A list may name other
audiences beside this server, a client id among them. Refused, under `deny`:

- an `aud` naming another resource, or a path this server does not have;
- a missing or empty `aud`;
- a list that holds anything but strings, even beside a matching one (RFC 7519 §4.1.3);
- a string `aud` that is not a URI, or is malformed (a port out of range, an unclosed
  IPv6 bracket); until 0.10.28 a malformed one raised out of the call under `warn` and
  `deny` alike;
- claims that are not a mapping, and no claims at all.

### Modes

| `token_audience_mode` | Wrong or missing audience |
|---|---|
| `"warn"` (default) | one structured `airlock_token_audience_warn_only` event per call, then the call runs |
| `"deny"` | the call is refused and `on_blocked` is called |
| `"off"` | not checked |

`warn` is the default so that turning the check on cannot break a deployment whose host
does not attach claims yet: set the audience, read the warnings, then switch to `deny`.

A refusal is the usual blocked response: `block_reason` `"token_audience"`, an `error` and
`fix_hints` for the model, and `metadata.violation`, one of `no_claims`,
`claims_unreadable` or `audience_mismatch`. The audience the token named is in the
`on_blocked` reason and the log, not in the text the model reads.

The `policy_presets.token_audience_defaults(expected_audience=...)` preset returns the
same check as a `check(claims)` callable that raises `TokenAudienceError`, and an
`airlock_config` with `token_audience_mode="deny"` to pass to `@Airlock(config=...)`.

## Startup hooks

While the interpreter starts, CPython's `site` module runs two kinds of hook, before the
first line of your program and before `import agent_airlock`:

- a line of a `*.pth` file in a site directory that starts with `import` and a space or a
  tab is passed to `exec()` (every other line is a directory added to `sys.path`);
- a module named `sitecustomize`, then one named `usercustomize`, is imported when the
  import system finds one.

Either runs in every process that interpreter starts, so a compromised dependency that
drops a `.pth` file persists: its line runs before the program it rides in, every time.

**What this check cannot do.** These hooks run before any Python code of yours, this
library included, so the check cannot stop them running and cannot undo what they did. It
tells you the interpreter is not clean. Under `deny` it also keeps every tool guarded by a
config that sets it, credential-bearing ones included, from running in that interpreter;
a tool whose config turns the check off still runs. Scanning packages when
they are installed is not this library's job; use your dependency scanner for that.

The case it was made the default for: agent-framework 1.26.1 and 1.26.2 on PyPI were
malicious ([GHSA-764m-3ppc-5m73](https://github.com/advisories/GHSA-764m-3ppc-5m73),
OpenSSF MAL-2026-20101). Each wheel added a `.pth` file, `agent_framework_meta.pth` in
1.26.1 and `af_runtime_diag.pth` in 1.26.2, whose import line ran at every interpreter
start and read secret-named environment variables, cloud credentials and CI tokens. Any
agent host that installed it ran that before its own first line. A malware list helps only
once an advisory exists; the hook is on disk from the first install.

```python
from agent_airlock.runtime import check_startup_hooks

report = check_startup_hooks()
for finding in report.findings:
    print(finding.kind.value, finding.path, finding.sha256)
```

`check_startup_hooks()` walks `site.getsitepackages()`, `site.getusersitepackages()` and
every `sys.path` entry that is a directory. It lists each `*.pth` file holding an
executable line, and finds `sitecustomize` and `usercustomize` with
`importlib.util.find_spec`, which locates a module without running it. Each finding has a
`path`, a `kind` (`pth`, `sitecustomize`, `usercustomize`) and the `sha256` of its
content. A path-only `.pth` file is not a finding.

### Hooks every install has

Four kinds of hook are on most machines and are set apart as benign, in
`report.benign`, with `recognized` saying which. They do not make the report unclean and
are logged once per process at debug level (`airlock_startup_hook_recognized`). Each is
recognised by its content and where it sits, never by its file name alone:

| Hook | Recognised when |
|---|---|
| setuptools' `distutils-precedence.pth` | its content, stripped, is exactly a line setuptools has shipped (`SETUPTOOLS_DISTUTILS_PRECEDENCE_LINES`, read from every release from 49.3.0 to 84.2.1) |
| virtualenv's `_virtualenv.pth` | its content is `import _virtualenv` and `_virtualenv.py` is beside it |
| a setuptools editable install's `__editable__.<name>.pth` | every executable line is `import __editable___<name>_finder; __editable___<name>_finder.install()` and that finder module is beside it |
| `sitecustomize` / `usercustomize` | it sits directly in the interpreter's standard-library directory (Debian and Ubuntu ship one there) |

Two more conditions hold for all four, because a wheel could ship a file of the same name
and content together with a module of its own:

- the module the line imports must resolve on `sys.path` to the file beside the hook, so a
  same-named module found first elsewhere is not passed;
- no installed distribution's `RECORD` may claim the hook or that module, except the one
  that writes it: only setuptools for setuptools' hook, only an editable install (its
  `direct_url.json` says so) for an editable one, and nothing at all for virtualenv's and
  the interpreter's, which pip never installs. Outside a virtual environment a wheel's
  data files can reach the standard-library directory; its `RECORD` names them there.

Reading those file lists is what the check costs: one read of each installed
distribution's `RECORD`, once per process, and only when a hook looks benign.

### Known incidents

A hook whose file name a published advisory documents carries it: `finding.known_incident`
(and `known_incident` in `to_dict()`, so in `metadata.startup_hooks` of a refusal), and its
event is logged at error level. The table is `KNOWN_INCIDENT_HOOKS`:

| File name | Advisory |
|---|---|
| `agent_framework_meta.pth` | GHSA-764m-3ppc-5m73 (agent-framework 1.26.1) |
| `af_runtime_diag.pth` | GHSA-764m-3ppc-5m73 (agent-framework 1.26.2) |

A renamed copy is still a finding, just without the advisory id.

It reports a hook whether or not this interpreter's start-up ran it: `python -S`, a user
site the interpreter does not load, a `.pth` file `site` skips because it is hidden.
Another interpreter on the same machine may run it.

### Allowlist and modes

Beyond the four above, many environments carry hooks of their own. A virtualenv with this
repo's `[dev]` extras has coverage's `a1_coverage.pth`; a long-lived interpreter adds the
`-nspkg.pth` files of legacy namespace packages. Both are findings. List the ones you know
by file name and SHA-256. A known name whose content has changed is a
finding again, and a key that is a path or a value that is not a SHA-256 digest raises
`ValueError` rather than never matching. An entry pins the hook file's own bytes, not the
modules its `import` lines load: `distutils-precedence.pth` imports `_distutils_hack`, and a
change to that module is not a finding, because the check does not hash it:

```python
from agent_airlock import Airlock, AirlockConfig
from agent_airlock.runtime import check_startup_hooks

# Review each hook before you trust it: this copies whatever is there.
allowlist = {finding.name: finding.sha256 for finding in check_startup_hooks().findings}

config = AirlockConfig(startup_hook_check="deny", startup_hook_allowlist=allowlist)


@Airlock(config=config)
def read_secret() -> str:
    return "PLACEHOLDER"
```

| `startup_hook_check` | A hook that is neither benign nor allowlisted |
|---|---|
| `"warn"` (default since 0.10.36) | one structured `airlock_startup_hook_found` event per hook and one `RuntimeWarning` per process, then every call runs |
| `"deny"` | the same, and every call guarded by a config with `"deny"` is refused, naming the files |
| `"off"` (the default before 0.10.36) | nothing is walked |

The walk runs once per process, the first time a guarded call is admitted with the check
on; nothing is walked at import or when a function is decorated. Each hook is logged once,
not on every call. A hook added after that walk is not seen until the process restarts;
`check_startup_hooks()` itself walks every time it is called.

The `RuntimeWarning` is there for a script that configures no logging. Under `-W error`
(or `filterwarnings = ["error"]` in pytest), Python raises it instead: the first guarded
call in the process raises `RuntimeWarning` before its tool runs, and later calls run. A
test suite that treats warnings as errors and runs with coverage's `a1_coverage.pth`
installed meets that on its first guarded call; allowlist the hook, or set
`startup_hook_check="off"` for the tests.

A refusal has `block_reason` `"startup_hook"`. The `error` names the files; their full
paths and digests are in `metadata.startup_hooks` and the `on_blocked` reason.

## TOML

Both checks read from `[airlock]` in `AirlockConfig.from_toml()`:

```toml
[airlock]
expected_token_audience = "https://mcp.example.test"
token_audience_mode = "deny"
startup_hook_check = "warn"

[airlock.startup_hook_allowlist]
"distutils-precedence.pth" = "<the file's sha256, 64 hex characters>"
```

A mode is read case-insensitively. An unknown mode, a non-string audience or an
allowlist that is not a table raises `ValueError` when the file is loaded.

See also: [Configuration](../getting-started/configuration.md),
[the `AirlockConfig` reference](../api/config.md).
