# Code-sandbox host-bridge guard (CVE-2026-120338, v0.10.31+)

`agent_airlock.mcp_spec.code_sandbox_bridge_guard.CodeSandboxBridgeGuard` refuses a
tool-call argument that reaches out of a code sandbox to the host runtime, before the
string is handed to the interpreter.

## Why

[CVE-2026-120338][nvd] (CNA JFrog, CVSS 3.1 10.0, CWE-94/269/693): a generative-UI tool
ran caller-supplied Python inside a Pyodide (CPython-on-WASM) runtime hosted in a Deno
subprocess. The subprocess held read, write and network permission, and the runner left the
Deno API reachable on the JavaScript global object, so the sandboxed Python reached the host
through Pyodide's `js` proxy and read and wrote files as the server user — persisting by
writing a `.pth` into the server virtualenv. The remote path is an MCP tool
(`generate_prefab_ui`) that forwards its `code` argument into the sandbox; on an
unauthenticated server any client can call it. Fixed upstream by revoking the host
permissions before accepting code.

The class is not one product's: any code-execution tool whose sandbox leaves a host bridge
reachable is exposed.

## What it matches

Any string argument, at any depth (mappings, lists, tuples, sets; `bytes` decoded strictly):

- **Pyodide-to-JS bridge**: `from js import`, `import js`, `pyodide.ffi`, `pyodide.code`,
  `js.Deno`.
- **Deno host API**: `Deno.` followed by `writeTextFile`, `writeFile`, `readTextFile`,
  `readFile`, `open`, `remove`, `mkdir`, `Command`, `run`, `env`, `connect`, `listen`.
- **Node bridge**: `process.binding(`, `require("child_process")`, `import("child_process")`,
  `node:child_process`.
- Operator-supplied `extra_bridges` (each matched as a literal substring).

Input the guard cannot fully read — nesting past 32 levels, a container holding itself,
bytes that are not UTF-8 — is refused (`DENY_UNINSPECTABLE`), not skipped.

## Quickstart

```python
from agent_airlock import CodeSandboxBridgeGuard, CodeSandboxBridgeVerdict

guard = CodeSandboxBridgeGuard()
decision = guard.evaluate({"code": "import js\njs.Deno.readTextFile('/etc/passwd')"})
# decision.allowed is False
# decision.verdict is CodeSandboxBridgeVerdict.DENY_BRIDGE
# decision.matched_primitive == "js.Deno"
```

## Companion preset

`agent_airlock.policy_presets.code_sandbox_bridge_defaults()` returns the guard scoped to
the code-execution tool class (`generate_prefab_ui`, `run_python`, `execute_python`,
`execute_code`, `code_interpreter`, `run_code`). Every bridge group denies: legitimate code
sent to a generative-UI tool is Python and UI components only, so a `js` import in that
argument is an escape, not a feature. The preset's `recommended_config` is
`{"startup_hook_check": "warn"}`.

## Honest scope

A syntax-shape screen, the second defence at the argument seam. It catches the disclosed
class and the obvious spellings. It does **not** catch a bridge assembled at run time inside
the sandbox (a name built from pieces, a blob decoded and executed): a string it cannot see
through is a string it cannot screen. The real fix is to upgrade the sandbox runtime so the
host API is unreachable and its permissions are revoked before untrusted code runs — how
CVE-2026-120338 was fixed upstream. Pair this guard with:

- `AirlockConfig(startup_hook_check="warn")` on any process that hosts a code-execution
  tool, so a persistence file written through another path is caught at the next start; and
- the default [`SafePath`](../api/airlock.md) deny list, which refuses `.pth` writes into
  site directories and `sitecustomize.py` / `usercustomize.py`.

Related: [`EvalRCEGuard`](eval-rce-cve-2026-44717.md) screens the same argument seam for
bare Python eval-family sinks.

[nvd]: https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-120338
