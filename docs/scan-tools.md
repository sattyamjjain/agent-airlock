# `airlock scan-tools` — a static contract / type-checker for MCP tool calls

`scan-tools` is a **static type-checker for AI tool declarations**. It answers one
question per tool:

> Does this tool's *declared contract* fit inside a least-privilege
> `SecurityPolicy` envelope?

It is deliberately **not** two things it is often confused with:

- **Not the runtime `@Airlock` decorator.** `@Airlock` validates and enforces at
  *call time* (ghost-arg stripping, strict Pydantic validation, policy checks,
  sandboxing). `scan-tools` runs *before* your agent ever loads the tools — on the
  declarations themselves — so you catch an over-broad or trust-widening contract in
  CI, not in production.
- **Not a content-signature tool-poisoning scanner.** [MCP-Scan (Invariant
  Labs)](https://github.com/invariantlabs-ai/mcp-scan) and [eSentire's
  MCP-Scanner](https://www.esentire.com/) scan tool metadata for known
  *poisoning signatures*. `scan-tools` checks the **type contract** against a
  policy. The two overlap only on the description-poisoning subset (which
  `scan-tools` covers by reusing the shipped Server-Card guard); the distinct value
  is the contract checks — argument surface, type constraints, capability caps —
  that a signature scanner does not perform.

Pydantic-only, zero-dep core.

## Install & invoke

```bash
pip install "agent-airlock>=0.8.42"

airlock-scan-tools ./tools/ --policy strict
python -m agent_airlock.cli.scan_tools ./mcp.json --output json
```

> The shipped console script is `airlock-scan-tools` (hyphenated), matching
> `airlock-explain` / `airlock-conformance`. The unified `airlock scan-tools`
> space-form lands with the deferred CLI-dispatcher PR (see `pyproject.toml`).

### Inputs

`scan-tools` accepts any of:

- a single `.json` tool definition (`{"name": …, "inputSchema": …}`),
- a server card / tool-list export (`{"tools": [ … ]}`),
- a bare list of tool defs (`[ … ]`),
- an MCP client config with **inlined** tool schemas
  (`{"mcpServers": {"srv": {"command": …, "tools": [ … ]}}}`),
- a **directory** of any of the above (known config names — `mcp.json`,
  `claude_desktop_config.json`, `.mcp.json` — are loaded first, then any `*.json`).

A config that only registers server *commands* with no inlined tool schemas yields
zero tools to check — there is nothing to statically type-check, and the loader says
so rather than inventing schemas.

## Grades and checks

Each tool is graded **pass / warn / fail**. The run's exit code is the worst grade.

| Code | Grade | What it means |
| --- | --- | --- |
| `SCAN001` | fail | The tool is denied / not allow-listed by the least-privilege policy (`SecurityPolicy.check_tool_allowed`). |
| `SCAN002` | fail | The tool description carries injected instructions (Server-Card trust boundary). Reuses the shipped `mcp_spec_2026_07` guard. |
| `SCAN003` | fail | A **destructive/mutating** tool declares an open argument surface (`additionalProperties` not `false`) — a ghost/hallucinated-argument vector into a high-blast-radius op. |
| `SCAN004` | warn | A non-destructive tool declares an open argument surface. |
| `SCAN005` | warn | A property has no type constraint, or a sensitive string arg (`path`/`url`/`command`/…) has no `enum`/`pattern`/`format`/`maxLength`. |
| `SCAN006` | fail | The tool's inferred capability is **denied or not granted** by the policy's `CapabilityPolicy`. |
| `SCAN007` | warn | The tool needs a sandbox-gated capability; the policy allows it only under sandbox execution. |
| `SCAN008` | warn | A declared OAuth `issuer` is malformed (SEP-2468 / RFC 9207 companion; the live `iss` check is a runtime concern). |

**Capability inference** (most authoritative first): an explicit `capabilities`
list of `Capability` member names → MCP `annotations`
(`destructiveHint` / `readOnlyHint` / `openWorldHint`, real MCP-spec fields) → a
coarse tool-name heuristic (documented as a heuristic).

## Policies

`--policy` maps 1:1 to a **shipped** `SecurityPolicy` constant — no invented policy:

| `--policy` | Constant | Behaviour |
| --- | --- | --- |
| `permissive` | `PERMISSIVE_POLICY` | Allow all; only contract / type / trust checks bite. |
| `read-only` | `READ_ONLY_POLICY` | `read_*`/`get_*`/`list_*` allowed; `write_*`/`delete_*` denied (SCAN001). |
| `strict` *(default)* | `STRICT_POLICY` | STRICT capability caps: `PROCESS_SHELL`/`FILESYSTEM_DELETE` denied, write not granted, DANGEROUS requires sandbox (SCAN006/SCAN007). |
| `deny-by-default` | `CAMOUFLAGE_RESISTANT_POLICY` | Empty allow-list + `default_deny`: every tool must be opted in by name (maximal posture). |

## Exit codes (CI)

- `0` — all tools pass.
- `1` — warnings only (under-specified contracts).
- `2` — at least one failure.

### CI example

```yaml
# .github/workflows/mcp-contract.yml
name: mcp-tool-contract
on: [pull_request]
jobs:
  scan-tools:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install "agent-airlock>=0.8.42"
      # Fail the build on any contract FAIL (exit 2). Drop `|| [ $? -eq 1 ]`
      # to also fail on warnings.
      - run: airlock-scan-tools --policy strict ./tools/
```

## Coverage — measured, reported as-is

`python -m benchmarks.scantools_mcptox` runs `scan-tools` over fixtures
reconstructed from the tool-poisoning technique in
[**MCPTox** (arXiv:2508.14925)](https://arxiv.org/abs/2508.14925) and reports:

- **69.2% static contract-checking coverage** of the injection-shaped descriptions,
- **100% precision** (no false positives on clean descriptions).

This is a *static* coverage number on labeled fixtures — **not** MCPTox's
model-in-the-loop Attack Success Rate (up to 72% across 1,312 cases on 45 live
servers), which is a property of agents, not of a static checker. The
`declarative_side_effect` fixtures (a malicious side effect stated with no
imperative marker) are honest misses, which is why coverage is 69.2%, not 100%. See
[`benchmarks/scantools_mcptox/RESULTS.md`](../benchmarks/scantools_mcptox/RESULTS.md).

## Programmatic use

```python
from agent_airlock.scan import scan_tools, resolve_policy, load_tool_defs

loaded = load_tool_defs("./tools/")
report = scan_tools(loaded.tools, resolve_policy("strict"), policy_name="strict")
print(report.exit_code)                 # 0 / 1 / 2
for result in report.failed:
    print(result.tool_name, [v.code for v in result.violations])
```
