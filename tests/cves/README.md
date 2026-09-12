# CVE regression suite

Every test in this directory reproduces a disclosed CVE's vulnerable
tool-call pattern and asserts that the corresponding agent-airlock
primitive blocks it.

The suite is a **second defence**. Upstream vendors have shipped fixes for
every CVE listed below; agent-airlock's job is to catch the same class of
bug when a vulnerable server is still running, or when a new tool ships
with the same shape.

## Layout

**This table is a curated selection, not the index.** It carries the rows worth
reading for the *shape* of a fit, and it has never covered every file — at the time
of writing it lists 9 of the 33 `test_cve_*.py` modules here. The complete,
machine-generated catalogue of every CVE in this suite is
[`docs/cves/index.md`](../../docs/cves/index.md), regenerated from these modules'
docstrings by `scripts/gen_cve_catalog.py` and gated in CI, so that file cannot
drift from the suite. This one can, which is why it says so.

| CVE | File | Airlock fit | Primary source |
|---|---|---|---|
| CVE-2025-59536 | `test_cve_2025_59536_claude_code_hooks_rce.py` | partial (exfil leg) | [Check Point research, 2026](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/) |
| CVE-2025-68143 | `test_cve_2025_68143_git_init_path_traversal.py` | strong | [GHSA-5cgr-j3jf-jw3v](https://github.com/advisories/GHSA-5cgr-j3jf-jw3v) |
| CVE-2025-68144 | `test_cve_2025_68144_git_arg_injection.py` | strong | [GHSA-9xwc-hfwc-8w59](https://github.com/advisories/GHSA-9xwc-hfwc-8w59) |
| CVE-2025-68145 | `test_cve_2025_68145_git_repo_root_escape.py` | strong | [GHSA-j22h-9j4x-23w5](https://github.com/advisories/GHSA-j22h-9j4x-23w5) |
| CVE-2026-26118 | `test_cve_2026_26118_azure_mcp_ssrf.py` | strong (already in v0.4.1) | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26118) |
| CVE-2026-27825 | `test_cve_2026_27825_mcp_atlassian_arbitrary_write.py` | strong | [GitLab advisory](https://advisories.gitlab.com/pkg/pypi/mcp-atlassian/CVE-2026-27825/) |
| CVE-2026-27826 | `test_cve_2026_27826_mcp_atlassian_header_ssrf.py` | partial (if URL is a tool param) | [GitLab advisory](https://advisories.gitlab.com/pkg/pypi/mcp-atlassian/CVE-2026-27826/) |
| CVE-2026-79748 | `test_cve_2026_79748_mcphub_spawn_config.py` | partial (spawn primitive only, not the missing authz) | [GHSA-mx89-jjx9-gjr8](https://github.com/samanhappy/mcphub/security/advisories/GHSA-mx89-jjx9-gjr8) |
| CVE-2026-19591 | `test_cve_2026_19591_codex_stop_parsing.py` | strong | [openai/codex#22643](https://github.com/openai/codex/pull/22643) |

## Out of scope as a *fix* (the defect itself is not blockable here)

These CVEs are **out of scope for runtime middleware**: agent-airlock cannot
close the defect. The operator must solve it at the transport or server-framework
layer. Out-of-scope is the expected outcome of triage, not an admission — see
[`docs/cve-triage.md`](../../docs/cve-triage.md) for the disposition vocabulary.

**Two of them are still tested**, and this section used to say they were not.
A `Tested?` column now records which, because "out of scope" and "untested" are
different claims and only the first one was ever true for all four rows. Where a
test exists it asserts an *adjacent* primitive — second defence on the same tool
inventory — never the missing check itself. That is the same `partial` framing
CVE-2026-79748 carries in the Layout table above.

| CVE | Vendor | Tested? | Why the defect itself is out-of-scope |
|---|---|---|---|
| CVE-2026-33032 | nginx-ui ≤ 2.3.4 | **yes, partial** — `test_cve_2026_33032_mcpwn.py` proves the `MCPProxyGuard` preset fires on the exact nginx-ui tool inventory and on an IP-allowlist-only bypass. It does **not** add the missing middleware. | Missing `AuthRequired()` middleware on `/mcp_message` endpoint. agent-airlock wraps the tool execution path but cannot add auth to HTTP endpoints that never call into it. |
| CVE-2026-23744 | `@mcpjam/inspector` ≤ 1.4.2 | **yes, partial** — `test_cve_2026_23744_mcpjam.py` covers the public-bind leg via `BindAddressGuard` / `mcpjam_cve_2026_23744_defaults`. It does **not** add auth to `/api/mcp/connect`. | Missing auth on `/api/mcp/connect` plus arbitrary-package install. Same class as CVE-2026-33032; not reachable from a tool decorator. |
| CVE-2026-18486 | IBM ContextForge MCP Gateway ≤ 1.0.7 | no | CWE-200. "Improper validation of jq filters" leaking `JWT_SECRET_KEY` and database credentials, which the attacker then uses to forge admin tokens. **No public source states the filter shape.** IBM's bulletin is the only disclosure (no GHSA, no upstream advisory), its remediation is "upgrade and rotate credentials", and the exposure is of the gateway's *own* secrets from inside its filter evaluator — not a value passing through a tool call. A guard here would have to invent the threat shape, and a guessed pattern is worse than none. |
| CVE-2026-85620 | Postgres MCP Pro 0.3.0 | no | CWE-863. `SafeSqlDriver`'s allowlist checks function names only on `FuncCall` AST nodes; a function in a `FROM` clause parses as `RangeFunction`, which is in `ALLOWED_NODE_TYPES` and never name-checked — so `SELECT * FROM pg_read_file('/etc/passwd')` returns the file while `SELECT pg_read_file(...)` is blocked. Blocking this needs a real SQL parser to walk the AST. The Pydantic-only core forbids that dependency, and a regex approximation would be **the same defect this CVE is**: a validator that covers some syntax positions and silently misses others. Solve it by upgrading postgres-mcp, or with a read-only DB role that lacks `pg_read_file`. |

**Why all three of CVE-2026-79748, CVE-2026-33032 and CVE-2026-23744 are
`partial`**, given all three are missing-authorization defects: the split is the
*primitive* the missing check hands the attacker, not the CWE. CVE-2026-79748
hands over a stdio spawn config (`command` / `args` / `env`) heading for
`child_process.spawn` — a shape this library already refuses, so its test asserts
the refusal directly. CVE-2026-33032 hands over an MCP message to an
unauthenticated endpoint and CVE-2026-23744 an arbitrary package install; neither
leaves an argument at a boundary agent-airlock sits on, so their tests assert the
next-best thing — that the destructive tool inventory and the public bind are
themselves refused — and say in their own docstrings that this is not the missing
auth check.

The same rule decides the two 2026-09 additions, and it cuts differently in
each. CVE-2026-85620 *does* leave an argument at the boundary — a SQL string —
but reading it correctly requires an AST the core cannot parse, and the
approximation would reproduce the CVE. CVE-2026-18486 leaves no argument shape
anyone has published. Both are refusals for stated, checkable reasons rather
than for lack of interest. The vocabulary is written down in
[`docs/cve-triage.md`](../../docs/cve-triage.md).

## How to add a new CVE test

1. Verify the CVE resolves on NVD and that the vendor advisory is public.
   Record the retrieval date and URL in the test's module docstring.
2. Identify the exact argument pattern that triggers the bug. If it's
   not an argument to a tool call, this is probably not the right place
   for the test — see "Out of scope" above.
3. Pick the narrowest airlock primitive that blocks the pattern
   (`SafePath` / `SafeURL` / `EndpointPolicy` / `Pydantic strict` /
   `@requires`). Write the assertion against that primitive.
4. Name the file `test_cve_YYYY_NNNNN_<short_description>.py` and include
   the CVE summary + advisory URL at the top of the module.
5. Update this README's table.
