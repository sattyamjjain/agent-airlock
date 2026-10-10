# CVE regression suite

Every test in this directory reproduces a disclosed CVE's vulnerable
tool-call pattern and asserts that the corresponding agent-airlock
primitive blocks it. A CVE that is in scope and not refused yet is held as a
strict `xfail` instead, which fails the build the day a primitive starts
refusing it; CVE-2026-102911 was one until 0.10.22.

The suite is a **second defence**: agent-airlock's job is to catch the same
class of bug when a vulnerable server is still running, or when a new tool
ships with the same shape. Most CVEs the suite tests have an upstream fix;
where none existed when a test was added, its module docstring says so, and
for that CVE the second defence is the only one there is. CVE-2026-79538
(MetaMCP) is one.

## Layout

**This table is a curated selection, not the index.** It carries the rows worth
reading for the *shape* of a fit, and it has never covered every file: it lists a
minority of the `test_cve_*.py` modules here (`ls tests/cves/test_cve_*.py | wc -l`
counts them). The complete,
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
| CVE-2026-102911 | `test_cve_2026_102911_pi_llm_wiki_url.py` | partial (refuses every payload that runs a command; `$NAME` expansion inside the quotes is URL syntax and passes) | [zosmaai/pi-llm-wiki#185](https://github.com/zosmaai/pi-llm-wiki/issues/185) |
| CVE-2026-79538 | `test_cve_2026_79538_metamcp_stdio_proxy.py` | partial (spawn primitive only, not the missing authz; no fixed release yet) | [Traceforce advisory](https://www.traceforce.ai/security-advisories/cve-2026-79538) |
| CVE-2026-19591 | `test_cve_2026_19591_codex_stop_parsing.py` | strong | [openai/codex#22643](https://github.com/openai/codex/pull/22643) |
| CVE-2026-19753 | `test_cve_2026_19753_rdf_explorer_ssrf.py` | strong | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-19753) |
| CVE-2026-75062 | `test_cve_2026_75062_langfun_eval.py` | partial (payload shape only; langfun evaluates internally) | [google/langfun#725](https://github.com/google/langfun/issues/725) |
| CVE-2026-78575 | `test_cve_2026_78575_langflow_mcp_stdio.py` | partial (spawn primitive; needs BOTH stdio guards) | [IBM 7286666](https://www.ibm.com/support/pages/node/7286666) |
| CVE-2026-90898 | `test_cve_2026_90898_bifrost_stdio_registration.py` | partial (spawn primitive only, not the missing auth) | [maximhq/bifrost#6757](https://github.com/maximhq/bifrost/pull/6757) |
| CVE-2026-57124 | `test_cve_2026_57124_praisonai_mcp_connect.py` | partial (spawn primitive only, not the missing auth) | [GHSA-p75f-6fp4-p57w](https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-p75f-6fp4-p57w) |
| CVE-2026-53710 | `test_cve_2026_53710_contextforge_sandbox_getattr.py` | partial (eval-sink primitive only, not the missing auth and not the RestrictedPython policy) | [GHSA-xm98-3vcf-fph7](https://github.com/advisories/GHSA-xm98-3vcf-fph7) |
| CVE-2026-77521 | `test_cve_2026_77521_maxkb_sandbox_shell.py` | partial (metachar primitive only, not the exposed tool or the missing approval gate) | [GHSA-f36j-f34j-h3rx](https://github.com/1Panel-dev/MaxKB/security/advisories/GHSA-f36j-f34j-h3rx) |
| CVE-2026-105697 | `test_cve_2026_105697_langflow_stdio_spawn.py` | partial (spawn primitive only, not the settings-endpoint authz) | [GHSA-w794-rj3p-xv45](https://github.com/langflow-ai/langflow/security/advisories/GHSA-w794-rj3p-xv45) |
| CVE-2026-105740 | `test_cve_2026_105740_langflow_stdio_env.py` | partial (env-injection primitive only, not the authenticated-add authz) | [GHSA-7w94-79vh-5mr2](https://github.com/langflow-ai/langflow/security/advisories/GHSA-7w94-79vh-5mr2) |
| CVE-2026-105788 | `test_cve_2026_105788_ufo_type_text.py` | partial (strict typing refuses the narrow `package_name`; free-text `text` is the callee's quoting) | [GHSA-6ppj-5886-4f26](https://github.com/microsoft/UFO/security/advisories/GHSA-6ppj-5886-4f26) |
| CVE-2026-105793 | `test_cve_2026_105793_ufo_press_key.py` | partial (strict typing refuses the narrow `key_code`; the reparsing adb shell is the callee's quoting) | [GHSA-5cjx-4375-4877](https://github.com/microsoft/UFO/security/advisories/GHSA-5cjx-4375-4877) |
| CVE-2026-105797 | `test_cve_2026_105797_simplechat_stdio_plugin.py` | partial (spawn primitive only, refused even with the `type` field omitted; not the route's authz ordering) | [GHSA-h4mw-qw8m-5x4j](https://github.com/microsoft/simplechat/security/advisories/GHSA-h4mw-qw8m-5x4j) |
| CVE-2026-104120 | `test_cve_2026_104120_mcp_fetch_ssrf.py` | strong (SSRF via the `url` argument; `SSRFEgressGuard` refuses metadata/loopback/private; no upstream fix when catalogued) | [modelcontextprotocol/servers#4492](https://github.com/modelcontextprotocol/servers/issues/4492) |

## Out of scope as a *fix* (the defect itself is not blockable here)

These CVEs are **out of scope for runtime middleware**: agent-airlock cannot
close the defect. The operator must solve it at the transport or server-framework
layer. Out-of-scope is the expected outcome of triage, not an admission — see
[`docs/cve-triage.md`](../../docs/cve-triage.md) for the disposition vocabulary.

**Two of them are still tested**, and this section used to say they were not.
A `Tested?` column now records which, because "out of scope" and "untested" are
different claims and only the first one was ever true for every row. Where a
test exists it asserts an *adjacent* primitive — second defence on the same tool
inventory — never the missing check itself. That is the same `partial` framing
CVE-2026-79748 carries in the Layout table above.

| CVE | Vendor | Tested? | Why the defect itself is out-of-scope |
|---|---|---|---|
| CVE-2026-33032 | nginx-ui ≤ 2.3.4 | **yes, partial** — `test_cve_2026_33032_mcpwn.py` proves the `MCPProxyGuard` preset fires on the exact nginx-ui tool inventory and on an IP-allowlist-only bypass. It does **not** add the missing middleware. | Missing `AuthRequired()` middleware on `/mcp_message` endpoint. agent-airlock wraps the tool execution path but cannot add auth to HTTP endpoints that never call into it. |
| CVE-2026-23744 | `@mcpjam/inspector` ≤ 1.4.2 | **yes, partial** — `test_cve_2026_23744_mcpjam.py` covers the public-bind leg via `BindAddressGuard` / `mcpjam_cve_2026_23744_defaults`. It does **not** add auth to `/api/mcp/connect`. | Missing auth on `/api/mcp/connect` plus arbitrary-package install. Same class as CVE-2026-33032; not reachable from a tool decorator. |
| CVE-2026-18486 | IBM ContextForge MCP Gateway ≤ 1.0.7 | no | CWE-200. "Improper validation of jq filters" leaking `JWT_SECRET_KEY` and database credentials, which the attacker then uses to forge admin tokens. **No public source states the filter shape.** IBM's bulletin is the only disclosure (no GHSA, no upstream advisory), its remediation is "upgrade and rotate credentials", and the exposure is of the gateway's *own* secrets from inside its filter evaluator — not a value passing through a tool call. A guard here would have to invent the threat shape, and a guessed pattern is worse than none. |
| CVE-2026-85787 | Amazon awslabs postgres-mcp-server &lt; 1.1.7 | no | CWE-184, "incomplete list of disallowed inputs" in the SQL validation component, letting crafted SQL modify data beyond the read-only scope. **Same class as CVE-2026-85620 below, and refused for the same stated reason**: separating a read from a write needs the SQL parsed, the Pydantic-only core forbids that dependency, and a regex approximation would reproduce the defect — a denylist that covers some syntax and silently misses the rest is what this CVE *is*. Solve it by upgrading to 1.1.7, or with a read-only DB role. |
| CVE-2026-85620 | Postgres MCP Pro 0.3.0 | no | CWE-863. `SafeSqlDriver`'s allowlist checks function names only on `FuncCall` AST nodes; a function in a `FROM` clause parses as `RangeFunction`, which is in `ALLOWED_NODE_TYPES` and never name-checked — so `SELECT * FROM pg_read_file('/etc/passwd')` returns the file while `SELECT pg_read_file(...)` is blocked. Blocking this needs a real SQL parser to walk the AST. The Pydantic-only core forbids that dependency, and a regex approximation would be **the same defect this CVE is**: a validator that covers some syntax positions and silently misses others. Solve it by upgrading postgres-mcp, or with a read-only DB role that lacks `pg_read_file`. |
| CVE-2026-90617 | GH05TCREW PentestAgent, rolling release (audited at `cf882da`) | no | CWE-77, CWE-78. NVD: *"This vulnerability affects the function run_task of the file interface/main.py of the component MCP HTTP Server. Performing a manipulation results in os command injection."* The classifier filed it because `run_task` really is a registered MCP tool taking `{task, target, scope}`, which is the seam this library sits on. **The argument does not carry the command.** `task` is a natural-language prompt; the shell string is authored downstream by the LLM and run by `LocalRuntime`'s `asyncio.create_subprocess_shell`, which is the product working as designed for a caller that got in. The defect is that the aiohttp `/mcp` routes carry no authentication and bind `0.0.0.0:8080` by default, so any network client can drive the agent at all. Upstream [PR #101](https://github.com/GH05TCREW/pentestagent/pull/101) fixes it with `Authorization: Bearer` middleware plus a `127.0.0.1` default, and changes no argument or schema. Neither an auth check on someone else's route nor a bind default is expressible at the tool-call boundary. (NVD names `interface/main.py`; at `cf882da` that file only bootstraps the registry, and `run_task` is defined in `pentestagent/mcp/server/mcp_tools.py`.) |
| CVE-2026-59971 | mysql-mcp-server &lt; 0.4.2 | no | CWE-306, CWE-346. NVD: *"setting MCP_TRANSPORT=sse causes src/mysql_mcp_server/server.py to construct SseServerTransport without security_settings or enable_dns_rebinding_protection, while the Starlette routes /, /sse, and /messages/ have no authentication and the service binds to 0.0.0.0 by default."* Every one of those is a transport-layer defect in another process. The remaining half — *"supply a query that reaches cursor.execute(query)"* — is **not** an argument-shaped defect, and that is the whole disposition: `execute_sql` declares no restriction on its `query`, so running caller-supplied SQL is the tool working as designed and nothing is smuggled past a contract. Contrast CVE-2026-53710 above, filed the same day and also CVSS 10.0, where `execute_code` *does* declare a restricted subset (`validate_code`, curated `safe_builtins`) that the payload escapes — that one is in scope for exactly that reason. agent-airlock ships the two primitives that would have prevented this (`validate_bind_address` for the `0.0.0.0` default, `McpOriginHostGuard` for the absent DNS-rebinding protection), but both are guards for a server **you** build with them; neither can be retrofitted onto mysql-mcp-server's Starlette app. Upstream 0.4.2 passes `TransportSecuritySettings(enable_dns_rebinding_protection=True)` and documents `127.0.0.1` as the recommended bind. This record is also why the watcher now skips sink words inside exonerating sentences: its sole sink match was `stdio`, in *"The default stdio transport is not affected."* |
| CVE-2026-51996 | geelen `mcp-remote` 0.1.16 through 0.1.38 | no | Filed under CWE-94; NVD has listed CWE-328 since. NVD: *"An issue in geelen mcp-remote 0.1.16 through 0.1.38 allows a remote attacker to execute arbitrary code via the src/lib/utils.ts and the getServerUrlHash function"*. `getServerUrlHash` runs inside mcp-remote, a client-side proxy, over its own launch configuration: the server URL from its command line plus `--resource` and headers. At 0.1.38 its whole body joins those values and returns `crypto.createHash('md5')` of them as a token-file prefix. No tool-call argument reaches it, and nothing in it executes anything. The only write-up NVD cites ([playb0t F-04](https://github.com/playb0t/mcp-remote-oauth-security/blob/v1.0.1/advisories/F-04-md5-token-isolation.md)) classifies it as a weak hash for a storage namespace, and its v1.0.1 correction says no token takeover or real-token access was demonstrated. |
| CVE-2026-55176 | Soft Machine ≤ 0.2.247 | no | CWE-863. NVD: *"two authentication helpers in /app/server.js — verifyContainerAuth() and authenticateWorkspaceHttp() — accept the global CONTAINER_SHARED_SECRET as a bearer token without verifying which workspace the caller belongs to."* The secret is one value for the whole Fly app, set on every container and reachable from the user-facing process environment inside each workspace, so the missing check is which workspace a caller belongs to, a question only Soft Machine's own server can answer. The advisory's proof of concept ([GHSA-63gh-vp9f-vxhj](https://github.com/Soft-Machine-io/security/security/advisories/GHSA-63gh-vp9f-vxhj)) is one `Authorization: Bearer $CONTAINER_SHARED_SECRET` header, sent from a shell inside the attacker's own workspace to a peer workspace's `/archive` and `/upload-file` routes. No tool call is involved and nothing in the request is malformed: the token is the real secret. The classifier filed it on the sink word `shell`, from *"reachable from any paying customer's shell"*, which says where the attacker sits, not what a tool argument reaches. NVD records no patch at publication, and the advisory names no patched version as of 2026-10-05. |
| CVE-2026-108263 | iflytek Astron Agent &lt; 1.1.2 | no | CWE-95 plus CWE-306, CWE-653, CWE-863, CWE-1392. NVD: *"the default workflow code-node path through /console-api/workflow/code/run and /workflow/v1/run selects LocalExecutor ... when CODE_EXEC_TYPE is not explicitly changed. LocalExecutor supplies complete Python builtins to dynamic code execution without the documented sandbox restrictions."* Four of the five CWEs are server-side: the wrong default executor (CWE-1392), missing isolation (CWE-653), and the cross-tenant authz bypass (CWE-306/863) that lets escaped code read other tenants' data with shared credentials. All are Astron's to fix, and [1.1.2](https://github.com/iflytek/astron-agent/security/advisories/GHSA-mh3w-4q3f-2fg5) does. The remaining CWE-95 half is a code-node **designed to run arbitrary Python**: once LocalExecutor is selected it runs with full builtins, so `import os; os.system(...)` is the tool working as designed, not a payload smuggled past a contract. agent-airlock's `EvalRCEGuard` refuses eval-family sinks (`eval(` / `exec(` / `__import__(` / `getattr(`), but a no-sandbox executor needs none of them — the plain `import` escape carries no sink, so a sink/regex approximation would be **the same defect this CVE is**: a check that covers some syntax and silently misses the rest (the CVE-2026-85620 / CVE-2026-59971 reasoning). Sandboxing untrusted code is agent-airlock's own execution layer (`sandbox_required=True`) for a tool **you** decorate, not something retrofittable onto Astron's core-workflow container. Solve it by upgrading to 1.1.2, or by setting `CODE_EXEC_TYPE` to the documented sandbox. |

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

The same rule decides CVE-2026-85620 and CVE-2026-18486, and it cuts
differently in each. CVE-2026-85620 *does* leave an argument at the boundary — a SQL string —
but reading it correctly requires an AST the core cannot parse, and the
approximation would reproduce the CVE. CVE-2026-18486 leaves no argument shape
anyone has published. Both are refusals for stated, checkable reasons rather
than for lack of interest.

CVE-2026-90617 is the `both` case `docs/cve-triage.md` describes, resolved
without a second-defence test. Its missing authentication is out of scope on the
same grounds as CVE-2026-33032 and CVE-2026-23744. What separates it from
CVE-2026-79748 is the primitive the missing check hands over: not a stdio spawn
config, but a sentence of English aimed at an LLM that is *designed* to run
commands. Refusing that at the argument boundary would mean classifying prose,
and on a penetration-testing agent the malicious task and the legitimate one are
the same string. No adjacent argument is left at a boundary this library sits on,
so there is no fixture to write. The vocabulary is written down in
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
