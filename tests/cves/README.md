# CVE regression suite

Every test in this directory reproduces a disclosed CVE's vulnerable
tool-call pattern and asserts that the corresponding agent-airlock
primitive blocks it.

The suite is a **second defence**. Upstream vendors have shipped fixes for
every CVE listed below; agent-airlock's job is to catch the same class of
bug when a vulnerable server is still running, or when a new tool ships
with the same shape.

## Layout

| CVE | File | Airlock fit | Primary source |
|---|---|---|---|
| CVE-2025-59536 | `test_cve_2025_59536_claude_code_hooks_rce.py` | partial (exfil leg) | [Check Point research, 2026](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/) |
| CVE-2025-68143 | `test_cve_2025_68143_git_init_path_traversal.py` | strong | [GHSA-5cgr-j3jf-jw3v](https://github.com/advisories/GHSA-5cgr-j3jf-jw3v) |
| CVE-2025-68144 | `test_cve_2025_68144_git_arg_injection.py` | strong | [GHSA-9xwc-hfwc-8w59](https://github.com/advisories/GHSA-9xwc-hfwc-8w59) |
| CVE-2025-68145 | `test_cve_2025_68145_git_repo_root_escape.py` | strong | [GHSA-j22h-9j4x-23w5](https://github.com/advisories/GHSA-j22h-9j4x-23w5) |
| CVE-2026-26118 | `test_cve_2026_26118_azure_mcp_ssrf.py` | strong (already in v0.4.1) | [MSRC](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26118) |
| CVE-2026-27825 | `test_cve_2026_27825_mcp_atlassian_arbitrary_write.py` | strong | [GitLab advisory](https://advisories.gitlab.com/pkg/pypi/mcp-atlassian/CVE-2026-27825/) |
| CVE-2026-27826 | `test_cve_2026_27826_mcp_atlassian_header_ssrf.py` | partial (if URL is a tool param) | [GitLab advisory](https://advisories.gitlab.com/pkg/pypi/mcp-atlassian/CVE-2026-27826/) |

## Out of scope (documented, not tested)

Two CVEs from the April 2026 corpus are **out of scope for runtime
middleware** and are not included in this suite. The table below
documents why; the operator must solve these at the transport or
server-framework layer.

| CVE | Vendor | Why out-of-scope |
|---|---|---|
| CVE-2026-33032 | nginx-ui ≤ 2.3.4 | Missing `AuthRequired()` middleware on `/mcp_message` endpoint. agent-airlock wraps the tool execution path but cannot add auth to HTTP endpoints that never call into it. |
| CVE-2026-23744 | `@mcpjam/inspector` ≤ 1.4.2 | Missing auth on `/api/mcp/connect` plus arbitrary-package install. Same class as CVE-2026-33032; not reachable from a tool decorator. |

## How to add a new CVE test

1. Verify the CVE resolves on NVD and that the vendor advisory is public.
   Add the retrieval date and URL to `docs/research-log.md`.
2. Identify the exact argument pattern that triggers the bug. If it's
   not an argument to a tool call, this is probably not the right place
   for the test — see "Out of scope" above.
3. Pick the narrowest airlock primitive that blocks the pattern
   (`SafePath` / `SafeURL` / `EndpointPolicy` / `Pydantic strict` /
   `@requires`). Write the assertion against that primitive.
4. Name the file `test_cve_YYYY_NNNNN_<short_description>.py` and include
   the CVE summary + advisory URL at the top of the module.
5. Update this README's table.
