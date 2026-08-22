# CVE catalog

This page is auto-generated from the regression tests in
[`tests/cves/`](https://github.com/sattyamjjain/agent-airlock/tree/main/tests/cves).

Every CVE listed here has a corresponding test that reproduces the
vulnerable tool-call pattern and asserts an agent-airlock primitive blocks
it. The suite is a **second defence** — upstream vendors have shipped fixes
for every CVE below. Agent-airlock's job is to catch the same class of bug
when a vulnerable server is still running, or when a new tool ships with the
same shape.

See [`tests/cves/README.md`](https://github.com/sattyamjjain/agent-airlock/blob/main/tests/cves/README.md)
for the classification rules and a list of CVEs we deliberately chose NOT
to cover (transport-layer and web-framework bugs that sit outside the
airlock execution seam).

To regenerate this page:

```bash
python3 scripts/gen_cve_catalog.py --write
```

CI runs `python3 scripts/gen_cve_catalog.py --check` on every PR, so the
catalog and the tests stay in lockstep.


## Summary

| CVE | Component / title | CVSS | Airlock fit |
| --- | --- | --- | --- |
| [CVE-2025-59528](#cve-2025-59528) | Flowise CustomMCP RCE via JS ``Function()`` constructor | — | — |
| [CVE-2025-59536](#cve-2025-59536) | Claude Code hooks RCE + MCP consent bypass (exfil leg) | 8.7 (High) | Partial |
| [CVE-2025-68143](#cve-2025-68143) | Anthropic mcp-server-git `git_init` path traversal | 8.2 (High) | Strong |
| [CVE-2025-68144](#cve-2025-68144) | Anthropic mcp-server-git argument injection | 8.1 (High) | Strongest |
| [CVE-2025-68145](#cve-2025-68145) | mcp-server-git `--repository` root not enforced | 7.1 (High) | Strong |
| [CVE-2026-11393](#cve-2026-11393) | AgentCore CLI triple-quote codegen RCE | — | — |
| [CVE-2026-11624](#cve-2026-11624) | MCP HTTP-transport Origin/Host DNS-rebinding | 9.4 | — |
| [CVE-2026-21520](#cve-2026-21520) | Capsule ShareLeak / PipeLeak | — | — |
| [CVE-2026-23744](#cve-2026-23744) | MCPJam Inspector unauthenticated public bind | 9.8 | — |
| [CVE-2026-25874](#cve-2026-25874) | HuggingFace LeRobot pickle-deserialization RCE | 9.3 | — |
| [CVE-2026-26118](#cve-2026-26118) | Microsoft Azure MCP Server SSRF (IMDS token theft) | 8.8 (High) | Strong |
| [CVE-2026-27825](#cve-2026-27825) | mcp-atlassian arbitrary file write via download_path | 9.1 (Critical) | Strong |
| [CVE-2026-27826](#cve-2026-27826) | mcp-atlassian SSRF via `X-Atlassian-*-Url` headers | 7.5 (High, AV:A/PR:N/UI:N, C:H) | Partial |
| [CVE-2026-30615](#cve-2026-30615) | (Windsurf zero-click MCP config) — spawn-time config pin | — | — |
| [CVE-2026-30615](#cve-2026-30615) | Windsurf zero-click MCP config auto-load | — | — |
| [CVE-2026-30616](#cve-2026-30616) | MCP STDIO transport command-injection (Ox Security class) | 9.8 (Critical) | Strongest |
| [CVE-2026-32625](#cve-2026-32625) | (LibreChat MCP server-URL env-interpolation secret leak) | 9.6 | — |
| [CVE-2026-33032](#cve-2026-33032) | "MCPwn" — nginx-ui missing /mcp_message auth middleware | 9.8 | — |
| [CVE-2026-39884](#cve-2026-39884) | flux159/mcp-server-kubernetes argv injection | — | — |
| [CVE-2026-40933](#cve-2026-40933) | Flowise MCP-stdio adapter RCE regression | 9.9 | — |
| [CVE-2026-41349](#cve-2026-41349) | OpenClaw agentic consent-bypass | 8.8 | — |
| [CVE-2026-41361](#cve-2026-41361) | OpenClaw IPv6 SSRF guard bypass | 7.1 | — |
| [CVE-2026-42271](#cve-2026-42271) | CISA KEV regression fixture (LiteLLM MCP command injection) | 3.1 | — |
| [CVE-2026-42271](#cve-2026-42271) | (LiteLLM MCP-bridge subprocess command/args/env RCE) | — | — |
| [CVE-2026-44211](#cve-2026-44211) | Cline Kanban cross-origin WebSocket hijack | 9.7 | — |
| [CVE-2026-47390](#cve-2026-47390) | SSRF-protection bypass via alternate IP encodings | — | — |
| [CVE-2026-48782](#cve-2026-48782) | SafeURL IPv6-transition cloud-metadata SSRF bypass | — | — |
| [CVE-2026-5023](#cve-2026-5023) | codebase-mcp RepoMix OS command injection | — | — |
| [CVE-2026-53820](#cve-2026-53820) | OpenClaw exec-denylist bypass at MCP loopback spawn | 6.9 | — |
| [CVE-2026-6980](#cve-2026-6980) | GitPilot-MCP repo_path injection | — | — |
| [CVE-2026-75130](#cve-2026-75130) | Upstash Context7 "ContextCrush" MCP instruction injection | 9.0 (Critical, CVSS v3.1; NVD also records 6.4 Medium under v4.0) | Strongest |

## Details

### CVE-2025-59528

**Flowise CustomMCP RCE via JS ``Function()`` constructor**

- **Advisory:** [https://labs.cloudsecurityalliance.org/research/csa-research-note-flowise-mcp-rce-exploitation-20260409-csa/](https://labs.cloudsecurityalliance.org/research/csa-research-note-flowise-mcp-rce-exploitation-20260409-csa/)
- **Regression test:** [`tests/cves/test_cve_2025_59528_flowise.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/tests/cves/test_cve_2025_59528_flowise.py)

**Vulnerability**

Flowise's ``/api/v1/node-load-method/customMCP`` passed user-supplied
strings directly into JavaScript ``Function()`` and ``eval``. CVSS 10.0.
Patched in v3.0.6 (Sept 2025) but CSA documented active exploitation
in April 2026 — ~12-15K instances still exposed.
This regression codifies the offending token set (``Function(``,
``new Function``, ``eval(``, ``Deno.eval``, ``vm.runInNewContext``) so

<a id="cve-2025-59528"></a>

### CVE-2025-59536

**Claude Code hooks RCE + MCP consent bypass (exfil leg)**

- **CVSS:** 8.7 (High)
- **Airlock fit:** PARTIAL
- **NVD:** [https://nvd.nist.gov/vuln/detail/CVE-2025-59536](https://nvd.nist.gov/vuln/detail/CVE-2025-59536)
- **Advisory:** [https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- **Regression test:** [`tests/cves/test_cve_2025_59536_claude_code_hooks_rce.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/tests/cves/test_cve_2025_59536_claude_code_hooks_rce.py)

**Vulnerability**

Claude Code (< 1.0.111) executes repository-controlled configuration
— project `hooks`, registered MCP servers, and environment variables
including `ANTHROPIC_BASE_URL` — BEFORE showing the user the trust
dialog. Opening a malicious repository is therefore enough to
(1) run arbitrary shell commands via hooks, and (2) redirect the
agent's base URL to an attacker-controlled host that exfiltrates
the API key on the first request.

**Airlock mitigation**

The hook-execution leg runs on the Claude Code *client* before any
tool call exists, so runtime middleware has no seam. That half is
out-of-scope for agent-airlock and is fixed by upgrading Claude Code.

The exfiltration leg — sending the API key to an attacker-controlled
`ANTHROPIC_BASE_URL` — IS blockable. `EndpointPolicy` rejects any
hostname not in the caller's allow-list, and `SafeURL` applies the
same guard at the tool-signature level. If the agent's outbound
requests are routed through an airlock-wrapped HTTP tool, the attempt
to post to `https://evil.example.com/...` never leaves the process.

<a id="cve-2025-59536"></a>

### CVE-2025-68143

**Anthropic mcp-server-git `git_init` path traversal**

- **CVSS:** 8.2 (High)
- **Airlock fit:** strong
- **NVD:** [https://nvd.nist.gov/vuln/detail/CVE-2025-68143](https://nvd.nist.gov/vuln/detail/CVE-2025-68143)
- **Advisory:** [https://github.com/advisories/GHSA-5cgr-j3jf-jw3v](https://github.com/advisories/GHSA-5cgr-j3jf-jw3v)
- **Regression test:** [`tests/cves/test_cve_2025_68143_git_init_path_traversal.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/tests/cves/test_cve_2025_68143_git_init_path_traversal.py)

**Vulnerability**

The `git_init` tool of anthropics/mcp-server-git (< 2025.9.25 / 2025.12.18)
accepts an arbitrary filesystem path as its `repo_path` argument without
validating it against the configured repository root. An attacker who can
prompt-inject the agent can therefore initialise a .git directory anywhere
the server process can write, and — chained with a filesystem MCP — drop
a malicious .git/config that achieves RCE on the next `git` invocation.

**Airlock mitigation**

This is the canonical `SafePath` / `FilesystemPolicy` defense. The fix
upstream and the fix here are the same: reject any `repo_path` that
escapes the configured repo root via `os.path.commonpath()`.

We assert both:
1. `SafePathValidator` with the bare defaults rejects traversal strings
   (the pre-normalisation defense).
2. `FilesystemPolicy.validate_path` rejects paths outside the allowed
   root even when the path is syntactically clean (the post-resolution
   defense).

<a id="cve-2025-68143"></a>

### CVE-2025-68144

**Anthropic mcp-server-git argument injection**

- **CVSS:** 8.1 (High)
- **Airlock fit:** strongest
- **NVD:** [https://nvd.nist.gov/vuln/detail/CVE-2025-68144](https://nvd.nist.gov/vuln/detail/CVE-2025-68144)
- **Advisory:** [https://github.com/advisories/GHSA-9xwc-hfwc-8w59](https://github.com/advisories/GHSA-9xwc-hfwc-8w59)
- **Regression test:** [`tests/cves/test_cve_2025_68144_git_arg_injection.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/tests/cves/test_cve_2025_68144_git_arg_injection.py)

**Vulnerability**

`git_diff` / `git_checkout` in anthropics/mcp-server-git (< 2025.12.18)
pass user-controlled refs directly to the `git` CLI. A ref value
starting with a hyphen (for example `--output=/etc/profile.d/rce.sh`)
is interpreted by git as an OPTION rather than a ref, allowing
arbitrary file overwrite through the resulting git subprocess call.

**Airlock mitigation**

The ghost/strict argument validator is exactly the primitive for
"LLM passes a string that looks like a flag into a typed parameter."
A Pydantic-strict model with a custom validator that rejects any ref
beginning with `-` is a one-liner at the tool-decoration layer.

<a id="cve-2025-68144"></a>

### CVE-2025-68145

**mcp-server-git `--repository` root not enforced**

- **CVSS:** 7.1 (High)
- **Airlock fit:** strong
- **NVD:** [https://nvd.nist.gov/vuln/detail/CVE-2025-68145](https://nvd.nist.gov/vuln/detail/CVE-2025-68145)
- **Advisory:** [https://github.com/advisories/GHSA-j22h-9j4x-23w5](https://github.com/advisories/GHSA-j22h-9j4x-23w5)
- **Regression test:** [`tests/cves/test_cve_2025_68145_git_repo_root_escape.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/tests/cves/test_cve_2025_68145_git_repo_root_escape.py)

**Vulnerability**

When anthropics/mcp-server-git (< 2025.12.18) is started with the
`--repository` flag to declare an allowed repo root, the server
fails to verify on each subsequent tool call that the `repo_path`
argument stays inside that root. A crafted argument such as
`/var/lib/otheruser/.git` lets the server operate on any repo the
process user can read.

**Airlock mitigation**

`FilesystemPolicy` with an `allowed_roots` list is the canonical
mitigation. `validate_path` uses `os.path.commonpath()` (not string
prefix) so it catches the three common escape variants:

- absolute path outside the root
- relative path with `..` that would normalise outside the root
- a symlink that points outside the root

<a id="cve-2025-68145"></a>

### CVE-2026-11393

**AgentCore CLI triple-quote codegen RCE**

- **Advisory:** [https://www.thehackerwire.com/agentcore-cli-rce-via-triple-quote-neutralization-bypass-cve-2026-11393/](https://www.thehackerwire.com/agentcore-cli-rce-via-triple-quote-neutralization-bypass-cve-2026-11393/)
- **Regression test:** [`tests/cves/test_cve_2026_11393_codegen_delimiter.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/tests/cves/test_cve_2026_11393_codegen_delimiter.py)

**Vulnerability**

AWS AgentCore CLI < 0.14.2 (CVSS 9, CWE-94, published 2026-06-08)
generates Python source by interpolating a model-/user-controlled
``collaborationInstruction`` into a code string **without neutralising
triple-quote characters**. A crafted instruction containing ``"""``
closes the generated literal and injects statements that execute when
another account user imports the agent — RCE on the AgentCore Runtime

<a id="cve-2026-11393"></a>

### CVE-2026-11624

**MCP HTTP-transport Origin/Host DNS-rebinding**

- **CVSS:** 9.4
- **NVD:** [https://nvd.nist.gov/vuln/detail/CVE-2026-11624](https://nvd.nist.gov/vuln/detail/CVE-2026-11624)
- **Advisory:** [https://github.com/googleapis/mcp-toolbox/issues/3113](https://github.com/googleapis/mcp-toolbox/issues/3113)
- **Regression test:** [`tests/cves/test_cve_2026_11624_mcp_origin_host.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/tests/cves/test_cve_2026_11624_mcp_origin_host.py)

**Vulnerability**

Google MCP Toolbox for Databases < 0.25.0 (CWE-346 Origin Validation Error,
CVSS 9.4): the MCP server exposed an HTTP/SSE transport that did **not
validate the ``Origin`` (or ``Host``) header**, so a browser the developer
visits can DNS-rebind to ``127.0.0.1`` and script MCP tool calls at the local
server (file reads, command execution, database access). Fixed in 0.25.0 with
an ``--allowed-hosts`` flag alongside ``--allowed-origins``, warning when

<a id="cve-2026-11624"></a>

### CVE-2026-21520

**Capsule ShareLeak / PipeLeak**

- **Regression test:** [`tests/cves/test_cve_2026_21520_capsule_indirect_injection.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/tests/cves/test_cve_2026_21520_capsule_indirect_injection.py)

**Vulnerability**

Pins the deny-by-default + denied-exfil-sinks + reauth-on-untrusted
posture of :func:`capsule_indirect_injection_cve_2026_21520_defaults`
end-to-end:
- Eagerly-constructed defaults are byte-identical to a fresh factory call.
- Empty ``allowed_tools`` denies any read-side call (default_deny).
- Every canonical exfil sink in the bundle is denied by name AND by glob.

<a id="cve-2026-21520"></a>

### CVE-2026-23744

**MCPJam Inspector unauthenticated public bind**

- **CVSS:** 9.8
- **Advisory:** [https://github.com/advisories/GHSA-232v-j27c-5pp6](https://github.com/advisories/GHSA-232v-j27c-5pp6)
- **Regression test:** [`tests/cves/test_cve_2026_23744_mcpjam.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/tests/cves/test_cve_2026_23744_mcpjam.py)

**Vulnerability**

Primary source (cited per v0.5.1+ convention):
- GHSA-232v-j27c-5pp6 / CVE-2026-23744 (CVSS 9.8, fixed 1.4.3):
  <https://github.com/advisories/GHSA-232v-j27c-5pp6>

<a id="cve-2026-23744"></a>

### CVE-2026-25874

**HuggingFace LeRobot pickle-deserialization RCE**

- **CVSS:** 9.3
- **Advisory:** [https://www.sentinelone.com/vulnerability-database/cve-2026-25874/](https://www.sentinelone.com/vulnerability-database/cve-2026-25874/)
- **Regression test:** [`tests/cves/test_cve_2026_25874_lerobot.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/tests/cves/test_cve_2026_25874_lerobot.py)

**Vulnerability**

LeRobot's async-inference PolicyServer / robot-client call ``pickle.loads()``
on payloads received over an **unauthenticated, non-TLS** gRPC channel
(``SendObservations`` / ``SendPolicyInstructions`` / ``GetActions``). An
unauthenticated, network-reachable attacker reaches arbitrary OS command
execution by sending a crafted pickle blob (CVSS 9.3, published
2026-04-23, unpatched as of disclosure).

<a id="cve-2026-25874"></a>

### CVE-2026-26118

**Microsoft Azure MCP Server SSRF (IMDS token theft)**

- **CVSS:** 8.8 (High)
- **Airlock fit:** strong
- **NVD:** [https://nvd.nist.gov/vuln/detail/CVE-2026-26118](https://nvd.nist.gov/vuln/detail/CVE-2026-26118)
- **Advisory:** [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26118](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-26118)
- **Regression test:** [`tests/cves/test_cve_2026_26118_azure_mcp_ssrf.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/tests/cves/test_cve_2026_26118_azure_mcp_ssrf.py)

**Vulnerability**

Azure MCP Server Tools (< 2.0.0-beta.17) fetch URLs passed through
tool arguments without validating the destination. A crafted argument
of `http://169.254.169.254/metadata/identity/oauth2/token?...` causes
the server process to hit the Azure Instance Metadata Service and
return the managed-identity access token to the caller — trivially
escalating any prompt-injection bug into full Azure resource takeover.

**Airlock mitigation**

`validate_endpoint(...)` rejects:
- all four cloud-metadata hosts in `_METADATA_HOSTS`
  (169.254.169.254 / 253 / fd00:ec2::254 / metadata.google.internal),
- any hostname that resolves to a private / loopback / link-local IP
  when `allow_private_ips=False` (the default),
- any hostname matching a caller-supplied blocklist pattern.

<a id="cve-2026-26118"></a>

### CVE-2026-27825

**mcp-atlassian arbitrary file write via download_path**

- **CVSS:** 9.1 (Critical)
- **Airlock fit:** strong
- **NVD:** [https://nvd.nist.gov/vuln/detail/CVE-2026-27825](https://nvd.nist.gov/vuln/detail/CVE-2026-27825)
- **Advisory:** [https://advisories.gitlab.com/pkg/pypi/mcp-atlassian/CVE-2026-27825/](https://advisories.gitlab.com/pkg/pypi/mcp-atlassian/CVE-2026-27825/)
- **Write-up:** [https://pluto.security/blog/mcpwnfluence-cve-2026-27825-critical/](https://pluto.security/blog/mcpwnfluence-cve-2026-27825-critical/)
- **Regression test:** [`tests/cves/test_cve_2026_27825_mcp_atlassian_arbitrary_write.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/tests/cves/test_cve_2026_27825_mcp_atlassian_arbitrary_write.py)

**Vulnerability**

mcp-atlassian (< 0.17.0) exposes a `confluence_download_attachment`
tool with a `download_path` argument. The tool writes the downloaded
file to the provided path without boundary enforcement. An attacker
who can prompt-inject the argument can therefore overwrite
`~/.ssh/authorized_keys`, `~/.bashrc`, or any other file the server
process can reach — and on the exposed HTTP transport deployment
this requires no authentication.

**Airlock mitigation**

`SafePath` + `FilesystemPolicy.allowed_roots` is the textbook
mitigation. The upstream fix (in 0.17.0) introduces a
`validate_safe_path` function — agent-airlock has had this since
v0.3.0.

<a id="cve-2026-27825"></a>

### CVE-2026-27826

**mcp-atlassian SSRF via `X-Atlassian-*-Url` headers**

- **CVSS:** 7.5 (High, AV:A/PR:N/UI:N, C:H)
- **Airlock fit:** partial
- **NVD:** [https://nvd.nist.gov/vuln/detail/CVE-2026-27826](https://nvd.nist.gov/vuln/detail/CVE-2026-27826)
- **Advisory:** [https://advisories.gitlab.com/pkg/pypi/mcp-atlassian/CVE-2026-27826/](https://advisories.gitlab.com/pkg/pypi/mcp-atlassian/CVE-2026-27826/)
- **Regression test:** [`tests/cves/test_cve_2026_27826_mcp_atlassian_header_ssrf.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/tests/cves/test_cve_2026_27826_mcp_atlassian_header_ssrf.py)

**Vulnerability**

mcp-atlassian (< 0.17.0) uses unvalidated `X-Atlassian-Jira-Url` and
`X-Atlassian-Confluence-Url` request headers to decide where to send
upstream API calls. An attacker can redirect outbound requests to the
IMDS endpoint or to an internal host to steal credentials or
fingerprint the internal network.

**Airlock mitigation**

The vulnerability is at the HTTP-transport layer — headers aren't
tool-call arguments. Runtime middleware cannot validate a header on
an incoming request that never invokes a decorated tool.

BUT: when an MCP server is fronted by agent-airlock and the base
URL is surfaced as a tool parameter (the common operator pattern
these days — per-call URL selection instead of a static config),
the same `SafeURL` + `EndpointPolicy` primitives that block
CVE-2026-26118 block this too. That narrower case is what we
assert here.

For the transport-header path, operators should (a) upgrade
mcp-atlassian to ≥ 0.17.0 and (b) front their MCP server with an
HTTP reverse proxy that strips or validates these headers before
they reach application code.

<a id="cve-2026-27826"></a>

### CVE-2026-30615

**(Windsurf zero-click MCP config) — spawn-time config pin**

- **NVD:** [https://nvd.nist.gov/vuln/detail/CVE-2026-30615](https://nvd.nist.gov/vuln/detail/CVE-2026-30615)
- **Advisory:** [https://www.tenable.com/cve/CVE-2026-30615](https://www.tenable.com/cve/CVE-2026-30615)
- **Regression test:** [`tests/cves/test_cve_2026_30615_mcp_config_pin.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/tests/cves/test_cve_2026_30615_mcp_config_pin.py)

**Vulnerability**

Companion to ``test_cve_2026_30615_zero_click.py`` (which covers the
*config-file* diff guard). This suite covers the **spawn-time** half: the
``mcp_config_pin`` preset / :class:`McpConfigPinSet`, which fingerprints the
resolved STDIO spawn config at invocation time and **fails closed** (raises,
never warns) on an injected or mutated server — catching the zero-click
pattern even when the mutation never touched a watched config file.

<a id="cve-2026-30615"></a>

### CVE-2026-30615

**Windsurf zero-click MCP config auto-load**

- **NVD:** [https://nvd.nist.gov/vuln/detail/CVE-2026-30615](https://nvd.nist.gov/vuln/detail/CVE-2026-30615)
- **Advisory:** [https://www.tenable.com/cve/CVE-2026-30615](https://www.tenable.com/cve/CVE-2026-30615)
- **Regression test:** [`tests/cves/test_cve_2026_30615_zero_click.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/tests/cves/test_cve_2026_30615_zero_click.py)

**Vulnerability**

Primary source (cited per v0.5.1+ convention):
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-30615
- Tenable: https://www.tenable.com/cve/CVE-2026-30615

<a id="cve-2026-30615"></a>

### CVE-2026-30616

**MCP STDIO transport command-injection (Ox Security class)**

- **CVSS:** 9.8 (Critical)
- **Airlock fit:** strongest
- **NVD:** [https://nvd.nist.gov/vuln/detail/CVE-2026-30616](https://nvd.nist.gov/vuln/detail/CVE-2026-30616)
- **Advisory:** [https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem](https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem)
- **Write-up:** [https://www.theregister.com/2026/04/16/anthropic_mcp_design_flaw/](https://www.theregister.com/2026/04/16/anthropic_mcp_design_flaw/)
- **Regression test:** [`tests/cves/test_cve_2026_30616_mcp_stdio_rce.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/tests/cves/test_cve_2026_30616_mcp_stdio_rce.py)

**Vulnerability**

The MCP STDIO transport, implemented in the official Anthropic MCP
SDKs across Python, TypeScript, Java, and Rust, passes the
``command`` and ``args`` fields of a client's STDIO server entry
directly to a subprocess without validation, sanitisation, or
sandboxing. The subprocess is spawned BEFORE the MCP handshake
completes — so if the attacker controls the payload, the OS-level
command runs whether or not the "server" ever returns a valid
handshake. Ox catalogued four attack classes:

    1. Unauthenticated command injection via a poisoned
       ``mcp.json`` / ``claude_desktop_config.json`` / ``.cursor``
       entry.
    2. Authenticated command injection via a trusted-but-vulnerable
       MCP server that forwards user-controlled strings into a new
       STDIO invocation.
    3. Zero-click prompt-injection chains across Claude Code,
       Cursor, Gemini-CLI, Windsurf, and GitHub Copilot — the agent
       writes a config entry on the attacker's behalf.
    4. Config-file takeover — an attacker who can write to
       ``~/.cursor`` or the Claude Desktop config directory owns
       the machine on next launch.

Tenable has CVE-2026-30616 live against Jaaz 1.0.30 as one
instance of this class. Ox documents 30+ affected open-source
projects (LangChain-ChatChat, Agent Zero, LibreChat, MaxKB,
WeKnora, Flowise, MCPJam Inspector, and more), and estimates
~200,000 vulnerable server instances across the ecosystem.

**Airlock mitigation**

The root cause is "the STDIO transport runs arbitrary OS commands
with no policy layer in front of it." That is precisely the seam
agent-airlock was designed to fill.

Anthropic's public position (per The Register, 2026-04-16) is that
input sanitisation is the application author's responsibility and
that STDIO behaviour is "expected." Agent-airlock is the
Anthropic-side answer to that: a deny-by-default, in-process
middleware that sits between the tool call and the subprocess.

We assert:
1. ``SecurityPolicy`` with an explicit tool allow-list blocks any
   call to an out-of-list tool (stops attack class 1 at the
   configuration seam — if ``spawn_stdio_server`` or equivalent is
   not in the allow-list, the payload never reaches ``execve``).
2. ``UnknownArgsMode.BLOCK`` rejects ghost / LLM-invented arguments
   on a known tool (stops attack class 2, where the model was
   talked into inventing a malicious ``env`` or ``args`` field).
3. ``SafePath`` rejects a config-path traversal that would let the
   attacker write a poisoned entry into ``~/.cursor`` or Claude
   Desktop's config directory (stops attack class 4).

Attack class 3 (prompt-injection of the chat UI) is a
client-surface problem and out-of-scope for runtime middleware;
see ``docs/cves/index.md`` fit-matrix notes.

<a id="cve-2026-30616"></a>

### CVE-2026-32625

**(LibreChat MCP server-URL env-interpolation secret leak)**

- **CVSS:** 9.6
- **Advisory:** [https://github.com/danny-avila/LibreChat/security/advisories/GHSA-6vqg-rgpm-qvf9](https://github.com/danny-avila/LibreChat/security/advisories/GHSA-6vqg-rgpm-qvf9)
- **Regression test:** [`tests/cves/test_cve_2026_32625_mcp_env_interpolation.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/tests/cves/test_cve_2026_32625_mcp_env_interpolation.py)

**Vulnerability**

LibreChat ≤ 0.8.3 (CVSS 9.6, CWE-200, published 2026-06-02) resolves
``${VAR}`` placeholders in a user-supplied MCP server URL against the
host ``process.env`` during schema validation, so an authenticated user
exfiltrates server-side secrets (``JWT_SECRET`` / ``CREDS_KEY`` /
``MONGO_URI``) by embedding them in a URL that dials an attacker host.
Patched in 0.8.4-rc1.

<a id="cve-2026-32625"></a>

### CVE-2026-33032

**"MCPwn" — nginx-ui missing /mcp_message auth middleware**

- **CVSS:** 9.8
- **NVD:** [https://nvd.nist.gov/vuln/detail/CVE-2026-33032](https://nvd.nist.gov/vuln/detail/CVE-2026-33032)
- **Advisory:** [https://www.rapid7.com/blog/post/etr-cve-2026-33032-nginx-ui-missing-mcp-authentication/](https://www.rapid7.com/blog/post/etr-cve-2026-33032-nginx-ui-missing-mcp-authentication/)
- **Regression test:** [`tests/cves/test_cve_2026_33032_mcpwn.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/tests/cves/test_cve_2026_33032_mcpwn.py)

**Vulnerability**

letting unauthenticated clients invoke 12 destructive MCP tools.
CVSS 9.8, ~2,689 exposed instances, actively exploited in April 2026.

agent-airlock doesn't ship nginx-ui, but we're the canonical place for
the "would my MCPProxyGuard have caught a missing-auth on a destructive
tool?" question. This module proves the preset fires on the exact
nginx-ui tool inventory and on an IP-allowlist-only bypass attempt.

Primary sources
---------------
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-33032
- Rapid7 ETR (2026-04-15):
  https://www.rapid7.com/blog/post/etr-cve-2026-33032-nginx-ui-missing-mcp-authentication/

<a id="cve-2026-33032"></a>

### CVE-2026-39884

**flux159/mcp-server-kubernetes argv injection**

- **NVD:** [https://nvd.nist.gov/vuln/detail/CVE-2026-39884](https://nvd.nist.gov/vuln/detail/CVE-2026-39884)
- **Advisory:** [https://www.sentinelone.com/vulnerability-database/cve-2026-39884/](https://www.sentinelone.com/vulnerability-database/cve-2026-39884/)
- **Regression test:** [`tests/cves/test_cve_2026_39884_kubectl.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/tests/cves/test_cve_2026_39884_kubectl.py)

**Vulnerability**

Primary source (cited per v0.5.1+ convention):
- <https://www.sentinelone.com/vulnerability-database/cve-2026-39884/> (2026-04-14, fixed in 3.5.0)
- <https://nvd.nist.gov/vuln/detail/CVE-2026-39884>

<a id="cve-2026-39884"></a>

### CVE-2026-40933

**Flowise MCP-stdio adapter RCE regression**

- **CVSS:** 9.9
- **Advisory:** [https://advisories.gitlab.com/npm/flowise-components/CVE-2026-40933/](https://advisories.gitlab.com/npm/flowise-components/CVE-2026-40933/)
- **Regression test:** [`tests/cves/test_cve_2026_40933_flowise_mcp_stdio.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/tests/cves/test_cve_2026_40933_flowise_mcp_stdio.py)

**Vulnerability**

Flowise <= 3.0.x lets an authenticated user define a CustomMCP server
with the **stdio** transport, supplying an arbitrary ``command`` +
``args`` that Flowise serialises straight into a child-process spawn on
the server — no sandbox, no argv sanitisation. CVSS 9.9. Fixed upstream
in Flowise 3.1.0.
This regression pins the agent-airlock-side control:

<a id="cve-2026-40933"></a>

### CVE-2026-41349

**OpenClaw agentic consent-bypass**

- **CVSS:** 8.8
- **Advisory:** [https://www.thehackerwire.com/vulnerability/CVE-2026-41349/](https://www.thehackerwire.com/vulnerability/CVE-2026-41349/)
- **Regression test:** [`tests/cves/test_cve_2026_41349_consent_bypass.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/tests/cves/test_cve_2026_41349_consent_bypass.py)

**Vulnerability**

Primary source (cited per v0.5.1+ convention):
- <https://www.thehackerwire.com/vulnerability/CVE-2026-41349/> (CVSS 8.8,
  disclosed 2026-04-23).
The fix surface is :meth:`SecurityPolicy.freeze` +
:meth:`SecurityPolicy.verify_frozen`, plus the
``openclaw_cve_2026_41349_defaults()`` preset that returns a frozen

<a id="cve-2026-41349"></a>

### CVE-2026-41361

**OpenClaw IPv6 SSRF guard bypass**

- **CVSS:** 7.1
- **Advisory:** [https://www.redpacketsecurity.com/cve-alert-cve-2026-41361-openclaw-openclaw/](https://www.redpacketsecurity.com/cve-alert-cve-2026-41361-openclaw-openclaw/)
- **Regression test:** [`tests/cves/test_cve_2026_41361_ipv6_ssrf.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/tests/cves/test_cve_2026_41361_ipv6_ssrf.py)

**Vulnerability**

Primary source (cited per v0.5.1+ convention):
- <https://www.redpacketsecurity.com/cve-alert-cve-2026-41361-openclaw-openclaw/>
  (CVSS 7.1, disclosed 2026-04-23).
The bypass was that OpenClaw's IPv6 guard covered only the four
canonical ranges (``::/128``, ``::1/128``, ``fe80::/10``, ``fc00::/7``)
and left IPv4-mapped / NAT64 / 6to4 / documentation ranges routable.

<a id="cve-2026-41361"></a>

### CVE-2026-42271

**CISA KEV regression fixture (LiteLLM MCP command injection)**

- **CVSS:** 3.1
- **NVD:** [https://nvd.nist.gov/vuln/detail/CVE-2026-42271,](https://nvd.nist.gov/vuln/detail/CVE-2026-42271,)
- **Regression test:** [`tests/cves/test_cve_2026_42271_kev_regression.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/tests/cves/test_cve_2026_42271_kev_regression.py)

**Vulnerability**

This complements ``test_cve_2026_42271_mcp_subprocess_arg.py`` (which unit-tests
the guard's internals) by reproducing the **actual HTTP request-body shape** of
the two affected LiteLLM endpoints and proving the deny-by-default preset blocks
it end-to-end. It is a credibility-proof of *existing* coverage of an
actively-exploited KEV CVE — not a new guard.
NVD verbatim (https://nvd.nist.gov/vuln/detail/CVE-2026-42271, retrieved

<a id="cve-2026-42271"></a>

### CVE-2026-42271

**(LiteLLM MCP-bridge subprocess command/args/env RCE)**

- **Advisory:** [https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-42271](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-42271)
- **Regression test:** [`tests/cves/test_cve_2026_42271_mcp_subprocess_arg.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/tests/cves/test_cve_2026_42271_mcp_subprocess_arg.py)

**Vulnerability**

LiteLLM 1.74.2–1.83.6 (CVSS v3.1 **8.8 High** / v4.0 **8.7 High**, CWE-78,
**CISA KEV, added 2026-06-08**, actively
exploited): the MCP server preview endpoints
``POST /mcp-rest/test/connection`` and ``POST /mcp-rest/test/tools/list``
accepted a full MCP server config (stdio-transport ``command`` / ``args``
/ ``env``) in the request body and spawned it as a subprocess on the

<a id="cve-2026-42271"></a>

### CVE-2026-44211

**Cline Kanban cross-origin WebSocket hijack**

- **CVSS:** 9.7
- **Advisory:** [https://advisories.gitlab.com/npm/cline/CVE-2026-44211/](https://advisories.gitlab.com/npm/cline/CVE-2026-44211/)
- **Regression test:** [`tests/cves/test_cve_2026_44211_ws_origin.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/tests/cves/test_cve_2026_44211_ws_origin.py)

**Vulnerability**

Cline Kanban server (npm ``kanban`` < 2.13.0, CVSS 9.7, CWE-1385 + CWE-306,
published 2026-06): the agent's control WebSocket server on
``127.0.0.1:3484`` accepts every upgrade **without validating the ``Origin``
header**. Because browsers do not apply same-origin/CORS to ``ws://``, any
website the developer visits can open a WebSocket to the loopback control
server and drive the agent (leak workspace data, inject prompts → RCE, kill

<a id="cve-2026-44211"></a>

### CVE-2026-47390

**SSRF-protection bypass via alternate IP encodings**

- **Advisory:** [https://www.cve.org/CVERecord?id=CVE-2026-47390](https://www.cve.org/CVERecord?id=CVE-2026-47390)
- **Regression test:** [`tests/cves/test_cve_2026_47390_ssrf_egress.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/tests/cves/test_cve_2026_47390_ssrf_egress.py)

**Vulnerability**

CWE-918: an agent egress filter that validates the *literal hostname string*
of an outbound URL — rather than the **resolved IP** — is bypassed by encoding
a loopback / link-local / cloud-metadata address in a form ``ipaddress``
rejects but ``socket.inet_aton`` (and the HTTP client / kernel) resolves
straight back to an internal address, or by DNS rebinding.
This suite pins, per the brief:

<a id="cve-2026-47390"></a>

### CVE-2026-48782

**SafeURL IPv6-transition cloud-metadata SSRF bypass**

- **Advisory:** [https://github.com/pydantic/pydantic-ai/security/advisories/GHSA-cg7w-rg45-pc59](https://github.com/pydantic/pydantic-ai/security/advisories/GHSA-cg7w-rg45-pc59)
- **Regression test:** [`tests/cves/test_cve_2026_48782_safeurl_ipv6_metadata.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/tests/cves/test_cve_2026_48782_safeurl_ipv6_metadata.py)

**Vulnerability**

pydantic-ai 1.56.0–1.101.0 / 2.0.0b1–b2 (CWE-918 SSRF): the cloud-metadata
blocklist compared the *hostname string*, so encoding the metadata IP
``169.254.169.254`` in an IPv6-transition form (IPv4-mapped, IPv4-compatible,
6to4, Teredo) or as a decimal/octal/hex integer slipped past it while the HTTP
client still connected to the metadata endpoint — exposing cloud IAM
credentials. This is an **incomplete-fix** follow-up to CVE-2026-46678 (which

<a id="cve-2026-48782"></a>

### CVE-2026-5023

**codebase-mcp RepoMix OS command injection**

- **Advisory:** [https://www.sentinelone.com/vulnerability-database/cve-2026-5023/](https://www.sentinelone.com/vulnerability-database/cve-2026-5023/)
- **Regression test:** [`tests/cves/test_cve_2026_5023_codebase_mcp.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/tests/cves/test_cve_2026_5023_codebase_mcp.py)

**Vulnerability**

Primary source (cited per v0.5.1+ convention):
- <https://www.sentinelone.com/vulnerability-database/cve-2026-5023/>
  (unpatched upstream as of 2026-04-24).
The package ``codebase-mcp`` wrapped the RepoMix CLI and shelled out
with user-controlled paths across four handlers. This preset refuses
to run those handlers unless the caller explicitly opts into

<a id="cve-2026-5023"></a>

### CVE-2026-53820

**OpenClaw exec-denylist bypass at MCP loopback spawn**

- **CVSS:** 6.9
- **NVD:** [https://nvd.nist.gov/vuln/detail/CVE-2026-53820](https://nvd.nist.gov/vuln/detail/CVE-2026-53820)
- **Regression test:** [`tests/cves/test_cve_2026_53820_loopback_spawn.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/tests/cves/test_cve_2026_53820_loopback_spawn.py)

**Vulnerability**

OpenClaw < 2026.5.12 (exec-denylist bypass, CVSS 6.9, CWE-693 Protection
Mechanism Failure): the bundled MCP loopback session-spawn path let an
authenticated caller reach a denylisted command because the **surface**
command checked against the exec restriction differs from the **effective**
command actually spawned — a name that passes the surface check resolves, via
an alias / wrapper binary / shell, to a denied executable.

<a id="cve-2026-53820"></a>

### CVE-2026-6980

**GitPilot-MCP repo_path injection**

- **Advisory:** [https://www.redpacketsecurity.com/cve-alert-cve-2026-6980-divyanshu-hash-gitpilot-mcp/](https://www.redpacketsecurity.com/cve-alert-cve-2026-6980-divyanshu-hash-gitpilot-mcp/)
- **Regression test:** [`tests/cves/test_cve_2026_6980_gitpilot.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/tests/cves/test_cve_2026_6980_gitpilot.py)

**Vulnerability**

Primary source (cited per v0.5.1+ convention):
- RedPacket Security CVE alert (2026-04-25):
  https://www.redpacketsecurity.com/cve-alert-cve-2026-6980-divyanshu-hash-gitpilot-mcp/
- vulnerability.circl.lu
Vendor unresponsive; project does not version. Preset matches by
tool-name regex only.

<a id="cve-2026-6980"></a>

### CVE-2026-75130

**Upstash Context7 "ContextCrush" MCP instruction injection**

- **CVSS:** 9.0 (Critical, CVSS v3.1; NVD also records 6.4 Medium under v4.0)
- **Airlock fit:** strongest
- **NVD:** [https://nvd.nist.gov/vuln/detail/CVE-2026-75130](https://nvd.nist.gov/vuln/detail/CVE-2026-75130)
- **Advisory:** [https://www.vulncheck.com/advisories/context7-prompt-injection-via-custom-ai-instructions](https://www.vulncheck.com/advisories/context7-prompt-injection-via-custom-ai-instructions)
- **Write-up:** [https://noma.security/blog/contextcrush-context7-the-mcp-server-vulnerability/](https://noma.security/blog/contextcrush-context7-the-mcp-server-vulnerability/)
- **Regression test:** [`tests/cves/test_cve_2026_75130_context7_contextcrush.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/tests/cves/test_cve_2026_75130_context7_contextcrush.py)

**Vulnerability**

Context7 through 2.1.2 serves a per-library **Custom AI Instructions**
("Custom Rules") field through its MCP server without sanitising it.
An attacker registers a library in the public Context7 registry and
embeds instructions in that field; when any developer later asks their
coding agent about that library, the text is inserted directly into the
model's working context as though it were documentation. No
user interaction with the attacker is required beyond a routine
documentation request.

Noma Security's proof of concept chained three legs through the
connected agent's own, already-authorised tools:

    1. Search the workspace for ``.env`` files and read them.
    2. File the contents as a **GitHub issue** on an attacker-owned
       repository.
    3. Delete local folders on the victim's machine.

NVD records two very different scores. v3.1 rates it 9.0 Critical.
v4.0 rates it 6.4 Medium — because it scores ``VC:N/VI:N/VA:N`` with
``SC:H/SI:H/SA:H``: Context7 itself is unharmed and the entire impact
lands on the *connected downstream system*. That gap is not a
disagreement about how bad this is; it is an accurate description of
the class, and the reason a server-side fix does not protect an agent
talking to some other poisoned source. Upstash accepted the findings
and shipped rule sanitisation with guardrails to production within
days.

**Airlock mitigation**

Nothing in the chain crosses a network boundary the agent was not
already authorised to cross. The agent may read files. It may call the
GitHub tool. It may delete. Every individual call is in-policy for an
authenticated principal — what is wrong is the *arguments*: a ``.env``
path nobody asked for, an issue body full of credentials, a delete
nobody requested. A transport or identity layer sees three authorised
calls and has nothing to object to. That is an argument-level failure,
which is the seam this library exists to cover.

<a id="cve-2026-75130"></a>
