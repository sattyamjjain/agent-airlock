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
| [CVE-2025-59536](#cve-2025-59536) | Claude Code hooks RCE + MCP consent bypass (exfil leg) | 8.7 (High) | Partial |
| [CVE-2025-68143](#cve-2025-68143) | Anthropic mcp-server-git `git_init` path traversal | 8.2 (High) | Strong |
| [CVE-2025-68144](#cve-2025-68144) | Anthropic mcp-server-git argument injection | 8.1 (High) | Strongest |
| [CVE-2025-68145](#cve-2025-68145) | mcp-server-git `--repository` root not enforced | 7.1 (High) | Strong |
| [CVE-2026-26118](#cve-2026-26118) | Microsoft Azure MCP Server SSRF (IMDS token theft) | 8.8 (High) | Strong |
| [CVE-2026-27825](#cve-2026-27825) | mcp-atlassian arbitrary file write via download_path | 9.1 (Critical) | Strong |
| [CVE-2026-27826](#cve-2026-27826) | mcp-atlassian SSRF via `X-Atlassian-*-Url` headers | 7.5 (High, AV:A/PR:N/UI:N, C:H) | Partial |
| [CVE-2026-30616](#cve-2026-30616) | MCP STDIO transport command-injection (Ox Security class) | 9.8 (Critical) | Strongest |

## Details

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
