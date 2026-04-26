# `tools/scan_stdio_remote_input_flow.py` — STDIO-taint CI gate

**New in v0.5.7.** A static-analysis CI rule that flags any code path
where remote / network / user input flows into an STDIO command
construction site (`subprocess.Popen`, `subprocess.run`,
`StdioServerParameters`, `mcp.client.stdio.stdio_client`, etc.).

## Why this exists

OX Security's [2026-04-15 deep dive](https://www.ox.security/blog/mother-of-all-ai-supply-chains-2026-04-20)
established that arbitrary strings reaching `StdioServerParameters.command`
is **the** agent-supply-chain class of bug. Anthropic confirmed the
behavior is "by design" and declined to patch the protocol — see
[The Hacker News (2026-04-16)](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html)
and [SecurityWeek (2026-04-16)](https://www.securityweek.com/by-design-flaw-in-mcp/).

[CVE-2026-6980](https://www.redpacketsecurity.com/cve-alert-cve-2026-6980-divyanshu-hash-gitpilot-mcp/)
(GitPilot-MCP, 2026-04-25) and
[CVE-2026-30615](https://nvd.nist.gov/vuln/detail/CVE-2026-30615)
(Windsurf zero-click) are both this same flow shape.

The v0.5.1 `stdio_guard.validate_stdio_command` is a **runtime** allowlist
that catches a malicious value at the moment of `execve`. This scanner
catches the **flow shape** at PR time, before such a value is ever
constructed — the leverage point Anthropic explicitly punted to
"developer responsibility."

## What it flags

A finding is generated when a tainted value reaches one of:

- `subprocess.Popen`, `subprocess.run`, `subprocess.check_call`,
  `subprocess.check_output`, `subprocess.call`
- `StdioServerParameters(command=...)`
- `mcp.client.stdio.stdio_client(...)` (or bare `stdio_client(...)`)

A value is tainted when it originates from:

| Source | Detection |
|---|---|
| `requests.*`, `httpx.*`, `aiohttp.*`, `urllib.request.*` | direct call or chained attribute (`requests.get(...).text`) |
| FastAPI / Flask request bodies | `request.body`, `request.get_json()`, `request.form`, `request.args` |
| Function parameters of decorated handlers | `@post`, `@get`, `@put`, `@patch`, `@delete`, `@route`, `@tool`, `@secure_tool` (matched on trailing token, so `@app.post`, `@router.tool`, `@v1.api.get` all qualify) |

Multi-hop flows are tracked via local-variable assignments.

## Usage

```bash
python tools/scan_stdio_remote_input_flow.py src/ tests/ examples/
```

Exit codes:
- `0` — no findings (or all suppressed by pragma)
- `1` — at least one unsuppressed finding; `.airlock-stdio-taint.json`
  written to cwd
- `2` — usage error

## Suppression pragma

```python
subprocess.Popen([body])  # noqa: AIRLOCK-TAINT-OK signed-internal-only
```

The pragma **must** include a one-line reason after the marker.
`# noqa: AIRLOCK-TAINT-OK` (no reason) does **not** suppress. The
suppressed finding is still emitted into the JSON summary as an
audit-trail row.

## Calibration

Today the scanner runs clean on the agent-airlock repo (170 files
scanned, 0 findings) — proving the gate isn't broken by our own
code. If your repo's first run produces a high false-positive rate,
the spec calibration target is **<5% per 100 LoC**; pragma
suppressions are the documented escape hatch rather than relaxing
the rule.

## CI integration

A maintainer must apply the workflow change manually (automated PRs
lack the `workflow` OAuth scope to write `.github/workflows/*.yml`).
A copy-paste-ready job is at
[`docs/security/stdio-taint-scan-ci.yml.sample`](./stdio-taint-scan-ci.yml.sample).
