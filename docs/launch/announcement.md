# agent-airlock v0.5.0 — the runtime defense Anthropic chose not to ship

*Draft launch post, anchored on the Ox Security timeline. Not yet
posted. Update the dates and numbers in place before firing.*

---

**Four days ago**, [Ox Security disclosed](https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem)
a systemic RCE class in the Model Context Protocol's STDIO transport.
~200,000 vulnerable server instances. 150M+ downloads. 10+ CVEs. The
vulnerability lives in the official Anthropic SDKs — Python,
TypeScript, Java, Rust — so every downstream project that trusts the
SDK inherits it.

**Three days ago**, Anthropic's response ran in
[The Register](https://www.theregister.com/2026/04/16/anthropic_mcp_design_flaw/):
*"expected behavior."* Nine days from disclosure to response. One doc
update advising developers to *"use the STDIO adapter cautiously."*
No SDK patch. No protocol change.

**The same day**, OpenAI shipped the
[next evolution of the Agents SDK](https://openai.com/index/the-next-evolution-of-the-agents-sdk/)
— sandbox-by-default, harness separated from compute, first-class
integrations with Blaxel, Cloudflare, Daytona, E2B, Modal, Runloop,
and Vercel.

Today we're shipping **agent-airlock v0.5.0** — the Anthropic-side
answer. Deny-by-default, in-process, MIT-licensed.

## What it does

`@Airlock()` is a Python decorator that wraps your MCP tool and puts
six layers of defense between the LLM and the subprocess:

1. **Validation** — Pydantic V2 strict. No type coercion.
2. **Ghost-argument rejection** — `UnknownArgsMode.BLOCK` refuses
   LLM-invented `env`, `args`, or any other parameter your tool
   didn't declare. This is Ox attack class 2, stopped at the
   signature.
3. **Policy** — `SecurityPolicy` with deny-by-default allow-lists,
   RBAC, rate limits, time windows. Ox attack class 1, stopped at
   the policy seam.
4. **Filesystem** — `SafePath` rejects writes to `~/.cursor/mcp.json`,
   Claude Desktop config paths, and traversal strings. Ox attack
   class 4, stopped at the path validator.
5. **Network egress** — `EndpointPolicy` rejects outbound HTTP to
   hosts not on the allow-list. Stops the exfil leg of
   CVE-2025-59536 even when the hook-execution leg is already gone.
6. **Sandbox** — Pluggable backends (E2B Firecracker, Docker, Local
   for dev). Managed stub for Anthropic Managed Agents.

## The specific CVEs this blocks

Eight regression tests in `tests/cves/` reproduce the vulnerable
tool-call pattern and assert the matching airlock primitive blocks
it. See [the auto-generated catalog](../cves/index.md). Highlights:

- **CVE-2026-30616** (Ox STDIO RCE class) — 3 of 4 attack classes
- **CVE-2025-59536** (Claude Code hooks RCE, exfil leg)
- **CVE-2025-68143/44/45** (mcp-server-git path traversal / arg
  injection / repo root escape)
- **CVE-2026-26118** (Azure MCP SSRF)
- **CVE-2026-27825/26** (mcp-atlassian arbitrary write / header SSRF)

## What it is NOT

- Not a prompt-layer firewall. Use Lakera / Model Armor for that.
  We ship an opt-in Model Armor adapter so you can use both.
- Not a reverse proxy. Use Kong AI Gateway / Traefik Hub if your
  agents talk to MCP over HTTP. We're the in-process case — same
  policy primitives, but as a decorator, enforced even for STDIO
  and air-gapped runners.
- Not a silver bullet for Ox attack class 3 (prompt-injection of the
  chat UI itself). That's a client-surface bug — upgrade your agent
  host.
- Not hosted. No SaaS. The value prop is air-gap-safe. A hosted
  version dilutes that.

## Install

```bash
pip install agent-airlock                    # core only (two deps)
pip install "agent-airlock[mcp]"             # + FastMCP
pip install "agent-airlock[sandbox]"         # + E2B Firecracker
pip install "agent-airlock[model-armor]"     # + Google Model Armor
pip install "agent-airlock[claude-agent]"    # + Claude Agent SDK
pip install "agent-airlock[all]"             # everything
```

```python
from agent_airlock import Airlock, SecurityPolicy

@Airlock(policy=SecurityPolicy(allowed_tools=["read_file", "list_dir"]))
def read_file(path: str) -> str:
    ...
```

## Why now

- **Thesis proven externally.** OpenAI shipped sandbox-by-default
  the same week Anthropic declined to. Every enterprise buyer with a
  Claude Code or Cursor deployment now has a concrete "what do we do"
  conversation. Agent-airlock is a concrete answer you can deploy
  before lunch.
- **MCP is still the largest ecosystem.** 10,000+ public servers per
  [WorkOS](https://workos.com/blog/everything-your-team-needs-to-know-about-mcp-in-2026),
  even with Perplexity's departure and the CLI-vs-MCP efficiency
  debate. The attack surface isn't going anywhere; the enforcement
  layer needs to.
- **Deny-by-default is cheap.** 85 μs overhead per tool call on the
  no-sandbox path. If you're paying hundreds of milliseconds for the
  model round-trip anyway, spending 85 μs on validation is free.

## Links

- Repo: <https://github.com/sattyamjjain/agent-airlock>
- PyPI: <https://pypi.org/project/agent-airlock/>
- Docs: <https://agent-airlock.dev>
- CVE catalog: [`docs/cves/index.md`](../cves/index.md)
- Security policy: [`SECURITY.md`](../../SECURITY.md)
- Launch FAQ: [`docs/launch/faq.md`](faq.md)

MIT. Two runtime deps (pydantic + structlog). Designed for the exact
seam the MCP spec refuses to legislate.

---

*If you are Sattyam reviewing this before posting: the tone is
deliberately declarative, not conciliatory. Anthropic's "expected
behavior" quote is a gift — leaning into it positions airlock as the
responsible-adult answer to an abdicated architectural responsibility.
If you want a softer version, strip the "chose not to ship" line from
the title.*
