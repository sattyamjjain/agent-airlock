# Launch-day FAQ

Questions we expect from HN, Reddit, and the security Twitter
contingent. Keep answers short and cite primary sources.

## Positioning

### Q: How is agent-airlock different from Lakera / Snyk Agent Scan / PANW / Invariant / Cloudflare Firewall for AI / Google Model Armor?

**Runtime seam, not prompt seam.** All of the above intercept at or near
the LLM prompt boundary — they scan prompts, responses, or proxy HTTP
traffic. Agent-airlock sits in front of **tool execution**, inside the
agent process. If your model never calls a tool, airlock never fires.
If your model invents a tool argument that shouldn't exist
(ghost argument), airlock catches it before the tool runs — a layer
none of the prompt-layer products reach.

### Q: Is this a replacement for Model Armor / Lakera?

No — complementary. We ship an opt-in Model Armor adapter
(`pip install agent-airlock[model-armor]`) so you can use both. Use
Model Armor to score prompts/responses; use airlock to block a tool
from ever running with bad arguments.

### Q: Why no hosted SaaS?

The value prop is "offline, stdlib-first, air-gap-safe." A hosted
version dilutes that. We'd rather be the best local-only primitive than
a middling SaaS.

## Threat model

### Q: What does airlock NOT block?

- Vulnerabilities at the HTTP/transport layer of an MCP server
  (e.g. missing auth on `/api/mcp/connect`). We sit in front of tool
  execution, not the HTTP router. Use a reverse proxy for that.
- Vulnerabilities before a tool is registered (e.g. the Claude Code
  CVE-2025-59536 hook-execution path, which runs on client launch).
  We block the exfil leg via `EndpointPolicy`; we can't block the
  hook-execution leg.
- Prompt-injection into the model itself. That's an LLM safety
  problem — use Model Armor, Lakera, or your model vendor's native
  guardrails.
- See `docs/cves/index.md` for the full fit matrix.

### Q: What's the attack surface of airlock itself?

Middleware that enforces policies is a juicy target. We mitigate with:

- Zero heavyweight deps — core is pydantic + structlog
- No `eval()` anywhere in runtime paths
- `SafePath` + `SafeURL` validators on every input
- Honest CVE regression suite (see `docs/cves/`)
- Private vulnerability reporting via `SECURITY.md` with 48 h triage

## Performance

### Q: How much does this cost per tool call?

From `tests/benchmarks/` on a MacBook M-series:

- `@Airlock` decorator overhead: **~85 μs** per call (no sandbox, no
  network, no sanitizer). With Pydantic strict validation of 2 fields:
  **~77 μs**.
- Output sanitization on a 4 KB clean payload: **~580 μs**.
- PKCE round-trip: **~100 μs**.

In other words: sub-millisecond on every path that isn't a sandboxed
execution or a long-output sanitize. For launch we're deliberately NOT
publishing a single "X μs overhead" headline number because it's
workload-dependent.

## Usage

### Q: How do I install just the parts I need?

```bash
pip install agent-airlock                    # core only
pip install "agent-airlock[mcp]"              # + FastMCP integration
pip install "agent-airlock[sandbox]"          # + E2B
pip install "agent-airlock[model-armor]"      # + Google Model Armor
pip install "agent-airlock[claude-agent]"     # + Claude Agent SDK
pip install "agent-airlock[all]"              # everything
```

### Q: Which frameworks work out of the box?

LangChain, LangGraph, CrewAI, AutoGen, OpenAI SDK, Anthropic SDK,
PydanticAI, smolagents, LlamaIndex. Each has a tested example under
`examples/`.

### Q: How do I wire it into my MCP server?

```python
from agent_airlock.mcp import secure_tool

@secure_tool
def run_sql(query: str) -> list[dict]:
    ...
```

Or construct your own `@Airlock(...)` with a custom policy. See
`docs/getting-started/quickstart.md`.

## Roadmap / community

### Q: Are you looking for design partners?

Yes — email `platform.dev@attri.ai` with your use case. We're
prioritizing 3 partners for case studies at weeks 8, 10, and 12 after
launch.

### Q: Is there a Discord?

Link in README. Not fancy — a `#help`, a `#cve-rules`, and a `#dev`
channel.

### Q: What's the license?

MIT. See `LICENSE`.

### Q: How do you handle CVE disclosures you want to add as regression tests?

File an issue with the [CVE rule request template](https://github.com/sattyamjjain/agent-airlock/issues/new?template=cve_rule_request.md).
Primary-source link is required — we won't write a test against a
rumored CVE.

## Business-y stuff

### Q: Who's behind this?

Sattyam Jain at attri.ai. Open-source MIT. Not a company product.
