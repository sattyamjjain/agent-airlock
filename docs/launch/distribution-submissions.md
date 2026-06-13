# Distribution submissions — ready-to-paste entries

Status: **DRAFT / checklist.** Evergreen, low-effort, high-ROI: passive discovery
surfaces that keep sending installs for months. Do these *before* the Show HN spike
so traffic has somewhere to land.

## Important honesty / fit note

agent-airlock is a **security middleware / library that protects MCP servers and agent
tool calls** — it is **not itself an MCP server**. So:

- ✅ **Right targets:** the *security / utilities / frameworks* sections of "awesome-MCP"
  and "awesome-AI/LLM-security" lists.
- ❌ **Wrong targets:** the official **MCP Server Registry** (registry.modelcontextprotocol.io)
  and pure *server* directories (Smithery, Glama, mcpservers.org server index) — those
  index runnable servers, not libraries. Submitting there is a mis-fit and will likely be
  rejected. Don't.

If you later ship a thin example MCP server that *demonstrates* agent-airlock, that example
could go in the server directories — but the library itself belongs in the security/tooling
lists.

## The canonical entry (paste this)

**One-liner (awesome-list bullet format):**

```markdown
- [agent-airlock](https://github.com/sattyamjjain/agent-airlock) - A type-checker for AI tool calls: strict argument validation, ghost-argument stripping, and self-healing retries for MCP servers and agent frameworks. Ships CVE-targeted guards with a reproducible block-rate benchmark. (Python, MIT)
```

**Shorter variant (for terse lists):**

```markdown
- [agent-airlock](https://github.com/sattyamjjain/agent-airlock) - In-process, per-argument tool-call validation for MCP servers & agents (ghost-arg stripping, strict Pydantic, self-healing retries). Python, MIT.
```

**Plain description (for forms / "about" fields):**

> agent-airlock validates the arguments an LLM passes to your tools, in-process: it strips
> hallucinated ("ghost") arguments, enforces strict Pydantic types, returns self-healing
> error hints the model can retry, and ships guards for known MCP CVE classes — with a
> reproducible block-rate benchmark. MIT, Python 3.10+.

## Target lists + how to submit

Each is a GitHub repo; submit a small PR adding the bullet to the right section. Verify the
exact section name in the repo's current README before opening the PR.

| List | Repo | Section to target | Notes |
|---|---|---|---|
| Awesome MCP Servers (punkpeye) | `punkpeye/awesome-mcp-servers` | "Frameworks" / "Utilities" / any security subsection | Largest (~89k★). Read CONTRIBUTING — it's strict about format/alphabetical order. Library, so a utilities/security section, not a server category. |
| Awesome MCP Servers (wong2) | `wong2/awesome-mcp-servers` | Utilities / Tooling | Second major list; powers mcpservers.org. |
| Awesome LLM Security | `corca-ai/awesome-llm-security` | Tools / Defense | Direct fit — defensive LLM tooling. |
| Awesome AI Security | search `awesome-ai-security` | Tools / Guardrails | Verify the most-maintained fork before submitting. |
| Awesome MCP Security | search `awesome-mcp-security` | Tools / Defenses | Newer, MCP-specific; strong fit if active. |
| Awesome Agents / Agentic AI | e.g. `e2b-dev/awesome-ai-agents` | Security / Tooling | Fit if it has a safety/security subsection. |

## Submission discipline (so PRs get merged)

1. Read each list's `CONTRIBUTING.md` — most require a specific bullet format, alphabetical
   placement, and "no marketing language." Keep the description factual.
2. One small PR per list, title like `Add agent-airlock (tool-call validation / MCP security)`.
3. Don't inflate — no "best", no "powerful". Factual description only. These lists reject
   hype, and the honesty matches the project's positioning.
4. Lead the PR description with the *what* (per-argument tool-call validation) and the
   *benchmark* (reproducible), not "please add my project".

## Order of operations (the whole launch)

1. ✅ Benchmark asset exists (`BENCHMARK.md`, reproducible).
2. **These list submissions** (evergreen; this file).
3. Blog post on your domain + dev.to (the long version in `show-hn-tool-call-validation.md`).
4. Show HN + r/LocalLLaMA + r/Python (the spike; lead with the benchmark).
5. Conference CFPs (BSides / PyCon / Arsenal) — credential you cite forever.

Lead every one of these with the benchmark, not the tool.
