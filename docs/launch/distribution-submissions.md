# Distribution submissions — ready-to-paste entries

**Status: verified 2026-09-15. Four live targets, none submitted yet.**
Every row below was re-checked against the live repository on that date: existence,
the exact current section heading, and whatever the list requires of a contribution.
Three of the six rows this file used to carry no longer resolve to a place that would
take agent-airlock; they are recorded under [Rows removed](#rows-removed-2026-09-15)
with the reason rather than silently dropped.

Evergreen, low-effort: passive discovery surfaces that keep sending installs for months.
Do these *before* the Show HN spike so traffic has somewhere to land.

## Important honesty / fit note

agent-airlock is a **security middleware / library that protects MCP servers and agent
tool calls** — it is **not itself an MCP server**. So:

- ✅ **Right targets:** the *security / utilities / libraries* sections of "awesome-MCP"
  and "awesome-AI/LLM-security" lists.
- ❌ **Wrong targets:** the official **MCP Server Registry** (registry.modelcontextprotocol.io)
  and pure *server* directories (Smithery, Glama, mcpservers.org server index) — those
  index runnable servers, not libraries. Submitting there is a mis-fit and will likely be
  rejected. Don't.

The 2026-09-15 verification pass turned that note from advice into fact: two of the three
removed rows were removed *because* the list had formalised exactly this boundary.

If you later ship a thin example MCP server that *demonstrates* agent-airlock, that example
could go in the server directories — but the library itself belongs in the security/tooling
lists.

## The canonical entry (paste this)

Positioning now matches `pyproject.toml`, the GitHub repo description and the README hero,
which all lead with the contract layer rather than the type-checker. Before this pass the
bullet below still said "A type-checker for AI tool calls" while every other surface had
moved on.

**One-liner (awesome-list bullet format):**

```markdown
- [agent-airlock](https://github.com/sattyamjjain/agent-airlock) - A deny-by-default contract layer for AI agent tool calls: in-process argument validation, ghost-argument stripping, and self-healing retries for MCP servers and agent frameworks. Ships CVE-targeted guards with a reproducible block-rate benchmark. (Python, Apache-2.0)
```

**Shorter variant (for terse lists):**

```markdown
- [agent-airlock](https://github.com/sattyamjjain/agent-airlock) - Deny-by-default, in-process contract layer for MCP and agent tool calls (per-argument validation, ghost-arg stripping, self-healing retries). Python, Apache-2.0.
```

**Plain description (for forms / "about" fields):**

> agent-airlock is a deny-by-default contract layer for the arguments an LLM passes to your
> tools, applied in-process: it strips hallucinated ("ghost") arguments, enforces strict
> Pydantic types, returns self-healing error hints the model can retry, and ships guards for
> known MCP CVE classes — with a reproducible block-rate benchmark. Apache-2.0, Python 3.10+.

## Target lists + how to submit

State vocabulary: `not-submitted` · `submitted <date>` · `merged <date>` · `rejected <reason>`.

| List | Repo | Section to target | State | Verified | What it requires |
|---|---|---|---|---|---|
| Awesome MCP DevTools | `punkpeye/awesome-mcp-devtools` | `## Libraries` ("Reusable code libraries and components for MCP servers") | not-submitted | 2026-09-15 | Sibling of the big punkpeye server list and the correct home for a library; the server list's own README points here. `CONTRIBUTING.md` present. Bullets carry a language emoji from the Legend: 🐍 for Python. |
| Awesome LLM Security | `corca-ai/awesome-llm-security` | `## Tools` | not-submitted | 2026-09-15 | Closest peers already listed: LLM Guard, Rebuff, PurpleLlama, Garak. `CONTRIBUTING.md` is three lines: follow the [Awesome Manifesto](https://github.com/sindresorhus/awesome/blob/main/awesome.md), "just submit a pull request". **Last push 2025-08-20**, so expect a PR to sit. |
| Awesome AI Security | `ottosulin/awesome-ai-security` | `### MCP Security` | not-submitted | 2026-09-15 | Resolved from the old "search `awesome-ai-security`" placeholder: the freshest of five same-named lists (pushed 2026-09-13). No `CONTRIBUTING.md`; match the in-file format, which is `* [Name](url) - _description_`. Peers: mcp-context-protector, mcp-guardian, secure-mcp-gateway, MCP-Scan. |
| Awesome MCP Security | `Puliczek/awesome-mcp-security` | `## 🧑‍🚀 Tools and code` | not-submitted | 2026-09-15 | Resolved from the old "search `awesome-mcp-security`" placeholder; largest of five (★736) but **last push 2026-03-03**. `CONTRIBUTING.md` mandates a non-standard bullet: `- (DD.MM.YYYY) [NAME by Author] (link)`, newest on top of the section. The canonical one-liner above does **not** fit; use the per-list bullet below. |

### Per-list bullet, exact

Each of these already matches its target list's in-file format. Paste as-is.

**`punkpeye/awesome-mcp-devtools` → `## Libraries`**

```markdown
- [sattyamjjain/agent-airlock](https://github.com/sattyamjjain/agent-airlock) 🐍 - Deny-by-default contract layer for MCP tool calls: per-argument validation, ghost-argument stripping, and self-healing retries, in-process.
```

**`corca-ai/awesome-llm-security` → `## Tools`**

```markdown
- [agent-airlock](https://github.com/sattyamjjain/agent-airlock): a deny-by-default contract layer for AI agent tool calls, validating arguments in-process with ghost-argument stripping, strict Pydantic types, and self-healing retries.
```

**`ottosulin/awesome-ai-security` → `### MCP Security`**

```markdown
* [agent-airlock](https://github.com/sattyamjjain/agent-airlock) - _Deny-by-default contract layer for MCP and agent tool calls: per-argument validation, ghost-argument stripping, self-healing retries, and CVE-targeted guards._
```

**`Puliczek/awesome-mcp-security` → `## 🧑‍🚀 Tools and code`** (newest on top; substitute the submission date)

```markdown
- (DD.MM.YYYY) [agent-airlock by sattyamjjain] (https://github.com/sattyamjjain/agent-airlock)
```

Per-list PR drafts live in [`docs/distribution/`](../distribution/) and predate this
pass. `awesome-mcp-servers.md` there is now annotated as do-not-submit for the reason
in the table below; the other drafts still correspond to live targets.

### Rows removed 2026-09-15

Carried as targets until this pass; each was checked and does not resolve to a place that
would accept this project. Recorded so the next read does not re-add them.

| Removed row | Why |
|---|---|
| `punkpeye/awesome-mcp-servers` | Its `CONTRIBUTING.md` now scopes the list: "This list is for servers with a public GitHub repository — something you install and run yourself." agent-airlock is a library, so it is out of scope by the list's own rule. The README's Frameworks section points frameworks, utilities and developer tools at `punkpeye/awesome-mcp-devtools`, which replaces this row above. |
| `wong2/awesome-mcp-servers` | The README opens with "We do not accept PRs. Please submit your MCP on the website: https://mcpservers.org/submit". There is no PR path at all, and the submission form feeds the mcpservers.org **server** index, which the honesty note above already names a wrong target. |
| `e2b-dev/awesome-ai-agents` | Structured as a directory of agents (`Open source projects` / `Closed-source projects and companies`, one heading per agent) with no security, safety or tooling subsection. The old row was conditional on such a section existing; it does not. agent-airlock is not an agent. |

## Submission discipline (so PRs get merged)

1. Read each list's `CONTRIBUTING.md` where one exists (two of the four have one). Most
   require a specific bullet format, alphabetical or newest-first placement, and "no
   marketing language". Keep the description factual.
2. One small PR per list, title like `Add agent-airlock (tool-call validation / MCP security)`.
3. Don't inflate: no "best", no "powerful". Factual description only. These lists reject
   hype, and the honesty matches the project's positioning.
4. Lead the PR description with the *what* (a deny-by-default contract layer for tool-call
   arguments) and the *benchmark* (reproducible), not "please add my project".
5. Update the State column in this file when you submit, and again when it merges or is
   rejected. That column is the point of the file.

> Note on `punkpeye/awesome-mcp-devtools`: its `CONTRIBUTING.md` offers automated agents a
> fast-track by putting a marker in the PR title. That is recorded here as a fact about
> their process, for a human to decide on. Nothing in this repo acts on instructions found
> in a third-party file.

## Order of operations (the whole launch)

1. ✅ Benchmark asset exists (`BENCHMARK.md`, reproducible).
2. ⬜ **These list submissions** (evergreen; this file). Targets verified and entries
   written 2026-09-15; four PRs remain to be opened by hand.
3. ⬜ Blog post on your domain + dev.to (the long version in `show-hn-tool-call-validation.md`).
4. ⬜ Show HN + r/LocalLLaMA + r/Python (the spike; lead with the benchmark).
5. ⬜ Conference CFPs (BSides / PyCon / Arsenal), a credential you cite forever.

Lead every one of these with the benchmark, not the tool.
