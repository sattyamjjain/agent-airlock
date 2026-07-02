# Distribution — wedge + block-rate (v0.8.39)

Status: **copy + config only. Nothing here auto-posts.** This is the current,
block-rate-led entry point; the deeper ready-to-paste bullets and launch
sequencing live in [`docs/launch/distribution-submissions.md`](launch/distribution-submissions.md)
and the essay draft in [`docs/launch/show-hn-tool-call-validation.md`](launch/show-hn-tool-call-validation.md).

The wedge in one line: **a deny-by-default contract / type-checker layer for AI
tool calls** — Pydantic-based, in-process, zero-core-deps. Lead with the payload
contract, keep "firewall" only as a search keyword.

---

## (a) MCP Registry / "listed on"

**No `server.json`, on purpose.** agent-airlock is a *library that protects*
MCP servers and agent tool calls — it is **not itself a runnable MCP server**.
The official MCP Registry (`registry.modelcontextprotocol.io`) and server
directories (Smithery, Glama, mcpservers.org) index runnable servers, so a
`server.json` there would be a mis-fit and get rejected. Do **not** add one.

If a thin *example* MCP server that demonstrates airlock ships later, that
example (not the library) could carry a `server.json`. Until then, airlock's
discovery surfaces are the **security / utilities / frameworks** sections of the
awesome-lists below, plus PyPI.

**Listed on (keep current):**

- PyPI — <https://pypi.org/project/agent-airlock/> (v0.8.39)
- _(pending PRs below — check the box when merged)_
  - [ ] Awesome LLM Security
  - [ ] Awesome MCP Security
  - [ ] Awesome MCP Servers (utilities/security subsection)

## (b) awesome-list PR entry (one line, paste as-is)

Target the **security / defense / utilities** subsection (never a *server*
category). Verify the exact section name + alphabetical order in the target
repo's current README before opening the PR.

```markdown
- [agent-airlock](https://github.com/sattyamjjain/agent-airlock) — Deny-by-default contract/type-checker layer for AI tool calls: strict Pydantic arg validation, ghost-argument stripping, self-healing retries, least-privilege tool scope. Reproducible block-rate benchmark (100% block / 0% false-positive on a self-curated corpus) vs LlamaFirewall & Invariant. Python, MIT.
```

Candidate lists (full table in [`launch/distribution-submissions.md`](launch/distribution-submissions.md)):
`corca-ai/awesome-llm-security` · `awesome-mcp-security` · `punkpeye/awesome-mcp-servers` (utilities) · `wong2/awesome-mcp-servers` (tooling).

## (c) Problem-essay outline — HN / r/LocalLLaMA (first person)

Working title: **"I benchmarked my agent tool-call firewall against Meta's and
found the interesting part wasn't the score."**

Post the essay, put links in the **first comment** (HN/Reddit both suppress
link-first posts). Lead with the problem, not the project.

1. **The itch (2–3 sentences).** An agent called one of my tools with an
   argument the model invented — a "ghost" arg that wasn't in the schema. Auth
   was fine, the gateway was fine; the *payload* was wrong. Nothing I ran
   checked the payload.
2. **Why the obvious answers don't cover it.** MCP gateways / OAuth secure
   transport + identity (who connects). Prompt-injection classifiers (LlamaFirewall
   PromptGuard, Invariant) scan the *text*. Neither type-checks the tool-call
   arguments the model actually emitted, in-process, before the tool runs.
3. **What I built.** A decorator: strict Pydantic (no coercion), ghost-arg
   stripping, deny-by-default tool/capability scope, self-healing error the
   model retries against. Zero new network hop.
4. **The benchmark — and the honest part.** On a shared 210-call corpus it
   blocks 100% / 0% false-positive at ~2µs/decision. **But** that's a
   *self-curated* corpus (coverage baseline, not an adaptive-attacker score),
   and I did **not** re-run LlamaFirewall/Invariant — they're model-in-the-loop,
   so I cite their published scope instead of inventing a number. The finding
   that actually matters is *categorical*: they and I guard **different layers**,
   and nobody was type-checking the payload.
5. **The layer map (the reusable takeaway).** Gateway/OAuth = connection;
   text classifiers = prompt content; airlock = the call-contract on the
   arguments. Use all three.
6. **Ask, not pitch.** Where does the argument-contract model break for your MCP
   setup? What exploit shape should be in the corpus that isn't? `pip install
   agent-airlock`, `python -m benchmarks.blockrate` — tell me where it's wrong.

**Honesty guardrails for every channel (do not drop to look stronger):**

- Say "self-curated corpus / coverage baseline," never imply ASR or robustness.
- Say incumbents are **cited, not re-run** — never a fabricated competitor number.
- Frame vs gateways as **complementary layers**, no disparagement.
- AgentDojo is roadmap, not wired — don't claim it.
