# agent-airlock — Roadmap to Top 1% (April 2026)

**Starting point (Apr 2026):** v0.4.0 "Enterprise" · ~25,900 LoC · 1,157 tests · 79%+ coverage · stars in single digits.
**Goal:** 1,000+ GitHub stars, top-1% positioning in "runtime MCP security middleware" category within 90 days; top-0.1% within a year.

Read `ECOSYSTEM_STATE_2026-04.md` first for the market context behind this plan.

---

## 1. The positioning problem

Today's README says "open-source security middleware for MCP servers." In a category that now includes NeMo Guardrails, LlamaFirewall, Guardrails AI, Lakera, Prisma AIRS, CalypsoAI, Pillar, Noma, Straiker, Lasso, Aim, openai-guardrails, AWS Bedrock Guardrails, Azure Prompt Shields, Anthropic Constitutional Classifiers, and **Microsoft Agent Governance Toolkit (launched Apr 2, 2026)** — that sentence wins nothing.

What you actually ship that no competitor combines in a single decorator:

1. **Ghost-argument tri-mode** (`BLOCK` / `STRIP_AND_LOG` / `STRIP_SILENT`) on tool arguments — nobody formalizes this. NeMo / LlamaFirewall / Lakera / OpenAI Guardrails all do prompt-level detection, not argument-level enforcement.
2. **Pydantic V2 strict validation with self-healing `fix_hints` JSON** — the LLM-retry-loop is a primitive no runtime competitor ships.
3. **E2B Firecracker MicroVM sandbox + warm pool** inside the same decorator.
4. **Capability gating via `@requires(Capability.*)`** for fine-grained RBAC.
5. **Multi-framework vaccination** — LangChain, OpenAI Agents SDK, CrewAI, AutoGen, LlamaIndex, smolagents, PydanticAI, Anthropic, LangGraph.
6. **PII detection including the India pack** — Aadhaar, PAN, UPI, IFSC. No competitor ships this in OSS.
7. **Circuit breaker + cost tracking + retry + OTel audit** in the same guardrail layer (competitors split these across separate libraries).

**Recommended one-line tagline:** *"The airlock between your agent and the internet — argument-level schema enforcement, ghost-arg stripping, sandbox execution, and OTel audit in a single `@Airlock(...)` decorator."*

**Hero use case:** a tool call that would have leaked a secret via an LLM-invented argument, blocked and returned a self-healing `fix_hints` payload the LLM actually uses to retry correctly. That is the 60-second video.

---

## 2. Critical gaps vs April 2026 state of the art

### 2.1 Must-ship before any launch

| Gap | Current state | Target state | Why |
|---|---|---|---|
| **SDK rename** | Code and docs reference "Claude Code SDK" | Full rename to **Claude Agent SDK** (`claude-agent-sdk` on PyPI and npm, Apr 16) | Anything still saying "Claude Code SDK" looks stale on launch day |
| **MCP transport** | Stdio-first, streamable HTTP partial | **Streamable HTTP + OAuth 2.1 + PKCE/S256** per MCP `2025-11-25` spec | Remote servers are now mandatory-OAuth; stdio-only middleware is legacy |
| **MCP Tasks primitive** | Not handled | Handle `working / input_required / completed / failed / cancelled` state machine, including the long-running elicitation flow | Adopted across real MCP servers in 2026 |
| **DPoP / client-credentials support** | Missing | Implement client-credentials grant (SEP-1046) and DPoP (SEP draft) | Required by enterprise MCP adopters |
| **CVE-2025-68143/68144/68145 coverage** | Not tested | Include a regression test that proves airlock blocks the three `mcp-server-git` prompt-injection chains | Validation-of-thesis marketing moment |
| **CVE-2025-59536 coverage** | Not covered | Regression test for the Claude Code hooks RCE + MCP consent bypass | Same |
| **Nginx-UI CVE-2026-33032, Atlassian CVE-2026-27825, MS MCP CVE-2026-26118, MCPJam CVE-2026-23744** | Not covered | At minimum a reproduction scenario under `tests/cves/` | Defensive credibility |
| **Published AgentDojo / PINT / AgentHarm scores** | None | First OSS MCP middleware on these leaderboards | Competitive credibility |
| **Opus 4.7 tokenizer** | Unaware | Update cost-tracking tables with the new tokenizer ratios | Otherwise cost reports mis-count by up to 35% |
| **`claude-managed-agents` interop** | Unaware | Document an explicit "what to use when Managed Agents is enough vs when to add airlock" comparison | Claude Managed Agents (Apr 8) is now a substitute for middleware in simple cases; own the narrative |

### 2.2 Features that widen the moat

1. **`SandboxBackend.Managed`** — pluggable backend that delegates execution to Anthropic Managed Agents or OpenAI SandboxAgent. Users keep airlock as the validation/audit layer while Anthropic/OpenAI runs the container. Turns a competitive threat into a distribution partnership.
2. **Google A2A protocol middleware** — A2A is complementary to MCP. Wrap A2A peer invocations with the same policy/capability model. You'd be the first OSS project doing this.
3. **Model Armor integration** — Google Cloud's Model Armor is default-on for Gemini Enterprise. Ship a `ModelArmorAdapter` so airlock's event stream registers with Model Armor (and vice-versa). Cross-ecosystem adapter = enterprise RFP lever.
4. **Anthropic Advisor tool awareness** — pair-model pattern is a new primitive (Apr 9 beta). Ship a `@Airlock.advised(Capability.PRIVILEGED)` decorator that enforces a second-model advisor call before a privileged tool runs.
5. **Automatic prompt caching** telemetry — read the `cache_control` header and emit OTel spans so users can see what fraction of their agent loop hit cache.
6. **Managed honeypot rotation** — your `honeypot.py` is static. Ship deception templates generated per-request so attackers can't fingerprint. 2026 red-team reports (Anthropic GTG-1002, Mexican government breach) show persistent-jailbreak attackers who need dynamic deception.
7. **Distributed rate limiting** on Redis / Upstash — your roadmap already lists this. Do it. Single-node token-bucket is a non-starter in any multi-node deploy.
8. **Per-tool Zod / TypeScript support** — ship a sibling TypeScript package `@airlock/core` that mirrors the decorator and uses Zod for strict validation. Next.js / OpenAI Agents TS SDK users are 40%+ of the agent-building world now.
9. **Airlock Studio** (open-source GUI) — a local dashboard that reads the OTel audit stream and renders blocked calls, `fix_hints` history, policy hits, cost curves. Sell the dashboard as the "why I install airlock on Monday" moment.
10. **Signed release tarballs + SLSA Level 3 provenance** — enterprise prerequisites.

### 2.3 Policy content that earns press

Ship these as `airlock.policies` sub-package modules, each named for a 2026 incident:

- `GTG_1002_DEFENSE` — blocks the tool-call patterns from Anthropic's November disclosure.
- `MEX_GOV_2026` — blocks the persistent-jailbreak vector described in the Mexican-government breach report.
- `OWASP_MCP_TOP10_2026` — one preset per MCP Top 10 category.
- `OWASP_AGENTIC_2026_ASI01_ASI10` — one preset per Agentic Top 10 category.
- `EU_AI_ACT_ARTICLE_15` — cybersecurity controls matching the high-risk obligation that applies Aug 2, 2026.
- `INDIA_DPDP_2023` — pairs with the India PII pack; a regional wedge for Indian fintech design partners.

Each policy ships with an explainer blog post — that is 6 posts of good content.

---

## 3. Milestones and timeline

### Week 0 (prep — 7 days before launch)

- Rename every "Claude Code SDK" reference. Grep and kill.
- Update `pyproject.toml` dependency constraints against Claude Agent SDK 0.1.58+, FastMCP 2.x, OpenAI SDK 2.x (Agents SDK "next evolution" breaks v1.x).
- Cut v0.5.0 with MCP 2025-11-25 support, OAuth 2.1, Tasks primitive, Opus 4.7 tokenizer.
- Land the CVE regression tests as `tests/cves/`.
- Publish AgentDojo / PINT / AgentHarm numbers as `benchmarks/results.md`.
- Pick a name for the dashboard. "Airlock Studio" is available.

### Week 1 (launch)

- **Tuesday, 13:00 UTC** — HN submission. Title: *"Airlock: Python middleware that blocked all three `mcp-server-git` prompt-injection CVEs — here's how."* The URL is the benchmarks page, not the README. Reference the 30-in-60-days CVE storm. Be live in the thread for 4 hours.
- **Tuesday +1h** — 8-tweet X thread: Tweet 1 is the blocked-CVE-replay GIF, Tweets 2–6 are the seven distinguishing primitives (ghost args, strict schema, sandbox, capabilities, vaccination, India PII, OTel audit), Tweet 7 is the benchmark table, Tweet 8 is the repo.
- **Wednesday** — `/r/LocalLLaMA` post, lead with the technical win (CVE defense), link in comments. `/r/netsec` post in the same format.
- **Thursday** — long-form blog post on your own domain (recommended new domain: `airlock.dev` or `agentairlock.dev`). Topic: "We reproduced three disclosed MCP CVEs. Here is how each would have been blocked at the decorator layer."
- **Friday** — dev.to cross-post.

### Weeks 2–4 (drumbeat)

- Ship v0.5.1 with the `SandboxBackend.Managed` adapter for Anthropic Managed Agents.
- "How to migrate from openai-guardrails to airlock for MCP workloads" post.
- File a PR to NeMo Guardrails' LangChain integration that documents airlock as a complementary argument-level validator. Cross-repo reach.
- Submit to OWASP MCP Top 10 project as a reference implementation.
- Open a Discord; seed with 20 people you already know.

### Weeks 5–8 (category leadership)

- Ship Airlock Studio (local dashboard).
- Ship TypeScript sibling `@airlock/core`.
- Conference: propose a BlackHat / DEF CON AI Village / RSAC talk. The 2026 CVE corpus is a strong abstract.
- Design-partner outreach to 5 Indian fintechs and 2 US banks (India PII pack + OAuth 2.1 enforcement is the pitch).
- Publish a monthly "State of MCP Security" report on your domain. Own the category the way Aider owns coding benchmarks.

### Weeks 9–12 (distribution expansion)

- Ship A2A protocol support.
- Ship Model Armor adapter.
- Submit a `RuleDefinition` reference pack to Snyk's `agent-scan` (ironic — share your rules, own the narrative of "the airlock rule library").
- Submit an OTel semconv proposal upstream with co-authors from Google / AWS / Langfuse.

---

## 4. What to measure

| Metric | Baseline | 30-day target | 90-day target | 1-year target |
|---|---|---|---|---|
| GitHub stars | ~3 | 150 | 1,500 | 8,000 |
| PyPI monthly downloads | <50 | 2,000 | 25,000 | 250,000 |
| Production design partners | 0 | 3 | 10 | 40 |
| Benchmark leaderboard entries | 0 | 3 (AgentDojo, PINT, AgentHarm) | 6 (add ToxicSkills, Gandalf, InjecAgent) | 10 |
| Tracked CVE coverage | 0 | 8 | 25 | 60 |
| Discord members | 0 | 75 | 500 | 3,000 |
| GitHub Actions using airlock | 0 | 5 | 50 | 500 |
| Framework integrations green | 9 | 12 | 15 | 20 |

---

## 5. What *not* to do

- **Don't chase generic prompt-injection detection.** Lakera / Prompt Security / LlamaFirewall are miles ahead and have classifier-LM training resources you don't. Cite them, don't compete.
- **Don't build your own benchmark** from scratch before publishing on existing ones.
- **Don't fight MCP.** Embrace `2025-11-25` fully and be first-class on Google-managed MCP servers, Anthropic Managed Agents, and OpenAI Responses remote MCP.
- **Don't rebuild an eval tool.** That's Verdict's job; pipe OTel events into Verdict instead.
- **Don't accept Assistants API interoperability PRs.** Sunsets Aug 26, 2026. Close as wontfix.

---

## 6. One-pager the CEO should be able to read

> *Airlock* is a single Python decorator — `@Airlock(...)` — that sits between an MCP tool handler and the LLM that called it. It blocks hallucinated arguments before they execute, validates tool parameters against Pydantic V2 strict schemas, returns a self-healing `fix_hints` JSON so the LLM can retry correctly, runs dangerous calls in an E2B Firecracker MicroVM, masks 14 PII types (including Aadhaar / PAN / UPI / IFSC), enforces capability-based RBAC, and streams OpenTelemetry audit records — all in ~50 lines of configuration. It's the runtime layer to our static scanner (agent-audit-kit) and our output-quality judge (Verdict), and it ships policy presets for the OWASP MCP Top 10, OWASP Agentic Top 10, EU AI Act Article 15, and the thirty MCP CVEs disclosed since January 2026.
