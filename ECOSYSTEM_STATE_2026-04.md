# State of the AI-Agent Ecosystem — April 18, 2026

**Source:** Six parallel deep-research passes (Anthropic, OpenAI, Google, agent-security competitors, eval/observability competitors, GitHub-growth case studies). Every claim in this file is traceable to a URL documented in the research agents' raw-source lists; in this summary I cite only the key anchors.

This is the shared context behind the four per-repo roadmaps. Read this once, then jump to the roadmap for whichever project you're working on.

---

## 1. Anthropic — the ground has shifted under all four repos

**Models (April 2026)** — `claude-opus-4-7` (Apr 16), `claude-opus-4-6` (Feb 5), `claude-sonnet-4-6` (Feb 17), `claude-haiku-4-5` (still current from Oct 2025), plus the gated `Claude Mythos Preview` research model (Apr 7, Project Glasswing cybersecurity cohort). Opus 4.7 ships a **new tokenizer** that yields up to 1.35× more tokens for the same input, so any code measuring cost/tokens against Opus 4.6 numbers will under-count.

**SDK rename** — the Claude Code SDK is now the **Claude Agent SDK** (`claude-agent-sdk` on PyPI and npm, Python release Apr 16). Anything in your code referencing "Claude Code SDK" is out-of-date.

**Claude Code** is on the **2.1.x line** (2.1.112 on Apr 16). New surfaces that matter:
- **Hooks** — 12 lifecycle events, including a new **agent hook** that spawns a tool-using subagent (60 s timeout, 50 turns) alongside command/HTTP/prompt hooks.
- **Plugins + marketplaces GA** — canonical format is `.claude-plugin/marketplace.json`. There is **no `.plugin` file extension** — plugins are folders with skills/agents/hooks/MCP/LSP. 2,500+ marketplaces tracked; Anthropic's official marketplace is `anthropics/claude-plugins-official`.
- **Routines** (research preview, Apr 14) — cloud-scheduled prompts on cron, HTTP webhooks, or GitHub events.
- **Skills 2.0** — renderer/discovery overhaul April 2026; 17 first-party skill directories.
- **Slash commands** added in 2026 include `/ultrareview`, `/effort`, `/loop`, `/team-onboarding`.

**Claude Cowork** is now **GA on macOS and Windows**. Shared marketplace with Claude Code. There is a known bug where marketplace-installed plugins don't surface skills in Cowork (zip uploads work) — [GH #39400](https://github.com/anthropics/claude-code/issues/39400).

**MCP spec 2025-11-25** is current. Key changes that break pre-2026 middleware:
- **Tasks** primitive (SEP-1686) — async `working/input_required/completed/failed/cancelled` state machine.
- **Streamable HTTP** transport replacing stdio for remote servers.
- **OAuth 2.1 mandatory** for remote servers, PKCE+S256 required, client-credentials added, DPoP under SEP review.
- **URL-mode elicitation** for credentials/OAuth/payments.
- Governance moved to the **Linux Foundation Agentic AI Foundation**.

**MCP CVE storm** — 30+ CVEs filed against MCP servers in Jan–Feb 2026 alone. Notables: CVE-2026-33032 (Nginx-UI MCP auth bypass, CVSS 9.8), CVE-2026-27825/27826 (Atlassian MCP RCE), CVE-2026-26118 (Microsoft MCP hijacking), CVE-2026-23744 (MCPJam Inspector RCE), plus the three Anthropic `mcp-server-git` prompt-injection chains (CVE-2025-68143/68144/68145). A survey of 2,614 implementations found 82% with path-traversal issues; 36.7% of 7,000 servers were SSRF-vulnerable.

**Claude API platform** — `claude-managed-agents` beta (Apr 8), `advisor-tool` beta (Apr 9), `effort` parameter GA, adaptive thinking default on Opus 4.6+, **automatic prompt caching** since Feb 19 (single `cache_control` field, system chooses breakpoints), code-execution v2 (bash + multi-language), code-execution FREE when combined with web-search/fetch, and **Messages API on Amazon Bedrock** GA Apr 16.

**Safety** — **Constitutional Classifiers++** (Jan 9, jailbreak ASR 86% → 4.4% at ~1% compute overhead), **RSP v3.0** (Feb 24, controversially removed the hard-pause commitment), **Project Glasswing / Claude Mythos** (Apr 7, gated cyber-model). Two incidents matter: the **GTG-1002 disclosure** (first largely autonomous AI-orchestrated cyber-espionage via Claude Code) and the **Mexican government breach** (Feb 2026, ~150 GB exfil via prompt-engineering jailbreak).

---

## 2. OpenAI — has caught up on agents

**Models.** `gpt-5.4` (Mar 5, 272 k context expandable to 1.05 M), `gpt-5.4-pro`, `gpt-5.4-mini`, `gpt-5.4-nano`, `gpt-5.2` (Dec 2025), `gpt-5.2-codex`, `gpt-5.3-codex` (Feb 5 — first OpenAI release classified High Cybersecurity under the Preparedness Framework, gated rollout), `gpt-5.3-codex-spark` research preview. GPT-4o / 4.1 / o4-mini retired from ChatGPT Feb 13 (API unchanged).

**Codex is OpenAI's flagship agent surface** — **3 M weekly active users as of Apr 8**, per Altman. GPT-5.4 is the default Codex model since Mar 5. Codex CLI is ~74 k stars (#3 behind Claude Code and Gemini CLI). April 2026 Desktop update: background computer use, in-app browser, persistent memory, scheduled automations, 90+ plugins, Windows sandbox with proxy-only egress. **Codex Pro** tier at $100/mo launched Apr 9 (5× usage vs Plus).

**Agents SDK "next evolution"** (Apr 15) — `SandboxAgent`, `Manifest`, `SandboxRunConfig`, Codex-like filesystem tools, `apply_patch`, shell tool, skills (progressive disclosure), `AGENTS.md`, MCP-based tool use. **Pluggable sandbox providers**: Blaxel, Cloudflare, Daytona, E2B, Modal, Runloop, Vercel. Breaking: drops `openai` SDK v1.x.

**Responses API** absorbed the Assistants API role; Assistants shuts down **Aug 26, 2026**. Built-in tools: `web_search`, `file_search`, `code_interpreter` ($0.03/container), `image_generation`, `computer_use` (native in 5.4), `shell` (hosted Debian 12 with Python 3.11 / Node 22 / Java 17 / Go 1.23 / Ruby 3.1), remote MCP (no extra cost beyond output tokens), connectors.

**MCP is universal across OpenAI products** — Responses, Realtime, Codex, Agents SDK, Apps SDK, Connector Registry. Tens of thousands of community MCP servers consumed.

**OpenAI Atlas** (ChatGPT browser) + plans to merge ChatGPT / Codex / Atlas into a single desktop "superapp" (announced Mar 20).

**openai-guardrails** library is the direct parallel to agent-airlock's role but with a known bypass: HiddenLayer's "Same Model Different Hat" research shows the guardrail LLM can be compromised by the same prompt that compromises the production model.

---

## 3. Google — meaningful competitor now

**Models.** `gemini-3.1-pro-preview` (Feb 19, now Google's flagship — 77.1% ARC-AGI-2, double Gemini 3 Pro's score three months earlier), **Gemini 3 Deep Think** (Feb 12, 84.6% ARC-AGI-2, IMO 2025 gold). `gemini-3.1-flash-lite-preview` (free tier available). `gemini-3.1-flash` TTS. **Gemini Nano 4 / Gemma 4** Android preview Apr 2 (4× speedup, 60% less battery).

**Gemini CLI** is v0.38.1 (Apr 15), Apache-2.0, **70+ marketplace extensions** (Dynatrace, Elastic, Figma, Harness, Postman, Shopify, Snyk, Stripe). **Free tier** — 60 req/min + 1000 req/day on a personal Google account. **GitHub Actions** integration (beta): issue triage, PR review, on-demand `@gemini-cli`.

**Jules** is out of beta; **Jules Tools** (CLI + public API) available late 2025/early 2026 — direct Claude Code / Codex CLI competitor.

**A2A protocol** — **150+ organizations** at its one-year anniversary (Apr 9, 2026), in production at Tyson Foods / Gordon Food Service, now in Azure AI Foundry and AWS Bedrock AgentCore. Complementary to MCP (A2A is agent-to-agent; MCP is agent-to-tool).

**Vertex AI Agent Builder / ADK** — Python, Java, Go, TypeScript; `google/adk-python` v1.28.1 (Apr 2). **Enhanced Tool Governance** in Agent Builder (Dec 2025) via **Apigee-backed custom MCP servers** from existing APIs.

**Google Cloud native MCP** — **Managed remote MCP servers** for Google services: BigQuery, Google Maps Grounding Lite, Compute Engine, with Cloud Run / Storage / AlloyDB / Cloud SQL / Spanner / Looker / Pub/Sub / Dataplex rolling out.

**Model Armor** is GA and default-on for Gemini Enterprise — prompt injection, jailbreak, DLP, toxic content, four responsible-AI categories; **floor settings for Google-managed MCP** in preview (first cloud baseline firewall over MCP traffic).

**NotebookLM Cinematic Video Overviews** — Mar 5, 2026; Gemini + Imagen + Veo as a creative director.

---

## 4. Agent-security market — consolidation is over, window is narrow

**12-month M&A:** Check Point → Lakera (~$300 M, Nov 2025); Palo Alto Networks → Protect AI (Jul 2025, pulled into Prisma AIRS); Snyk → Invariant Labs (Jun 2025, rebranded MCP-Scan → `snyk/agent-scan`); SentinelOne → Prompt Security; F5 → CalypsoAI (~$180 M announced).

**Commercial landscape (GA):** Cisco AI Defense, Prisma AIRS, Lakera Guard (Check Point), Prompt Security (S1), CalypsoAI (F5), HiddenLayer AISec, Noma Security ($132 M, 1,300% ARR growth), Pillar Security, Straiker ($21 M), Lasso, Aim Security, Giskard, Arthur Shield, WhyLabs.

**Hyperscaler primitives:** Anthropic Constitutional Classifiers++, AWS Bedrock Guardrails, Azure Prompt Shields + Azure AI Content Safety + PyRIT + Red Teaming Agent, **Microsoft Agent Governance Toolkit** (OSS, Apr 2, 2026 — directly overlaps agent-airlock's framework-vaccination pattern), OpenAI Guardrails.

**Open source direct competitors to agent-airlock:**
- NVIDIA NeMo Guardrails (~5.7 k stars) — Colang DSL; conversational-focused; no ghost-arg stripping, no MCP argument-level validation, no sandbox.
- Guardrails AI (~6.7 k) — structured-output-centric, validator hub.
- Meta LlamaFirewall / PurpleLlama — PromptGuard-2 + Agent Alignment + CodeShield; ASR 17.6% → 1.7%.
- Protect AI LLM Guard (~1.8 k), Rebuff (~1.4 k), Invariant OSS (~42), WhyLabs LangKit (~1 k).

**Open source direct competitors to agent-audit-kit:**
- **Snyk Agent Scan** (ex-Invariant MCP-Scan) — the big one. Multi-model analysis, claims 90–100% recall / 0% FP on ToxicSkills.
- Cisco AI-Defense `mcp-scanner`, `riseandignite/mcp-shield`, `mcpshield/mcpshield`, `affaan-m/agentshield`, `HeadyZhang/agent-audit` (49 rules, OWASP Agentic 2026 — close overlap with your 77).
- Semgrep Multimodal SAST (2026): AI reasoning + deterministic, 8× TP, 50% fewer FP.
- Protect AI `modelscan` + `mmaitre314/picklescan` for model files.

**Benchmarks now standard:** AgentDojo (97 tasks × 629 security cases), AgentHarm (ICLR 2025), InjecAgent, ToolEmu, AgentBench, **Lakera PINT** (4,314 inputs), Gandalf, **ToxicSkills** (Snyk). Neither `agent-airlock` nor `agent-audit-kit` appears on any public leaderboard — easy credibility lift.

**Regulation timeline that forces adoption:**
- **EU AI Act high-risk obligations** apply **Aug 2, 2026** (Article 15 cybersecurity, Article 55 GPAI).
- **OWASP Top 10 for Agentic Applications 2026** (ASI01–ASI10) released Dec 2025.
- **OWASP MCP Top 10** project live.
- **ISO/IEC 42001** AI Management System certification — now required in some enterprise RFPs.
- Singapore Agentic AI Governance Framework (Jan 2026) — first national framework.

---

## 5. LLM-eval market — dense but Verdict has unique white space

**Production observability + eval:** LangSmith, Braintrust, Helicone (~4.8 k), Langfuse (~12.8 k), Phoenix/Arize (~6.4 k), Langtrace, AgentOps (~4.6 k), Opik (~9.4 k).
**Eval-first frameworks:** Promptfoo (~7.2 k), DeepEval (~7.9 k), Ragas (~9.7 k), Inspect AI (~1.6 k UK AISI), Autoevals (~2.1 k), TruLens (~2.5 k), Giskard (~4.4 k), OpenAI Evals (~16.1 k).
**Agent-runtime scorers:** AgentOps, Galileo Luna-2, Patronus Lynx.

**Small-judge models** cutting eval cost by 50×: Atla AI **Selene** (8 B, Dec 2025), Patronus Lynx, Galileo Luna-2, LastMile AutoEval.

**Benchmarks landscape (Apr 2026):** static benchmarks (MMLU-Pro, AlpacaEval, MT-Bench) saturated. The action is on **τ-bench / τ²-bench** (Sierra, Q1 2026), **LiveBench** (monthly refresh, contamination-free), **SWE-bench Verified / Live**, **ARC-AGI-2**, **HLE (Humanity's Last Exam)**, **BrowseComp / BrowseComp-Long**, **SWE-Lancer**, **MLE-Bench**, **Cybench**, **GDPval**.

**Claude Code native evaluators:** Anthropic ships none. Community `agent-judge` skill exists (~150 stars) but no persistence, no hooks, no rubrics. **Verdict occupies genuine white space** as a Claude Code plugin with hook-based auto-scoring + persistent scorecards + offline heuristics.

---

## 6. Viral consumer AI — the playbook is now standardized

**Verdict-machine canon (most relevant to whyCantWeHaveAnAgentForThis):** Roast My Resume / Website (2023), Wrapped-for-X clones (2024), Delphi.ai (2024–25), Websim (~2 M users summer 2024), roast-my-x (Levels, $30 k first week), AI personality quizzes (16 Personalities pattern).

**What separates winners:**
1. Per-result OG images optimized for screenshot-sharing.
2. Tier-claiming behavior ("I got SHUT_UP_AND_TAKE_MY_MONEY!").
3. One-click share with prefilled content (not "take a screenshot").
4. Public gallery / leaderboard.
5. Founder-led seeding of 10–50 micro-influencers in week one.
6. Structured verdict with "evidence" the user accepts (tables, scores, competitors).
7. Consulting / premium funnel on positive-tier verdicts.

**Regulatory hygiene for satirical AI (now enforced):** EU AI Act Article 50 transparency (in force Aug 2026), DSA notice-and-takedown, Anthropic Usage Policies on defamation, trademark risk on auto-generated agent names, post-*Anderson v. TikTok* Section 230 erosion for AI-generated content.

---

## 7. GitHub-growth quantitative baseline

From peer-reviewed arXiv paper **"Launch-Day Diffusion"** (2511.04453, Nov 2025), analyzing 138 AI-tool HN launches during 2024–2025:
- Average gain after HN exposure: **+121 stars in 24 h, +189 in 48 h, +289 in a week.**
- Best post window: **12:00–17:00 UTC** (~8 am–1 pm US Eastern). Gap between optimal and suboptimal hours ≈ 200 stars.
- The literal "Show HN:" prefix shows **no statistical advantage** after controlling for time-of-day.

**Case-study patterns that recur in 10 k+ projects:**
1. Launch with a news-cycle hook (OpenHands = "open-source Devin"; browser-use rode Manus's virality for 5× downloads in a week; Cline rode Claude 3.5 Sonnet).
2. Ride an ecosystem's distribution (Cline lives in VS Code Marketplace; FastMCP rode the MCP wave to 10 k stars in 6 weeks; Claude Code now has 9,000+ plugins in 2,500+ marketplaces).
3. Demo with a 20-second loopable GIF in the README, not a static screenshot.
4. **Own a benchmark/leaderboard.** Aider publishes the Polyglot leaderboard; every major LLM launch links back. Single highest-leverage tactic in the data.
5. Community flywheel — Discord with 1 k+ engaged members before 10 k stars. Continue had 11 k Discord before 30 k stars.
6. Short name, matching domain (Aider, Cline, Trivy, Nuclei, Roo, Kilo, Zed).

---

## 8. Biggest shifts since January 2026 (ranked by impact on these four repos)

1. **Claude Agent SDK rename + Python release (Apr 16)** — every mention of "Claude Code SDK" in these repos is now stale.
2. **Claude Managed Agents beta + OpenAI SandboxAgent (Apr 8 / Apr 15)** — both clouds now ship managed agent harnesses that bundle sandbox + guardrails. Middleware positioning has to shift toward "bring-your-own MCP fleet."
3. **MCP spec 2025-11-25 (OAuth 2.1 mandatory + Tasks + Streamable HTTP)** — stdio-only or unauthenticated middleware is legacy.
4. **30+ MCP CVEs in Jan–Feb 2026** — perfect validation-of-thesis moment for agent-airlock and agent-audit-kit.
5. **Plugins/marketplaces consumed Skills** — Verdict should be distributed as a marketplace plugin, not a standalone skill repo.
6. **Microsoft Agent Governance Toolkit (Apr 2)** — first-party entrant overlapping agent-airlock's framework-vaccination pattern.
7. **Snyk bought Invariant Labs** — `snyk/agent-scan` is now the dominant OSS MCP scanner; agent-audit-kit needs sharper differentiation.
8. **Gemini CLI + A2A protocol + Google-managed MCP** — expand coverage beyond Claude if these projects want to stay relevant.
9. **OWASP Top 10 Agentic 2026 + OWASP MCP Top 10 + EU AI Act Aug 2026** — compliance-evidence output is the strongest commercial wedge.
10. **Opus 4.7 tokenizer change** — any cost/efficiency scoring in Verdict will mis-count on post-4.6 models.

---

## 9. Where the four repos stand after this research

| Repo | Category | Direct competitors | White space that's still open | Risk window |
|---|---|---|---|---|
| agent-airlock | MCP runtime middleware | NeMo, LlamaFirewall, Microsoft Governance Toolkit, Lakera | Arg-level Pydantic-strict validation + E2B sandbox + ghost-arg modes + multi-framework vaccination in one decorator. Nobody else combines these. | 3–6 months before Microsoft toolkit grows integrations |
| agent-audit-kit | MCP / agent static scanner | Snyk Agent Scan, mcp-shield, Semgrep Multimodal | Compliance-evidence reports (EU AI Act, ISO 42001, HIPAA) + CVE-to-rule velocity + India PII pack | 2–4 months before Snyk ships equivalent compliance output |
| Verdict | Claude Code eval plugin | No direct competitor (community `agent-judge` is tiny) | Entire category is empty — plugin marketplace + hook auto-scoring + offline heuristics + rubric library | 6+ months; genuinely first-mover |
| whyCantWeHaveAnAgentForThis | Satirical consumer AI | Copycats welcome; no single dominant "idea validator" | Tier-as-identity + consulting funnel + curated leaderboard + newsletter | Short because trend-dependent; ship within 2–3 weeks |

---

## 10. Cross-repo dependencies and shared work

Three pieces of work should be done **once** and shared across repos:

1. **`agent_security_commons`** shared Python library — pull the strong secret patterns, the India PII pack, the OWASP mapping tables, and the new-2026-CVE rule bundle into one dependency used by both agent-airlock and agent-audit-kit.
2. **Unified rule ID schema** — `AAK-MCP-003` must mean the same thing at scan time (audit-kit finding) and runtime (airlock block reason) so an engineer can trace either direction.
3. **Unified OpenTelemetry semconv for agent security events** — contribute upstream to OTel GenAI semconv. Once accepted, agent-airlock audit records and agent-audit-kit scan results both emit the same event schema, and Verdict consumes those events as one of its scoring signals.

Together these three pieces reduce maintenance cost and give the portfolio a consistent story when pitched.

---

*See per-repo `ROADMAP_2026.md` files for concrete action plans, and the shared `LAUNCH_PLAYBOOK_2026.md` for the 90-day growth playbook.*
