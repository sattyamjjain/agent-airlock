# Claude Code — Execution Prompt for agent-airlock

Paste everything below the line into a fresh Claude Code session opened in the root of this repository. Do not edit it. Do not add follow-up instructions.

---

You are taking over the `agent-airlock` repository and executing a 90-day plan to take it from ~5 GitHub stars to 1,000+ stars as a top 1% MCP security middleware. This prompt is the full brief — act on it end-to-end. Keep a running TODO list and tick items off as you finish them. Work in continuous sessions; when a session ends, re-read this prompt and resume from the first unchecked item.

## 0. Ground rules

- Today is after April 18, 2026. Claude Opus 4.7 is current. The Python SDK has been renamed from "Claude Code SDK" to "Claude Agent SDK". The MCP spec version is 2025-11-25. Cowork is GA. Verify anything you're unsure about via web search before writing code.
- Before making ANY non-trivial change, run a web search to confirm the current spec/API/CVE. Cite the URL with a retrieval date in the commit message.
- Never invent version numbers, CVE IDs, or API signatures. If a search returns no authoritative result, flag it `UNVERIFIED:` in the code comment or commit body and ask me in the PR description rather than guessing.
- Python 3.10+, mypy strict, ruff, pytest with coverage ≥79%. Do not lower the coverage gate. Do not add third-party deps unless the roadmap explicitly calls for it.
- Conventional commits. One logical change per PR. Open PRs early and iterate; don't batch weeks of work into one commit.
- Use feature branches named `feat/<topic>`, `fix/<topic>`, `security/<topic>`, `docs/<topic>`. Merge via squash.
- Security-sensitive code lives behind feature flags until proven with tests.

## 1. Read before you start

Read these files in order. Do not skim:

1. `CLAUDE.md` — project conventions
2. `ECOSYSTEM_STATE_2026-04.md` — what the world looks like as of April 2026
3. `ROADMAP_2026.md` — the full 90-day plan for this repo
4. `LAUNCH_PLAYBOOK_2026.md` — shared growth tactics for the three dev-tool repos
5. `README.md`, `CHANGELOG.md`, `PRODUCTION_ROADMAP.md` if present
6. `src/agent_airlock/` directory — scan every file, build a mental model
7. `tests/` directory — run `pytest -v` to confirm the baseline is green before you change anything

If `ECOSYSTEM_STATE_2026-04.md` or `ROADMAP_2026.md` is missing, STOP and tell me; do not proceed from memory.

## 2. Phase 0 — verify the baseline (first session)

1. `pip install -e ".[dev,all]"` — confirm install works on a fresh env.
2. `pytest tests/ -v --cov=agent_airlock --cov-fail-under=79` — record baseline pass count.
3. `mypy src/` and `ruff check src/ tests/` — fix any regressions before touching anything else.
4. Build docs/examples and verify `examples/fastmcp_integration.py` runs.
5. Open a GitHub issue titled "v0.5.0 roadmap — April 2026" and paste a checklist from ROADMAP_2026.md §2.1 and §2.2 into the issue body. Reference this issue from every subsequent PR.
6. Tag the current commit as `v0.4.0-pre-april-2026` so there is a clean rollback point.

## 3. Phase 1 — Must-ship compatibility fixes (Week 0–1)

For each item below, open a PR, link the roadmap issue, write tests first, then code. Verify with web search that the target API is what you think it is.

1. **Claude Agent SDK rename.** Update all references from "Claude Code SDK" to "Claude Agent SDK" in README, examples, and docs. Keep back-compat import shims that emit `DeprecationWarning`. Verify the current package name via web search on the Anthropic docs and PyPI before renaming imports.
2. **MCP 2025-11-25 compliance.** Implement the Tasks primitive (SEP-1686), Streamable HTTP transport, OAuth 2.1 with mandatory PKCE/S256, and DPoP support. Each behind a feature flag in `airlock.toml`. Add `tests/mcp_spec/` with transport-level conformance tests against the reference spec. Search `modelcontextprotocol.io/specification/2025-11-25` to confirm the shape of every field.
3. **2026 CVE regression suite.** Create `tests/cves/` with one test file per CVE listed in ROADMAP §2.1. Each test should reproduce the vulnerable pattern and assert agent-airlock blocks it. Cover at minimum: CVE-2025-59536 (Claude Code hooks), CVE-2025-68143/4/5 (mcp-server-git), CVE-2026-26118 (MS), CVE-2026-27825/27826 (Atlassian), CVE-2026-33032 (Nginx-UI), CVE-2026-23744 (MCPJam). If any CVE number does not resolve on NVD/MITRE, flag `UNVERIFIED` and stop; do not fabricate.
4. **Policy presets.** Add `GTG_1002_DEFENSE`, `MEX_GOV_2026`, `OWASP_MCP_TOP10_2026`, `EU_AI_ACT_ARTICLE_15`, `INDIA_DPDP_2023` to `policy.py`. Each is a `SecurityPolicy` factory with documented rationale linking to the source framework. Tests assert the preset blocks a canonical offending call and allows a canonical compliant call.
5. **SandboxBackend.Managed** for Anthropic Managed Agents. Implement as a new `sandbox_backend.py` subclass. Verify current Managed Agents API via the Anthropic docs before writing the adapter.
6. **A2A protocol middleware.** Add a hook point in `core.py` that lets users plug an A2A validator. Ship a default implementation covering request/response schema validation against the current A2A spec. Web-search the A2A spec repo for the current schema.
7. **Model Armor adapter.** Add an optional `integrations/model_armor.py` that forwards prompts/responses to Google's Model Armor API and surfaces violations as airlock blocks. Opt-in only.
8. **Fix known bugs** from the deep-analysis report: sensitive-param filter misses custom names, streaming sanitizer double-counts tokens on re-entry, capability gating bypass when `@requires` stacked with `@functools.wraps`. Each gets a failing test before the fix.

## 4. Phase 2 — Moat features (Week 2–6)

1. **Airlock Studio** — a local-only dashboard (single binary, stdlib + one small frontend dep allowed). Shows real-time blocks, policy violations, cost/budget burn, and CVE-rule triggers from the OTel stream. Runs on `airlock studio` CLI. Include a 30-second demo GIF in `/docs/media/studio.gif`.
2. **Opt-in small judge model.** Wire Claude Haiku 4.5 (default) and Atla Selene 8B (alt) as second-opinion scorers for borderline blocks. Cost-capped by default.
3. **Marketplace plugin packaging.** Add `.claude-plugin/marketplace.json`, `plugin.json`, and package the install flow. Submit PRs to `anthropics/claude-plugins-official`, `claudemarketplaces.com`, `aitmpl.com`, `buildwithclaude.com`. Track PR URLs in the roadmap issue.
4. **Blocked-CVE demo.** Record a 60-second screencast showing a live CVE payload blocked with `fix_hints` returned. Upload to `/docs/media/blocked-cve.mp4` and also as a GIF.
5. **Performance benchmarks in CI.** Add `benchmarks/` with pytest-benchmark suites for the hot paths (validator, sanitizer, policy resolve, sandbox roundtrip). Fail CI on >15% regression vs baseline.
6. **OTel semconv stabilization.** Publish the agent-airlock semantic conventions (spans, attributes) in `docs/observability/semconv.md`. Align with the OpenTelemetry GenAI semconv working group — web-search `opentelemetry.io/docs/specs/semconv/gen-ai` for current attribute names.

## 5. Phase 3 — Documentation and polish

1. Rewrite the README hero to: tagline from roadmap §5, a 20-second looping GIF, a 3-command quickstart, and a "why airlock over X" matrix (X = Snyk Agent Scan, Lakera Guard, PANW, Invariant, Cloudflare MCP, Google Model Armor). Keep each cell to one sentence.
2. Add `docs/` site using MkDocs Material. Structure: Getting Started → Concepts → Security Layers → Policy Cookbook → CVE Catalog → Integrations → Observability → Compliance → Reference.
3. Publish a CVE catalog page auto-generated from `tests/cves/` — every regression test surfaces as a catalog entry with a remediation snippet.
4. Add an `examples/` folder that runs end-to-end against a real MCP server (use Anthropic's reference MCP server repo). Each example is a one-file demo with inline comments.
5. Add `CONTRIBUTING.md`, `SECURITY.md` with a public PGP key and a 48h triage SLA, `CODE_OF_CONDUCT.md`, and an issue-template set (bug, feature, CVE-rule-request, vuln-report).

## 6. Phase 4 — Launch

Launch only after Phase 1 is 100% merged and tests are green. Do not launch on a Friday.

1. **Target date**: a Tuesday at 13:00 UTC. Confirm the date with me in the launch-readiness PR.
2. **HN submission**: title per LAUNCH_PLAYBOOK_2026.md. Link the GIF, not the repo. You stay in the thread for 4 hours replying to every question. Draft the top-3 anticipated questions and canned answers in `/docs/launch/hn-faq.md` first.
3. **Reddit**: `/r/ClaudeAI` (747k), `/r/LocalLLaMA` (688k), `/r/netsec`. Same day, different angle in each. Never cross-post verbatim.
4. **X/Twitter thread**: 8 tweets, lead with the blocked-CVE GIF, one tweet per defense layer, final tweet links the repo. Drafts in `/docs/launch/x-thread.md`.
5. **DM list**: 10 targeted creators (simonw, swyx, karpathy, Theo, and 6 security-focused devs). Drafts in `/docs/launch/dm-templates.md` — each personalized with a repo-specific demo.
6. **Changelog + release**: cut `v0.5.0`, publish to PyPI, attach release notes with GIF. Tag release with `launch-2026-04-xx`.

## 7. Phase 5 — Post-launch (Week 5–12)

Run these concurrently:

1. 48-hour CVE-to-rule SLA: for every new MCP CVE published on NVD, open a PR with a regression test within 48 hours. Automate detection via a GitHub Action that watches the NVD feed keyword `MCP` and `Model Context Protocol`.
2. Weekly CVE digest blog post on `/blog/` (Substack mirror). This is the leaderboard-ownership play from the playbook.
3. Issue SLA: triage within 24h, label, respond within 72h for the first 60 days. Track SLA compliance in a pinned issue.
4. Partner case studies: three design partners running airlock in production, each gets a 500-word case study published at weeks 8, 10, 12.
5. Conference submissions: Latent Space (warm intro via Discord first), Changelog, Fireship, ThePrimeagen. Drafts in `/docs/launch/pitches.md`.

## 8. Research discipline

Before every non-trivial change, do the following and cite in the PR:

1. Web-search the authoritative source (Anthropic docs, modelcontextprotocol.io, NVD, vendor security advisory).
2. Paste the URL + retrieval date into the PR description.
3. If the source disagrees with the roadmap, open a discussion in the roadmap issue before coding. Roadmap is a plan, not a law — correct it when reality moves.
4. Maintain `docs/research-log.md` with one row per research session: date, topic, URLs, conclusion.

## 9. Metrics I care about

Update `docs/metrics.md` weekly with:

- GitHub stars, forks, watchers
- PyPI downloads (pypistats)
- Docs site uniques (Plausible/Umami, not GA)
- Discord signups
- CVE-to-rule latency (hours)
- Median PR review time
- Open issue SLA compliance %

Target at 90 days: 1,500 stars, 100k PyPI downloads, 500 Discord members, 90% SLA compliance.

## 10. What you must not do

- Do not ship a "hosted SaaS" version. The moat is offline + OSS + stdlib.
- Do not add heavyweight deps (torch, transformers) — keep install instantaneous.
- Do not remove the E2B sandbox backend; add alternatives alongside it.
- Do not fabricate CVE numbers, model names, or API signatures. When unsure, flag `UNVERIFIED:` and search.
- Do not publish the HN/Reddit posts without first opening a launch-readiness PR that checks: demo GIF exists, CVE regression suite is green, release is tagged, FAQ is drafted, rollback plan is documented.

## 11. When you get stuck

- If a spec is ambiguous — web-search the spec repo for recent issues/discussions.
- If a CVE is unclear — read the vendor advisory AND the NVD entry AND any published POC; triangulate.
- If a test fails intermittently — mark it `@pytest.mark.flaky` with a TODO and open an issue; do not ignore it.
- If you make a change and stars don't move within two weeks post-launch — revisit the playbook, run a small post-mortem, then pivot the next week's work.

Begin with Phase 0. Open PRs as you go. When Phase 1 is 100% merged, ping me in the roadmap issue before starting Phase 2.
