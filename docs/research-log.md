# Research Log

Per [`CLAUDE_PROMPT.md`](../CLAUDE_PROMPT.md) §8: every non-trivial roadmap change must cite a primary-source verification. This log records each research session — date, topic, URLs consulted, and the conclusion that informed the change.

Cite this file from PR descriptions via anchor (e.g. `docs/research-log.md#2026-04-18-claude-agent-sdk-rename`).

---

## 2026-04-18 — Claude Agent SDK rename

**Driver:** Roadmap [#6](https://github.com/sattyamjjain/agent-airlock/issues/6) Phase 1.1. Prompt: *"Update all references from 'Claude Code SDK' to 'Claude Agent SDK' ... Verify the current package name via web search on the Anthropic docs and PyPI before renaming imports."*

**Sources consulted:**
- PyPI: https://pypi.org/project/claude-agent-sdk/ — latest `0.1.63`; requires Python ≥ 3.10.
- PyPI JSON: https://pypi.org/pypi/claude-agent-sdk/json — confirmed release metadata.
- GitHub: https://github.com/anthropics/claude-agent-sdk-python — active repo, Python entry point.
- npm: https://www.npmjs.com/package/@anthropic-ai/claude-agent-sdk — TypeScript/JS equivalent.
- Anthropic docs: https://platform.claude.com/docs/en/agent-sdk/overview — official SDK overview.
- Migration guide: https://platform.claude.com/docs/en/agent-sdk/migration-guide — `from claude_code_sdk import query` → `from claude_agent_sdk import query`.

**Findings:**
1. Rename from `claude-code-sdk` → `claude-agent-sdk` is **stable** (first renamed ~Sept 29 2025, current version 0.1.63).
2. The Python import path is `claude_agent_sdk` (underscore). The old `claude_code_sdk` path still exists on PyPI as a separate package but is frozen.
3. **agent-airlock does not import `claude_code_sdk` anywhere in source** — only `examples/anthropic_integration.py` Example 7 references the SDK, and it already uses `from claude_agent_sdk import ClaudeAgentOptions`.

**Conclusion:**
- No code rename required in `src/` or `tests/`.
- Added `[claude-agent]` optional extra in `pyproject.toml` pinned to `claude-agent-sdk>=0.1.58` so users can `pip install "agent-airlock[claude-agent]"`.
- README integration matrix updated to list Claude Agent SDK explicitly.
- No back-compat `claude_code_sdk` shim added: the agent-airlock package does not own that namespace and adding one would shadow a legitimate third-party install.

**Retrieval date:** 2026-04-18.

---

## 2026-04-18 — CI baseline (mypy + bandit regressions on `main`)

**Driver:** Phase 0 verification. CI on `main` had been red since 2026-02-06.

**Sources consulted:**
- GitHub Actions run logs for `sattyamjjain/agent-airlock` runs `23116590327`, `23094908660`, `21738421286`.
- Bandit docs: https://bandit.readthedocs.io/en/1.9.4/plugins/b104_hardcoded_bind_all_interfaces.html — B104 plugin details (CWE-605).
- Mypy changelog: `unused-ignore` flag behavior on mypy 1.8+.

**Findings:**
1. `test (3.11)` failed with single error: `src/agent_airlock/integrations/langchain.py:169: error: Unused "type: ignore" comment`.
2. `security` job failed with single issue: `B104 hardcoded_bind_all_interfaces` at `src/agent_airlock/network.py:249:66` — false positive; the string `"0.0.0.0"` is in a **blocklist** `in` check (`hostname in ("localhost", "0.0.0.0")`) that *rejects* these aliases, not a `socket.bind()` target.

**Conclusion:** Two minimal edits restore CI green. See PR #7.

**Retrieval date:** 2026-04-18.

---

## 2026-04-18 — 2026 policy presets

**Driver:** Roadmap [#6](https://github.com/sattyamjjain/agent-airlock/issues/6) Phase 1.4. `src/agent_airlock/policy_presets.py`.

**Sources consulted:**
- OWASP MCP Top 10 (beta): https://owasp.org/www-project-mcp-top-10/ · https://nest.owasp.org/projects/mcp-top-10 — categories MCP01 token mismanagement, MCP02 excessive permissions, MCP03 tool poisoning, MCP04 supply chain, MCP05 command injection, MCP07 insufficient auth, MCP09 shadow MCP servers, MCP10 context oversharing.
- OWASP Top 10 for Agentic Applications 2026: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ — ASI01 Agent Goal Hijack, ASI02 Tool Misuse, ASI03 Identity/Privilege Abuse, ASI04 Supply Chain, ASI05 Unexpected Code Execution, ASI06 Memory/Context Poisoning, ASI07 Insecure Inter-Agent Communication, ASI08 Cascading Failures, ASI09 Human-Agent Trust, ASI10 Rogue Agents.
- EU AI Act Article 15: https://artificialintelligenceact.eu/article/15/ · https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-15 — cybersecurity resilience for high-risk AI; applies 2 Aug 2026.
- India DPDP Act 2023: https://www.meity.gov.in/static/uploads/2024/06/2bf1f0e9f04e6fb4f8fef35e82c42aa5.pdf — notified by MeitY Nov 13, 2025 + DPDP Rules 2025.
- Anthropic GTG-1002 disclosure (public threat intelligence, late 2025).
- Mexican-government breach public press coverage, Feb 2026.

**Findings:**
1. 5 presets implemented: `GTG_1002_DEFENSE`, `MEX_GOV_2026`, `OWASP_MCP_TOP_10_2026`, `EU_AI_ACT_ARTICLE_15`, `INDIA_DPDP_2023`.
2. Each preset is both an eager constant AND a factory function (mirrors the `_get_strict_capability_policy()` pattern in existing `policy.py`).
3. Presets only change the `SecurityPolicy` / `CapabilityPolicy` layer. Output sanitization (India PII pack), OTel export, and conversation tracking are orthogonal and must be wired by the caller — each preset's docstring says so.
4. `OWASP_AGENTIC_2026_ASI01_ASI10` preset deferred to a follow-up PR: the Agentic Top 10 is broader than what runtime policy alone can cover (ASI01 "goal hijack" needs prompt-layer defenses; ASI07 "inter-agent communication" is the A2A middleware in Phase 1.6). Split rather than overstate.

**Conclusion:**
25 new tests in `tests/test_policy_presets.py`, all passing. Each preset has at least one blocking + one allowing canonical test. Factory-vs-constant equivalence tested.

**Retrieval date:** 2026-04-18.

---

## 2026-04-18 — 9 MCP-adjacent CVEs

**Driver:** Roadmap [#6](https://github.com/sattyamjjain/agent-airlock/issues/6) Phase 1.3 `tests/cves/` gate.

**Sources consulted:** NVD entries + vendor advisories for CVE-2025-59536, CVE-2025-68143, CVE-2025-68144, CVE-2025-68145, CVE-2026-26118, CVE-2026-27825, CVE-2026-27826, CVE-2026-33032, CVE-2026-23744. See https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNNN for each.

**Findings:**
- All nine resolve on NVD. Not UNVERIFIED.
- Strong airlock fit (writable regression): **CVE-2025-68143** (git_init path traversal — SafePath), **CVE-2025-68144** (git ref argument injection — Pydantic strict), **CVE-2025-68145** (repo root confinement — SafePath/filesystem), **CVE-2026-26118** (Azure MCP SSRF — EndpointPolicy, already shipped v0.4.1), **CVE-2026-27825** (mcp-atlassian arbitrary-write — SafePath).
- Partial fit: **CVE-2025-59536** (Claude Code hooks RCE — exfil leg only via network egress), **CVE-2026-27826** (mcp-atlassian header SSRF — only if URL surfaces as a tool param).
- Out of scope for runtime middleware: **CVE-2026-33032** (nginx-ui missing HTTP auth middleware), **CVE-2026-23744** (@mcpjam/inspector missing auth on /api/mcp/connect). These are transport-layer / web-framework bugs; airlock sits in front of tool execution, not HTTP auth.

**Conclusion:**
Phase 1.3 will write regression tests for the 5 strong-fit CVEs in `tests/cves/` with the argument-level patterns that airlock blocks. Partial-fit CVEs get explanatory test cases documenting the bounds of runtime coverage. The two out-of-scope CVEs are excluded from the suite with a note in `tests/cves/README.md`.

**Retrieval date:** 2026-04-18.

---

*Template for future entries:*

```
## YYYY-MM-DD — <topic>

**Driver:** <issue/PR + roadmap section>

**Sources consulted:**
- <URL> — <one-line what it says>

**Findings:**
1. ...

**Conclusion:** <action taken + any UNVERIFIED flags>

**Retrieval date:** YYYY-MM-DD.
```
