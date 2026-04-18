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

## 2026-04-18 — Deep-analysis bug triage

**Driver:** Roadmap [#6](https://github.com/sattyamjjain/agent-airlock/issues/6) Phase 1.8. The execution brief listed three claimed bugs: (1) sensitive-param filter misses custom names; (2) streaming sanitizer double-counts tokens on re-entry; (3) capability gating bypass when `@requires` stacked with `@functools.wraps`.

**Sources consulted:** the source tree (`src/agent_airlock/core.py`, `streaming.py`, `capabilities.py`) and the Python `functools` module (for `functools.wraps` semantics — `WRAPPER_ASSIGNMENTS` + `WRAPPER_UPDATES = ('__dict__',)`).

**Findings:**
1. **Bug 1 is real.** `_filter_sensitive_keys` used `k.lower() not in SENSITIVE_PARAM_NAMES` — an exact-match frozenset check. Custom compound names (`user_password`, `my_api_key`, `aws_secret_key`, `session_cookie`, `db_token`) bypassed the filter and leaked to debug logs. Fix: substring match against a new `SENSITIVE_PARAM_SUBSTRINGS` tuple.
2. **Bug 2 is UNVERIFIED.** I could not reproduce a double-count in `StreamingAirlock`. `wrap_generator` / `wrap_async_generator` call `self.reset()` before iterating, `create_streaming_wrapper` constructs one instance per decorated function but every call goes through `wrap_generator` (which resets), and `_sanitize_chunk` increments `sanitized_count` exactly once per chunk. Asserted the current (correct) behaviour with three regression tests so a future change that introduces a double-count trips the suite. Flagged UNVERIFIED rather than silently fabricating a fix.
3. **Bug 3 claim is mis-stated; underlying bug is real.** `functools.wraps` merges the wrapped function's `__dict__` into the wrapper's, which PRESERVES `__airlock_capabilities__`. The real failure mode is an OUTER decorator that does NOT use `functools.wraps` — such a wrapper drops the attribute, and `get_required_capabilities` (using a plain `getattr`) returned `Capability.NONE`, allowing a bypass. Fix: `get_required_capabilities` now walks the `__wrapped__` chain (bounded to 32 hops to avoid pathological cycles) so that any decorator that preserves `__wrapped__` still surfaces the capability.

**Conclusion:**
- `src/agent_airlock/core.py`: `_filter_sensitive_keys` now uses substring matching. The old `SENSITIVE_PARAM_NAMES` frozenset remains for backward compatibility but is no longer used inside the filter.
- `src/agent_airlock/capabilities.py`: `get_required_capabilities` walks the `__wrapped__` chain.
- `tests/test_deep_analysis_bugs.py`: 15 new tests. 7 failed before the fixes (TDD per the brief) and pass after; 8 cover the UNVERIFIED streaming claim and adjacent correct paths.

**Retrieval date:** 2026-04-18.

---

## 2026-04-18 — Google Cloud Model Armor adapter

**Driver:** Roadmap [#6](https://github.com/sattyamjjain/agent-airlock/issues/6) Phase 1.7. `src/agent_airlock/integrations/model_armor.py`.

**Sources consulted:**
- Overview: https://docs.cloud.google.com/model-armor/overview
- Sanitize prompts / responses: https://docs.cloud.google.com/model-armor/sanitize-prompts-responses
- REST reference: https://docs.cloud.google.com/model-armor/reference/rest
- Python client: https://docs.cloud.google.com/python/docs/reference/google-cloud-modelarmor/latest
- PyPI: https://pypi.org/project/google-cloud-modelarmor/
- Product/pricing: https://cloud.google.com/security/products/model-armor — free up to 2M tokens/month, then $0.10 per million tokens.
- Floor settings for Google-managed MCP (PREVIEW): https://docs.cloud.google.com/model-armor/model-armor-mcp-google-cloud-integration

**Findings:**
1. Regional endpoint: `https://modelarmor.LOCATION.rep.googleapis.com`.
2. Two API methods: `projects/P/locations/L/templates/T:sanitizeUserPrompt` and `...:sanitizeModelResponse`. PyPI: `google-cloud-modelarmor`, client class `ModelArmorClient` from `google.cloud.modelarmor_v1`.
3. Response shape has `sanitization_result.filter_match_state ∈ {MATCH_FOUND, NO_MATCH_FOUND}`, plus `rai_filter_result`, `sdp_filter_result`, `pi_and_jailbreak_filter_result`, `malicious_uri_filter_result`, `csam_filter_filter_result`.
4. Auth: ADC, service account JSON via `GOOGLE_APPLICATION_CREDENTIALS`, or OAuth bearer token. No API-key flow.
5. Floor settings for Google-managed MCP are PREVIEW — enforced server-side, no adapter code required.

**UNVERIFIED items (per background research agent):**
- Exact proto field names in `modelarmor_v1` (snake_case vs camelCase in the Python client). Adapter uses documented snake_case names wrapped in `getattr` + safe fallbacks so a Google-side rename surfaces as "no detection" rather than a crash.
- `sanitize_model_response` canonical request field (`userPrompt` vs `userPromptData`). Adapter sends both via `user_prompt=...` kwarg; lets server ignore unrecognised fields.
- Quota / RPS numbers (not quoted on the public docs page fetched).
- Billed in tokens vs characters — phrasing is ambiguous on the product page.

**Conclusion:**
- `src/agent_airlock/integrations/model_armor.py` implements `ModelArmorScanner` (opt-in, `AIRLOCK_MODEL_ARMOR_ENABLED=1` + `AIRLOCK_MODEL_ARMOR_TEMPLATE=...`). Callers invoke `scan_user_prompt(...)` / `scan_model_response(...)` explicitly before/after tool execution.
- `[model-armor]` optional extra pinned `google-cloud-modelarmor>=0.2`.
- 14 tests in `tests/test_model_armor_integration.py` using stub client (no live API calls).

**Retrieval date:** 2026-04-18.

---

## 2026-04-18 — A2A protocol middleware

**Driver:** Roadmap [#6](https://github.com/sattyamjjain/agent-airlock/issues/6) Phase 1.6. `src/agent_airlock/a2a.py`.

**Sources consulted:**
- Canonical repo: https://github.com/a2aproject/A2A — the older `google/A2A` redirects here; project donated to Linux Foundation.
- Rendered spec: https://a2a-protocol.org/latest/specification/ — v1.0 shipped early 2026, with `/v0.3.0/` and `/dev/` versioned branches.
- "What's new in v1.0": https://a2a-protocol.org/latest/whats-new-v1/
- A2A + MCP relationship (complementary): https://a2a-protocol.org/latest/topics/a2a-and-mcp/
- Python SDK: https://pypi.org/project/a2a-sdk/ (Apache 2.0, Python ≥ 3.10, covers transport/HTTP/gRPC).
- Normative `.proto` file: `spec/a2a.proto` in the A2A repo (search-only access; not fetched line-by-line).

**Findings:**
1. A2A is JSON-RPC 2.0 over HTTP(S). Methods in the v1.0 core set: `message/send`, `message/stream`, `tasks/get`, `tasks/cancel`, `tasks/resubscribe`. Three transport bindings: JSON-RPC over HTTP POST, gRPC, HTTP+JSON (REST). Streaming uses Server-Sent Events.
2. Core shapes: `Message` has required `messageId`, `role ∈ {user, agent}`, `parts`, `kind = "message"`; optional `taskId`, `contextId`, `referenceTaskIds`, `extensions`, `metadata`. `Task` has required `id`, `status`, `kind = "task"`; optional `contextId`, `history`, `artifacts`, `metadata`. `Part` is a union (text / file / data).
3. Auth lives at the HTTP layer — OAuth2 / OIDC advertised in the AgentCard security schemes. **JSON-RPC payloads do NOT carry identity.** The middleware must not try to authenticate from the body.
4. A2A is complementary to MCP: A2A = agent-to-agent (horizontal), MCP = agent-to-tool (vertical). Confirmed at `a2a-protocol.org/latest/topics/a2a-and-mcp/`.

**UNVERIFIED items (flagged in code):**
- Exact v1.0 release date and field-level diff vs v0.3.0. Models below mirror v0.3.0 fields that search results indicate are unchanged in v1.0.
- `Task.contextId` required-vs-optional in the normative proto.
- AgentCard full required/optional split (not modelled here; belongs in a future PR if we add full AgentCard validation).

**Conclusion:**
- `src/agent_airlock/a2a.py` implements: `JSONRPCRequest` / `JSONRPCResponse` / `JSONRPCError` Pydantic models, `Message` / `Task` / `Part` / `TaskStatus` models (Pydantic strict, `extra="forbid"` at envelope level, `extra="allow"` on `Part` to preserve binding-specific content), and an `A2AValidator` with a pluggable `A2ACustomValidator` hook.
- 25 tests in `tests/test_a2a.py` covering envelope validation, method allow-list, `result` XOR `error` response invariant, `Message` / `Task` schema violations, and the custom-hook lifecycle (including exception containment).
- Transport concerns (HTTP, gRPC, SSE) deliberately out of scope — callers should use `a2a-sdk` for transport and feed payloads to this validator.

**Retrieval date:** 2026-04-18.

---

## 2026-04-18 — MCP 2025-11-25 compliance

**Driver:** Roadmap [#6](https://github.com/sattyamjjain/agent-airlock/issues/6) Phase 1.2. `src/agent_airlock/mcp_spec/`.

**Sources consulted (all fetched 2026-04-18):**
- https://modelcontextprotocol.io/specification/2025-11-25 — top-level spec (protocol overview, normative references).
- https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization — **primary source** for every OAuth / PKCE / resource-parameter requirement implemented here. Includes the exact normative `WWW-Authenticate` examples used in test fixtures.
- https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1686 — SEP-1686 tracking issue for the Tasks primitive.
- https://blog.modelcontextprotocol.io/posts/2025-11-25-first-mcp-anniversary/ — release-notes summary confirming the Tasks primitive, Streamable HTTP, and OAuth 2.1 mandate are the three load-bearing additions.
- RFC 7636 §4.1 + §4.2 (PKCE generation/transform) — known-vector test in `test_rfc7636_known_vector`.
- RFC 8707 (Resource Indicators) — canonical URI rules per spec §"Canonical Server URI".
- RFC 8414 (OAuth 2.0 AS Metadata) and RFC 9728 (Protected Resource Metadata) — referenced by the spec for discovery.

**Findings:**
1. **PKCE S256 is the only acceptable method.** Spec §"Authorization Code Protection": "MCP clients MUST use the `S256` code challenge method when technically capable" + "If `code_challenge_methods_supported` is absent, the authorization server does not support PKCE and MCP clients MUST refuse to proceed." → `AuthorizationServerMetadata.code_challenge_methods_supported` Pydantic validator rejects any value set lacking `"S256"`.
2. **Redirect URIs MUST be localhost or HTTPS** (spec §"Communication Security"). `validate_redirect_uri` accepts `https://`, rejects `http://` unless the host is `localhost` / `127.0.0.1` / `[::1]`.
3. **Access tokens MUST be `Authorization: Bearer`** (spec §"Access Token Usage"). Query-string tokens explicitly forbidden — the Streamable HTTP validator rejects `?access_token=` or `?bearer=` on any URL.
4. **`resource` parameter (RFC 8707) is mandatory.** `canonicalize_resource_uri` normalises to lowercase scheme+host, strips trailing slash except on bare `/`, and rejects fragments per spec §"Canonical Server URI".
5. **Token audience validation is mandatory.** Spec §"Token Handling": "MCP servers MUST validate that access tokens were issued specifically for them as the intended audience." `validate_access_token_audience` accepts string `aud`, list `aud`, canonicalises both sides, and rejects missing/mismatched/non-string types.
6. **401 responses MUST include `WWW-Authenticate`** with either a `resource_metadata` param (preferred) or enough Bearer-scheme info for well-known-URI fallback.
7. **MCP-Protocol-Version header** is enforced on every Streamable HTTP request; value `2025-11-25` matches the spec revision this module implements.

**UNVERIFIED items (flagged in code):**
- Exact Tasks primitive state-name spelling (`working` / `input_required` / `completed` / `failed` / `cancelled`) — confirmed by release-notes summary but not verified against `spec/schema.ts` line-by-line. If the normative proto uses different casing, `TaskState` is the only module to update.
- `tasks/resubscribe` method shape — listed in search results; not modelled in this PR. Follow-up can add `TaskResubscribeRequest`.
- **DPoP deliberately skipped.** The executed spec page lists DPoP only under "MCP Authorization Extensions" as an optional additive extension — not a normative requirement for 2025-11-25. No implementation attempt was made; flagged UNVERIFIED rather than guessed.

**Conclusion:**
- New submodule `src/agent_airlock/mcp_spec/` with `oauth.py` (PKCE + metadata + redirect URI + audience validation), `tasks.py` (Pydantic V2 strict models for SEP-1686), and `transport.py` (Streamable HTTP request/response validators).
- 81 conformance tests in `tests/mcp_spec/`, all passing. Uses the literal `WWW-Authenticate` examples from the spec page as fixtures so the parser is checked against the canonical wire format.
- Scope: runtime validators, not an OAuth server or MCP server framework. Callers (e.g. the FastMCP integration) invoke `validate_streamable_http_request(...)` on incoming requests and `validate_access_token_audience(...)` inside their token middleware.

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
