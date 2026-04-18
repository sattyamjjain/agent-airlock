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
