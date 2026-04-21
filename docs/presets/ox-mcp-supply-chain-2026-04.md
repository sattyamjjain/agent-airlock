# OX MCP Supply-Chain Dossier umbrella preset (v0.5.3+)

On **2026-04-20** [OX Security published](https://www.ox.security/blog/mother-of-all-ai-supply-chains-2026-04-20)
the "Mother of All AI Supply Chains" dossier — 10+ coordinated MCP-
ecosystem CVEs disclosed in a single report. Anthropic publicly
declined to patch four of the six Claude Desktop tool-definition
tampering CVEs, citing "defense-in-depth is the caller's job."
agent-airlock ships the caller's side of that defense as one
umbrella preset that composes existing primitives plus three new
micro-checks.

## Coverage

| CVE | Component | Class | Handled by |
|---|---|---|---|
| CVE-2025-65720 | mcp-python-sdk | path traversal | pre-existing `SafePath` |
| CVE-2026-30615 | Claude Desktop MCP | tool-def tamper | `ToolDefinitionRegistry` (new) |
| CVE-2026-30617 | Claude Desktop MCP | tool-def tamper | `ToolDefinitionRegistry` (new) |
| CVE-2026-30618 | Claude Desktop MCP | tool-def tamper | `ToolDefinitionRegistry` (new) |
| CVE-2026-30623 | Claude Desktop MCP | tool-def tamper | `ToolDefinitionRegistry` (new) |
| CVE-2026-30624 | Claude Desktop MCP | tool-def tamper | `ToolDefinitionRegistry` (new) |
| CVE-2026-30625 | Claude Desktop MCP | tool-def tamper | `ToolDefinitionRegistry` (new) |
| CVE-2026-26015 | OpenAI MCP Bridge | SSRF | `check_mcp_bridge_target()` (new) |
| CVE-2026-33224 | LlamaIndex MCP adapter | unsafe deserialization | `check_tool_response_content_type()` (new) |
| CVE-2026-40933 | Semantic Kernel MCP | auth-header leak | pre-existing `header_audit` (Azure preset) |

## Usage

```python
from agent_airlock.policy_presets import ox_mcp_supply_chain_2026_04_defaults

cfg = ox_mcp_supply_chain_2026_04_defaults()

# Tool manifest registration + verification (TOFU — trust first, detect change)
cfg["tool_registry"].register("read_file", manifest)
cfg["tool_registry"].verify("read_file", manifest_at_call_time)

# SSRF guard for any tool that fetches a URL
cfg["bridge_ssrf_check"]("https://api.example.com/x")

# Deserialization refusal
cfg["content_type_check"]("application/x-python-pickle", tool_name="llama_x")

# Destructive-tool + eval-token checks (same as the individual presets)
cfg["destructive_tool_check"](my_tools)
cfg["eval_token_check"](my_tools)
```

## What it does NOT do

- It does not patch upstream. Every component above has an upstream
  fix you should apply. The umbrella is a **second layer** that
  catches regressions when the upstream patch is skipped or delayed.
- It does not verify tool-manifest signatures — the registry uses a
  trust-on-first-use (TOFU) model. If the attacker tampers with the
  first manifest you see, the digest is poisoned. Pair with code-
  review / SBOM + package-signature checks.
- It does not block every SSRF target — custom internal ranges
  specific to your deployment need to be added to your own allow-
  or deny-list.

## Primary sources

- [OX dossier](https://www.ox.security/blog/mother-of-all-ai-supply-chains-2026-04-20)
- [The Hacker News coverage](https://thehackernews.com/2026/04/ox-security-mcp-dossier.html)
- Per-CVE NVD URLs in [`tests/cves/fixtures/ox_supply_chain_2026_04.json`](../../tests/cves/fixtures/ox_supply_chain_2026_04.json)
- Regression tests: [`tests/cves/test_ox_supply_chain_2026_04.py`](../../tests/cves/test_ox_supply_chain_2026_04.py)
