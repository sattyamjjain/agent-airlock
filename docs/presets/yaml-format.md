# Declarative preset YAML format (v1)

**New in v0.5.7.** Compose multiple agent-airlock presets in a single
YAML file. The loader uses a **stdlib-only** restricted-grammar
parser — no PyYAML dependency.

## Why declarative?

The OX Security 2026-04-15 disclosure produced 14+ CVEs in two
weeks. The Python factory `ox_mcp_supply_chain_2026_04_defaults()`
covers the umbrella, but Go / TS / Rust SDK consumers can't call
Python factories. A declarative file gives every SDK a
machine-readable target — they can render the same composite by
walking the YAML.

## Quick start

```bash
# The shipped composite preset for the OX-disclosure family:
airlock --preset-file presets/ox-mcp-2026-04.yaml
```

Or programmatically:

```python
from pathlib import Path
from agent_airlock.preset_loader import load_yaml_preset, compose_preset_factories

loaded = load_yaml_preset(Path("presets/ox-mcp-2026-04.yaml"))
composed = compose_preset_factories(loaded)
# composed["gitpilot_mcp_cve_2026_6980"] is the same dict as
# gitpilot_mcp_cve_2026_6980_defaults() returns.
```

## v1 schema

```yaml
schema_version: 1
preset_id: ox-mcp-2026-04            # kebab-case; pattern `[a-z0-9][a-z0-9-]*`
description: "free-form text"        # optional
primary_source: https://...          # required
disclosed_at: 2026-04-15              # ISO YYYY[-MM[-DD]]
presets:                              # list of preset entries
  - id: stdio_guard_ox_defaults      # entry id
    factory: stdio_guard_ox_defaults # factory name in policy_presets module
    primary_source: https://...      # required
    cve_id: CVE-2026-XYZAB           # optional, CVE-prefixed
    disclosed_at: 2026-04-15          # optional override of file-level
    enabled: true                     # optional, default true
    allowlist_fallback: true          # forwarded to factories that accept it
```

JSON-schema spec at [`schemas/preset_v1.json`](../../schemas/preset_v1.json).

## What the parser accepts

- Top-level scalar `key: value` pairs
- Multi-line **double-quoted** string values (continuation lines
  glued with single spaces, terminated by a closing `"`)
- A single `presets:` list whose entries are dicts of scalar fields
- `# ...` line and inline comments
- `true` / `false`, integer literals, `null`, quoted strings

Anything outside this grammar raises `PresetParseError`. This is
**not** a full YAML implementation — by design.

## Why no PyYAML?

agent-airlock has 3 runtime deps (`pydantic`, `structlog`,
`tomli`-on-3.10). Adding PyYAML for a 50-line config grammar
hurts the install footprint and the security-supply-chain story.
The restricted parser is ~200 LOC of stdlib code with full test
coverage.

## Errors

`PresetParseError` (subclasses `AirlockError`) is raised on:

- Missing required top-level field
- `schema_version != 1`
- Empty / non-list `presets`
- Preset entry missing `id`, `factory`, or `primary_source`
- File not found
- Unknown factory name (raised by `compose_preset_factories`)
- Grammar errors (lines the parser cannot interpret)

## OX-MCP composite preset

The shipped [`presets/ox-mcp-2026-04.yaml`](../../presets/ox-mcp-2026-04.yaml)
enables the nine April-2026 OX-disclosure-class presets:

| Entry id | Factory | CVE |
|---|---|---|
| `stdio_guard_ox_defaults` | `stdio_guard_ox_defaults` | (umbrella) |
| `manifest_only_mode` | `manifest_only_mode` | — |
| `gitpilot_mcp_cve_2026_6980` | `gitpilot_mcp_cve_2026_6980_defaults` | CVE-2026-6980 |
| `windsurf_cve_2026_30615` | `windsurf_cve_2026_30615_defaults` | CVE-2026-30615 |
| `mcpjam_cve_2026_23744` | `mcpjam_cve_2026_23744_defaults` | CVE-2026-23744 |
| `flux159_mcp_kubernetes_cve_2026_39884` | `flux159_mcp_kubernetes_cve_2026_39884_defaults` | CVE-2026-39884 |
| `azure_mcp_cve_2026_32211` | `azure_mcp_cve_2026_32211_defaults` | CVE-2026-32211 |
| `unit42_mcp_sampling` | `unit42_mcp_sampling_defaults` | (sampling-vector class) |
| `archived_mcp_server_advisory` | `archived_mcp_server_advisory_defaults` | (Puppeteer advisory class) |

`manifest_only_mode` is `enabled: false` by default — opt in
explicitly per the [manifest-only-mode docs](../mcp/manifest-only-mode.md).

## Primary source

- [OX Security — Mother of All AI Supply Chains (2026-04-15)](https://www.ox.security/blog/mother-of-all-ai-supply-chains-2026-04-20)
