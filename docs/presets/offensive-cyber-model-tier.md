# Offensive-cyber model tier preset (v0.5.5)

**Module:** `agent_airlock.policy_presets.offensive_cyber_model_defaults`
**Companion:** `agent_airlock.capabilities.ModelCapabilityTier`,
`agent_airlock.integrations.model_tier.classify_model`

## Why this exists

On 2026-04-23 InfoQ published [Anthropic Claude Mythos
Preview](https://www.infoq.com/news/2026/04/anthropic-claude-mythos/),
reporting autonomous zero-day discovery capabilities in frontier
models. Earlier in April, Unit 42 ran MCP attack-vector benchmarks
against GPT-5-2-Codex and Claude Opus 4.x showing reliable
chained-reasoning on reconnaissance + privilege-escalation +
exploit-synthesis prompts.

The *capability floor* for agentic tool calls has shifted in the
direction of danger. agent-airlock's existing `CapabilityPolicy`
already lets callers hand-deny sensitive flags — this preset adds a
**model-aware default** so the same Python app can be driven by a
weak model with permissive policy and by a frontier model with
automatically-tightened policy, with only a `model_id` argument
changing between them.

## Tier table

| Tier                         | Example model IDs                              | Denied capabilities                                                          |
|------------------------------|------------------------------------------------|------------------------------------------------------------------------------|
| `STANDARD`                   | `gpt-4`, `claude-3-sonnet`, `llama-2`, `gemini-pro` | *none* — caller owns policy entirely                                      |
| `OFFENSIVE_CYBER_CAPABLE`    | `claude-opus-4`, `claude-opus-4-6/4-7`, `gpt-5-2-codex`, `o4` | `PROCESS_SHELL`, `FILESYSTEM_WRITE`, `FILESYSTEM_DELETE`, `NETWORK_ARBITRARY` |
| `ZERO_DAY_CAPABLE`           | `claude-mythos-preview`                        | all of the above plus `PROCESS_EXEC`, `NETWORK_ALL`                          |

The table is deliberately conservative: unknown model IDs fall back to
`STANDARD` so a typo never *weakens* policy. To tighten unknown
models, classify explicitly by constructing a `CapabilityPolicy` with
`model_tier=ModelCapabilityTier.OFFENSIVE_CYBER_CAPABLE` yourself.

## Usage

```python
from agent_airlock import Airlock
from agent_airlock.policy_presets import offensive_cyber_model_defaults

cap_policy = offensive_cyber_model_defaults(model_id="claude-opus-4-7")

@Airlock(capability_policy=cap_policy)
def run_tool(cmd: str) -> str: ...
```

If the driving model is later swapped for GPT-5-2-Codex, the same
one-liner produces the same tier-level defaults — no branching in
application code.

### Escape hatch

If a trusted workflow genuinely needs e.g. `PROCESS_SHELL` under an
offensive-cyber-capable model, layer a broader policy on top:

```python
from agent_airlock.capabilities import Capability, CapabilityPolicy

baseline = offensive_cyber_model_defaults(model_id="claude-opus-4-7")
relaxed = CapabilityPolicy(
    granted=baseline.granted | Capability.PROCESS_SHELL,
    denied=baseline.denied & ~Capability.PROCESS_SHELL,
    require_sandbox_for=baseline.require_sandbox_for,
    model_tier=baseline.model_tier,  # keep the tier tag for audit logs
)
```

The `model_tier` field is preserved for observability so audit logs
carry the classification even when the application overrides the
denied set.

## Primary sources

- Anthropic Mythos Preview — InfoQ, 2026-04-23:
  <https://www.infoq.com/news/2026/04/anthropic-claude-mythos/>
- Unit 42 MCP attack-vector catalog — 2026-04-24:
  <https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/>
