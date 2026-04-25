# Claude Managed Agents audit hook (v0.5.6+)

**Module:** `agent_airlock.integrations.claude_managed_agents`
**Preset:** `agent_airlock.policy_presets.claude_managed_agents_safe_defaults`

## Why this exists

Anthropic launched [Claude Managed Agents](https://claude.com/blog/claude-managed-agents)
to public beta on **2026-04-08** at $0.08/runtime-hour, with Notion,
Rakuten, Asana, Vibecode, and Sentry as named adopters. The runtime
ships a managed harness that exposes a curated tool surface
(`read_file`, `bash`, `web_browse`, `code_execute`) and streams raw
tool inputs/outputs over Server-Sent Events.

Two integration concerns the existing agent-airlock surfaces don't
cover, and this module does:

1. **The harness's tool list bypasses any local
   `SecurityPolicy.allowed_tools` constraint** — a managed agent can
   use `bash` even if your local policy denied shell. This module
   enforces the intersection at the request boundary, before egress.
2. **SSE streaming surfaces raw tool inputs/outputs to the calling
   process** — including any secrets the model emitted while
   reasoning. This module pipes those frames through the v0.5.3
   `log_redaction` filter before the caller's log surface sees them.

## Pin points

The integration pins two constants so you detect Anthropic schema
drift early instead of silently sending malformed requests:

| Constant | Value | What it pins |
|---|---|---|
| `MANAGED_AGENTS_BETA_HEADER` | `"managed-agents-2026-04-01"` | The exact `anthropic-beta` value |
| `AGENT_TOOLSET_VERSION` | `"agent_toolset_20260401"` | The toolset schema |

When Anthropic promotes a newer schema, agent-airlock will bump these
constants and ship a minor version. Until then, requests carrying a
different `toolset_version` raise `UnknownToolsetVersionError`.

## Quick start

```python
from agent_airlock.integrations.claude_managed_agents import (
    ManagedAgentsAuditConfig,
    ManagedAgentSession,
    audit_managed_agent_invocation,
    redact_sse_event,
    MANAGED_AGENTS_BETA_HEADER,
    AGENT_TOOLSET_VERSION,
)

cfg = ManagedAgentsAuditConfig(
    allowed_tools=("read_file", "web_browse"),  # opt in to two harness tools
    require_beta_header=True,
    toolset_version=AGENT_TOOLSET_VERSION,
    redact_sse_payloads=True,
)
session = ManagedAgentSession(session_id="prod-42")

# Before sending the request to Anthropic:
audit_managed_agent_invocation(
    request={
        "tool": "read_file",
        "betas": [MANAGED_AGENTS_BETA_HEADER],
        "toolset_version": AGENT_TOOLSET_VERSION,
        # ... your usual managed-agents request fields
    },
    cfg=cfg,
    session=session,
)

# Per SSE frame the runtime emits:
for line in stream:
    safe = redact_sse_event(line) if cfg.redact_sse_payloads else line
    log.info(safe)
```

## Errors

All three subclass `AirlockError` and are top-level re-exports:

| Error | Raised when |
|---|---|
| `ManagedAgentBetaHeaderMissingError` | Request body's `betas` list doesn't contain `MANAGED_AGENTS_BETA_HEADER` |
| `UnknownToolsetVersionError` | Request `toolset_version` ≠ pinned `AGENT_TOOLSET_VERSION` |
| `ManagedAgentToolBlocked` | Request `tool` not in `cfg.allowed_tools` (intersection refused) |

## Preset

`claude_managed_agents_safe_defaults()` ships **opt-in**: the
returned `ManagedAgentsAuditConfig.allowed_tools` is the empty
tuple. Callers must explicitly list which harness tools they want to
permit — there is no "allow everything" default.

```python
from agent_airlock.policy_presets import claude_managed_agents_safe_defaults

cfg = claude_managed_agents_safe_defaults()
audit = cfg["audit_config"]
audit.allowed_tools = ("read_file", "web_browse")  # opt in explicitly
```

The preset mapping also exposes:
- `cfg["harness_tools"]` — the four documented tools
- `cfg["beta_header"]` — `MANAGED_AGENTS_BETA_HEADER`
- `cfg["toolset_version"]` — `AGENT_TOOLSET_VERSION`
- `cfg["source"]` — primary URL

## Observability

Every clean audit emits an OpenTelemetry span named
`airlock.managed_agents.invoke` with attributes:

- `airlock.managed_agents.session_id`
- `airlock.managed_agents.allowed_count`

Span emission is best-effort — a misconfigured OTel provider will
never break the audit path.

## Composition with `task_budget`

`ManagedAgentSession.invocations` increments on every clean audit, so
you can compose with the v0.5.1 `task_budget` adapter to enforce a
per-session cap:

```python
from agent_airlock.integrations.claude_task_budget import build_output_config

# After each successful audit, render budget into the next request:
body = {
    **build_output_config(total=100_000, remaining=remaining_for(session), soft=False),
    # ... other request fields
}
```

## Primary sources

- [Anthropic — Claude Managed Agents launch (2026-04-08)](https://claude.com/blog/claude-managed-agents)
- [platform.claude.com — Managed Agents overview](https://platform.claude.com/docs/en/managed-agents/overview)
