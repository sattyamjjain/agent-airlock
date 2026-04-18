# OpenTelemetry semantic conventions

This page documents the spans and attributes agent-airlock emits on the
OTel audit exporter (`agent_airlock.audit_otel`, enabled via
`AirlockConfig.otel_enabled=True`). Treat these as a contract: downstream
dashboards, saved searches, and SIEM rules depend on the names below.

## Design principles

1. **Namespace first.** All airlock-specific attributes live under
   `airlock.*`. When an upstream OTel semantic convention exists (OTel
   GenAI SIG `gen_ai.*`, OTel HTTP `http.*`, `server.*`), use the upstream
   name and mirror to `airlock.*` for discoverability.
2. **Only stable names here.** Anything under `airlock.experimental.*` is
   NOT part of this contract and can change between minor releases.
3. **Low cardinality.** `airlock.tool_name` is medium cardinality; tool
   arguments are never attached as attributes (they're sent through the
   audit sink or hashed, not raw).

## Spans

### `airlock.tool_call`

One span per invocation of an `@Airlock()`-wrapped function. Parent-child
relationship: a wrapped function called from another wrapped function
creates a child span.

| Status | Meaning |
| --- | --- |
| `OK` | Tool ran to completion. `airlock.blocked = false`. |
| `ERROR` | Block, validation failure, or execution exception. `airlock.block_reason` carries the reason. |

## Required attributes

Set on every `airlock.tool_call` span.

| Attribute | Type | Notes |
| --- | --- | --- |
| `airlock.version` | string | `agent_airlock.__version__`, e.g. `0.5.0`. |
| `airlock.tool_name` | string | Qualified name of the wrapped function (`module.func`). |
| `airlock.blocked` | bool | `true` if airlock returned before the wrapped function ran. |

## Optional attributes

Set when the relevant feature produced data for this call.

### Identity

| Attribute | Type | Notes |
| --- | --- | --- |
| `airlock.agent_id` | string | Logical agent identifier supplied by the caller. `"unknown"` if the caller did not set it. |
| `airlock.session_id` | string | Session identifier from `AirlockContext`. Useful for correlating a conversation across multiple tool calls. |

### Policy / validation

| Attribute | Type | Notes |
| --- | --- | --- |
| `airlock.policy_id` | string | Human-readable policy name (e.g. `GTG_1002_DEFENSE`). |
| `airlock.policy_hash` | string | SHA-256 hash of the serialized policy object. Same hash ⇒ same rules; lets you prove which policy was in effect at the time of the call. |
| `airlock.unknown_args_mode` | string | One of `BLOCK`, `STRIP_AND_LOG`, `STRIP_SILENT`. |
| `airlock.required_capabilities` | string | Comma-separated list of `Capability` flags required by the wrapped function. |
| `airlock.granted_capabilities` | string | Comma-separated list of capabilities actually granted by the active `CapabilityPolicy`. |

### Block-path detail (set only when `airlock.blocked=true`)

| Attribute | Type | Notes |
| --- | --- | --- |
| `airlock.block_reason` | string | One of `validation_error`, `policy_violation`, `capability_denied`, `rate_limited`, `filesystem_denied`, `network_denied`, `circuit_open`, `budget_exceeded`, `sandbox_unavailable`. |
| `airlock.error` | string | Short error message (no PII, no stack frames). |
| `airlock.violation_type` | string | When `block_reason=policy_violation`, the `ViolationType` enum value. |

### Sandbox execution

| Attribute | Type | Notes |
| --- | --- | --- |
| `airlock.sandbox_backend` | string | `e2b`, `docker`, `managed`, `local`, or `none`. |
| `airlock.sandbox_id` | string | Backend-specific sandbox or session identifier. |
| `airlock.sandbox_duration_ms` | int | Wall-clock time spent inside the sandbox. |

### Network egress

| Attribute | Type | Notes |
| --- | --- | --- |
| `airlock.egress_domains` | string | Comma-separated list of domains the tool reached during this span. Populated when `NetworkPolicy` is attached. |

### Cost

| Attribute | Type | Notes |
| --- | --- | --- |
| `airlock.cost.input_tokens` | int | Prompt-side tokens charged to this call. |
| `airlock.cost.output_tokens` | int | Completion-side tokens charged to this call. |
| `airlock.cost.total_usd` | double | Total USD for this call (rounded to 6 decimal places). |

### Output sanitization

| Attribute | Type | Notes |
| --- | --- | --- |
| `airlock.sanitized_count` | int | Number of PII / secret detections the sanitizer masked on this response. |
| `airlock.truncated` | bool | `true` if the output was truncated by the configured token or character limit. |
| `airlock.args_hash` | string | SHA-256 of the canonicalised argument tuple. Useful for replay detection in post-incident analysis. Never contains argument *values*. |

## Events

The airlock exporter emits span events for notable in-span incidents so
they're attached to the same trace root without needing a separate
metric pipeline.

| Event name | When emitted |
| --- | --- |
| `airlock.validation_error` | Pydantic strict validation rejected arguments. Attributes: `airlock.validation.field`, `airlock.validation.message`. |
| `airlock.honeypot_triggered` | Honeypot path returned fake-success data instead of an error. Attributes: `airlock.honeypot.strategy`. |
| `airlock.circuit_state_changed` | Circuit breaker transitioned. Attributes: `airlock.circuit.from`, `airlock.circuit.to`. |

## Relationship to upstream conventions

- **OTel GenAI SIG** (`gen_ai.*`) — airlock sits in front of tool calls,
  not model inference. Spans that wrap an LLM call (e.g. a judge model
  scoring a borderline block) additionally set the `gen_ai.*` attributes
  per the OTel GenAI semconv draft. Airlock does NOT re-emit those under
  `airlock.*`.
- **OTel HTTP** (`http.*`, `server.*`, `url.*`) — when a wrapped tool
  hits an HTTP endpoint, the HTTP instrumentation sets those attributes
  on a child span. Airlock's `airlock.egress_domains` is a coarse
  summary for the parent span; the fine-grained request attributes live
  on the child.

## Stability

Names above are stable across the v0.5.0 minor series. Breaking changes
to an attribute name or removal ship in the next minor bump with a
deprecation note in `CHANGELOG.md`.

Anything under `airlock.experimental.*` may change or disappear without
notice.
