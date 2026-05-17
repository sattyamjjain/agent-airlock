# OpenAPI Drift Guard (v0.8.1+, Hermes 2026-05-13 paper anchor)

`agent_airlock.mcp_spec.openapi_drift_guard.OpenAPIDriftGuard` is the
runtime validator for the **payload-shape drift** failure class
identified by the Hermes paper ([arXiv:2605.14312][hermes],
2026-05-13).

## Why

Hermes measured production OpenAPI-driven agent failures and found
that the dominant failure mode is **payload-shape drift** — the
model emits a tool-call body that violates the published OpenAPI
schema. The three sub-categories the paper enumerates:

| Divergence kind | What it looks like |
|---|---|
| `missing_required` | A field listed under `required` in the schema is absent from the body |
| `unknown_field` | A field appears in the body that is not declared in `properties` (and `additionalProperties: false`) |
| `type_mismatch` | A declared field carries a value of the wrong JSON type (e.g. integer where string is required) |

agent-airlock's v0.7.x / v0.8.0 guards catch *exploit shapes* (eval
sinks, shell metachars, vulnerable packages). This guard catches
**drift** one layer earlier — the malformed payload never reaches
the eval guard because it never reaches the tool.

[hermes]: https://arxiv.org/abs/2605.14312

## Install

Core. No optional extra. The guard imports only `dataclasses` /
`enum` / `re` / `structlog` from the existing dependency set. **No
PyYAML, no JSON-Schema validator, no OpenAPI spec-loader is pulled
in** — the caller supplies a parsed dict.

## Drift modes

```python
from agent_airlock import OpenAPIDriftGuard

guard = OpenAPIDriftGuard(spec=my_spec_dict, drift_mode="strict")
```

| Mode | Behaviour on drift | When to use |
|---|---|---|
| `strict` (default) | `allowed=False`, verdict `DENY_DRIFT` | Production. Refuse the call. |
| `warn` | `allowed=True`, verdict `ALLOW_WARN`, structured log emitted | Rolling out the guard. Watch logs, fix the spec or the agent, then flip to strict. |
| `shadow` | `allowed=True`, verdict `ALLOW_SHADOW`, no log | Pre-rollout calibration. Record divergences off the decision object without polluting logs. |

## Quickstart

```python
import json
from pathlib import Path

from agent_airlock import OpenAPIDriftGuard, OpenAPIDriftVerdict

spec = json.loads(Path("openapi.json").read_text())
guard = OpenAPIDriftGuard(spec=spec, drift_mode="strict")

decision = guard.evaluate(
    operation_id="createUser",
    args={"email": "a@b.co"},  # age missing
)
assert decision.allowed is False
assert decision.verdict == OpenAPIDriftVerdict.DENY_DRIFT
for d in decision.divergences:
    print(d.kind.value, d.field, d.expected, d.observed)
```

## `vaccinate_openapi` helper

For drop-in tool wrapping:

```python
from agent_airlock import vaccinate_openapi

vaccine = vaccinate_openapi(spec, drift_mode="strict")

@vaccine("createUser")
def create_user(*, email: str, age: int, nickname: str | None = None) -> dict:
    return {"email": email, "age": age, "nickname": nickname}

# This call drifts and raises OpenAPIDriftViolation.
create_user(email="a@b.co")
```

## Honest scope

- **Body-schema only.** Query / path / header parameters are not
  yet inspected. The Hermes paper finding is dominantly request-body
  drift; the parameter surface is a deliberate follow-up.
- **`application/json` content type only.** `multipart/form-data`,
  `application/x-www-form-urlencoded`, `application/xml` are out of
  scope for this cut.
- **`additionalProperties: false` is required** to detect unknown
  fields. A permissive schema (no `additionalProperties` key, or
  set to `true`) means the operator has opted in to extra fields
  and the guard honours that.
- **`$ref` resolution is shallow.** Only direct `properties` /
  `required` keys on the body schema are inspected. Nested `$ref`
  chains should be resolved at spec-load time before passing the
  dict to the constructor.

## Decision shape

`OpenAPIDriftDecision` is a frozen dataclass and mirrors the v0.7.x
/ v0.8.0 decision family — every guard exposes `allowed: bool` for
chain-friendly composition.

```python
@dataclass(frozen=True)
class OpenAPIDriftDecision:
    allowed: bool
    verdict: OpenAPIDriftVerdict
    detail: str
    operation_id: str | None
    divergences: tuple[OpenAPIDivergence, ...]
```

## Factory

```python
from agent_airlock.policy_presets import openapi_doc_drift_guard_defaults

cfg = openapi_doc_drift_guard_defaults(spec=my_spec, drift_mode="strict")
# {'preset_id': 'openapi_doc_drift_guard_2026_05_17', 'severity': 'medium',
#  'default_action': 'deny', 'advisory_url': 'https://arxiv.org/abs/2605.14312',
#  'drift_mode': 'strict', 'spec': {...}}
```

## Related

- [`EvalRCEGuard`](eval-rce-cve-2026-44717.md) (v0.8.0) — exploit-shape
  detection one layer deeper.
- [`StdioCommandInjectionGuard`](mcp-stdio-command-injection-guard.md)
  (v0.7.6) — argv-vector metachar detection.
