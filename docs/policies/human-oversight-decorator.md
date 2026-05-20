# Human-oversight decorator (v0.8.4+, Code-as-Harness anchor)

`agent_airlock.oversight.requires_human_oversight` is a decorator
factory that gates a tool function on an operator-supplied approval
callable. Anchored on the Code-as-Harness survey
([arXiv:2605.18747][survey], Ning et al., 2026-05-18), which
identifies "human oversight for safety-critical actions" as an open
challenge in harness engineering.

[survey]: https://arxiv.org/abs/2605.18747

## What this is

A composable primitive that:

1. Builds a structured `OversightRequest` for every wrapped call.
2. Hands the request to an **operator-supplied `approver` callable**.
3. Acts on the returned `OversightResponse`:
   - `GRANT` → calls the wrapped function, returns its value.
   - `DENY` → raises `OversightDeniedError`.
   - `TIMEOUT` → raises `OversightTimeoutError`.

agent-airlock owns the gate logic + the protocol shapes. **The
operator owns the transport** (Slack, PagerDuty, CLI prompt, a
queue-backed worker, etc).

## What this is NOT

- **Not a bidirectional audit-emitter RPC.** The 2026-05-20 doc
  proposed grafting an `audit_emitter.await_response(...)` channel
  onto agent-airlock's existing one-way audit emitter. That would
  have invented a new transport abstraction inside the library.
  Instead, the operator supplies the transport via the `approver`
  callable; the audit emitter remains one-way (we still emit
  `oversight.request|grant|deny|timeout` events for the audit
  trail).
- **Not async.** v0.8.4 ships the sync surface. Async support is
  a deferred follow-up that needs a separate API design pass.
- **Not bundled-transport.** No Slack / PagerDuty / webhook
  approver ships in the library — operators wire those in their
  own audit hooks.

## Quickstart

```python
from agent_airlock import (
    OversightRequest,
    OversightResponse,
    OversightVerdict,
    requires_human_oversight,
)


def slack_approver(req: OversightRequest) -> OversightResponse:
    # Operator-owned transport: post to Slack, wait for emoji react,
    # interpret the result. agent-airlock doesn't care how.
    decision = my_slack_client.request_approval(
        channel=req.channel,
        tool_name=req.tool_name,
        args=req.args,
        timeout=req.timeout_seconds,
    )
    return OversightResponse(
        request_id=req.request_id,   # MUST round-trip
        verdict=OversightVerdict.GRANT if decision == "approve" else OversightVerdict.DENY,
        detail=f"slack thread {decision.thread_id}",
        approver=decision.user_email,
    )


@requires_human_oversight(
    approver=slack_approver,
    channel="prod-deploys",
    timeout_seconds=600,
)
def deploy_to_prod(version: str) -> str:
    return cluster.deploy(version)
```

## Composition with `@Airlock`

The oversight gate composes cleanly with the existing `@Airlock`
decorator. The outer decorator runs first; stack them so the
oversight gate fires *before* the validation layer (you don't want
to spend a human approval cycle on a payload that's about to be
rejected by Pydantic).

```python
@requires_human_oversight(approver=slack_approver, channel="finance")
@Airlock(policy=STRICT_POLICY)
def transfer_funds(account: str, amount: int) -> dict:
    ...
```

## Data shapes

All frozen dataclasses; mirror the v0.7.x / v0.8.x decision family.

```python
@dataclass(frozen=True)
class OversightRequest:
    request_id: str             # UUID4
    tool_name: str
    args: Mapping[str, Any]     # {"args": (...), "kwargs": {...}}
    channel: str
    timeout_seconds: float
    requested_at: str           # ISO 8601 UTC


@dataclass(frozen=True)
class OversightResponse:
    request_id: str             # MUST echo OversightRequest.request_id
    verdict: OversightVerdict
    detail: str = ""
    approver: str | None = None # human identifier, optional
```

## Testing helper

`InProcessRecordedApprover` returns pre-set verdicts per tool name;
unrecorded tools default to `TIMEOUT` so tests fail loudly:

```python
from agent_airlock import InProcessRecordedApprover, OversightVerdict

approver = InProcessRecordedApprover(
    decisions={
        "deploy_to_prod": OversightVerdict.GRANT,
        "delete_database": OversightVerdict.DENY,
    }
)

@requires_human_oversight(approver=approver)
def deploy_to_prod() -> str:
    return "deployed"


def test_deploy_passes() -> None:
    assert deploy_to_prod() == "deployed"
    assert approver.calls[0].tool_name == "deploy_to_prod"
```

## Audit events

When `audit_emitter` is supplied, the decorator emits one event per
phase:

| Event type           | Fired when                                |
|----------------------|-------------------------------------------|
| `oversight.request`  | Before calling the approver               |
| `oversight.grant`    | Approver returned `GRANT`                 |
| `oversight.deny`     | Approver returned `DENY`                  |
| `oversight.timeout`  | Approver returned `TIMEOUT`               |

The same events also flow through the module's `structlog` logger
(`agent-airlock.oversight`) regardless of whether `audit_emitter`
is set, so OTel/log-tailing pipelines pick them up without extra
wiring.

## Protocol fault: mismatched `request_id`

The approver MUST echo the `request_id` from the `OversightRequest`
on its `OversightResponse`. A mismatch raises `ValueError` at the
decorator boundary — this catches buggy approver implementations
loudly rather than silently letting a wrong-tool decision through.

## Honest scope

- Sync only. Async gating is a deferred follow-up.
- One protocol verdict set (`GRANT|DENY|TIMEOUT`). Multi-step
  approval (e.g. "request changes") is out of scope; operators
  can multiplex inside their approver.
- No bundled transports. Operators wire Slack / PagerDuty / CLI
  themselves.
- Sync `approver(request)` blocks the calling thread until it
  returns. If the operator's approver needs a long-running wait,
  it should respect `request.timeout_seconds` and return
  `OversightVerdict.TIMEOUT` when the budget is exhausted.

## Related

- [`OpenAPIDriftGuard`](openapi-drift-guard.md) (v0.8.1) — schema-shape gate.
- [`MetisInspiredCorpusBlockRateGuard`](metis-inspired-corpus-block-rate.md)
  (v0.8.2) — release-gate primitive.
- [`Stainless SDK provenance`](stainless-provenance-probe.md) (v0.8.3) —
  visibility classifier.
