# Approvals bound to the call

Since 0.10.29 an approval binds to the exact call it approves: the arguments, once, and
for a limited time. Until then an approver saw only the escalation's reason and rule, and
an `authorize_once` grant admitted the next call of its tool whatever its arguments.

## What the approver sees

An escalated call (`SecurityPolicy.escalate_tools`) asks `policy.approver` with an
`OversightRequest` that now carries:

| Field | What it is |
| --- | --- |
| `args_digest` | sha256 of the call's bound arguments in canonical JSON (`agent_airlock.approvals.args_digest`) |
| `args_preview` | the arguments by name, masked like an audit preview: a value under a secret-sounding name is `[REDACTED]`, personal data and keys are masked |
| `agent_id`, `session_id` | the call's identity, when it carries one |
| `policy_digest` | the digest of the policy that escalated, frozen or not, so a stored decision can be checked against the policy in force on resume |
| `expires_at` | `requested_at` plus `escalation_timeout_seconds` |

The fields have defaults, so an approver written for 0.10.28 keeps working.

To bind its decision, the approver echoes the digest:

```python
from agent_airlock.oversight import OversightRequest, OversightResponse, OversightVerdict


def approver(request: OversightRequest) -> OversightResponse:
    ok = ask_a_human(request.tool_name, request.args_preview)
    return OversightResponse(
        request_id=request.request_id,
        verdict=OversightVerdict.GRANT if ok else OversightVerdict.DENY,
        args_digest=request.args_digest,
    )
```

A response that echoes another digest is refused as `policy_indeterminate`. A response
with no `args_digest` is read as before.

Two more refusals close the gap between the decision and the call:

- If the call's arguments change while the approver decides (a shared dict another task
  edits), the call is refused as `policy_indeterminate`: the digest is worked out again
  just before the tool runs.
- If the arguments cannot be read (nested deeper than 32 levels, or containing
  themselves), the call is refused as `policy_indeterminate` without asking anyone,
  since no approval can be bound to them.

`@requires_human_oversight` fills the same fields, and raises `ValueError` on a decision
about other arguments or arguments changed after the approval was asked.

## One-shot grants

`AirlockContext.authorize_once`, which re-opens the reauthorization guard and a tripped
action-contradiction gate, can name the call it admits and a time to live:

```python
from agent_airlock.approvals import args_digest

run.authorize_once("pay", args_digest=args_digest({"to": "bob", "amount": 10}))
run.authorize_once("pay", ttl_seconds=60)
```

A bound grant admits only a call whose arguments hash to it, positional or keyword. A
grant is spent under a lock, so two concurrent calls never both spend it, and a grant is
expired at `now >= expires_at`. `with_metadata()` clones share the run's grants, so a
grant spent through a clone is spent. A grant naming no digest admits one call of its
tool, as before.

## Approvals recorded ahead of the call

`SecurityPolicy(approval_ledger=...)` takes approvals recorded before the call, for
example by a human approving in a dashboard, and lets exactly one call spend each one:

```python
import time

from agent_airlock import SecurityPolicy
from agent_airlock.approvals import SQLiteApprovalLedger, args_digest

ledger = SQLiteApprovalLedger("approvals.db")
ledger.grant("pay", args_digest({"to": "bob", "amount": 10}), expires_at=time.time() + 300)

policy = SecurityPolicy(
    escalate_tools={"pay": "moves money"},
    approver=approver,
    approval_ledger=ledger,
)
```

An escalated call claims a matching approval before asking the approver. The claim is
atomic: `SQLiteApprovalLedger` runs it in a `BEGIN IMMEDIATE` transaction, so replicas
sharing the file never both run one approval. `InMemoryApprovalLedger` does the same
within one process. An approval is expired at `now >= expires_at`, and a ledger that
raises claims nothing, so the approver is asked.

## Standing grants

An operator can approve one tool called with exact target arguments for good:

```python
from agent_airlock import SecurityPolicy
from agent_airlock.approvals import StandingGrant

payroll = StandingGrant(tool="pay", arguments={"to": "payroll"})
policy = SecurityPolicy(
    escalate_tools={"pay": "moves money"},
    approver=approver,
    standing_grants=[payroll],
)
```

- The tool name is exact (a glob is refused) and at least one target argument is named.
  Values compare as the digest encodes them, so `1` is not `True` or `1.0`.
- Only host code makes one. An approver's `GRANT` or an `authorize_once` never turns into
  a standing grant.
- The call's audit record names the grant (`standing_grant`).
- `policy.revoke_standing_grant(payroll.grant_id)` stops it from the next call on.
- Adding a grant after `freeze()` moves the digest, so a frozen policy refuses every call.
  A revocation only narrows the policy, so it does not, and `freeze()` keeps it.
- A denied tool stays denied: escalation, and so a standing grant, is checked last.

## What this does not do

- A ledger approval binds to the tool and the digest, not to an agent: any agent making
  that exact call can claim it.
- There is no reviewer step that auto-approves below a threshold.
- The digest reads a host object that model JSON cannot build (a framework's injected
  context) as its type alone, so two such objects of one type share a digest.
