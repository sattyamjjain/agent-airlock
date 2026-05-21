# Layer-contract block on `airlock attest receipt` (v0.8.5+)

`agent_airlock.attest.LayerContract` is an **opt-in** assume/guarantee
block on the signed receipt payload. Anchored on the assume-guarantee
layer-contract framing from arXiv:2605.18672.

## What this is

A small, additive block on the existing v1 receipt schema:

```json
{
  "schema_version": 1,
  "run_id": "run_…",
  "policy_bundle_hash": "…",
  "inputs_hash": "…",
  "verdicts": [ … ],
  "contract": {
    "guarantees": [
      {"name": "EvalRCEGuard",   "pass_rate": 0.9943, "sample_size": 351},
      {"name": "GhostArgFilter", "pass_rate": 1.0,    "sample_size": 412},
      {"name": "PIIMasker",      "pass_rate": 0.0,    "sample_size": 17}
    ],
    "assumes": [
      "upstream.tls.tlsv1.3",
      "upstream.dpop.bound"
    ]
  },
  "signature": { "keyid": "…", "sig": "…" }
}
```

The block lets a verifier read **what this airlock layer claims to
guarantee** (per-guard measured pass rates over the receipt's sample)
**and what it assumes from upstream** (operator-declared identifiers
of upstream-layer guarantees).

## What this is NOT

- **Not a window-counter store.** The 2026-05-21 prompt that motivated
  this feature assumed a sliding-window counter store inside
  agent-airlock that tracked deny-by-default hits / ghost-arg strips /
  PII masks / validation failures. That store doesn't exist. v0.8.5
  ships the **derived** path instead: `pass_rate` is computed from
  the `verdicts` list the operator already supplies. The window
  approach is a future addition that would compose cleanly with this
  surface.
- **Not a behaviour change.** Receipts emitted without `--contract`
  are byte-identical to v0.8.4 receipts. Schema version stays at 1.
- **Not a formal verification claim.** The `pass_rate` is a measured
  statistic over the sample, not a proof. A 1.0 pass rate over 3
  samples is not the same as a 1.0 pass rate over 30,000 samples —
  hence the `sample_size` field on every guarantee.

## Derivation

For every unique `guard` name in the verdicts list:

```
pass_rate(guard) = count(verdict == "allow" for that guard) / total_for_that_guard
sample_size(guard) = total_for_that_guard
```

Verdict kinds other than `"allow"` (`warn` / `block` / `error`) all
count as non-pass. Guarantees are emitted in name-sorted order so the
canonical-payload bytes used for signing are stable across runs.

## CLI usage

```bash
airlock attest receipt emit \
    --policy-bundle-hash "$BUNDLE_SHA" \
    --inputs-hash "$INPUTS_SHA" \
    --model-id claude-opus-4-7 \
    --verdicts-json /tmp/verdicts.json \
    --key-file ~/.airlock/keys/test.bin \
    --keyid test-key \
    --contract \
    --assumes upstream.tls.tlsv1.3,upstream.dpop.bound \
    --output receipt.json
```

Flags:

| Flag | Effect |
|---|---|
| `--contract` | Opt-in. Derive a `LayerContract` from the verdicts and embed in the signed payload. Without this flag, receipts are emitted in the legacy v0.8.4 shape. |
| `--assumes id1,id2,...` | Comma-separated free-form identifiers of upstream-layer guarantees the operator declares this layer depends on. Requires `--contract`. |

## Python API

```python
from agent_airlock.attest import (
    derive_contract_from_verdicts,
    build_receipt,
    ReceiptVerdict,
)

verdicts = [
    ReceiptVerdict(guard="EvalRCEGuard", verdict="allow", tool_name="x"),
    ReceiptVerdict(guard="EvalRCEGuard", verdict="block", tool_name="x"),
    # ...
]

contract = derive_contract_from_verdicts(
    verdicts,
    assumes=("upstream.tls.tlsv1.3",),
)

receipt = build_receipt(
    policy_bundle_hash=bundle_sha,
    inputs=None,
    inputs_hash=inputs_sha,
    model_id="claude-opus-4-7",
    verdicts=verdicts,
    signer=my_signer,
    contract=contract,
)
```

## Honest scope

- **Sample size matters.** A 1.0 pass rate over 3 samples is statistically
  noise. Verifiers should weight `sample_size` accordingly. The Guarantee
  dataclass surfaces this directly.
- **Verdict-source-of-truth is the operator.** The operator supplies
  the verdicts list. If their upstream verdict log lies, the receipt
  will faithfully sign the lie. The signature attests the operator
  declared these verdicts at this time — not that the verdicts
  themselves are true.
- **`assumes` is free-form.** agent-airlock doesn't interpret the
  identifier strings. They're operator-meaningful labels for an
  external upstream-guarantee catalog.

## Related

- [`airlock attest receipt`](./receipt.md) (v0.6.0) — the signed
  receipt surface this extends.
- [`@requires_human_oversight`](../policies/human-oversight-decorator.md)
  (v0.8.4) — a policy primitive whose per-call audit events can
  feed the verdicts list this contract is derived from.
