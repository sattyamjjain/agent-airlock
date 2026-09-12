# `airlock attest receipt` — signed evidence that a run was gated

**Landed in v0.6.0.** Implementation `src/agent_airlock/attest/`; CLI
`src/agent_airlock/cli/attest.py`.

A receipt is a small signed JSON document asserting: *this run, against this policy
bundle, over these inputs, on this model, produced these verdicts.* It exists so a
claim about a past run can be checked by someone who was not there.

## Emit

```console
$ airlock attest receipt emit \
    --policy-bundle-hash abc123 \
    --inputs-hash def456 \
    --model-id claude-opus-5 \
    --kms-stub \
    --output receipt.json
OK: receipt written to receipt.json
```

```json
{
  "inputs_hash": "def456",
  "model_id": "claude-opus-5",
  "policy_bundle_hash": "abc123",
  "run_id": "run_7a5b2fdcde234f0c9c06d001be1359e2",
  "schema_version": 1,
  "signature": { "keyid": "kms-stub", "sig": "4a2cec1f03…" },
  "ts": "2026-09-12T16:05:49Z",
  "verdicts": []
}
```

| flag | meaning |
|---|---|
| `--policy-bundle-hash` | hash of the bundle the run was gated by (**required**) |
| `--inputs-hash` | hash of the run's inputs (**required**) |
| `--model-id` | model the run used (**required**) |
| `--run-id` | defaults to a random id |
| `--verdicts-json PATH` | a JSON list of verdicts to embed |
| `--output PATH` | defaults to stdout |
| `--contract` | embed a derived `LayerContract` (assume/guarantee) block |
| `--assumes` | comma-separated upstream-guarantee identifiers |

## Verify

```console
$ airlock attest receipt verify receipt.json --kms-stub
OK: receipt run_7a5b2fdcde234f0c9c06d001be1359e2 verified by 'kms-stub'
```

`airlock attest verify <envelope>` is the sibling for DSSE attestation envelopes, and
takes the same key flags.

## Signing keys

All four subcommands share one key-selection surface:

| flag | source |
|---|---|
| `--key-file PATH` | key bytes from a file |
| `--env-var NAME` | key bytes from an environment variable |
| `--kms-stub` | the dev-only stub |
| `--keyid NAME` | override the keyid recorded in the signature |

## Honest scope — read this before relying on a receipt

- **Every shipped signer is HMAC-SHA256, including `--kms-stub`.** There is no KMS
  and no Sigstore Fulcio implementation in this package. `KMSStubSigner` is named
  "stub" because it is one: it exercises the envelope shape, the CLI and the verify
  flow end to end, and it is not a KMS.

  A symmetric HMAC means **anyone who can verify a receipt can also forge one** —
  verification proves possession of the shared key, not authorship. For evidence that
  survives a hostile reader you need an asymmetric signer, which means substituting
  your own `Signer`. The protocol is small and the swap changes no envelope shape.

- A receipt records **hashes you supply**. Nothing checks that
  `--policy-bundle-hash` is the bundle that actually gated the run, or that
  `--inputs-hash` matches real inputs. The receipt binds them together and signs the
  binding; it does not attest that you computed them honestly. Pair it with
  [`policy_bundle.lock`](policy-bundle-lock.md), which is the piece that makes a
  bundle hash reproducible.

- `verdicts` is whatever `--verdicts-json` contained, or empty. The operator feeds
  them in; there is no in-process collector that harvests them automatically, and no
  sliding-window store behind them. Both remain unbuilt.

## See also

- [LayerContract](../attest/layer-contract.md) — the assume/guarantee block `--contract` embeds
- [`airlock policy-bundle-lock`](policy-bundle-lock.md) — making the bundle hash mean something
