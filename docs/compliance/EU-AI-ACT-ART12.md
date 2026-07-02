# EU AI Act Article 12 — record-keeping evidence (tool-call layer)

> **Scope in one line:** agent-airlock provides **Art. 12-style record-keeping
> evidence for the tool-call decision layer** — an append-only, tamper-evident,
> restart-surviving log of every policy decision. It is **not** a full quality
> management system and **not** a substitute for a provider's conformity
> assessment.

## What Article 12 asks for

Article 12 of Regulation (EU) 2024/1689 (the "AI Act") requires high-risk AI
systems to **automatically record events (logs)** throughout their lifetime, at
a level of traceability **appropriate to the intended purpose**, so that
situations which may present a risk or lead to a substantial modification can be
identified and the system's functioning can be monitored.

High-risk obligations (including Art. 12) apply from **2 August 2026**.

This document is an engineering note, not legal advice. Whether a given system
is "high-risk," and what its full obligations are, is the provider's
determination.

## What airlock's decision log *does* satisfy

airlock records each `validate → policy → execute → sanitize` decision to a
hash-chained JSON Lines log
(`agent_airlock.conformance.DecisionLog`). For the **tool-call decision layer**
it gives you:

| Art. 12 record-keeping expectation | airlock field / mechanism |
|---|---|
| Automatic recording of events over operation | `DecisionLog` — one append-only record per decision |
| Traceability across the lifecycle | `seq` + `prev_hash` + `record_hash` hash chain |
| Integrity / tamper-evidence of logs | `record_hash = SHA-256(canonical(fields incl. prev_hash))` — any edit/reorder/deletion breaks every later hash |
| Identifying risk / modification situations | `decision` (block/warn/error) + `reason` + `stage` |
| Attribution to actor / context | `agent_id` + `session_id` |
| Time reference per event | `ts` (ISO-8601 UTC) |
| Availability for the retention period | plain JSONL on the operator's own storage |

The evidence is **offline**: no network call, no cloud, and the log stores
decision **metadata only** — never raw tool arguments or results, so recording
does not itself create a new data-exposure surface.

### Reproduce the evidence

```bash
# append decisions (normally your @Airlock integration does this automatically)
airlock-conformance record --log decisions.jsonl --stage policy  --tool read_file  --decision allow
airlock-conformance record --log decisions.jsonl --stage execute --tool spawn_mcp  --decision block --reason "deny-by-default"

# prove the chain survives and verifies (exit 1 if broken)
airlock-conformance verify --log decisions.jsonl

# export the Art. 12 record-keeping evidence bundle (JSON + coverage table)
airlock-conformance export --log decisions.jsonl --output art12-evidence.json
```

The restart-survival + tamper-evidence properties are pinned by
`tests/test_conformance_decision_log.py` — the log is written, the process is
dropped, a fresh instance reloads from disk, and the chain must re-verify with
no record lost; any edited, deleted, or reordered record is detected at its
exact sequence number.

## What airlock's decision log does **NOT** do

Stated plainly so this artifact never over-claims:

- **Not a full quality management system (Art. 17).** airlock logs one layer —
  the tool-call decisions — not the organisational QMS, risk-management system,
  or technical documentation the Act also requires.
- **Not a conformity assessment / CE marking.** This evidence can *support* a
  provider's assessment; it does not perform or replace it.
- **Not model-internal or training-data logging.** It records the tool-call
  boundary, not the model's internals or datasets.
- **Not a guaranteed retention duration.** Retention, rotation, and secure
  storage of the JSONL file are the operator's responsibility and storage
  policy; airlock never ships the log off-box.

We do **not** claim airlock makes any system "fully compliant" with the EU AI
Act. It provides Art. 12-style record-keeping evidence for the tool-call layer —
one concrete, reproducible, verifiable piece of the picture.

## References

- Regulation (EU) 2024/1689, Article 12 (record-keeping) and Article 17
  (quality management system).
- Application date for high-risk obligations: **2 August 2026**.
