"""EU AI Act Article 12 (record-keeping) evidence bundle for the decision log.

Article 12 requires high-risk AI systems to **automatically record events
(logs) over their lifetime** and to keep those logs traceable and appropriate
to their purpose. airlock's hash-chained :class:`~agent_airlock.conformance.decision_log.DecisionLog`
provides that record-keeping **for the tool-call decision layer**: an
append-only, tamper-evident, restart-surviving log of every validate → policy →
execute → sanitize decision.

This module maps each Article 12 record-keeping expectation to the concrete
decision-log field that satisfies it, and exports an offline evidence bundle
(JSON + a human-readable coverage table). It makes **no** network call and
carries **no** raw tool arguments or results — only decision metadata + hashes.

Scope honesty (see docs/compliance/EU-AI-ACT-ART12.md): this is Art. 12-style
record-keeping *evidence for the tool-call layer*. It is **not** a full quality
management system (Art. 17) and **not** a substitute for the provider's
conformity assessment. High-risk obligations under the AI Act apply from
**2 August 2026**.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .decision_log import DECISION_LOG_SCHEMA_VERSION, DecisionLog

ART12_EVIDENCE_SCHEMA_VERSION = 1

# Each row: (Article 12 record-keeping expectation, the decision-log field that
# satisfies it for the tool-call layer, a short note). Deliberately conservative
# — it claims coverage only for what the log actually records.
ART12_COVERAGE: tuple[tuple[str, str, str], ...] = (
    (
        "Automatic recording of events (logs) over the system's operation",
        "DecisionLog (append-only JSONL, one record per decision)",
        "Every validate/policy/execute/sanitize decision is appended automatically.",
    ),
    (
        "Traceability of the system's functioning across its lifecycle",
        "seq + prev_hash + record_hash (hash chain)",
        "Records form a re-derivable ordered chain; gaps and edits are detectable.",
    ),
    (
        "Integrity / tamper-evidence of the recorded logs",
        "record_hash = SHA-256(canonical(fields incl. prev_hash))",
        "Any edit, reorder, or deletion breaks every subsequent hash; verify() proves it.",
    ),
    (
        "Identification of situations that may present a risk / result in modification",
        "decision (block/warn/error) + reason + stage",
        "Blocked and errored decisions are recorded with the stage and the guard/policy reason.",
    ),
    (
        "Attribution to the actor / operating context",
        "agent_id + session_id",
        "Optional identity fields tie a decision to an agent and session/run.",
    ),
    (
        "Time reference for each recorded event",
        "ts (ISO-8601 UTC per record)",
        "Each record carries a UTC timestamp.",
    ),
    (
        "Availability of records for the retention period",
        "Plain JSONL file on the operator's storage (offline)",
        "Retention/rotation is the operator's storage policy; airlock never ships logs off-box.",
    ),
)

# Expectations this layer explicitly does NOT satisfy — surfaced in the bundle
# so the artifact never reads as over-claiming.
ART12_OUT_OF_SCOPE: tuple[str, ...] = (
    "Full quality management system (Art. 17) — airlock logs one layer, not the QMS.",
    "Provider conformity assessment / CE marking — this evidence supports it, is not it.",
    "Model-internal / training-data logging — this is the tool-call decision layer only.",
    "Guaranteed retention duration — that is the operator's storage/rotation policy.",
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def export_evidence_bundle(log: DecisionLog, *, generated_ts: str | None = None) -> dict[str, Any]:
    """Build the offline Art. 12 record-keeping evidence bundle.

    Contains the chain-verification result, the head hash, per-stage decision
    counts, and the coverage/out-of-scope mapping — no raw args/results, no
    network. A verifier can independently re-run ``log.verify()`` against the
    same file to confirm ``chain_verified``.
    """
    verification = log.verify()
    records = log.records()
    by_stage: dict[str, dict[str, int]] = {}
    for rec in records:
        stage_counts = by_stage.setdefault(rec.stage, {})
        stage_counts[rec.decision] = stage_counts.get(rec.decision, 0) + 1

    return {
        "schema": "eu-ai-act-art12-record-keeping-evidence",
        "schema_version": ART12_EVIDENCE_SCHEMA_VERSION,
        "decision_log_schema_version": DECISION_LOG_SCHEMA_VERSION,
        "generated_ts": generated_ts or _now_iso(),
        "log_path": str(log.path),
        "record_count": verification.record_count,
        "chain_head_hash": verification.head_hash,
        "chain_verified": verification.ok,
        "chain_detail": verification.detail,
        "first_bad_seq": verification.first_bad_seq,
        "decisions_by_stage": by_stage,
        "art12_coverage": [
            {"expectation": exp, "airlock_field": field, "note": note}
            for exp, field, note in ART12_COVERAGE
        ],
        "out_of_scope": list(ART12_OUT_OF_SCOPE),
        "high_risk_applicability_date": "2026-08-02",
        "disclaimer": (
            "Art. 12-style record-keeping evidence for the tool-call decision layer. "
            "Not a full quality management system and not a substitute for the "
            "provider's conformity assessment."
        ),
    }


def render_coverage_table(bundle: dict[str, Any]) -> str:
    """Human-readable coverage table for the evidence bundle (stdout / report)."""
    lines: list[str] = []
    verified = "VERIFIED" if bundle["chain_verified"] else f"BROKEN ({bundle['chain_detail']})"
    lines.append("EU AI Act Art. 12 — record-keeping evidence (tool-call layer)")
    lines.append(f"  log: {bundle['log_path']}")
    lines.append(f"  records: {bundle['record_count']}  |  chain: {verified}")
    lines.append(f"  head hash: {bundle['chain_head_hash']}")
    lines.append(f"  high-risk obligations apply from: {bundle['high_risk_applicability_date']}")
    lines.append("")
    lines.append("  Art. 12 record-keeping expectation                          -> airlock field")
    lines.append("  " + "-" * 74)
    for row in bundle["art12_coverage"]:
        exp = row["expectation"]
        exp = exp if len(exp) <= 56 else exp[:53] + "..."
        lines.append(f"  {exp:<56} -> {row['airlock_field']}")
    lines.append("")
    lines.append("  Explicitly NOT covered by this layer:")
    for item in bundle["out_of_scope"]:
        lines.append(f"    - {item}")
    lines.append("")
    lines.append(f"  {bundle['disclaimer']}")
    return "\n".join(lines)
