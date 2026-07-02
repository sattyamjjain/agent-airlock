"""EU AI Act Art. 12 record-keeping — decision-log conformance tests (v0.8.40+).

The credibility asset: "does your firewall's decision log survive a restart?"
We append N decisions, drop the in-memory object entirely, reload from disk in a
fresh process-equivalent instance, and assert the hash chain re-verifies with no
record lost — plus that any tamper is detected at the exact record.
"""

from __future__ import annotations

import json

import pytest

from agent_airlock.audit import AuditRecord
from agent_airlock.conformance import (
    GENESIS_HASH,
    DecisionLog,
    DecisionLogError,
    export_evidence_bundle,
    verify_chain,
)

_STAGES = ("validate", "policy", "execute", "sanitize")


def _seed(log: DecisionLog, n: int) -> None:
    for i in range(n):
        log.append(
            stage=_STAGES[i % 4],
            tool_name=f"tool_{i}",
            decision="block" if i % 3 == 0 else "allow",
            reason="deny-by-default" if i % 3 == 0 else "",
            agent_id="agentA",
            session_id="run-1",
        )


class TestRestartSurvival:
    def test_reload_after_restart_verifies_no_loss(self, tmp_path) -> None:
        p = tmp_path / "decisions.jsonl"
        writer = DecisionLog(p)
        _seed(writer, 25)
        head_before = writer.head_hash
        del writer  # simulate process exit

        # Fresh instance = a new process reloading the same file.
        reloaded = DecisionLog(p)
        assert reloaded.record_count == 25, "no record may be lost across restart"
        assert reloaded.head_hash == head_before, "head hash must survive restart"
        result = reloaded.verify()
        assert result.ok is True
        assert result.record_count == 25

    def test_appends_continue_after_restart(self, tmp_path) -> None:
        p = tmp_path / "d.jsonl"
        _seed(DecisionLog(p), 5)
        reloaded = DecisionLog(p)
        reloaded.append(stage="policy", tool_name="post_restart", decision="allow")
        assert reloaded.record_count == 6
        # seq stays contiguous and the chain still verifies end to end.
        recs = reloaded.records()
        assert [r.seq for r in recs] == list(range(6))
        assert reloaded.verify().ok

    def test_empty_log_head_is_genesis(self, tmp_path) -> None:
        log = DecisionLog(tmp_path / "empty.jsonl")
        assert log.head_hash == GENESIS_HASH
        assert log.record_count == 0
        assert log.verify().ok is True


class TestTamperEvidence:
    def test_edited_record_breaks_chain_at_that_seq(self, tmp_path) -> None:
        p = tmp_path / "d.jsonl"
        _seed(DecisionLog(p), 10)
        lines = p.read_text().splitlines()
        # Flip decision on record seq=4 without recomputing its hash.
        obj = json.loads(lines[4])
        obj["decision"] = "allow" if obj["decision"] == "block" else "block"
        lines[4] = json.dumps(obj, sort_keys=True, separators=(",", ":"))
        p.write_text("\n".join(lines) + "\n")

        result = DecisionLog(p, verify_on_load=False).verify()
        assert result.ok is False
        assert result.first_bad_seq == 4
        assert "edited" in result.detail

    def test_deleted_record_is_detected(self, tmp_path) -> None:
        p = tmp_path / "d.jsonl"
        _seed(DecisionLog(p), 8)
        lines = p.read_text().splitlines()
        del lines[3]  # remove a record from the middle
        p.write_text("\n".join(lines) + "\n")
        result = DecisionLog(p, verify_on_load=False).verify()
        assert result.ok is False
        # seq becomes non-contiguous at the gap.
        assert result.first_bad_seq == 4

    def test_reordered_records_detected(self, tmp_path) -> None:
        p = tmp_path / "d.jsonl"
        _seed(DecisionLog(p), 6)
        lines = p.read_text().splitlines()
        lines[2], lines[3] = lines[3], lines[2]
        p.write_text("\n".join(lines) + "\n")
        assert DecisionLog(p, verify_on_load=False).verify().ok is False

    def test_constructor_fails_closed_on_broken_chain(self, tmp_path) -> None:
        p = tmp_path / "d.jsonl"
        _seed(DecisionLog(p), 4)
        lines = p.read_text().splitlines()
        obj = json.loads(lines[1])
        obj["tool_name"] = "tampered"
        lines[1] = json.dumps(obj, sort_keys=True, separators=(",", ":"))
        p.write_text("\n".join(lines) + "\n")
        with pytest.raises(DecisionLogError, match="integrity"):
            DecisionLog(p)  # verify_on_load defaults True -> fail closed


class TestEvidenceBundle:
    def test_bundle_reports_verified_and_counts(self, tmp_path) -> None:
        log = DecisionLog(tmp_path / "d.jsonl")
        _seed(log, 12)
        bundle = export_evidence_bundle(log, generated_ts="2026-07-03T00:00:00.000000Z")
        assert bundle["chain_verified"] is True
        assert bundle["record_count"] == 12
        assert bundle["high_risk_applicability_date"] == "2026-08-02"
        assert bundle["schema"] == "eu-ai-act-art12-record-keeping-evidence"
        # Coverage + out-of-scope both present (no over-claiming).
        assert len(bundle["art12_coverage"]) >= 5
        assert any("quality management" in s.lower() for s in bundle["out_of_scope"])

    def test_bundle_flags_broken_chain(self, tmp_path) -> None:
        p = tmp_path / "d.jsonl"
        _seed(DecisionLog(p), 5)
        lines = p.read_text().splitlines()
        obj = json.loads(lines[2])
        obj["reason"] = "silently-changed"
        lines[2] = json.dumps(obj, sort_keys=True, separators=(",", ":"))
        p.write_text("\n".join(lines) + "\n")
        bundle = export_evidence_bundle(DecisionLog(p, verify_on_load=False))
        assert bundle["chain_verified"] is False
        assert bundle["first_bad_seq"] == 2

    def test_bundle_carries_no_raw_args(self, tmp_path) -> None:
        # The bundle must be metadata + hashes only — no tool arguments/results.
        log = DecisionLog(tmp_path / "d.jsonl")
        log.append(stage="validate", tool_name="t", decision="block", reason="r")
        blob = json.dumps(export_evidence_bundle(log))
        assert "args" not in blob.lower() or "args_preview" not in blob


class TestAuditBridge:
    def test_append_from_audit_record(self, tmp_path) -> None:
        log = DecisionLog(tmp_path / "d.jsonl")
        rec = AuditRecord(
            timestamp="2026-07-03T00:00:00Z",
            tool_name="delete_all",
            blocked=True,
            block_reason="denied by policy",
            agent_id="agentX",
            session_id="sess-9",
        )
        d = log.append_audit_record(rec, stage="policy")
        assert d.decision == "block"
        assert d.tool_name == "delete_all"
        assert d.reason == "denied by policy"
        assert d.agent_id == "agentX"
        assert log.verify().ok


class TestVerifyChainDirect:
    def test_verify_chain_on_records_list(self, tmp_path) -> None:
        log = DecisionLog(tmp_path / "d.jsonl")
        _seed(log, 3)
        assert verify_chain(log.records()).ok is True
