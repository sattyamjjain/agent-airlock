"""Capability-union boundary at grant time (runtime half; agent-audit-kit does the static scan).

Decisions, not liveness — matches the existing capability_caps test posture. The core case:
two individually-approved leases (a filesystem-read and a non-allowlisted egress) are correctly
**denied in combination**, and the denial names the specific prior lease; a legitimate two-lease
combination is correctly **allowed**; the override escape hatch is allowed and logged.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_airlock.capability_caps import (
    CapabilityCapEngine,
    CapabilityCategory,
    CapabilityRulesConfig,
    CapabilityUnionDeniedError,
    Lease,
    UnionOverride,
    evaluate_union_grant,
)
from agent_airlock.conformance.decision_log import DecisionLog

_FS = frozenset({CapabilityCategory.FILESYSTEM_READ})
_CRED = frozenset({CapabilityCategory.CREDENTIAL_ACCESS})
_EGRESS = frozenset({CapabilityCategory.NETWORK_EGRESS})


def _engine() -> CapabilityCapEngine:
    return CapabilityCapEngine(CapabilityRulesConfig())


class TestUnionDeniedInCombination:
    def test_two_approved_leases_denied_in_combination(self) -> None:
        eng = _engine()
        # Each lease is individually permitted (no exception on its own grant).
        eng.grant_lease("agent", Lease("L-fs", "read_config", _FS, granted_by="op"))
        with pytest.raises(CapabilityUnionDeniedError) as exc:
            eng.grant_lease("agent", Lease("L-egress", "fetch_url", _EGRESS, granted_by="op"))
        err = exc.value
        assert err.boundary is not None and err.boundary.name == "exfiltration"
        # The denial NAMES the specific prior lease that combined to trigger it.
        assert [lease.lease_id for lease in err.triggering_leases] == ["L-fs"]
        assert "L-fs" in str(err) and "read_config" in str(err)

    def test_credential_plus_egress_denied(self) -> None:
        eng = _engine()
        eng.grant_lease("agent", Lease("L-cred", "get_api_key", _CRED))
        with pytest.raises(CapabilityUnionDeniedError) as exc:
            eng.grant_lease("agent", Lease("L-egress", "post_data", _EGRESS))
        assert [lease.lease_id for lease in exc.value.triggering_leases] == ["L-cred"]

    def test_order_independent_egress_then_fs(self) -> None:
        eng = _engine()
        eng.grant_lease("agent", Lease("L-egress", "fetch_url", _EGRESS))
        with pytest.raises(CapabilityUnionDeniedError) as exc:
            eng.grant_lease("agent", Lease("L-fs", "read_config", _FS))
        assert [lease.lease_id for lease in exc.value.triggering_leases] == ["L-egress"]


class TestUnionAllowed:
    def test_allowlisted_egress_is_not_a_sink(self) -> None:
        eng = _engine()
        eng.grant_lease("agent", Lease("L-fs", "read_config", _FS))
        d = eng.grant_lease(
            "agent",
            Lease("L-egress", "fetch_trusted", _EGRESS, network_allowlisted=True),
        )
        assert d.allowed and not d.overridden

    def test_two_same_side_leases_allowed(self) -> None:
        eng = _engine()
        eng.grant_lease("agent", Lease("L-r1", "read_a", _FS))
        d = eng.grant_lease("agent", Lease("L-r2", "read_b", _FS))
        assert d.allowed

    def test_single_lease_with_both_categories_allowed(self) -> None:
        # A single reviewed unit (e.g. upload_file declared FILESYSTEM_READ | NETWORK egress)
        # is not a *combination* of two leases, so it is not denied here.
        eng = _engine()
        d = eng.grant_lease("agent", Lease("L-up", "upload_file", _FS | _EGRESS))
        assert d.allowed

    def test_revoking_the_prior_lease_frees_the_union(self) -> None:
        eng = _engine()
        eng.grant_lease("agent", Lease("L-fs", "read_config", _FS))
        assert eng.revoke_lease("agent", "L-fs") is True
        d = eng.grant_lease("agent", Lease("L-egress", "fetch_url", _EGRESS))
        assert d.allowed

    def test_different_agents_do_not_share_a_union(self) -> None:
        eng = _engine()
        eng.grant_lease("alice", Lease("L-fs", "read_config", _FS))
        # bob's egress lease is unaffected by alice's filesystem lease.
        d = eng.grant_lease("bob", Lease("L-egress", "fetch_url", _EGRESS))
        assert d.allowed


class TestOverride:
    def test_override_allows_and_records_identity(self, tmp_path: Path) -> None:
        log_path = tmp_path / "decisions.jsonl"
        log = DecisionLog(log_path)
        eng = _engine()
        eng.grant_lease("agent", Lease("L-fs", "read_config", _FS))
        d = eng.grant_lease(
            "agent",
            Lease("L-egress", "fetch_url", _EGRESS),
            override=UnionOverride(identity="secops@corp", reason="approved migration window"),
            decision_log=log,
        )
        assert d.allowed and d.overridden
        assert d.override is not None and d.override.identity == "secops@corp"
        # The escape hatch is recorded in the decision log with the granting identity.
        text = log_path.read_text(encoding="utf-8")
        assert "capability-union override" in text
        assert "secops@corp" in text
        # The chain still verifies (loud but non-repudiable).
        assert DecisionLog(log_path, verify_on_load=False).verify().ok

    def test_override_lease_is_then_held(self) -> None:
        eng = _engine()
        eng.grant_lease("agent", Lease("L-fs", "read_config", _FS))
        eng.grant_lease(
            "agent",
            Lease("L-egress", "fetch_url", _EGRESS),
            override=UnionOverride(identity="op", reason="x"),
        )
        assert {lease.lease_id for lease in eng.held_leases("agent")} == {"L-fs", "L-egress"}


class TestPureEvaluator:
    def test_evaluate_union_grant_is_pure_and_names_prior(self) -> None:
        held = [Lease("A", "read", _FS)]
        new = Lease("B", "egress", _EGRESS)
        d = evaluate_union_grant(held, new)
        assert not d.allowed
        assert [lease.lease_id for lease in d.triggering_leases] == ["A"]

    def test_no_boundary_crossed_allows(self) -> None:
        d = evaluate_union_grant([Lease("A", "read", _FS)], Lease("B", "read2", _FS))
        assert d.allowed and d.reason == "no capability-union boundary crossed"
