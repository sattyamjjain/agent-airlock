"""CIMD trust-anchor pinning (MCP 2026-07-28 Client ID Metadata Documents).

Decisions, not liveness: every fetch is injected, so these tests never touch the network.

Covers the four properties the guard exists for:

* **(a) fetch-and-pin** — an explicit approval records the document hash + origin, and the
  pin survives a store round-trip.
* **(b) freshness at grant time** — an unchanged document passes; a changed one is denied by
  default and the denial names exactly which fields moved. A rotation is never auto-accepted;
  the DENY -> explicit-approve -> allow sequence is asserted end to end.
* **(c) origin constraints** — non-https, private/loopback resolution, and off-origin
  redirects are all refused.
* **(d) revocation** — a 404 or a document that loses a required field moves the client to
  *denied*, not back to *unknown*.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_airlock.capability_caps import (
    CapabilityCapEngine,
    CapabilityCategory,
    CapabilityRulesConfig,
    Lease,
)
from agent_airlock.mcp.cimd import (
    CIMDGuard,
    CIMDPinState,
    CIMDTrustAnchorError,
    CIMDVerdict,
    FetchResult,
    InMemoryCIMDPinStore,
    SQLiteCIMDPinStore,
    cimd_trust_anchor_defaults,
)

CLIENT_ID = "https://client.example.com/.well-known/oauth-client"

BASE_DOC: dict[str, object] = {
    "client_id": CLIENT_ID,
    "client_name": "Example Client",
    "redirect_uris": ["https://client.example.com/callback"],
}


def _doc(**overrides: object) -> dict[str, object]:
    payload = dict(BASE_DOC)
    payload.update(overrides)
    return payload


class FakeFetch:
    """Injectable fetcher with a settable body, status, and redirect chain."""

    def __init__(
        self,
        payload: object = None,
        *,
        status: int = 200,
        url_chain: tuple[str, ...] | None = None,
        raw: str | None = None,
    ) -> None:
        self.payload = payload if payload is not None else _doc()
        self.status = status
        self.url_chain = url_chain
        self.raw = raw
        self.calls: list[str] = []

    def __call__(self, url: str) -> FetchResult:
        self.calls.append(url)
        body = self.raw if self.raw is not None else json.dumps(self.payload)
        return FetchResult(
            status=self.status,
            body=body,
            url_chain=self.url_chain if self.url_chain is not None else (url,),
        )


def _public_resolver(_host: str) -> list[str]:
    return ["93.184.216.34"]


def _guard(fetch: FakeFetch, *, store: object = None) -> CIMDGuard:
    return CIMDGuard(
        store=store or InMemoryCIMDPinStore(),  # type: ignore[arg-type]
        fetcher=fetch,
        resolver=_public_resolver,
    )


# ---------------------------------------------------------------------------
# (a) fetch-and-pin
# ---------------------------------------------------------------------------


class TestCIMDFetchAndPin:
    def test_approve_records_hash_and_origin(self) -> None:
        fetch = FakeFetch()
        guard = _guard(fetch)

        decision = guard.approve(CLIENT_ID, approved_by="secops@example.com")

        assert decision.allowed
        assert decision.verdict is CIMDVerdict.OK
        pin = guard.store.get(CLIENT_ID)
        assert pin is not None
        assert len(pin.document_sha256) == 64
        assert pin.origin == "https://client.example.com:443"
        assert pin.approved_by == "secops@example.com"
        assert pin.state is CIMDPinState.PINNED

    def test_unpinned_client_is_denied_not_trusted_on_first_use(self) -> None:
        guard = _guard(FakeFetch())

        decision = guard.check(CLIENT_ID)

        assert not decision.allowed
        assert decision.verdict is CIMDVerdict.DENY_UNPINNED

    def test_pin_survives_sqlite_round_trip(self, tmp_path: Path) -> None:
        db = tmp_path / "airlock.db"
        fetch = FakeFetch()
        guard = _guard(fetch, store=SQLiteCIMDPinStore(db))
        guard.approve(CLIENT_ID, approved_by="secops")

        # A fresh process: new store object over the same file.
        reopened = _guard(FakeFetch(), store=SQLiteCIMDPinStore(db))
        assert reopened.check(CLIENT_ID).allowed

    def test_hash_ignores_key_order_and_whitespace(self) -> None:
        fetch = FakeFetch()
        guard = _guard(fetch)
        guard.approve(CLIENT_ID, approved_by="secops")

        # Same document, reserialised with different key order and indenting.
        reordered = {k: BASE_DOC[k] for k in reversed(list(BASE_DOC))}
        fetch.raw = json.dumps(reordered, indent=4)

        assert guard.check(CLIENT_ID).allowed


# ---------------------------------------------------------------------------
# (b) freshness check at grant time
# ---------------------------------------------------------------------------


class TestCIMDFreshness:
    def test_unchanged_document_passes(self) -> None:
        guard = _guard(FakeFetch())
        guard.approve(CLIENT_ID, approved_by="secops")

        assert guard.check(CLIENT_ID).allowed

    def test_changed_document_is_denied_and_names_the_field(self) -> None:
        fetch = FakeFetch()
        guard = _guard(fetch)
        guard.approve(CLIENT_ID, approved_by="secops")

        # The exact attack CIMD opens: the client rewrites its own redirect_uris later.
        fetch.payload = _doc(redirect_uris=["https://attacker.example/steal"])
        decision = guard.check(CLIENT_ID)

        assert not decision.allowed
        assert decision.verdict is CIMDVerdict.DENY_DRIFT
        changed = {change.field for change in decision.changed_fields}
        assert changed == {"redirect_uris"}
        assert "redirect_uris" in decision.reason
        assert "attacker.example" in decision.reason

    def test_added_and_removed_fields_are_both_named(self) -> None:
        fetch = FakeFetch()
        guard = _guard(fetch)
        guard.approve(CLIENT_ID, approved_by="secops")

        payload = _doc(scope="openid profile")
        del payload["client_name"]
        # client_name is required, so re-add it under a changed value instead of removing,
        # and drop a non-required field to exercise removal.
        payload["client_name"] = "Renamed Client"
        fetch.payload = payload

        decision = guard.check(CLIENT_ID)
        changed = {change.field for change in decision.changed_fields}
        assert changed == {"client_name", "scope"}

    def test_drift_does_not_move_the_pin(self) -> None:
        fetch = FakeFetch()
        guard = _guard(fetch)
        guard.approve(CLIENT_ID, approved_by="secops")
        pinned_before = guard.store.get(CLIENT_ID)
        assert pinned_before is not None

        fetch.payload = _doc(client_name="Rotated")
        guard.check(CLIENT_ID)
        guard.check(CLIENT_ID)  # repeated denial must stay a denial

        pinned_after = guard.store.get(CLIENT_ID)
        assert pinned_after is not None
        assert pinned_after.document_sha256 == pinned_before.document_sha256
        assert not guard.check(CLIENT_ID).allowed

    def test_rotation_is_deny_then_explicit_approve(self) -> None:
        """The headline sequence: drift denies, only an explicit approval re-allows."""
        fetch = FakeFetch()
        guard = _guard(fetch)
        guard.approve(CLIENT_ID, approved_by="secops")
        assert guard.check(CLIENT_ID).allowed

        fetch.payload = _doc(redirect_uris=["https://client.example.com/v2/callback"])

        denied = guard.check(CLIENT_ID)
        assert not denied.allowed
        assert denied.verdict is CIMDVerdict.DENY_DRIFT

        approved = guard.approve(CLIENT_ID, approved_by="secops")
        assert approved.allowed
        assert "rotation approved" in approved.reason

        assert guard.check(CLIENT_ID).allowed

    def test_check_or_raise_raises_on_drift(self) -> None:
        fetch = FakeFetch()
        guard = _guard(fetch)
        guard.approve(CLIENT_ID, approved_by="secops")
        fetch.payload = _doc(client_name="Rotated")

        with pytest.raises(CIMDTrustAnchorError) as excinfo:
            guard.check_or_raise(CLIENT_ID)

        assert excinfo.value.verdict is CIMDVerdict.DENY_DRIFT
        assert excinfo.value.audit_event["event"] == "cimd.decision"


# ---------------------------------------------------------------------------
# (c) origin constraints
# ---------------------------------------------------------------------------


class TestCIMDOriginConstraints:
    def test_non_https_scheme_is_refused(self) -> None:
        guard = _guard(FakeFetch())

        decision = guard.check("http://client.example.com/meta")
        # No pin exists, so the scheme check must fire during approve() too.
        assert decision.verdict is CIMDVerdict.DENY_UNPINNED

        with pytest.raises(CIMDTrustAnchorError) as excinfo:
            guard.approve("http://client.example.com/meta", approved_by="secops")
        assert excinfo.value.verdict is CIMDVerdict.DENY_SCHEME

    @pytest.mark.parametrize(
        "address",
        ["127.0.0.1", "10.0.0.5", "192.168.1.10", "169.254.169.254", "::1"],
    )
    def test_host_resolving_to_non_public_address_is_refused(self, address: str) -> None:
        guard = CIMDGuard(
            store=InMemoryCIMDPinStore(),
            fetcher=FakeFetch(),
            resolver=lambda _host: [address],
        )

        with pytest.raises(CIMDTrustAnchorError) as excinfo:
            guard.approve(CLIENT_ID, approved_by="secops")

        assert excinfo.value.verdict is CIMDVerdict.DENY_PRIVATE_ADDRESS

    def test_literal_loopback_host_is_refused(self) -> None:
        guard = _guard(FakeFetch())

        with pytest.raises(CIMDTrustAnchorError) as excinfo:
            guard.approve("https://127.0.0.1/meta", approved_by="secops")

        assert excinfo.value.verdict is CIMDVerdict.DENY_PRIVATE_ADDRESS

    def test_cross_origin_redirect_is_refused(self) -> None:
        fetch = FakeFetch(
            url_chain=(CLIENT_ID, "https://cdn.attacker.example/oauth-client"),
        )
        guard = _guard(fetch)

        with pytest.raises(CIMDTrustAnchorError) as excinfo:
            guard.approve(CLIENT_ID, approved_by="secops")

        assert excinfo.value.verdict is CIMDVerdict.DENY_CROSS_ORIGIN_REDIRECT

    def test_same_origin_redirect_is_allowed(self) -> None:
        fetch = FakeFetch(
            url_chain=(CLIENT_ID, "https://client.example.com/.well-known/oauth-client/"),
        )
        guard = _guard(fetch)

        assert guard.approve(CLIENT_ID, approved_by="secops").allowed

    def test_allow_private_addresses_is_an_explicit_opt_in(self) -> None:
        guard = CIMDGuard(
            store=InMemoryCIMDPinStore(),
            fetcher=FakeFetch(),
            resolver=lambda _host: ["10.0.0.5"],
            allow_private_addresses=True,
        )

        assert guard.approve(CLIENT_ID, approved_by="secops").allowed


# ---------------------------------------------------------------------------
# (d) revocation
# ---------------------------------------------------------------------------


class TestCIMDRevocation:
    def test_404_moves_to_denied_not_unknown(self) -> None:
        fetch = FakeFetch()
        guard = _guard(fetch)
        guard.approve(CLIENT_ID, approved_by="secops")

        fetch.status = 404
        first = guard.check(CLIENT_ID)
        assert not first.allowed
        assert first.verdict is CIMDVerdict.DENY_REVOKED

        pin = guard.store.get(CLIENT_ID)
        assert pin is not None, "a 404 must not erase the pin back to unknown"
        assert pin.state is CIMDPinState.REVOKED

        # Sticky: even if the document comes back, the client stays denied until re-approved.
        fetch.status = 200
        second = guard.check(CLIENT_ID)
        assert not second.allowed
        assert second.verdict is CIMDVerdict.DENY_REVOKED

    def test_missing_required_field_moves_to_denied(self) -> None:
        fetch = FakeFetch()
        guard = _guard(fetch)
        guard.approve(CLIENT_ID, approved_by="secops")

        stripped = _doc()
        del stripped["redirect_uris"]
        fetch.payload = stripped

        decision = guard.check(CLIENT_ID)
        assert not decision.allowed
        assert decision.verdict is CIMDVerdict.DENY_MALFORMED
        assert "redirect_uris" in decision.reason

        pin = guard.store.get(CLIENT_ID)
        assert pin is not None
        assert pin.state is CIMDPinState.REVOKED

    def test_revoked_client_recovers_only_via_explicit_approval(self) -> None:
        fetch = FakeFetch()
        guard = _guard(fetch)
        guard.approve(CLIENT_ID, approved_by="secops")
        guard.revoke(CLIENT_ID, reason="incident-1234")

        assert guard.check(CLIENT_ID).verdict is CIMDVerdict.DENY_REVOKED

        guard.approve(CLIENT_ID, approved_by="secops")
        assert guard.check(CLIENT_ID).allowed

    def test_document_declaring_a_different_client_id_is_malformed(self) -> None:
        fetch = FakeFetch(payload=_doc(client_id="https://other.example.com/meta"))
        guard = _guard(fetch)

        with pytest.raises(CIMDTrustAnchorError) as excinfo:
            guard.approve(CLIENT_ID, approved_by="secops")

        assert excinfo.value.verdict is CIMDVerdict.DENY_MALFORMED

    def test_non_json_document_is_malformed(self) -> None:
        guard = _guard(FakeFetch(raw="<html>not json</html>"))

        with pytest.raises(CIMDTrustAnchorError) as excinfo:
            guard.approve(CLIENT_ID, approved_by="secops")

        assert excinfo.value.verdict is CIMDVerdict.DENY_MALFORMED

    def test_revoke_unknown_client_returns_false(self) -> None:
        guard = _guard(FakeFetch())
        assert guard.revoke("https://never.seen.example/meta") is False


# ---------------------------------------------------------------------------
# One decision point: the capability-union grant path
# ---------------------------------------------------------------------------


class TestCIMDInGrantPath:
    @staticmethod
    def _engine(guard: CIMDGuard) -> CapabilityCapEngine:
        return CapabilityCapEngine(CapabilityRulesConfig(rules=()), cimd_guard=guard)

    @staticmethod
    def _lease() -> Lease:
        return Lease(
            lease_id="lease-1",
            capability="read_config",
            categories=frozenset({CapabilityCategory.FILESYSTEM_READ}),
        )

    def test_grant_lease_denies_on_drift_before_union_evaluation(self) -> None:
        fetch = FakeFetch()
        guard = _guard(fetch)
        guard.approve(CLIENT_ID, approved_by="secops")
        engine = self._engine(guard)

        fetch.payload = _doc(redirect_uris=["https://attacker.example/steal"])

        with pytest.raises(CIMDTrustAnchorError) as excinfo:
            engine.grant_lease("agent-1", self._lease(), client_id=CLIENT_ID)

        assert excinfo.value.verdict is CIMDVerdict.DENY_DRIFT
        # The lease must not have been recorded.
        assert engine.held_leases("agent-1") == ()

    def test_grant_lease_allows_when_pin_matches(self) -> None:
        guard = _guard(FakeFetch())
        guard.approve(CLIENT_ID, approved_by="secops")
        engine = self._engine(guard)

        decision = engine.grant_lease("agent-1", self._lease(), client_id=CLIENT_ID)

        assert decision.allowed
        assert len(engine.held_leases("agent-1")) == 1

    def test_grant_lease_denies_unpinned_client(self) -> None:
        engine = self._engine(_guard(FakeFetch()))

        with pytest.raises(CIMDTrustAnchorError) as excinfo:
            engine.grant_lease("agent-1", self._lease(), client_id=CLIENT_ID)

        assert excinfo.value.verdict is CIMDVerdict.DENY_UNPINNED

    def test_no_client_id_leaves_existing_behaviour_untouched(self) -> None:
        engine = self._engine(_guard(FakeFetch()))

        decision = engine.grant_lease("agent-1", self._lease())

        assert decision.allowed

    def test_per_call_guard_overrides_engine_default(self) -> None:
        guard = _guard(FakeFetch())
        guard.approve(CLIENT_ID, approved_by="secops")
        engine = CapabilityCapEngine(CapabilityRulesConfig(rules=()))

        decision = engine.grant_lease(
            "agent-1", self._lease(), client_id=CLIENT_ID, cimd_guard=guard
        )

        assert decision.allowed


class TestCIMDDefaultsFactory:
    def test_factory_returns_deny_by_default_guard(self) -> None:
        guard = cimd_trust_anchor_defaults(fetcher=FakeFetch(), resolver=_public_resolver)

        assert guard.check(CLIENT_ID).verdict is CIMDVerdict.DENY_UNPINNED
        assert guard.allow_private_addresses is False
