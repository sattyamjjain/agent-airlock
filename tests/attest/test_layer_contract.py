"""Tests for the v0.8.5 LayerContract receipt extension.

Honest scope
------------
The v0.8.5 extension adds an **opt-in** ``contract: LayerContract | None``
field to the existing ``Receipt`` dataclass. When the operator passes
``--contract`` to ``airlock attest receipt emit``, the CLI derives the
contract block from the verdicts list it already received and embeds
it in the signed payload.

The 2026-05-21 prompt assumed a "policy outcomes tracked this window"
counter store. That store does NOT exist in agent-airlock. The honest
shape we ship instead: derive per-guard ``pass_rate`` from the
``verdicts: list[ReceiptVerdict]`` the operator already supplies to
``build_receipt`` — same source of truth, no new infrastructure.

What we explicitly do NOT ship in v0.8.5:
  - A new sliding-window counter store. (Future work; would let the
    contract be derived from a window rather than a per-run verdicts
    list.)
  - An automatic in-process collector. The operator still feeds
    verdicts in; we derive metrics from them.

Anchor
------
arXiv:2605.18672 — "assume-guarantee layer contract" framing. Cited
once in the README; this module does not make further claims about
the paper's specific content beyond adopting the terminology.
"""

from __future__ import annotations

import pytest

from agent_airlock.attest.receipt import (
    Guarantee,
    LayerContract,
    ReceiptVerdict,
    build_receipt,
    derive_contract_from_verdicts,
    receipt_from_dict,
    receipt_from_json,
    receipt_to_json,
    verify_receipt,
)
from agent_airlock.attest.signer import FileSigner

# ----------------------------------------------------------------------
# Shared fixtures
# ----------------------------------------------------------------------


def _verdicts() -> list[ReceiptVerdict]:
    """Three guards, varied verdict mix.

    Per :data:`ReceiptVerdictKind`, the valid verdicts are
    ``allow|warn|block|error``. We treat anything ``!= "allow"`` as a
    pass-rate miss (block/warn/error all count as non-pass for the
    purposes of guarantee accounting).

    EvalRCEGuard:   3 allow, 1 block -> pass_rate = 3/4 = 0.75
    PIIMasker:      2 warn           -> pass_rate = 0/2 = 0.00
    GhostArgFilter: 1 allow          -> pass_rate = 1/1 = 1.00
    """
    return [
        ReceiptVerdict(guard="EvalRCEGuard", verdict="allow", tool_name="x"),
        ReceiptVerdict(guard="EvalRCEGuard", verdict="allow", tool_name="x"),
        ReceiptVerdict(guard="EvalRCEGuard", verdict="allow", tool_name="x"),
        ReceiptVerdict(guard="EvalRCEGuard", verdict="block", tool_name="x"),
        ReceiptVerdict(guard="PIIMasker", verdict="warn", tool_name="y"),
        ReceiptVerdict(guard="PIIMasker", verdict="warn", tool_name="y"),
        ReceiptVerdict(guard="GhostArgFilter", verdict="allow", tool_name="z"),
    ]


def _make_signer(tmp_path) -> FileSigner:
    """Create a FileSigner pointing at a freshly-written key file."""
    key_path = tmp_path / "k.bin"
    key_path.write_bytes(b"dev-only-test-key-do-not-use-in-prod-0123456789abcdef")
    return FileSigner(keyid="test-key", key_path=key_path)


# ----------------------------------------------------------------------
# Guarantee + LayerContract dataclass shape
# ----------------------------------------------------------------------


class TestGuaranteeShape:
    """``Guarantee`` is a frozen dataclass with name + pass_rate + sample_size."""

    def test_guarantee_is_frozen(self) -> None:
        g = Guarantee(name="EvalRCEGuard", pass_rate=0.75, sample_size=4)
        with pytest.raises((AttributeError, Exception)):  # FrozenInstanceError
            g.pass_rate = 0.0  # type: ignore[misc]

    def test_guarantee_fields(self) -> None:
        g = Guarantee(name="g", pass_rate=0.5, sample_size=2)
        assert g.name == "g"
        assert g.pass_rate == 0.5
        assert g.sample_size == 2

    def test_pass_rate_out_of_range_rejected(self) -> None:
        with pytest.raises(ValueError, match="pass_rate"):
            Guarantee(name="g", pass_rate=1.5, sample_size=1)
        with pytest.raises(ValueError, match="pass_rate"):
            Guarantee(name="g", pass_rate=-0.1, sample_size=1)


class TestLayerContractShape:
    """``LayerContract`` is a frozen dataclass with guarantees + assumes tuples."""

    def test_contract_is_frozen(self) -> None:
        c = LayerContract(guarantees=(), assumes=())
        with pytest.raises((AttributeError, Exception)):
            c.assumes = ("x",)  # type: ignore[misc]

    def test_empty_contract_is_valid(self) -> None:
        c = LayerContract(guarantees=(), assumes=())
        assert c.guarantees == ()
        assert c.assumes == ()

    def test_contract_carries_guarantees_and_assumes(self) -> None:
        c = LayerContract(
            guarantees=(Guarantee("EvalRCEGuard", 0.75, 4),),
            assumes=("upstream.tls.tlsv1.3",),
        )
        assert len(c.guarantees) == 1
        assert c.assumes[0] == "upstream.tls.tlsv1.3"


# ----------------------------------------------------------------------
# derive_contract_from_verdicts — the honest, no-new-infra path
# ----------------------------------------------------------------------


class TestDeriveFromVerdicts:
    """Per-guard ``pass_rate = count(verdict='allow') / total_for_that_guard``."""

    def test_derive_per_guard_pass_rates(self) -> None:
        contract = derive_contract_from_verdicts(_verdicts())
        by_name = {g.name: g for g in contract.guarantees}
        assert by_name["EvalRCEGuard"].pass_rate == pytest.approx(0.75)
        assert by_name["EvalRCEGuard"].sample_size == 4
        assert by_name["PIIMasker"].pass_rate == pytest.approx(0.0)
        assert by_name["PIIMasker"].sample_size == 2
        assert by_name["GhostArgFilter"].pass_rate == pytest.approx(1.0)
        assert by_name["GhostArgFilter"].sample_size == 1

    def test_derive_includes_assumes_when_supplied(self) -> None:
        contract = derive_contract_from_verdicts(
            _verdicts(), assumes=("upstream.tls.tlsv1.3", "upstream.dpop.bound")
        )
        assert contract.assumes == ("upstream.tls.tlsv1.3", "upstream.dpop.bound")

    def test_derive_empty_assumes_when_not_supplied(self) -> None:
        contract = derive_contract_from_verdicts(_verdicts())
        assert contract.assumes == ()

    def test_derive_empty_verdicts_yields_empty_guarantees(self) -> None:
        contract = derive_contract_from_verdicts([])
        assert contract.guarantees == ()
        assert contract.assumes == ()

    def test_derive_guarantees_are_sorted_by_name(self) -> None:
        """Deterministic ordering so canonical payload bytes are stable."""
        contract = derive_contract_from_verdicts(_verdicts())
        names = [g.name for g in contract.guarantees]
        assert names == sorted(names)


# ----------------------------------------------------------------------
# Receipt.contract round-trip
# ----------------------------------------------------------------------


class TestReceiptContractRoundTrip:
    """The contract block survives to_dict / from_dict / canonical-payload signing."""

    def test_receipt_to_dict_includes_contract_when_present(self, tmp_path) -> None:
        signer = _make_signer(tmp_path)
        contract = derive_contract_from_verdicts(_verdicts(), assumes=("upstream.tls.tlsv1.3",))
        receipt = build_receipt(
            policy_bundle_hash="abc",
            inputs={"prompt": "hello"},
            inputs_hash=None,
            model_id="claude-opus-4-7",
            verdicts=_verdicts(),
            signer=signer,
            contract=contract,
        )
        payload = receipt.to_dict()
        assert "contract" in payload
        assert "guarantees" in payload["contract"]
        assert "assumes" in payload["contract"]
        assert payload["contract"]["assumes"] == ["upstream.tls.tlsv1.3"]

    def test_receipt_to_dict_omits_contract_when_none(self, tmp_path) -> None:
        """Back-compat: receipts without contract serialise with no contract key."""
        signer = _make_signer(tmp_path)
        receipt = build_receipt(
            policy_bundle_hash="abc",
            inputs={"prompt": "hello"},
            inputs_hash=None,
            model_id="claude-opus-4-7",
            verdicts=_verdicts(),
            signer=signer,
            # contract not supplied
        )
        payload = receipt.to_dict()
        assert "contract" not in payload

    def test_receipt_from_dict_parses_contract(self, tmp_path) -> None:
        signer = _make_signer(tmp_path)
        contract = derive_contract_from_verdicts(_verdicts(), assumes=("upstream.x",))
        original = build_receipt(
            policy_bundle_hash="abc",
            inputs={"prompt": "hello"},
            inputs_hash=None,
            model_id="claude-opus-4-7",
            verdicts=_verdicts(),
            signer=signer,
            contract=contract,
        )
        roundtripped = receipt_from_dict(original.to_dict())
        assert roundtripped.contract is not None
        assert roundtripped.contract.assumes == ("upstream.x",)
        assert {g.name for g in roundtripped.contract.guarantees} == {
            "EvalRCEGuard",
            "PIIMasker",
            "GhostArgFilter",
        }

    def test_receipt_from_dict_handles_missing_contract(self, tmp_path) -> None:
        """Legacy receipts without the contract field still deserialise."""
        signer = _make_signer(tmp_path)
        receipt = build_receipt(
            policy_bundle_hash="abc",
            inputs={"prompt": "hello"},
            inputs_hash=None,
            model_id="claude-opus-4-7",
            verdicts=_verdicts(),
            signer=signer,
        )
        roundtripped = receipt_from_dict(receipt.to_dict())
        assert roundtripped.contract is None

    def test_signature_verifies_with_contract(self, tmp_path) -> None:
        """The signature over the canonical payload remains valid with contract."""
        signer = _make_signer(tmp_path)
        contract = derive_contract_from_verdicts(_verdicts(), assumes=("upstream.x",))
        receipt = build_receipt(
            policy_bundle_hash="abc",
            inputs={"prompt": "hello"},
            inputs_hash=None,
            model_id="claude-opus-4-7",
            verdicts=_verdicts(),
            signer=signer,
            contract=contract,
        )
        matched = verify_receipt(receipt, [signer])
        assert matched is signer

    def test_json_round_trip_preserves_contract(self, tmp_path) -> None:
        signer = _make_signer(tmp_path)
        contract = derive_contract_from_verdicts(_verdicts())
        receipt = build_receipt(
            policy_bundle_hash="abc",
            inputs={"prompt": "hello"},
            inputs_hash=None,
            model_id="claude-opus-4-7",
            verdicts=_verdicts(),
            signer=signer,
            contract=contract,
        )
        text = receipt_to_json(receipt)
        decoded = receipt_from_json(text)
        assert decoded.contract is not None
        assert len(decoded.contract.guarantees) == 3
