"""``ReceiptBuilder`` — signed per-run attestation receipts (v0.6.0+).

A receipt is a Sigstore-compatible JSON document emitted at the end
of every airlock-enforced agent run. Third-party verifiers can
re-derive the run's policy posture and the inputs hash from the
receipt alone, with the airlock public key — no proprietary tooling
required.

Receipt shape::

    {
      "schema_version": 1,
      "run_id": "...",
      "policy_bundle_hash": "...",
      "verdicts": [{"guard": "...", "verdict": "block", ...}, ...],
      "inputs_hash": "...",
      "model_id": "...",
      "ts": "2026-04-29T09:00:00Z",
      "signature": {"keyid": "...", "sig": "..."}
    }

This is the OSS-tooling answer to the Pillar Security 2026-04-23
attestation benchmark gap.

Reference
---------
* Pillar Security agent-identity & attestation benchmark (2026-04-23):
  https://pillar.security/blog/agent-identity-attestation-2026-04
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

from ..exceptions import AirlockError
from .signer import Signer

RECEIPT_SCHEMA_VERSION = 1

ReceiptVerdictKind = Literal["allow", "warn", "block", "error"]


class ReceiptVerificationError(AirlockError):
    """Raised when a receipt's signature does not verify."""


class ReceiptFormatError(AirlockError):
    """Raised when a receipt is missing required fields or malformed."""


@dataclass(frozen=True)
class ReceiptVerdict:
    """One per-tool-call verdict line in the receipt."""

    guard: str
    verdict: ReceiptVerdictKind
    tool_name: str = ""
    detail: str = ""


# ---------------------------------------------------------------------------
# LayerContract — v0.8.5 opt-in assume/guarantee block
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Guarantee:
    """One per-guard measured guarantee line in a :class:`LayerContract`.

    Attributes:
        name: Guard identifier (matches :attr:`ReceiptVerdict.guard`).
        pass_rate: Fraction in ``[0.0, 1.0]`` of verdicts on this guard
            that emitted ``"allow"`` over the sample.
        sample_size: Total verdicts seen for this guard in the sample.
            Reported so verifiers can weight low-sample-size guarantees
            appropriately.

    Raises:
        ValueError: ``pass_rate`` is outside ``[0.0, 1.0]``.
    """

    name: str
    pass_rate: float
    sample_size: int

    def __post_init__(self) -> None:
        if not (0.0 <= self.pass_rate <= 1.0):
            raise ValueError(f"pass_rate must be in [0.0, 1.0]; got {self.pass_rate!r}")


@dataclass(frozen=True)
class LayerContract:
    """Assume / guarantee block in the v0.8.5+ receipt payload.

    Honest scope: this block is **opt-in** and **derived** — agent-airlock
    does not run a sliding-window counter store. The guarantees are
    derived from the ``verdicts`` list the operator already supplies
    to :func:`build_receipt`; ``assumes`` is a free-form list of
    upstream-guarantee identifiers the operator declares.

    Anchor: arXiv:2605.18672 — "assume-guarantee layer contract" framing.

    Attributes:
        guarantees: Per-guard measured pass rates over the receipt's
            sample. Sorted by guard name for canonical-payload stability.
        assumes: Free-form upstream-guarantee identifiers the operator
            declares this layer depends on (e.g.
            ``"upstream.tls.tlsv1.3"``, ``"upstream.dpop.bound"``).
    """

    guarantees: tuple[Guarantee, ...]
    assumes: tuple[str, ...]


def derive_contract_from_verdicts(
    verdicts: Iterable[ReceiptVerdict],
    *,
    assumes: Sequence[str] = (),
) -> LayerContract:
    """Compute a :class:`LayerContract` from a verdicts iterable.

    Per-guard ``pass_rate = count(verdict == "allow") / total_for_that_guard``.
    Any verdict kind other than ``"allow"`` (``warn`` / ``block`` /
    ``error``) counts as a non-pass for guarantee accounting.

    Guarantees are emitted in name-sorted order so the canonical
    payload bytes used for signing are stable across runs.

    Args:
        verdicts: Iterable of :class:`ReceiptVerdict`. Empty input
            yields an empty ``guarantees`` tuple.
        assumes: Free-form upstream-guarantee identifiers to embed
            in the contract verbatim.

    Returns:
        A :class:`LayerContract`.
    """
    totals: dict[str, int] = {}
    allows: dict[str, int] = {}
    for v in verdicts:
        totals[v.guard] = totals.get(v.guard, 0) + 1
        if v.verdict == "allow":
            allows[v.guard] = allows.get(v.guard, 0) + 1
    guarantees = tuple(
        Guarantee(
            name=name,
            pass_rate=allows.get(name, 0) / totals[name],
            sample_size=totals[name],
        )
        for name in sorted(totals)
    )
    return LayerContract(guarantees=guarantees, assumes=tuple(assumes))


@dataclass(frozen=True)
class Receipt:
    """A signed agent-run receipt."""

    schema_version: int
    run_id: str
    policy_bundle_hash: str
    inputs_hash: str
    model_id: str
    ts: str
    verdicts: tuple[ReceiptVerdict, ...] = field(default_factory=tuple)
    signature_keyid: str = ""
    signature_hex: str = ""
    contract: LayerContract | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "policy_bundle_hash": self.policy_bundle_hash,
            "inputs_hash": self.inputs_hash,
            "model_id": self.model_id,
            "ts": self.ts,
            "verdicts": [asdict(v) for v in self.verdicts],
            "signature": {
                "keyid": self.signature_keyid,
                "sig": self.signature_hex,
            },
        }
        if self.contract is not None:
            payload["contract"] = {
                "guarantees": [asdict(g) for g in self.contract.guarantees],
                "assumes": list(self.contract.assumes),
            }
        return payload


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------


def hash_inputs(inputs: dict[str, Any]) -> str:
    """SHA-256 over the canonical JSON form of an inputs dict."""
    canonical = json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


# ---------------------------------------------------------------------------
# Build / sign / verify
# ---------------------------------------------------------------------------


def _canonical_payload(receipt_data: dict[str, Any]) -> bytes:
    """Canonical bytes used for signing — receipt minus its own signature."""
    body = {k: v for k, v in receipt_data.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_receipt(
    *,
    policy_bundle_hash: str,
    inputs: dict[str, Any] | None,
    inputs_hash: str | None,
    model_id: str,
    verdicts: list[ReceiptVerdict],
    signer: Signer,
    run_id: str | None = None,
    ts: datetime | None = None,
    contract: LayerContract | None = None,
) -> Receipt:
    """Build and sign a receipt in one call.

    Either ``inputs`` (dict — hashed for you) OR ``inputs_hash`` (string,
    pre-computed) must be supplied. Pre-computed hashes let callers avoid
    materialising prompts in the receipt path.

    Args:
        contract: Optional :class:`LayerContract` (v0.8.5+). When
            supplied, the contract block is embedded in the signed
            payload. The schema version stays at 1 because the field
            is additive — legacy v1 receipts have no ``contract`` key
            and continue to deserialise unchanged.
    """
    if (inputs is None) == (inputs_hash is None):
        raise ReceiptFormatError("exactly one of inputs / inputs_hash must be provided")
    derived_hash = inputs_hash if inputs_hash is not None else hash_inputs(inputs or {})
    when = (
        ts.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        if ts is not None
        else datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )
    rid = run_id or f"run_{uuid.uuid4().hex}"
    body: dict[str, Any] = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "run_id": rid,
        "policy_bundle_hash": policy_bundle_hash,
        "inputs_hash": derived_hash,
        "model_id": model_id,
        "ts": when,
        "verdicts": [asdict(v) for v in verdicts],
    }
    if contract is not None:
        body["contract"] = {
            "guarantees": [asdict(g) for g in contract.guarantees],
            "assumes": list(contract.assumes),
        }
    sig_hex = signer.sign(_canonical_payload(body))
    return Receipt(
        schema_version=RECEIPT_SCHEMA_VERSION,
        run_id=rid,
        policy_bundle_hash=policy_bundle_hash,
        inputs_hash=derived_hash,
        model_id=model_id,
        ts=when,
        verdicts=tuple(verdicts),
        signature_keyid=signer.keyid,
        signature_hex=sig_hex,
        contract=contract,
    )


def verify_receipt(receipt: Receipt, signers: list[Signer]) -> Signer:
    """Verify the signature against any registered signer; return the matcher.

    Raises :class:`ReceiptVerificationError` when no signer matches.
    """
    if not receipt.signature_hex or not receipt.signature_keyid:
        raise ReceiptVerificationError("receipt is missing a signature")
    payload = _canonical_payload(receipt.to_dict())
    for signer in signers:
        if signer.keyid != receipt.signature_keyid:
            continue
        try:
            if signer.verify(payload, receipt.signature_hex):
                return signer
        except Exception:  # nosec B112 - try next candidate signer
            continue
    raise ReceiptVerificationError(f"no signer matched receipt keyid {receipt.signature_keyid!r}")


# ---------------------------------------------------------------------------
# Serde
# ---------------------------------------------------------------------------


def receipt_from_dict(data: dict[str, Any]) -> Receipt:
    """Inverse of :meth:`Receipt.to_dict`."""
    for required in (
        "schema_version",
        "run_id",
        "policy_bundle_hash",
        "inputs_hash",
        "model_id",
        "ts",
    ):
        if required not in data:
            raise ReceiptFormatError(f"receipt missing required field {required!r}")
    if int(data["schema_version"]) != RECEIPT_SCHEMA_VERSION:
        raise ReceiptFormatError(f"unsupported receipt schema_version: {data['schema_version']}")
    sig = data.get("signature") or {}
    verdicts = tuple(
        ReceiptVerdict(
            guard=str(v.get("guard", "")),
            verdict=str(v.get("verdict", "allow")),  # type: ignore[arg-type]
            tool_name=str(v.get("tool_name", "")),
            detail=str(v.get("detail", "")),
        )
        for v in data.get("verdicts", [])
        if isinstance(v, dict)
    )
    # v0.8.5+: optional contract block. Absence means a pre-0.8.5
    # receipt and is fine — contract stays None.
    contract: LayerContract | None = None
    contract_data = data.get("contract")
    if isinstance(contract_data, dict):
        raw_guarantees = contract_data.get("guarantees", [])
        raw_assumes = contract_data.get("assumes", [])
        guarantees = tuple(
            Guarantee(
                name=str(g.get("name", "")),
                pass_rate=float(g.get("pass_rate", 0.0)),
                sample_size=int(g.get("sample_size", 0)),
            )
            for g in raw_guarantees
            if isinstance(g, dict)
        )
        assumes = tuple(str(a) for a in raw_assumes)
        contract = LayerContract(guarantees=guarantees, assumes=assumes)
    return Receipt(
        schema_version=int(data["schema_version"]),
        run_id=str(data["run_id"]),
        policy_bundle_hash=str(data["policy_bundle_hash"]),
        inputs_hash=str(data["inputs_hash"]),
        model_id=str(data["model_id"]),
        ts=str(data["ts"]),
        verdicts=verdicts,
        signature_keyid=str(sig.get("keyid", "")),
        signature_hex=str(sig.get("sig", "")),
        contract=contract,
    )


def receipt_to_json(receipt: Receipt) -> str:
    return json.dumps(receipt.to_dict(), sort_keys=True, indent=2)


def receipt_from_json(text: str) -> Receipt:
    return receipt_from_dict(json.loads(text))


__all__ = [
    "RECEIPT_SCHEMA_VERSION",
    "Receipt",
    "ReceiptFormatError",
    "ReceiptVerdict",
    "ReceiptVerificationError",
    "build_receipt",
    "hash_inputs",
    "receipt_from_dict",
    "receipt_from_json",
    "receipt_to_json",
    "verify_receipt",
]
