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

    def to_dict(self) -> dict[str, Any]:
        return {
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
) -> Receipt:
    """Build and sign a receipt in one call.

    Either ``inputs`` (dict — hashed for you) OR ``inputs_hash`` (string,
    pre-computed) must be supplied. Pre-computed hashes let callers avoid
    materialising prompts in the receipt path.
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
    body = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "run_id": rid,
        "policy_bundle_hash": policy_bundle_hash,
        "inputs_hash": derived_hash,
        "model_id": model_id,
        "ts": when,
        "verdicts": [asdict(v) for v in verdicts],
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
