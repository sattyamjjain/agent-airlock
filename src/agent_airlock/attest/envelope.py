"""DSSE-style attestation envelope (v0.5.8+).

The envelope shape mirrors the in-toto / DSSE format closely enough
that v0.5.9 can drop in a real Sigstore Fulcio signer without
breaking on-disk artefacts:

.. code-block:: json

    {
      "_type": "https://airlock.dev/attestation/v1",
      "predicate_type": "https://airlock.dev/verdict/v1",
      "subject": {"agent_id": "...", "guard": "...", "verdict": "..."},
      "predicate": {"airlock_version": "0.5.8", "policy_id": "...",
                    "ts_epoch": 1700000000.0, "details": {...}},
      "signatures": [{"keyid": "...", "sig": "..."}]
    }
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from ..exceptions import AirlockError

ATTESTATION_TYPE = "https://airlock.dev/attestation/v1"
VERDICT_PREDICATE = "https://airlock.dev/verdict/v1"


class AttestationVerificationError(AirlockError):
    """Raised when an envelope's signature does not verify."""


@dataclass(frozen=True)
class AttestationSubject:
    """The thing being attested to."""

    agent_id: str
    guard: str
    verdict: str


@dataclass(frozen=True)
class AttestationPredicate:
    """Provenance metadata."""

    airlock_version: str
    policy_id: str
    ts_epoch: float
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AttestationSignature:
    keyid: str
    sig: str


@dataclass
class AttestationEnvelope:
    """The signed envelope."""

    subject: AttestationSubject
    predicate: AttestationPredicate
    signatures: tuple[AttestationSignature, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "_type": ATTESTATION_TYPE,
            "predicate_type": VERDICT_PREDICATE,
            "subject": {
                "agent_id": self.subject.agent_id,
                "guard": self.subject.guard,
                "verdict": self.subject.verdict,
            },
            "predicate": {
                "airlock_version": self.predicate.airlock_version,
                "policy_id": self.predicate.policy_id,
                "ts_epoch": self.predicate.ts_epoch,
                "details": self.predicate.details,
            },
            "signatures": [{"keyid": s.keyid, "sig": s.sig} for s in self.signatures],
        }

    def to_json(self, *, indent: int | None = None) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=indent)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> AttestationEnvelope:
        for required in ("_type", "predicate_type", "subject", "predicate", "signatures"):
            if required not in raw:
                raise AttestationVerificationError(f"missing envelope field {required!r}")
        if raw["_type"] != ATTESTATION_TYPE:
            raise AttestationVerificationError(f"unknown envelope _type: {raw['_type']!r}")
        s = raw["subject"]
        p = raw["predicate"]
        return cls(
            subject=AttestationSubject(
                agent_id=str(s["agent_id"]),
                guard=str(s["guard"]),
                verdict=str(s["verdict"]),
            ),
            predicate=AttestationPredicate(
                airlock_version=str(p["airlock_version"]),
                policy_id=str(p["policy_id"]),
                ts_epoch=float(p["ts_epoch"]),
                details=p.get("details", {}) or {},
            ),
            signatures=tuple(
                AttestationSignature(keyid=str(x["keyid"]), sig=str(x["sig"]))
                for x in raw["signatures"]
            ),
        )


def canonical_payload_bytes(envelope: AttestationEnvelope) -> bytes:
    """Bytes the signer signs over — everything except the signatures themselves."""
    payload = {
        "_type": ATTESTATION_TYPE,
        "predicate_type": VERDICT_PREDICATE,
        "subject": envelope.to_dict()["subject"],
        "predicate": envelope.to_dict()["predicate"],
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def envelope_sha256(envelope: AttestationEnvelope) -> str:
    return hashlib.sha256(canonical_payload_bytes(envelope)).hexdigest()


def build_envelope(
    *,
    agent_id: str,
    guard: str,
    verdict: str,
    airlock_version: str,
    policy_id: str,
    ts_epoch: float,
    details: dict[str, Any] | None = None,
    signer: Any | None = None,
) -> AttestationEnvelope:
    """Construct + (optionally) sign an envelope in one call."""
    envelope = AttestationEnvelope(
        subject=AttestationSubject(agent_id=agent_id, guard=guard, verdict=verdict),
        predicate=AttestationPredicate(
            airlock_version=airlock_version,
            policy_id=policy_id,
            ts_epoch=ts_epoch,
            details=details or {},
        ),
    )
    if signer is not None:
        sig = signer.sign(canonical_payload_bytes(envelope))
        envelope = AttestationEnvelope(
            subject=envelope.subject,
            predicate=envelope.predicate,
            signatures=(AttestationSignature(keyid=signer.keyid, sig=sig),),
        )
    return envelope


__all__ = [
    "ATTESTATION_TYPE",
    "AttestationEnvelope",
    "AttestationPredicate",
    "AttestationSignature",
    "AttestationSubject",
    "AttestationVerificationError",
    "VERDICT_PREDICATE",
    "build_envelope",
    "canonical_payload_bytes",
    "envelope_sha256",
]
