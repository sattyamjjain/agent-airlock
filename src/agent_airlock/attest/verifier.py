"""Envelope verifier (v0.5.8+).

Consumers verify an envelope by round-tripping the canonical payload
bytes through every signer's :meth:`verify` method until one matches
the stored signature. A failed verification raises
:class:`AttestationVerificationError`.
"""

from __future__ import annotations

from .envelope import (
    AttestationEnvelope,
    AttestationVerificationError,
    canonical_payload_bytes,
)
from .signer import Signer


def verify_envelope(
    envelope: AttestationEnvelope,
    signers: list[Signer],
) -> Signer:
    """Verify ``envelope`` against any of ``signers``.

    Returns the signer whose :meth:`Signer.verify` returned True.

    Raises:
        AttestationVerificationError: No signer matched, or the
            envelope has no signatures.
    """
    if not envelope.signatures:
        raise AttestationVerificationError("envelope has no signatures attached")
    payload = canonical_payload_bytes(envelope)
    for stored in envelope.signatures:
        for signer in signers:
            if signer.keyid != stored.keyid:
                continue
            try:
                if signer.verify(payload, stored.sig):
                    return signer
            except Exception:  # nosec B112 - try next candidate signer; no signer is fatal below
                continue
    raise AttestationVerificationError(
        f"no signer matched envelope keyids {[s.keyid for s in envelope.signatures]}"
    )


__all__ = ["verify_envelope"]
