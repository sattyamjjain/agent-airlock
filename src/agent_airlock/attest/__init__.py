"""``airlock attest`` — DSSE-style verdict provenance (v0.5.8+).

Motivation
----------
[Anthropic Project Deal launched 2026-04-25](https://www.anthropic.com/features/project-deal)
makes verdicts financially load-bearing. Auditors and procurement
reviewers will ask "prove this verdict was emitted by an unmodified
airlock at version X with policy Y at timestamp Z." This module
ships the in-toto/DSSE-style envelope plus pluggable signers (file,
env, KMS, Sigstore Fulcio stub) so that question has a one-command
answer.

Surfaces
--------
- :class:`AttestationEnvelope` — the signed payload.
- :class:`Signer` protocol + 3 implementations (file, env, kms-stub).
- :func:`build_envelope` — construct + sign in one call.
- :func:`verify_envelope` — round-trip check.

Off by default. Enable via ``attestation.enabled: true`` policy or
``--attest`` CLI flag. The full Sigstore Fulcio integration is a
v0.5.9 milestone (issue #75 follow-up); the v0.5.8 surface ships
the envelope shape + HMAC-SHA256 file/env signer that's drop-in
replaceable later.
"""

from __future__ import annotations

from .envelope import (
    AttestationEnvelope,
    AttestationVerificationError,
    build_envelope,
)
from .receipt import (
    RECEIPT_SCHEMA_VERSION,
    Receipt,
    ReceiptFormatError,
    ReceiptVerdict,
    ReceiptVerificationError,
    build_receipt,
    hash_inputs,
    receipt_from_dict,
    receipt_from_json,
    receipt_to_json,
    verify_receipt,
)
from .signer import (
    EnvSigner,
    FileSigner,
    KMSStubSigner,
    Signer,
)
from .verifier import verify_envelope

__all__ = [
    "AttestationEnvelope",
    "AttestationVerificationError",
    "EnvSigner",
    "FileSigner",
    "KMSStubSigner",
    "RECEIPT_SCHEMA_VERSION",
    "Receipt",
    "ReceiptFormatError",
    "ReceiptVerdict",
    "ReceiptVerificationError",
    "Signer",
    "build_envelope",
    "build_receipt",
    "hash_inputs",
    "receipt_from_dict",
    "receipt_from_json",
    "receipt_to_json",
    "verify_envelope",
    "verify_receipt",
]
