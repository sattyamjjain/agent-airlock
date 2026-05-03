"""Signed agent identity (v0.7.0+, #33).

Background
----------
Up through v0.6.1, :class:`agent_airlock.policy.AgentIdentity` was a
plain dataclass — any code in the agent's address space could mutate
or forge ``agent_id`` / ``session_id`` / ``roles``. That maps to
**OWASP 2026 ASI03 — Identity and Privilege Abuse**: the policy
engine trusts a value that the policy is supposed to gate.

This module ships **opt-in** ed25519 signing. The hard constraint is
*no behavior change by default*. Existing callers who pass an
unsigned :class:`AgentIdentity` to :class:`SecurityPolicy.check`
keep working. Only callers who configure a verifier on the policy
trip the new check.

Surface
-------
- :func:`sign_identity(identity, private_key) -> SignedAgentIdentity`
- :func:`verify_identity(signed, public_key) -> AgentIdentity`
- :class:`SignedAgentIdentity` — wire-shape carrier (agent_id +
  signature + canonical bytes), `verify`-friendly across processes
- :class:`IdentityVerificationError(AirlockError)` — raised by
  :func:`verify_identity` on tamper / signature mismatch / wrong key
- :func:`pubkey_fingerprint(public_key) -> str` — stable hex-encoded
  SHA-256 prefix of the raw 32-byte ed25519 public key. Useful as
  the ``signer`` field in downstream attestation envelopes (see
  @desiorac's note on issue #33: this lets a Merkle-chained
  attestation layer reference the signer without coupling runtimes).

Optional dep
------------
``pip install "agent-airlock[crypto]"`` pulls
`cryptography <https://cryptography.io>`_. The ``cryptography``
package is **not** imported at module load — callers that don't
sign or verify never pay the import cost. Tests skip when the extra
isn't installed.

Why ed25519
-----------
- Deterministic signatures (no nonce-reuse footgun).
- Small, fast: 64-byte signatures, ~0.05 ms verify on commodity HW.
- Standardised in RFC 8032; ``cryptography`` exposes it directly.
- @desiorac's external comment on issue #33 explicitly asked about
  ed25519 as the carrier — keeping the choice consistent with what
  the downstream attestation layer expects avoids a future
  algorithm-negotiation conversation.

Wire format
-----------
The signed payload is canonical JSON over a fixed key order::

    {"agent_id": "...", "metadata": {...}, "roles": [...], "session_id": "..."}

Keys are sorted, separators are ``(",", ":")`` (no whitespace), so
two equivalent identities always produce identical signed bytes.
The signature is the raw 64-byte ed25519 signature, hex-encoded for
JSON-friendliness.

Primary references
------------------
- Issue #33 — https://github.com/sattyamjjain/agent-airlock/issues/33
- @desiorac comment (Merkle-chained attestation interop) —
  https://github.com/sattyamjjain/agent-airlock/issues/33#issuecomment-4306659626
- OWASP Agentic 2026 Top 10 (ASI03) —
  https://owasp.org/www-project-agentic-ai/
- ed25519 — RFC 8032: https://www.rfc-editor.org/rfc/rfc8032
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any

import structlog

from .exceptions import AirlockError
from .policy import AgentIdentity

if TYPE_CHECKING:
    # Keep the cryptography types out of the import-time path.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

logger = structlog.get_logger("agent-airlock.identity")


_INSTALL_HINT = (
    "ed25519 signing requires the `cryptography` package. "
    'Install the extra: pip install "agent-airlock[crypto]"'
)


class IdentityVerificationError(AirlockError):
    """Raised when :func:`verify_identity` cannot verify a signed identity.

    Reasons:
    - Signature does not match the canonical bytes under the supplied
      public key.
    - The signed payload was tampered with after signing.
    - The wrong public key was used for verification.
    - The ``cryptography`` package is missing (we treat that as a
      verification failure rather than an opaque ImportError).
    """


@dataclass(frozen=True)
class SignedAgentIdentity:
    """A signed-on-the-wire :class:`AgentIdentity` envelope.

    Attributes:
        agent_id: Convenience copy of the inner ``agent_id`` so logs
            can show who's calling without verifying first.
        canonical_bytes: The exact JSON bytes that were signed. Stored
            so the verifier can recompute the signature input without
            re-canonicalising and risking a different key order.
        signature_hex: Hex-encoded 64-byte ed25519 signature.
        signer_fingerprint: Hex-encoded SHA-256 prefix (16 bytes / 32
            hex chars) of the raw ed25519 public key that produced
            this signature. Lets verifiers and downstream attestation
            layers identify which key without needing the full pubkey.
    """

    agent_id: str
    canonical_bytes: bytes
    signature_hex: str
    signer_fingerprint: str


def _canonical_identity_bytes(identity: AgentIdentity) -> bytes:
    """Deterministic JSON serialisation for stable signing.

    Sorted keys, no whitespace, UTF-8. Excludes nothing — every
    field of the identity is part of the signature, so any later
    mutation invalidates the signature.
    """
    payload: dict[str, Any] = asdict(identity)
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def pubkey_fingerprint(public_key: Ed25519PublicKey) -> str:
    """Return a stable hex-encoded SHA-256 prefix of an ed25519 public key.

    The fingerprint is the first 16 bytes of ``SHA-256(raw_pubkey)``,
    hex-encoded — short enough to log, long enough to be collision-
    resistant for any realistic deployment. This is the interop
    surface for downstream attestation layers (per @desiorac's note
    on issue #33: a Merkle-chained attestation layer can reference
    the signer by fingerprint without taking a runtime dep on this
    module).

    Args:
        public_key: An :class:`Ed25519PublicKey` from
            ``cryptography.hazmat.primitives.asymmetric.ed25519``.

    Returns:
        A 32-character lowercase hex string (16 bytes of SHA-256).
    """
    from cryptography.hazmat.primitives import serialization

    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()[:32]


def sign_identity(
    identity: AgentIdentity,
    private_key: Ed25519PrivateKey,
) -> SignedAgentIdentity:
    """Sign an :class:`AgentIdentity` with an ed25519 private key.

    Args:
        identity: The plain identity to sign.
        private_key: An :class:`Ed25519PrivateKey`. Generate one with
            ``Ed25519PrivateKey.generate()``.

    Returns:
        A :class:`SignedAgentIdentity` carrying the canonical bytes,
        the hex signature, and the signer's fingerprint.

    Raises:
        IdentityVerificationError: ``cryptography`` is not installed.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey as _Priv,
        )
    except ImportError as exc:
        raise IdentityVerificationError(_INSTALL_HINT) from exc

    if not isinstance(private_key, _Priv):
        raise IdentityVerificationError(
            f"private_key is not an Ed25519PrivateKey; got {type(private_key).__name__}"
        )

    canonical = _canonical_identity_bytes(identity)
    signature = private_key.sign(canonical)
    fingerprint = pubkey_fingerprint(private_key.public_key())

    logger.debug(
        "agent_identity_signed",
        agent_id=identity.agent_id,
        fingerprint=fingerprint,
    )
    return SignedAgentIdentity(
        agent_id=identity.agent_id,
        canonical_bytes=canonical,
        signature_hex=signature.hex(),
        signer_fingerprint=fingerprint,
    )


def verify_identity(
    signed: SignedAgentIdentity,
    public_key: Ed25519PublicKey,
) -> AgentIdentity:
    """Verify a :class:`SignedAgentIdentity` and return the inner identity.

    Args:
        signed: The signed envelope to verify.
        public_key: The :class:`Ed25519PublicKey` that should have
            produced the signature.

    Returns:
        The verified :class:`AgentIdentity`. Mutating the returned
        object does NOT invalidate the original signature — callers
        who care about tamper-detection should keep the
        :class:`SignedAgentIdentity` and re-verify, not mutate.

    Raises:
        IdentityVerificationError: ``cryptography`` is missing, the
            signature is malformed, the signer fingerprint disagrees
            with ``public_key``, or the signature does not verify.
    """
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey as _Pub,
        )
    except ImportError as exc:
        raise IdentityVerificationError(_INSTALL_HINT) from exc

    if not isinstance(public_key, _Pub):
        raise IdentityVerificationError(
            f"public_key is not an Ed25519PublicKey; got {type(public_key).__name__}"
        )

    expected_fp = pubkey_fingerprint(public_key)
    if expected_fp != signed.signer_fingerprint:
        raise IdentityVerificationError(
            f"signer fingerprint mismatch: signed envelope claims "
            f"{signed.signer_fingerprint!r} but verifier holds "
            f"{expected_fp!r}"
        )

    try:
        signature = bytes.fromhex(signed.signature_hex)
    except ValueError as exc:
        raise IdentityVerificationError(f"signature_hex is not valid hex: {exc}") from exc

    try:
        public_key.verify(signature, signed.canonical_bytes)
    except InvalidSignature as exc:
        raise IdentityVerificationError(
            "ed25519 signature does not verify under the supplied public key — "
            "envelope was tampered with or signed with a different key"
        ) from exc

    payload = json.loads(signed.canonical_bytes.decode("utf-8"))
    return AgentIdentity(
        agent_id=payload["agent_id"],
        session_id=payload.get("session_id"),
        roles=list(payload.get("roles", [])),
        metadata=dict(payload.get("metadata", {})),
    )


__all__ = [
    "IdentityVerificationError",
    "SignedAgentIdentity",
    "pubkey_fingerprint",
    "sign_identity",
    "verify_identity",
]
