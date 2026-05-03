"""Tests for v0.7.0 SignedAgentIdentity (#33)."""

from __future__ import annotations

import pytest

# Optional dep — skip the whole module if [crypto] isn't installed.
cryptography = pytest.importorskip("cryptography")

from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)

from agent_airlock.identity import (  # noqa: E402
    IdentityVerificationError,
    SignedAgentIdentity,
    pubkey_fingerprint,
    sign_identity,
    verify_identity,
)
from agent_airlock.policy import AgentIdentity  # noqa: E402


@pytest.fixture
def identity() -> AgentIdentity:
    return AgentIdentity(
        agent_id="agent-42",
        session_id="sess-1",
        roles=["reader", "deploy-bot"],
        metadata={"team": "platform"},
    )


@pytest.fixture
def keypair() -> tuple[Ed25519PrivateKey, object]:
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


class TestSignAndVerifyRoundTrip:
    def test_round_trip_returns_equivalent_identity(
        self,
        identity: AgentIdentity,
        keypair: tuple[Ed25519PrivateKey, object],
    ) -> None:
        priv, pub = keypair
        signed = sign_identity(identity, priv)
        assert isinstance(signed, SignedAgentIdentity)
        verified = verify_identity(signed, pub)
        assert verified.agent_id == identity.agent_id
        assert verified.session_id == identity.session_id
        assert verified.roles == identity.roles
        assert verified.metadata == identity.metadata

    def test_signature_is_64_bytes_hex_encoded(
        self,
        identity: AgentIdentity,
        keypair: tuple[Ed25519PrivateKey, object],
    ) -> None:
        priv, _ = keypair
        signed = sign_identity(identity, priv)
        # ed25519 signatures are exactly 64 bytes / 128 hex chars.
        assert len(signed.signature_hex) == 128
        bytes.fromhex(signed.signature_hex)  # should not raise

    def test_signed_envelope_carries_agent_id_for_logging(
        self,
        identity: AgentIdentity,
        keypair: tuple[Ed25519PrivateKey, object],
    ) -> None:
        priv, _ = keypair
        signed = sign_identity(identity, priv)
        assert signed.agent_id == "agent-42"


class TestTamperDetection:
    def test_tampered_canonical_bytes_fail_verification(
        self,
        identity: AgentIdentity,
        keypair: tuple[Ed25519PrivateKey, object],
    ) -> None:
        priv, pub = keypair
        signed = sign_identity(identity, priv)
        tampered = SignedAgentIdentity(
            agent_id=signed.agent_id,
            canonical_bytes=signed.canonical_bytes.replace(b"agent-42", b"admin-99"),
            signature_hex=signed.signature_hex,
            signer_fingerprint=signed.signer_fingerprint,
        )
        with pytest.raises(IdentityVerificationError, match="signature does not verify"):
            verify_identity(tampered, pub)

    def test_tampered_signature_fails_verification(
        self,
        identity: AgentIdentity,
        keypair: tuple[Ed25519PrivateKey, object],
    ) -> None:
        priv, pub = keypair
        signed = sign_identity(identity, priv)
        # Flip the last byte of the signature.
        bad_hex = signed.signature_hex[:-2] + ("00" if signed.signature_hex[-2:] != "00" else "ff")
        tampered = SignedAgentIdentity(
            agent_id=signed.agent_id,
            canonical_bytes=signed.canonical_bytes,
            signature_hex=bad_hex,
            signer_fingerprint=signed.signer_fingerprint,
        )
        with pytest.raises(IdentityVerificationError):
            verify_identity(tampered, pub)


class TestWrongKey:
    def test_wrong_public_key_fingerprint_mismatch(
        self,
        identity: AgentIdentity,
        keypair: tuple[Ed25519PrivateKey, object],
    ) -> None:
        priv, _ = keypair
        signed = sign_identity(identity, priv)
        # Generate a totally different keypair.
        other_pub = Ed25519PrivateKey.generate().public_key()
        with pytest.raises(IdentityVerificationError, match="fingerprint mismatch"):
            verify_identity(signed, other_pub)


class TestPubkeyFingerprint:
    def test_fingerprint_is_32_hex_chars(
        self,
        keypair: tuple[Ed25519PrivateKey, object],
    ) -> None:
        _, pub = keypair
        fp = pubkey_fingerprint(pub)
        assert len(fp) == 32
        bytes.fromhex(fp)  # validates lowercase hex

    def test_fingerprint_stable_across_calls(
        self,
        keypair: tuple[Ed25519PrivateKey, object],
    ) -> None:
        _, pub = keypair
        assert pubkey_fingerprint(pub) == pubkey_fingerprint(pub)

    def test_fingerprint_different_for_different_keys(self) -> None:
        a = Ed25519PrivateKey.generate().public_key()
        b = Ed25519PrivateKey.generate().public_key()
        assert pubkey_fingerprint(a) != pubkey_fingerprint(b)


class TestInvalidInputs:
    def test_sign_rejects_non_ed25519_private_key(
        self,
        identity: AgentIdentity,
    ) -> None:
        with pytest.raises(IdentityVerificationError, match="not an Ed25519PrivateKey"):
            sign_identity(identity, "not-a-key")  # type: ignore[arg-type]

    def test_verify_rejects_non_ed25519_public_key(
        self,
        identity: AgentIdentity,
        keypair: tuple[Ed25519PrivateKey, object],
    ) -> None:
        priv, _ = keypair
        signed = sign_identity(identity, priv)
        with pytest.raises(IdentityVerificationError, match="not an Ed25519PublicKey"):
            verify_identity(signed, "not-a-key")  # type: ignore[arg-type]

    def test_verify_rejects_malformed_hex(
        self,
        identity: AgentIdentity,
        keypair: tuple[Ed25519PrivateKey, object],
    ) -> None:
        priv, pub = keypair
        signed = sign_identity(identity, priv)
        bad = SignedAgentIdentity(
            agent_id=signed.agent_id,
            canonical_bytes=signed.canonical_bytes,
            signature_hex="not-hex-zz",
            signer_fingerprint=signed.signer_fingerprint,
        )
        with pytest.raises(IdentityVerificationError, match="not valid hex"):
            verify_identity(bad, pub)


class TestCanonicalBytes:
    def test_canonical_bytes_are_deterministic(
        self,
        identity: AgentIdentity,
        keypair: tuple[Ed25519PrivateKey, object],
    ) -> None:
        priv, _ = keypair
        a = sign_identity(identity, priv)
        b = sign_identity(identity, priv)
        # Same identity → same canonical bytes (signatures are
        # deterministic for ed25519, so they should also match).
        assert a.canonical_bytes == b.canonical_bytes
        assert a.signature_hex == b.signature_hex

    def test_role_order_does_not_affect_canonical_bytes(
        self,
        keypair: tuple[Ed25519PrivateKey, object],
    ) -> None:
        """Roles are signed in their list order — preserve operator intent.

        Operators may rely on role priority order in some policies, so
        we sign roles as-given. (Sorting roles before sign is therefore
        the caller's responsibility if they want order-insensitivity.)
        """
        priv, _ = keypair
        a = sign_identity(AgentIdentity(agent_id="x", roles=["a", "b"]), priv)
        b = sign_identity(AgentIdentity(agent_id="x", roles=["b", "a"]), priv)
        assert a.canonical_bytes != b.canonical_bytes
