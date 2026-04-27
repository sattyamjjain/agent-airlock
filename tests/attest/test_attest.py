"""Tests for the v0.5.8 ``airlock attest`` envelope + signers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_airlock.attest import (
    AttestationEnvelope,
    AttestationVerificationError,
    EnvSigner,
    FileSigner,
    KMSStubSigner,
    build_envelope,
    verify_envelope,
)
from agent_airlock.attest.envelope import (
    ATTESTATION_TYPE,
    canonical_payload_bytes,
    envelope_sha256,
)


def _build(signer) -> AttestationEnvelope:
    return build_envelope(
        agent_id="agent-buyer",
        guard="pr_metadata",
        verdict="block",
        airlock_version="0.5.8",
        policy_id="claude-code-ci@2026.04",
        ts_epoch=1_700_000_000.0,
        details={"matches": 2, "risk_score": 0.95},
        signer=signer,
    )


class TestEnvelopeShape:
    def test_to_dict_roundtrip(self) -> None:
        envelope = _build(KMSStubSigner())
        raw = envelope.to_dict()
        assert raw["_type"] == ATTESTATION_TYPE
        assert raw["subject"]["agent_id"] == "agent-buyer"
        assert raw["predicate"]["airlock_version"] == "0.5.8"
        roundtrip = AttestationEnvelope.from_dict(raw)
        assert roundtrip.subject.agent_id == "agent-buyer"

    def test_canonical_payload_excludes_signatures(self) -> None:
        envelope = _build(KMSStubSigner())
        # Adding more signatures shouldn't change the canonical payload.
        more = AttestationEnvelope(
            subject=envelope.subject,
            predicate=envelope.predicate,
            signatures=envelope.signatures + envelope.signatures,
        )
        assert canonical_payload_bytes(envelope) == canonical_payload_bytes(more)

    def test_envelope_sha256_stable(self) -> None:
        envelope = _build(KMSStubSigner())
        assert envelope_sha256(envelope) == envelope_sha256(envelope)
        assert len(envelope_sha256(envelope)) == 64

    def test_unknown_type_rejected(self) -> None:
        bad = {
            "_type": "https://example.com/something-else",
            "predicate_type": "x",
            "subject": {"agent_id": "a", "guard": "g", "verdict": "v"},
            "predicate": {
                "airlock_version": "0.5.8",
                "policy_id": "p",
                "ts_epoch": 0.0,
                "details": {},
            },
            "signatures": [],
        }
        with pytest.raises(AttestationVerificationError, match="unknown envelope"):
            AttestationEnvelope.from_dict(bad)


class TestSigners:
    def test_kms_stub_round_trip(self) -> None:
        signer = KMSStubSigner()
        envelope = _build(signer)
        assert envelope.signatures
        result = verify_envelope(envelope, [signer])
        assert result is signer

    def test_file_signer_round_trip(self, tmp_path: Path) -> None:
        key_path = tmp_path / "key.bin"
        key_path.write_bytes(b"x" * 32)
        signer = FileSigner(keyid="file-1", key_path=key_path)
        envelope = _build(signer)
        result = verify_envelope(envelope, [signer])
        assert result.keyid == "file-1"

    def test_env_signer_round_trip(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AIRLOCK_ATTEST_SIGNING_KEY", "y" * 32)
        signer = EnvSigner(keyid="env-1")
        envelope = _build(signer)
        result = verify_envelope(envelope, [signer])
        assert result.keyid == "env-1"

    def test_wrong_key_fails_verification(self, tmp_path: Path) -> None:
        good = tmp_path / "good.bin"
        good.write_bytes(b"a" * 32)
        bad = tmp_path / "bad.bin"
        bad.write_bytes(b"b" * 32)
        signer_good = FileSigner(keyid="x", key_path=good)
        signer_bad = FileSigner(keyid="x", key_path=bad)
        envelope = _build(signer_good)
        # Verifying with the bad key — same keyid but wrong bytes.
        with pytest.raises(AttestationVerificationError):
            verify_envelope(envelope, [signer_bad])

    def test_no_signature_fails(self) -> None:
        envelope = AttestationEnvelope(
            subject=_build(KMSStubSigner()).subject,
            predicate=_build(KMSStubSigner()).predicate,
            signatures=(),
        )
        with pytest.raises(AttestationVerificationError, match="no signatures"):
            verify_envelope(envelope, [KMSStubSigner()])


class TestCLI:
    def test_attest_verify_subcommand(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        from agent_airlock.cli import attest as acli

        envelope = _build(KMSStubSigner())
        f = tmp_path / "envelope.json"
        f.write_text(envelope.to_json(indent=2), encoding="utf-8")

        rc = acli.main(["verify", str(f), "--kms-stub"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "OK" in out

    def test_attest_verify_failure(self, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
        from agent_airlock.cli import attest as acli

        # Build a bare envelope with no signature — verifier rejects.
        f = tmp_path / "envelope.json"
        f.write_text(
            json.dumps(
                {
                    "_type": "https://airlock.dev/attestation/v1",
                    "predicate_type": "https://airlock.dev/verdict/v1",
                    "subject": {"agent_id": "a", "guard": "g", "verdict": "v"},
                    "predicate": {
                        "airlock_version": "0.5.8",
                        "policy_id": "p",
                        "ts_epoch": 0.0,
                        "details": {},
                    },
                    "signatures": [],
                }
            ),
            encoding="utf-8",
        )
        rc = acli.main(["verify", str(f), "--kms-stub"])
        assert rc == 1
