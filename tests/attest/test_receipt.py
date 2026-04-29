"""Tests for ``Receipt`` (Feature A — signed agent-run attestation)."""

from __future__ import annotations

import json
import secrets
import subprocess
import sys
from pathlib import Path

import pytest

from agent_airlock.attest import (
    KMSStubSigner,
    Receipt,
    ReceiptFormatError,
    ReceiptVerdict,
    ReceiptVerificationError,
    build_receipt,
    hash_inputs,
    receipt_from_json,
    receipt_to_json,
    verify_receipt,
)
from agent_airlock.attest.signer import FileSigner
from agent_airlock.exceptions import AirlockError


@pytest.fixture
def signer() -> KMSStubSigner:
    return KMSStubSigner()


class TestErrorHierarchy:
    def test_verification_error_is_airlock(self) -> None:
        assert issubclass(ReceiptVerificationError, AirlockError)

    def test_format_error_is_airlock(self) -> None:
        assert issubclass(ReceiptFormatError, AirlockError)


class TestHashing:
    def test_inputs_hash_is_deterministic(self) -> None:
        a = hash_inputs({"x": 1, "y": "z"})
        b = hash_inputs({"y": "z", "x": 1})
        assert a == b


class TestBuildAndVerify:
    def test_round_trip(self, signer: KMSStubSigner) -> None:
        verdicts = [ReceiptVerdict(guard="stdio_meta_guard", verdict="block", tool_name="exec")]
        receipt = build_receipt(
            policy_bundle_hash="abc123",
            inputs={"prompt": "hello"},
            inputs_hash=None,
            model_id="claude-opus-4-7",
            verdicts=verdicts,
            signer=signer,
        )
        # Round-trip JSON and verify.
        text = receipt_to_json(receipt)
        loaded = receipt_from_json(text)
        assert loaded.run_id == receipt.run_id
        assert loaded.signature_keyid == signer.keyid
        verify_receipt(loaded, [signer])

    def test_verify_rejects_tampered_payload(self, signer: KMSStubSigner) -> None:
        receipt = build_receipt(
            policy_bundle_hash="abc",
            inputs=None,
            inputs_hash="deadbeef",
            model_id="x",
            verdicts=[],
            signer=signer,
        )
        tampered = receipt_from_json(receipt_to_json(receipt))
        # Mutate the model_id but keep the original signature.
        evil = Receipt(
            schema_version=tampered.schema_version,
            run_id=tampered.run_id,
            policy_bundle_hash=tampered.policy_bundle_hash,
            inputs_hash=tampered.inputs_hash,
            model_id="evil-model",
            ts=tampered.ts,
            verdicts=tampered.verdicts,
            signature_keyid=tampered.signature_keyid,
            signature_hex=tampered.signature_hex,
        )
        with pytest.raises(ReceiptVerificationError):
            verify_receipt(evil, [signer])

    def test_verify_rejects_unknown_keyid(self, signer: KMSStubSigner) -> None:
        receipt = build_receipt(
            policy_bundle_hash="abc",
            inputs=None,
            inputs_hash="deadbeef",
            model_id="x",
            verdicts=[],
            signer=signer,
        )
        # No matching signer.
        with pytest.raises(ReceiptVerificationError):
            verify_receipt(receipt, [])

    def test_inputs_xor_inputs_hash(self, signer: KMSStubSigner) -> None:
        with pytest.raises(ReceiptFormatError):
            build_receipt(
                policy_bundle_hash="abc",
                inputs={"x": 1},
                inputs_hash="deadbeef",
                model_id="x",
                verdicts=[],
                signer=signer,
            )
        with pytest.raises(ReceiptFormatError):
            build_receipt(
                policy_bundle_hash="abc",
                inputs=None,
                inputs_hash=None,
                model_id="x",
                verdicts=[],
                signer=signer,
            )


class TestFromDict:
    def test_missing_field_raises(self) -> None:
        with pytest.raises(ReceiptFormatError, match="missing required field"):
            receipt_from_json('{"schema_version": 1}')

    def test_unsupported_schema_raises(self) -> None:
        body = {
            "schema_version": 999,
            "run_id": "r",
            "policy_bundle_hash": "h",
            "inputs_hash": "i",
            "model_id": "m",
            "ts": "2026-04-29T00:00:00Z",
            "verdicts": [],
            "signature": {"keyid": "x", "sig": "y"},
        }
        with pytest.raises(ReceiptFormatError, match="schema_version"):
            receipt_from_json(json.dumps(body))


class TestFileSignerRoundTrip:
    def test_file_signer_verification(self, tmp_path: Path) -> None:
        keypath = tmp_path / "signing.key"
        keypath.write_bytes(secrets.token_bytes(32))
        fs = FileSigner(keyid="local-file", key_path=keypath)
        receipt = build_receipt(
            policy_bundle_hash="abc",
            inputs=None,
            inputs_hash="deadbeef",
            model_id="x",
            verdicts=[],
            signer=fs,
        )
        # Verifier with the same key path verifies.
        fs2 = FileSigner(keyid="local-file", key_path=keypath)
        verify_receipt(receipt, [fs2])


class TestCLI:
    def test_emit_then_verify_roundtrip(self, tmp_path: Path) -> None:
        out = tmp_path / "receipt.json"
        emit = subprocess.run(
            [
                sys.executable,
                "-m",
                "agent_airlock.cli.attest",
                "receipt",
                "emit",
                "--policy-bundle-hash",
                "abc",
                "--inputs-hash",
                "deadbeef",
                "--model-id",
                "claude-opus-4-7",
                "--kms-stub",
                "--output",
                str(out),
            ],
            capture_output=True,
            text=True,
        )
        assert emit.returncode == 0, emit.stderr
        verify = subprocess.run(
            [
                sys.executable,
                "-m",
                "agent_airlock.cli.attest",
                "receipt",
                "verify",
                str(out),
                "--kms-stub",
            ],
            capture_output=True,
            text=True,
        )
        assert verify.returncode == 0, verify.stderr
        assert "verified" in verify.stdout
