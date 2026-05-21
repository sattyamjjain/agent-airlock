"""Tests for the v0.8.5 ``airlock attest receipt emit --contract`` CLI flag."""

from __future__ import annotations

import json
from pathlib import Path

from agent_airlock.attest import receipt_from_json
from agent_airlock.cli.attest import main as attest_main


def _key_file(tmp_path: Path) -> Path:
    path = tmp_path / "k.bin"
    path.write_bytes(b"dev-only-test-key-do-not-use-in-prod-0123456789abcdef")
    return path


def _verdicts_file(tmp_path: Path) -> Path:
    path = tmp_path / "verdicts.json"
    path.write_text(
        json.dumps(
            [
                {"guard": "EvalRCEGuard", "verdict": "allow", "tool_name": "x"},
                {"guard": "EvalRCEGuard", "verdict": "allow", "tool_name": "x"},
                {"guard": "EvalRCEGuard", "verdict": "block", "tool_name": "x"},
                {"guard": "PIIMasker", "verdict": "warn", "tool_name": "y"},
                {"guard": "GhostArgFilter", "verdict": "allow", "tool_name": "z"},
            ]
        ),
        encoding="utf-8",
    )
    return path


def _common_emit_args(tmp_path: Path) -> list[str]:
    """Args shared by every test: required flags + key-file signer."""
    return [
        "receipt",
        "emit",
        "--policy-bundle-hash",
        "abc",
        "--inputs-hash",
        "deadbeef",
        "--model-id",
        "claude-opus-4-7",
        "--verdicts-json",
        str(_verdicts_file(tmp_path)),
        "--key-file",
        str(_key_file(tmp_path)),
        "--keyid",
        "test-key",
    ]


class TestContractFlag:
    """``--contract`` opts in to the LayerContract block."""

    def test_emit_without_contract_has_no_contract_field(self, tmp_path: Path) -> None:
        out_path = tmp_path / "r.json"
        argv = _common_emit_args(tmp_path) + ["--output", str(out_path)]
        rc = attest_main(argv)
        assert rc == 0
        body = json.loads(out_path.read_text(encoding="utf-8"))
        assert "contract" not in body

    def test_emit_with_contract_embeds_derived_block(self, tmp_path: Path) -> None:
        out_path = tmp_path / "r.json"
        argv = _common_emit_args(tmp_path) + [
            "--output",
            str(out_path),
            "--contract",
        ]
        rc = attest_main(argv)
        assert rc == 0
        body = json.loads(out_path.read_text(encoding="utf-8"))
        assert "contract" in body
        assert "guarantees" in body["contract"]
        assert "assumes" in body["contract"]
        # Three distinct guards in the fixture -> three guarantees.
        assert len(body["contract"]["guarantees"]) == 3
        names = {g["name"] for g in body["contract"]["guarantees"]}
        assert names == {"EvalRCEGuard", "PIIMasker", "GhostArgFilter"}

    def test_emit_with_contract_signature_round_trips(self, tmp_path: Path) -> None:
        """The signed payload includes the contract; verify_receipt accepts it."""
        out_path = tmp_path / "r.json"
        argv = _common_emit_args(tmp_path) + [
            "--output",
            str(out_path),
            "--contract",
        ]
        assert attest_main(argv) == 0

        # Round-trip through the public from_json + run the verify subcommand
        receipt = receipt_from_json(out_path.read_text(encoding="utf-8"))
        assert receipt.contract is not None

        verify_argv = [
            "receipt",
            "verify",
            str(out_path),
            "--key-file",
            str(_key_file(tmp_path)),
            "--keyid",
            "test-key",
        ]
        # Note: _key_file() rewrites the file on every call; the verify
        # path must point at the SAME bytes we signed with. Re-using the
        # tmp_path key we wrote at emit time guarantees that.
        assert attest_main(verify_argv) == 0

    def test_emit_with_assumes_propagates_into_payload(self, tmp_path: Path) -> None:
        out_path = tmp_path / "r.json"
        argv = _common_emit_args(tmp_path) + [
            "--output",
            str(out_path),
            "--contract",
            "--assumes",
            "upstream.tls.tlsv1.3,upstream.dpop.bound",
        ]
        assert attest_main(argv) == 0
        body = json.loads(out_path.read_text(encoding="utf-8"))
        assert body["contract"]["assumes"] == [
            "upstream.tls.tlsv1.3",
            "upstream.dpop.bound",
        ]

    def test_assumes_without_contract_is_a_usage_error(self, tmp_path: Path) -> None:
        """``--assumes`` only makes sense with ``--contract``; reject otherwise."""
        out_path = tmp_path / "r.json"
        argv = _common_emit_args(tmp_path) + [
            "--output",
            str(out_path),
            "--assumes",
            "upstream.x",
        ]
        rc = attest_main(argv)
        # Non-zero exit; we accept either argparse usage (2) or app error (1).
        assert rc != 0


class TestBackCompatPayload:
    """Existing emit invocations continue to produce v1 receipts (no contract)."""

    def test_legacy_emit_still_parses_through_receipt_from_json(self, tmp_path: Path) -> None:
        out_path = tmp_path / "r.json"
        argv = _common_emit_args(tmp_path) + ["--output", str(out_path)]
        assert attest_main(argv) == 0
        receipt = receipt_from_json(out_path.read_text(encoding="utf-8"))
        assert receipt.contract is None
