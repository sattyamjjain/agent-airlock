"""``airlock attest`` CLI (v0.5.8+).

Subcommands:
    verify <envelope-path>     Verify a saved envelope JSON file.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..attest import (
    AttestationEnvelope,
    AttestationVerificationError,
    EnvSigner,
    FileSigner,
    KMSStubSigner,
    ReceiptVerdict,
    ReceiptVerificationError,
    Signer,
    build_receipt,
    receipt_from_json,
    receipt_to_json,
    verify_envelope,
    verify_receipt,
)


def _load(path: Path) -> AttestationEnvelope:
    return AttestationEnvelope.from_dict(json.loads(path.read_text(encoding="utf-8")))


def _cmd_verify(args: argparse.Namespace) -> int:
    envelope = _load(Path(args.envelope_path))
    signers: list[Signer] = []
    if args.key_file:
        signers.append(FileSigner(keyid=args.keyid or "file", key_path=Path(args.key_file)))
    if args.env_var:
        signers.append(EnvSigner(keyid=args.keyid or "env", env_var=args.env_var))
    if args.kms_stub:
        signers.append(KMSStubSigner())
    if not signers:
        signers.append(KMSStubSigner())
    try:
        signer = verify_envelope(envelope, signers)
    except AttestationVerificationError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"OK: envelope verified by {signer.keyid!r}")
    return 0


def _build_signers(args: argparse.Namespace) -> list[Signer]:
    signers: list[Signer] = []
    if getattr(args, "key_file", None):
        signers.append(FileSigner(keyid=args.keyid or "file", key_path=Path(args.key_file)))
    if getattr(args, "env_var", None):
        signers.append(EnvSigner(keyid=args.keyid or "env", env_var=args.env_var))
    if getattr(args, "kms_stub", False):
        signers.append(KMSStubSigner())
    if not signers:
        signers.append(KMSStubSigner())
    return signers


def _cmd_receipt_emit(args: argparse.Namespace) -> int:
    signers = _build_signers(args)
    verdicts: list[ReceiptVerdict] = []
    if args.verdicts_json:
        raw = json.loads(Path(args.verdicts_json).read_text(encoding="utf-8"))
        if not isinstance(raw, list):
            print("verdicts JSON must be a list of objects", file=sys.stderr)
            return 1
        for v in raw:
            if isinstance(v, dict):
                verdicts.append(
                    ReceiptVerdict(
                        guard=str(v.get("guard", "")),
                        verdict=str(v.get("verdict", "allow")),  # type: ignore[arg-type]
                        tool_name=str(v.get("tool_name", "")),
                        detail=str(v.get("detail", "")),
                    )
                )
    receipt = build_receipt(
        policy_bundle_hash=args.policy_bundle_hash,
        inputs=None,
        inputs_hash=args.inputs_hash,
        model_id=args.model_id,
        verdicts=verdicts,
        signer=signers[0],
        run_id=args.run_id,
    )
    text = receipt_to_json(receipt)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"OK: receipt written to {args.output}")
    else:
        print(text)
    return 0


def _cmd_receipt_verify(args: argparse.Namespace) -> int:
    signers = _build_signers(args)
    receipt = receipt_from_json(Path(args.receipt_path).read_text(encoding="utf-8"))
    try:
        signer = verify_receipt(receipt, signers)
    except ReceiptVerificationError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"OK: receipt {receipt.run_id} verified by {signer.keyid!r}")
    return 0


def _add_signer_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--key-file", help="path to signing key bytes")
    p.add_argument("--env-var", help="env var holding signing key")
    p.add_argument("--kms-stub", action="store_true", help="use the dev KMS stub")
    p.add_argument("--keyid", help="keyid override")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="airlock attest")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_verify = sub.add_parser("verify", help="verify a DSSE attestation envelope")
    p_verify.add_argument("envelope_path")
    _add_signer_args(p_verify)
    p_verify.set_defaults(func=_cmd_verify)

    p_receipt = sub.add_parser("receipt", help="agent-run receipts (Feature A / v0.6.0)")
    receipt_sub = p_receipt.add_subparsers(dest="receipt_cmd", required=True)

    p_emit = receipt_sub.add_parser("emit", help="emit a signed receipt")
    p_emit.add_argument("--policy-bundle-hash", required=True)
    p_emit.add_argument("--inputs-hash", required=True)
    p_emit.add_argument("--model-id", required=True)
    p_emit.add_argument("--run-id", help="run id (default: random)")
    p_emit.add_argument("--verdicts-json", help="path to verdicts JSON list")
    p_emit.add_argument("--output", help="write receipt to file (default: stdout)")
    _add_signer_args(p_emit)
    p_emit.set_defaults(func=_cmd_receipt_emit)

    p_rverify = receipt_sub.add_parser("verify", help="verify a saved receipt")
    p_rverify.add_argument("receipt_path")
    _add_signer_args(p_rverify)
    p_rverify.set_defaults(func=_cmd_receipt_verify)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = ["main"]
