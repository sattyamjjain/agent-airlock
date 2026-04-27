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
    Signer,
    verify_envelope,
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="airlock attest")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_verify = sub.add_parser("verify")
    p_verify.add_argument("envelope_path")
    p_verify.add_argument("--key-file", help="path to signing key bytes")
    p_verify.add_argument("--env-var", help="env var holding signing key")
    p_verify.add_argument("--kms-stub", action="store_true", help="use the dev KMS stub")
    p_verify.add_argument("--keyid", help="keyid override")
    p_verify.set_defaults(func=_cmd_verify)
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = ["main"]
