"""``airlock pack`` CLI (v0.5.8+).

Subcommands:
    list                       List shipped packs.
    install <pack-id>          Install a shipped pack.
    verify <manifest-path>     Verify a manifest's HMAC signature.
"""

from __future__ import annotations

import argparse
import json

from ..pack import (
    PackInstaller,
    load_manifest,
    sign_manifest,
    verify_manifest,
)
from ..pack.installer import discover_shipped_packs, find_shipped_pack


def _cmd_list(args: argparse.Namespace) -> int:
    paths = discover_shipped_packs()
    if args.format == "json":
        print(
            json.dumps(
                [
                    {
                        "pack_id": load_manifest(p).pack_id,
                        "version": load_manifest(p).version,
                        "manifest_path": str(p),
                    }
                    for p in paths
                ],
                indent=2,
            )
        )
    else:
        for p in paths:
            m = load_manifest(p)
            print(f"{m.pack_id}@{m.version} — {m.description}")
    return 0


def _cmd_install(args: argparse.Namespace) -> int:
    path = find_shipped_pack(args.pack_id)
    if path is None:
        print(f"unknown pack: {args.pack_id}", file=__import__("sys").stderr)
        return 2
    manifest = load_manifest(path)
    installed = PackInstaller().install(manifest)
    if args.format == "json":
        print(
            json.dumps(
                {
                    "pack_id": manifest.pack_id,
                    "version": manifest.version,
                    "installed_factories": sorted(installed.composed.keys()),
                },
                indent=2,
            )
        )
    else:
        print(
            f"installed {manifest.pack_id}@{manifest.version}: "
            f"{len(installed.composed)} preset(s) configured"
        )
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    from ..pack.signer import PackVerificationError

    manifest = load_manifest(__import__("pathlib").Path(args.manifest_path))
    try:
        verify_manifest(
            manifest,
            args.signature,
            signing_key=args.key.encode("utf-8") if args.key else None,
        )
    except PackVerificationError as exc:
        print(f"FAIL: {exc}", file=__import__("sys").stderr)
        return 1
    print(f"OK: {manifest.pack_id}@{manifest.version}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="airlock pack")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_list = sub.add_parser("list")
    p_list.set_defaults(func=_cmd_list)
    p_install = sub.add_parser("install")
    p_install.add_argument("pack_id")
    p_install.set_defaults(func=_cmd_install)
    p_verify = sub.add_parser("verify")
    p_verify.add_argument("manifest_path")
    p_verify.add_argument("signature")
    p_verify.add_argument("--key", help="signing key (default $AIRLOCK_PACK_SIGNING_KEY)")
    p_verify.set_defaults(func=_cmd_verify)
    args = parser.parse_args(argv)
    return int(args.func(args))


# Re-export for tests that don't want to import sign_manifest directly.
__all__ = ["main", "sign_manifest"]
