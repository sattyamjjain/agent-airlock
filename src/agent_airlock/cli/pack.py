"""``airlock pack`` CLI (v0.5.8+).

Subcommands:
    list                       List shipped packs.
    install <pack-id>          Install a shipped pack.
    verify <manifest-path>     Verify a manifest's HMAC signature.
"""

from __future__ import annotations

import argparse
import json
import sys

from ..pack import (
    PackInstaller,
    load_manifest,
    sign_manifest,
    verify_manifest,
)
from ..pack.installer import discover_shipped_packs, find_shipped_pack


def _cmd_list(args: argparse.Namespace) -> int:
    paths = discover_shipped_packs()
    # Load each manifest once and sort by (pack_id, version) so the
    # output order is deterministic regardless of filesystem listing
    # order. Pinned by ``test_pack_list_sorted_by_pack_id_then_version``.
    manifests = [(p, load_manifest(p)) for p in paths]
    manifests.sort(key=lambda pair: (pair[1].pack_id, pair[1].version))
    if args.format == "json":
        print(
            json.dumps(
                [
                    {
                        "pack_id": m.pack_id,
                        "version": m.version,
                        "manifest_path": str(p),
                    }
                    for p, m in manifests
                ],
                indent=2,
            )
        )
    else:
        for _p, m in manifests:
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


def _cmd_lock(args: argparse.Namespace) -> int:
    """Emit / verify ``policy_bundle.lock`` for a pack."""
    import json as _json
    from pathlib import Path as _Path

    from .. import __version__ as airlock_version
    from ..pack.lock import (
        LockfileDriftError,
        build_lock,
        read_lock,
        render_lock,
        verify_lock,
        write_lock,
    )

    path = _Path(args.manifest_path)
    if not path.exists():
        print(f"manifest not found: {path}", file=sys.stderr)
        return 2
    manifest = load_manifest(path)
    installer = PackInstaller()
    installed = installer.install(manifest)
    preset_data = {pid: dict(data) for pid, data in installed.composed.items()}
    lock = build_lock(preset_data, airlock_version=airlock_version)

    out_path = _Path(args.output) if args.output else path.parent / "policy_bundle.lock"
    if args.verify:
        existing = read_lock(out_path)
        try:
            verify_lock(existing, preset_data)
        except LockfileDriftError as exc:
            print(
                f"FAIL: {exc} (expected={exc.expected_sha256[:12]}, "
                f"actual={exc.actual_sha256[:12]})",
                file=sys.stderr,
            )
            return 2
        print(f"OK: lockfile at {out_path} matches current bundle")
        return 0
    write_lock(lock, out_path)
    if args.format == "json":
        print(
            _json.dumps(
                {
                    "lockfile": str(out_path),
                    "schema_version": lock.schema_version,
                    "airlock_version": lock.airlock_version,
                    "entries": [
                        {"preset_id": e.preset_id, "content_sha256": e.content_sha256}
                        for e in lock.entries
                    ],
                },
                indent=2,
            )
        )
    else:
        print(f"OK: {out_path} ({len(lock.entries)} presets pinned)")
        print(render_lock(lock))
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
    p_lock = sub.add_parser("lock", help="emit policy_bundle.lock for a pack manifest")
    p_lock.add_argument("manifest_path")
    p_lock.add_argument("--output", help="lockfile path (default: alongside manifest)")
    p_lock.add_argument(
        "--verify",
        action="store_true",
        help="verify an existing lockfile instead of regenerating",
    )
    p_lock.set_defaults(func=_cmd_lock)
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    import sys as _sys

    _sys.exit(main())


# Re-export for tests that don't want to import sign_manifest directly.
__all__ = ["main", "sign_manifest"]
