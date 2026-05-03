"""``airlock manifest`` CLI (v0.6.1+).

Subcommands::

    airlock manifest enforce --server <name> --manifest <path> -- argv0 argv1 ...

The ``enforce`` subcommand is the CI-friendly fail-closed runtime gate
demanded by the OX/BackBox 2026-05-01 re-publication of the 200K-server
MCP-STDIO matrix:

- exit 0 on allow
- exit 2 on deny (CI-friendly: matches replay's denial exit code in v0.5.9+)
- exit 3 on hard error (manifest unreadable, signing key missing)

The argv after ``--`` is the command vector being asked-about. Pass it
with explicit ``--`` so argparse does not consume your flags::

    airlock manifest enforce \\
        --server local-fs --manifest manifests.json \\
        -- python -m mcp_server_filesystem /tmp
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..runtime.manifest_only_allowlist import (
    AllowlistVerdictReason,
    enforce_allowlist,
)

_EXIT_ALLOW = 0
_EXIT_DENY = 2
_EXIT_HARD_ERROR = 3


def _cmd_enforce(args: argparse.Namespace) -> int:
    """Run :func:`enforce_allowlist` and return a CI-friendly exit code."""
    if not args.argv:
        print("error: argv after `--` is required", file=sys.stderr)
        return _EXIT_HARD_ERROR

    manifest_path = Path(args.manifest)
    try:
        verdict = enforce_allowlist(
            server_name=args.server,
            argv=list(args.argv),
            manifest_path=manifest_path,
        )
    except (FileNotFoundError, ValueError) as exc:
        print(f"manifest read error: {exc}", file=sys.stderr)
        return _EXIT_HARD_ERROR

    payload = {
        "allowed": verdict.allowed,
        "reason": verdict.reason.value,
        "detail": verdict.detail,
        "manifest_id": verdict.manifest_id,
    }

    if args.format == "json":
        print(json.dumps(payload, sort_keys=True, indent=2))
    else:
        status = "allow" if verdict.allowed else "DENY"
        print(f"{status}: {verdict.manifest_id} — {verdict.reason.value}: {verdict.detail}")

    if verdict.allowed:
        return _EXIT_ALLOW
    if verdict.reason == AllowlistVerdictReason.SIGNING_KEY_MISSING:
        return _EXIT_HARD_ERROR
    return _EXIT_DENY


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="airlock manifest — runtime allowlist enforcement")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_enforce = sub.add_parser(
        "enforce",
        help="fail-closed runtime allowlist gate against a signed manifest",
    )
    p_enforce.add_argument("--server", required=True, help="manifest_id to look up")
    p_enforce.add_argument("--manifest", required=True, help="path to signed JSON manifest")
    p_enforce.add_argument(
        "argv",
        nargs=argparse.REMAINDER,
        help="argv vector (separate from flags with `--`)",
    )
    p_enforce.set_defaults(func=_cmd_enforce)

    args = parser.parse_args(argv)
    # argparse REMAINDER captures the leading `--` — strip it.
    if hasattr(args, "argv") and args.argv and args.argv[0] == "--":
        args.argv = args.argv[1:]
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())


__all__ = ["main"]
