"""``airlock graph`` CLI (v0.5.9+).

Subcommands:

* ``airlock graph serve --audit-log <path> [--port 8765]``  Local UI
* ``airlock graph dump --audit-log <path>``                   JSON dump
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from ..graph.builder import build_snapshot
from ..graph.server import build_snapshot_for_path, serve


def _cmd_serve(args: argparse.Namespace) -> int:
    httpd = serve(
        jsonl_path=Path(args.audit_log) if args.audit_log else None,
        host=args.host,
        port=args.port,
    )
    print(f"airlock graph serving on http://{args.host}:{args.port}", file=sys.stderr)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        httpd.shutdown()
    return 0


def _cmd_dump(args: argparse.Namespace) -> int:
    snap = build_snapshot_for_path(Path(args.audit_log))
    print(json.dumps(snap.to_dict(), indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="airlock graph")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_serve = sub.add_parser("serve")
    p_serve.add_argument("--audit-log", default=None, help="path to a JSON-Lines audit file")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8765)
    p_serve.set_defaults(func=_cmd_serve)

    p_dump = sub.add_parser("dump")
    p_dump.add_argument("--audit-log", required=True)
    p_dump.set_defaults(func=_cmd_dump)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())


__all__ = ["build_snapshot", "main"]
