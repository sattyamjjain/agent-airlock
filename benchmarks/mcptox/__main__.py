"""CLI: ``python -m benchmarks.mcptox <command>``.

    python -m benchmarks.mcptox clean-view [--fetch] [--data PATH] [--server KEY|IDX]

``clean-view`` prints the clean side of each server only: its tool blocks, its clean
queries, and the roots and hosts the LP tier derives from those queries. It never prints
a poisoned tool, an attack query or a recorded response, so labels written from it are
blind to attack outcomes.
"""

from __future__ import annotations

import argparse
import sys
import textwrap
from pathlib import Path

from .clean import CleanServer, clean_servers
from .data import ChecksumMismatchError, DataUnavailableError, load, resolve_data_path


def _add_data_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--data", type=Path, help="use this response_all.json (verified)")
    parser.add_argument(
        "--fetch",
        action="store_true",
        help="download the pinned file into the cache if it is missing (about 21 MB)",
    )


def _select(servers: list[CleanServer], wanted: list[str] | None) -> list[CleanServer]:
    if not wanted:
        return servers
    out = []
    for item in wanted:
        match = [s for s in servers if s.key == item or s.name == item or str(s.index) == item]
        if not match:
            raise SystemExit(f"error: no server {item!r}")
        out.extend(match)
    return out


def render_clean_view(server: CleanServer, *, descriptions: bool = True) -> str:
    """The clean side of one server as plain text."""
    from .policies import derive_fs_roots, derive_hosts

    lines = [
        f"== [{server.index:02d}] {server.name}  (key {server.key!r}, "
        f"category {server.category_id}, {len(server.tools)} tool blocks)",
        f"   repository: {server.server_url}",
    ]
    for tool in server.tools:
        params = ", ".join(f"{p.name}{'*' if p.required else ''}" for p in tool.params)
        lines.append(f"  - {tool.name}({params})")
        if descriptions and tool.description:
            body = textwrap.indent(tool.description, "        ")
            lines.append(body)
    if server.clean_queries:
        lines.append(f"  clean queries ({len(server.clean_queries)}):")
        for i, query in enumerate(server.clean_queries):
            lines.append(f"    clean_querys[{i}]: {query}")
        roots = derive_fs_roots(server.clean_queries)
        hosts = derive_hosts(server.clean_queries)
        lines.append(f"  derived fs roots: {list(roots.roots)}  (refused: {list(roots.refused)})")
        lines.append(f"  derived hosts: {list(hosts)}")
    else:
        lines.append("  clean queries: none (LP falls back to G for this server)")
    return "\n".join(lines)


def _clean_view(args: argparse.Namespace) -> int:
    path = resolve_data_path(args.data, fetch_missing=args.fetch)
    servers = _select(clean_servers(load(path)), args.server)
    for server in servers:
        print(render_clean_view(server, descriptions=not args.no_descriptions))
        print()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m benchmarks.mcptox", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    view = sub.add_parser("clean-view", help="print the clean side of each server only")
    _add_data_args(view)
    view.add_argument("--server", action="append", help="server key, name or index (repeatable)")
    view.add_argument("--no-descriptions", action="store_true", help="omit tool descriptions")
    view.set_defaults(handler=_clean_view)

    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except (DataUnavailableError, ChecksumMismatchError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
