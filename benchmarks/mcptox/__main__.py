"""CLI: ``python -m benchmarks.mcptox <command>``.

    python -m benchmarks.mcptox clean-view [--fetch] [--data PATH] [--server KEY|IDX]
    python -m benchmarks.mcptox replay [--fetch] [--data PATH] [--write [--date D]]
    python -m benchmarks.mcptox fresh --models h55,s55,o55 [--pilot N] [--run --budget-usd N]

``clean-view`` prints the clean side of each server only: its tool blocks, its clean
queries, and the roots and hosts the LP tier derives from those queries. It never prints
a poisoned tool, an attack query or a recorded response, so labels written from it are
blind to attack outcomes.

``replay`` (free) scores every recorded call under G0, G and LP. ``--write`` rewrites the
replay block of ``RESULTS.md`` and ``replay_summary.json``; it refuses a non-Linux host
(macOS ``/etc``, ``/tmp`` and ``/var`` are symlinks that change filesystem verdicts) unless
``--non-canonical-host``, and a filesystem gate that takes ``~`` literally unless
``--allow-unexpanded-tilde``. Both overrides are recorded in the published provenance.

``fresh`` is the paid Claude 5.5 run (:mod:`.fresh`). Without ``--run`` it is a dry run that
prints request counts and costs and needs neither a key nor the SDK; ``--score RUN_ID``
re-scores stored outputs for free.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import textwrap
from pathlib import Path

from .clean import CleanServer, clean_servers
from .data import ChecksumMismatchError, DataUnavailableError, load, resolve_data_path

_UTC_TODAY = datetime.datetime.now(datetime.timezone.utc).date().isoformat()


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


def _replay_command(args: argparse.Namespace) -> str:
    parts = ["python -m benchmarks.mcptox replay --fetch --write"]
    if args.non_canonical_host:
        parts.append("--non-canonical-host")
    if args.allow_unexpanded_tilde:
        parts.append("--allow-unexpanded-tilde")
    if args.bootstrap != 2000:
        parts.append(f"--bootstrap {args.bootstrap}")
    return " ".join(parts)


def git_provenance() -> tuple[str, bool]:
    """``(HEAD sha, dirty)``, falling back to ``AIRLOCK_BENCH_GIT_SHA`` / ``_DIRTY``.

    The canonical replay runs in a container that has no ``git`` (or one that refuses a
    mounted repository it does not own); the host passes the state in instead.
    """
    from benchmarks._claude.store import git_state

    sha, dirty = git_state(Path(__file__).resolve().parents[2])
    if sha == "unknown":
        env_sha = os.environ.get("AIRLOCK_BENCH_GIT_SHA", "").strip()
        if env_sha:
            return env_sha, os.environ.get("AIRLOCK_BENCH_GIT_DIRTY", "1").strip() != "0"
    return sha, dirty


def _replay(args: argparse.Namespace) -> int:
    from .metrics import summarize
    from .replay import (
        REPLAY_SUMMARY_PATH,
        RESULTS_PATH,
        host_info,
        provenance,
        replay,
        scratch_cwd,
    )
    from .report import format_console, render_replay_block, replace_block

    host = host_info()
    if args.write and not host["canonical"] and not args.non_canonical_host:
        print(
            f"error: --write publishes the canonical replay, which runs on Linux; this host "
            f"is {host['system']}. Run it in a container (see benchmarks/mcptox/README.md) "
            "or pass --non-canonical-host, which the published block then states.",
            file=sys.stderr,
        )
        return 2
    path = resolve_data_path(args.data, fetch_missing=args.fetch)
    doc = load(path)
    git = git_provenance()
    with scratch_cwd():
        run = replay(doc)
    if args.write and not run.tilde_expanded and not args.allow_unexpanded_tilde:
        print(
            "error: this tree's filesystem gate takes '~' literally (the B7 fix is not in "
            "it); the replay must be scored after that fix. Pass --allow-unexpanded-tilde "
            "to publish anyway (the block states it).",
            file=sys.stderr,
        )
        return 2
    summary = summarize(run, bootstrap=args.bootstrap)
    summary["provenance"] = provenance(
        run, date=args.date, bootstrap=args.bootstrap, command=_replay_command(args), git=git
    )
    print(format_console(summary))
    if not host["canonical"]:
        print(
            f"note: {host['system']} is not the canonical host; filesystem verdicts may "
            "differ from the published Linux run.",
            file=sys.stderr,
        )
    text = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if args.json:
        args.json.write_text(text, encoding="utf-8")
    if args.write:
        REPLAY_SUMMARY_PATH.write_text(text, encoding="utf-8")
        results = RESULTS_PATH.read_text(encoding="utf-8")
        RESULTS_PATH.write_text(
            replace_block(results, render_replay_block(summary)), encoding="utf-8"
        )
        print(f"wrote {REPLAY_SUMMARY_PATH} and the replay block of {RESULTS_PATH}")
    return 0


def _fresh(args: argparse.Namespace) -> int:
    from .fresh import main as fresh_main

    return fresh_main(args)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m benchmarks.mcptox",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    view = sub.add_parser("clean-view", help="print the clean side of each server only")
    _add_data_args(view)
    view.add_argument("--server", action="append", help="server key, name or index (repeatable)")
    view.add_argument("--no-descriptions", action="store_true", help="omit tool descriptions")
    view.set_defaults(handler=_clean_view)

    rep = sub.add_parser("replay", help="score every recorded call under G0, G and LP (free)")
    _add_data_args(rep)
    rep.add_argument("--write", action="store_true", help="rewrite RESULTS.md and the summary")
    rep.add_argument("--date", default=_UTC_TODAY, help="run date (default: today, UTC)")
    rep.add_argument("--json", type=Path, help="also write the summary JSON here")
    rep.add_argument("--bootstrap", type=int, default=2000, help="server-bootstrap resamples")
    rep.add_argument(
        "--non-canonical-host", action="store_true", help="allow --write on a non-Linux host"
    )
    rep.add_argument(
        "--allow-unexpanded-tilde",
        action="store_true",
        help="allow --write when the filesystem gate takes '~' literally",
    )
    rep.set_defaults(handler=_replay)

    from .fresh import add_arguments as add_fresh_arguments

    fresh = sub.add_parser("fresh", help="the paid Claude 5.5 run (dry run by default)")
    _add_data_args(fresh)
    add_fresh_arguments(fresh)
    fresh.set_defaults(handler=_fresh)

    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except (DataUnavailableError, ChecksumMismatchError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
