"""CLI: ``python -m benchmarks.scantools_mcptox`` — print the coverage report.

    python -m benchmarks.scantools_mcptox                                  # 23 fixtures
    python -m benchmarks.scantools_mcptox --mcptox-data [PATH] [--fetch]   # + real corpus
    python -m benchmarks.scantools_mcptox --mcptox-data --write [--date D] # rewrite RESULTS.md

The fixture report is always printed (and is what CI's tests pin). ``--mcptox-data`` also
scores MCPTox's real descriptions from the verified cache (or ``PATH``); ``--fetch``
downloads the pinned file first. ``--write`` rewrites the dated "Real MCPTox corpus"
section of ``RESULTS.md`` between its markers.
"""

from __future__ import annotations

import argparse
import datetime
import sys
from pathlib import Path

from .report import format_report
from .runner import run_benchmark

RESULTS_PATH = Path(__file__).resolve().parent / "RESULTS.md"
REAL_BEGIN = "<!-- SCANTOOLS-MCPTOX-REAL:BEGIN -->"
REAL_END = "<!-- SCANTOOLS-MCPTOX-REAL:END -->"
REAL_COMMAND = "python -m benchmarks.scantools_mcptox --mcptox-data --fetch --write"


def _real(args: argparse.Namespace) -> int:
    from benchmarks.mcptox.data import (
        ChecksumMismatchError,
        DataUnavailableError,
        load,
        resolve_data_path,
    )
    from benchmarks.mcptox.report import replace_block

    from .real_corpus import render_real_section, run_real_corpus

    try:
        path = resolve_data_path(
            Path(args.mcptox_data) if args.mcptox_data else None, fetch_missing=args.fetch
        )
    except (DataUnavailableError, ChecksumMismatchError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    data = run_real_corpus(load(path)).to_dict()
    section = "\n".join(render_real_section(data, date=args.date, command=REAL_COMMAND))
    print()
    print(section)
    if args.write:
        text = RESULTS_PATH.read_text(encoding="utf-8")
        RESULTS_PATH.write_text(
            replace_block(text, section, begin=REAL_BEGIN, end=REAL_END), encoding="utf-8"
        )
        print(f"\nwrote the Real MCPTox corpus section of {RESULTS_PATH}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m benchmarks.scantools_mcptox",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--mcptox-data",
        nargs="?",
        const="",
        default=None,
        metavar="PATH",
        help="also score MCPTox's real corpus (the verified cache, or PATH)",
    )
    parser.add_argument("--fetch", action="store_true", help="download the pinned file first")
    parser.add_argument("--write", action="store_true", help="rewrite the real-corpus section")
    parser.add_argument(
        "--date",
        default=datetime.datetime.now(datetime.timezone.utc).date().isoformat(),
        help="run date for --write (default: today, UTC)",
    )
    args = parser.parse_args(argv)
    if args.mcptox_data is None and (args.write or args.fetch):
        parser.error("--write and --fetch need --mcptox-data")
    print(format_report(run_benchmark()))
    if args.mcptox_data is None:
        return 0
    return _real(args)


if __name__ == "__main__":
    raise SystemExit(main())
