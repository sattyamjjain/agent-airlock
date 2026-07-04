"""CLI entry point: ``python -m benchmarks.toolprivbench``.

Runs the least-privilege block-rate benchmark and prints a summary. Pass
``--write`` to (re)generate ``RESULTS.md`` next to this package.
"""

from __future__ import annotations

import argparse
import datetime
from pathlib import Path

from .harness import run_benchmark
from .report import render_results_md


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m benchmarks.toolprivbench")
    parser.add_argument(
        "--write",
        action="store_true",
        help="regenerate RESULTS.md alongside this package",
    )
    parser.add_argument(
        "--date",
        default=datetime.date.today().isoformat(),
        help="run date stamped into RESULTS.md (default: today)",
    )
    args = parser.parse_args(argv)

    report = run_benchmark()

    print(f"ToolPrivBench-style least-privilege block-rate  (source: {report.source})")
    print(f"  scenarios:                       {report.total}")
    print(f"  over-priv BLOCKED:               {report.overall_block_rate * 100:.1f}%")
    print(
        f"  over-priv BLOCKED after failure: {report.overall_block_rate_after_failure * 100:.1f}%"
    )
    print(f"  low-priv ALLOWED (precision):    {report.overall_low_priv_allow_rate * 100:.1f}%")
    if report.opur is not None:
        o = report.opur
        print(
            f"  OPUR baseline→enforced:          {o.opur_baseline * 100:.1f}% → "
            f"{o.opur_enforced * 100:.1f}%  (−{o.opur_delta * 100:.1f}pp over {o.denominator})"
        )
    print()
    for pattern, stats in report.by_pattern.items():
        print(
            f"  {pattern:22} {stats.block_rate * 100:5.1f}% blocked "
            f"({stats.total} scenarios, {len(stats.domains)} domains)"
        )

    if args.write:
        out = Path(__file__).parent / "RESULTS.md"
        out.write_text(render_results_md(report, args.date), encoding="utf-8")
        print(f"\nwrote {out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
