"""CLI: ``python -m benchmarks.harness_injection``.

Running this **spends real API budget** against whichever harness CLIs are logged in on the
machine, so nothing runs by default beyond a dry-run listing. Pass ``--run`` to execute.
"""

from __future__ import annotations

import argparse
import datetime
from pathlib import Path

from .fixture import ARMS, TASK_PROMPT, build_fixture
from .harnesses import HARNESSES, available_harnesses, resolve
from .report import render_results_md, render_summary
from .runner import DEFAULT_TIMEOUT, RunReport, run_matrix


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m benchmarks.harness_injection",
        description="Matched-pair multi-harness prompt-injection benchmark.",
    )
    parser.add_argument(
        "--run", action="store_true", help="actually invoke the harnesses (costs API $)"
    )
    parser.add_argument("--harness", action="append", help="restrict to a harness (repeatable)")
    parser.add_argument("--trials", type=int, default=1, help="trials per cell (default: 1)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="per-cell timeout")
    parser.add_argument("--write", action="store_true", help="(re)write RESULTS.md")
    parser.add_argument("--emit-fixture", type=Path, help="write both fixture arms here and exit")
    parser.add_argument("--json", type=Path, help="also write raw cell results as JSON")
    parser.add_argument("--date", default=datetime.date.today().isoformat())
    args = parser.parse_args(argv)

    if args.emit_fixture:
        for arm in ARMS:
            dest = build_fixture(args.emit_fixture / arm.name, arm)
            print(f"wrote {dest}")
        return 0

    harnesses = resolve(args.harness)

    if not args.run:
        print("DRY RUN — no harness invoked. Pass --run to execute (this costs API $).\n")
        print(f"Task prompt: {TASK_PROMPT}\n")
        print("Harnesses:")
        for harness in HARNESSES:
            mark = "available" if harness.is_available() else "NOT ON PATH"
            print(f"  {harness.name:16} [{mark}]  {' '.join(harness.argv('<PROMPT>'))}")
        cells = len(harnesses) * len(ARMS) * 2 * args.trials
        print(
            f"\nWould run {cells} cells ({len(harnesses)} harness x {len(ARMS)} arms x 2 airlock modes x {args.trials} trials)."
        )
        return 0

    if not available_harnesses():
        print("No harness CLI found on PATH; nothing to run.")
        return 1

    report: RunReport = run_matrix(harnesses, trials=args.trials, timeout=args.timeout)
    print(render_summary(report))

    if args.json:
        args.json.write_text(report.to_json(), encoding="utf-8")
        print(f"\nwrote {args.json}")
    if args.write:
        out = Path(__file__).parent / "RESULTS.md"
        out.write_text(render_results_md(report, args.date), encoding="utf-8")
        print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
