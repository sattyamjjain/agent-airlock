"""CLI: ``python -m benchmarks.scantools_mcptox`` — print the coverage report."""

from __future__ import annotations

from .report import format_report
from .runner import run_benchmark


def main() -> int:
    print(format_report(run_benchmark()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
