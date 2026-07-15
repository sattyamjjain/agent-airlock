"""Run the airlock vs native-MCP-gateway head-to-head.

    python -m benchmarks.vs_gateway            # human-readable table
    python -m benchmarks.vs_gateway --json     # machine-readable summary

Airlock decisions run LIVE, in-process, on every invocation. The gateway column
replays the recorded live measurement in ``gateway_measurement.json`` (see
``gateway_harness/`` to regenerate it against a real Docker MCP Gateway).
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

import structlog

from .report import build_report, render


def _silence_logs() -> None:
    """Drop airlock's structlog block-warnings so they can't pollute stdout/JSON."""
    logging.disable(logging.CRITICAL)
    structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="benchmarks.vs_gateway")
    parser.add_argument("--json", action="store_true", help="emit a JSON summary")
    args = parser.parse_args(argv)

    _silence_logs()
    report = build_report()

    if args.json:
        summary = {
            "malicious_total": report.malicious_total,
            "benign_total": report.benign_total,
            "airlock_blocked": report.airlock_blocked,
            "gateway_blocked": report.gateway_blocked,
            "airlock_false_positive": report.airlock_fp,
            "gateway_false_positive": report.gateway_fp,
            "airlock_p50_ms": round(report.airlock_p50_ms(), 4),
            "provenance": report.provenance,
        }
        print(json.dumps(summary, indent=2))
    else:
        print(render(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
