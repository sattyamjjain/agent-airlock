"""CLI: ``python -m benchmarks.blockrate`` — run the comparison, print a summary.

``--write`` (re)writes ``benchmarks/blockrate/RESULTS.md`` (block-rate + latency).
"""

from __future__ import annotations

import argparse
import datetime
from pathlib import Path

from .report import render_results_md
from .runner import run_blockrate
from .sandbox_arm import run_sandbox_arm


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m benchmarks.blockrate")
    parser.add_argument("--write", action="store_true", help="(re)write RESULTS.md")
    parser.add_argument(
        "--date",
        default=datetime.date.today().isoformat(),
        help="run date stamped into RESULTS.md (default: today)",
    )
    args = parser.parse_args(argv)

    report = run_blockrate()
    arm = run_sandbox_arm()

    print("Cross-tool block-rate comparison")
    print(f"  corpus items:                 {report.total}")
    print(f"  agent-airlock block-rate:     {report.overall_block_rate * 100:.1f}% (malicious)")
    print(f"  agent-airlock false-positives:{report.overall_fp_rate * 100:.1f}% (benign)")
    print(
        f"  latency p50 / p95:            {report.latency_pct(50):.4f} / {report.latency_pct(95):.4f} ms"
    )
    print()
    for cat, stats in report.by_category.items():
        print(
            f"  {cat:28} {stats.block_rate * 100:5.1f}% blocked "
            f"({stats.malicious_blocked}/{stats.malicious_total} malicious, "
            f"{stats.benign_blocked}/{stats.benign_total} benign FP)"
        )
    print()
    for comp in report.competitors:
        print(f"  {comp.name:22} scope-claimed, not re-run ({comp.approach})")

    print()
    print("sandbox=True dispatch arm")
    print(
        f"  argument contract on sandbox path: "
        f"{arm.contract_block_rate * 100:5.1f}% refused "
        f"({arm.probes_blocked_on_sandbox}/{arm.probes_total} probes)"
    )
    print(
        f"  verdict parity vs local path:      "
        f"{arm.probes_in_parity}/{arm.probes_total} contract, "
        f"{arm.policy_agreements}/{arm.policy_items} policy"
    )
    if arm.backend_available:
        print(f"  isolation backend execution:       ran on {arm.backend_name}")
    else:
        print(f"  isolation backend execution:       NOT RUN ({arm.backend_reason})")
    print(f"  corpus items the decorator cannot enforce: {arm.undeclared_items}")

    if args.write:
        out = Path(__file__).parent / "RESULTS.md"
        out.write_text(render_results_md(report, args.date, arm), encoding="utf-8")
        print(f"\nwrote {out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
