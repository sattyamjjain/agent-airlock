"""Ledger report and free API checks for the credit-funded benchmarks.

    python -m benchmarks._claude ledger           # spend so far (no network)
    python -m benchmarks._claude models --run     # GET /v1/models (free): ids are served

``models`` needs ``ANTHROPIC_API_KEY`` for this command only; it lists model ids and
spends nothing.
"""

from __future__ import annotations

import argparse
import sys

from .budget import hard_cap_usd
from .client import ClientConfigError, make_client
from .ledger import Ledger
from .models import MODELS


def _ledger_report(ledger: Ledger) -> int:
    print(f"ledger: {ledger.path}")
    for job, usd in ledger.by_job().items():
        print(f"  {job:<48} ${usd:9.4f}")
    print(f"spent    ${ledger.spent():9.4f}")
    print(f"reserved ${ledger.reserved():9.4f}")
    print(f"hard cap ${hard_cap_usd():9.4f}")
    return 0


def _models(run: bool) -> int:
    if not run:
        print("dry run: pass --run to call GET /v1/models (free; needs ANTHROPIC_API_KEY)")
        return 0
    try:
        client = make_client()
    except ClientConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    served = {m.id for m in client.models.list()}
    missing = [mid for mid in MODELS.values() if mid not in served]
    for mid in MODELS.values():
        print(f"  {mid:<22} {'served' if mid in served else 'NOT SERVED'}")
    return 1 if missing else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m benchmarks._claude", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("ledger", help="print spend per job (no network)")
    models = sub.add_parser("models", help="check the pinned model ids are served (free)")
    models.add_argument("--run", action="store_true", help="actually call the API")
    args = parser.parse_args(argv)
    if args.command == "ledger":
        return _ledger_report(Ledger())
    return _models(args.run)


if __name__ == "__main__":
    raise SystemExit(main())
