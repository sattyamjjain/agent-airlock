"""``airlock-conformance`` — EU AI Act Art. 12 record-keeping CLI (v0.8.40+).

Subcommands over an append-only, hash-chained, restart-surviving decision log:

    airlock-conformance record --log L --stage policy --tool read_file --decision allow
    airlock-conformance verify --log L
    airlock-conformance export --log L [--output bundle.json]

Everything is offline: no network call, no cloud, no user data leaves the box.
The unified ``airlock <subcommand>`` dispatcher is still deferred (see pyproject
``[project.scripts]``), so this ships as the ``airlock-conformance`` console
script, matching the existing ``airlock-explain`` convention.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from ..conformance.art12 import export_evidence_bundle, render_coverage_table
from ..conformance.decision_log import DecisionLog, DecisionLogError


def _cmd_record(args: argparse.Namespace) -> int:
    log = DecisionLog(args.log)
    rec = log.append(
        stage=args.stage,
        tool_name=args.tool,
        decision=args.decision,
        reason=args.reason or "",
        agent_id=args.agent_id,
        session_id=args.session_id,
    )
    print(
        f"recorded seq={rec.seq} stage={rec.stage} {rec.tool_name} -> {rec.decision} "
        f"(hash {rec.record_hash[:12]}…)"
    )
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    try:
        result = DecisionLog(args.log, verify_on_load=False).verify()
    except DecisionLogError as exc:
        print(f"decision log unreadable: {exc}", file=sys.stderr)
        return 2
    if result.ok:
        print(f"OK — chain verified: {result.record_count} records, head {result.head_hash[:12]}…")
        return 0
    print(f"FAIL — chain broken at seq {result.first_bad_seq}: {result.detail}", file=sys.stderr)
    return 1


def _cmd_export(args: argparse.Namespace) -> int:
    log = DecisionLog(args.log, verify_on_load=False)
    bundle: dict[str, Any] = export_evidence_bundle(log)
    payload = json.dumps(bundle, indent=2, sort_keys=True)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(payload + "\n")
        print(f"wrote evidence bundle -> {args.output}")
    else:
        print(payload)
    if not args.quiet:
        print("\n" + render_coverage_table(bundle), file=sys.stderr)
    # Exit non-zero if the chain does not verify, so export doubles as a gate.
    return 0 if bundle["chain_verified"] else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="airlock-conformance",
        description="EU AI Act Art. 12-style tamper-evident decision log (offline).",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_rec = sub.add_parser("record", help="append one decision to the log")
    p_rec.add_argument("--log", required=True, help="decision-log JSONL path")
    p_rec.add_argument(
        "--stage", required=True, choices=["validate", "policy", "execute", "sanitize"]
    )
    p_rec.add_argument("--tool", required=True, help="tool name the decision is about")
    p_rec.add_argument("--decision", required=True, choices=["allow", "warn", "block", "error"])
    p_rec.add_argument("--reason", default="", help="short, non-sensitive reason")
    p_rec.add_argument("--agent-id", default=None)
    p_rec.add_argument("--session-id", default=None)
    p_rec.set_defaults(func=_cmd_record)

    p_ver = sub.add_parser("verify", help="verify the hash chain (exit 1 if broken)")
    p_ver.add_argument("--log", required=True)
    p_ver.set_defaults(func=_cmd_verify)

    p_exp = sub.add_parser("export", help="export the Art. 12 evidence bundle")
    p_exp.add_argument("--log", required=True)
    p_exp.add_argument("--output", default=None, help="write JSON bundle here (default: stdout)")
    p_exp.add_argument("--quiet", action="store_true", help="suppress the coverage table")
    p_exp.set_defaults(func=_cmd_export)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = ["main"]
