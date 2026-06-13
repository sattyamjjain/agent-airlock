"""``airlock trace`` CLI — watermark detection + redaction report (v0.8.24+).

Subcommand:

- ``verify-watermark <trace.json>`` — detect the per-tenant behavioural
  watermark embedded by :func:`agent_airlock.trace_redaction.trace_redact`.
  Detection is cryptographic (keyed HMAC match), so a genuine watermark
  detects deterministically (high true-detection) and an unrelated trace
  cannot forge one under the secret key (low false-alarm) — the RedAct-style
  watermark goal.

  Flags:
    --tenant / --secret   the tenant id + HMAC key to check against (the
                          secret may also come from ``AIRLOCK_TRACE_SECRET``).
    --redaction-report    additionally run a redaction pass over the input and
                          print what was localized / rewritten / preserved.
    --format text|json

Usage::

    python -m agent_airlock.cli.trace verify-watermark leaked.json \\
        --tenant acme-co --secret "$AIRLOCK_TRACE_SECRET"
    python -m agent_airlock.cli.trace verify-watermark t.json --redaction-report
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

import structlog

from ..trace_redaction import TraceRedactionPolicy, trace_redact, verify_watermark

_EXIT_DETECTED = 0
_EXIT_NOT_DETECTED = 1
_EXIT_USAGE = 2


def _configure_structlog_to_stderr() -> None:
    """Route structlog to stderr so stdout stays clean for the report.

    Mirrors ``cli/corpus_bench._configure_structlog_to_stderr`` — the
    redaction pass emits ``trace_redacted`` diagnostics, which are
    operator-visible, not machine-readable output.
    """
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(colors=False),
        ],
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        wrapper_class=structlog.make_filtering_bound_logger(30),  # WARNING+
        cache_logger_on_first_use=True,
    )


def _policy_from_args(args: argparse.Namespace) -> TraceRedactionPolicy:
    secret = args.secret if args.secret is not None else os.environ.get("AIRLOCK_TRACE_SECRET", "")
    return TraceRedactionPolicy(enabled=True, tenant_id=args.tenant or "", watermark_secret=secret)


def _cmd_verify_watermark(args: argparse.Namespace) -> int:
    try:
        trace: Any = json.loads(args.trace.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read trace {args.trace}: {exc}", file=sys.stderr)
        return _EXIT_USAGE
    if not isinstance(trace, dict):
        print(f"error: trace {args.trace} is not a JSON object", file=sys.stderr)
        return _EXIT_USAGE

    policy = _policy_from_args(args)
    verdict = verify_watermark(trace, policy)

    payload: dict[str, Any] = {
        "detected": verdict.detected,
        "tenant_fp": verdict.tenant_fp,
        "reason": verdict.reason,
        "detail": verdict.detail,
    }

    if args.redaction_report:
        # Re-run a redaction pass over the input to show what the guard
        # localizes / rewrites / preserves for this trace shape.
        _, report = trace_redact(trace, policy)
        payload["redaction_report"] = {
            "localized": [{"path": p, "class": c} for p, c in report.localized],
            "rewritten": list(report.rewritten),
            "preserved": list(report.preserved),
        }

    if args.format == "json":
        print(json.dumps(payload, sort_keys=True, indent=2))
    else:
        status = "DETECTED" if verdict.detected else "not-detected"
        print(f"watermark: {status} (tenant_fp={verdict.tenant_fp or '<none>'}) — {verdict.reason}")
        print(f"  {verdict.detail}")
        if args.redaction_report:
            rr = payload["redaction_report"]
            print(
                f"redaction-report: localized={len(rr['localized'])} "
                f"rewritten={len(rr['rewritten'])} preserved={len(rr['preserved'])}"
            )
            for item in rr["localized"]:
                print(f"  localized  {item['path']}  [{item['class']}]")
            for path in rr["preserved"]:
                print(f"  preserved  {path}")

    return _EXIT_DETECTED if verdict.detected else _EXIT_NOT_DETECTED


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="airlock trace",
        description="airlock trace — trace-redaction watermark detection + report",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_vw = sub.add_parser(
        "verify-watermark",
        help="detect the per-tenant behavioural watermark in a trace.json",
    )
    p_vw.add_argument("trace", type=Path, help="path to the trace/receipt JSON file")
    p_vw.add_argument("--format", choices=["text", "json"], default="text")
    p_vw.add_argument("--tenant", default="", help="tenant id the watermark should bind to")
    p_vw.add_argument(
        "--secret",
        default=None,
        help="HMAC key (else $AIRLOCK_TRACE_SECRET, else derived from --tenant)",
    )
    p_vw.add_argument(
        "--redaction-report",
        action="store_true",
        help="also print what the redaction pass localizes / rewrites / preserves",
    )
    p_vw.set_defaults(func=_cmd_verify_watermark)

    args = parser.parse_args(argv)
    _configure_structlog_to_stderr()
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())


__all__ = ["main"]
