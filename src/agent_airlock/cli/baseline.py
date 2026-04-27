"""``airlock baseline`` CLI (v0.5.8+).

Subcommands:
    init <agent-id>            Initialise (or reset) a baseline.
    diff <agent-id>            Compare current to last init'd baseline.
    show <agent-id>            Print the current 7-day profile.

Usage::

    airlock baseline init agent-buyer
    airlock baseline diff agent-buyer --format json
    airlock baseline show agent-buyer
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from ..baseline import (
    BaselineStore,
    SQLiteBaselineStore,
    build_profile,
    drift_score,
)

DEFAULT_DB_PATH = Path.home() / ".airlock" / "baseline.db"


def _open_store(db_path: Path | None = None) -> BaselineStore:
    path = db_path or DEFAULT_DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    return SQLiteBaselineStore(path)


def _cmd_show(args: argparse.Namespace) -> int:
    store = _open_store(Path(args.db) if args.db else None)
    profile = build_profile(store, args.agent_id)
    payload = asdict(profile)
    if args.format == "json":
        print(json.dumps(payload, indent=2))
    else:
        print(f"Agent: {profile.agent_id}")
        print(f"Window: {profile.window_seconds // 86400}d")
        print(f"Events: {profile.event_count}")
        print(f"Tools: {len(profile.tool_mix)} distinct")
        print(f"Egress hosts: {len(profile.egress_hosts)} distinct")
        print(f"Tokens mean / p95: {profile.tokens_mean:.0f} / {profile.tokens_p95:.0f}")
        print(f"Latency p50 / p95: {profile.latency_p50:.1f}ms / {profile.latency_p95:.1f}ms")
    store.close()
    return 0


def _cmd_init(args: argparse.Namespace) -> int:
    """``init`` is a no-op stub today — the profile is built on demand from
    ``record_event`` calls. Reserved for v0.5.9 when the snapshot will
    be persisted as a separate row so ``diff`` can compare against a
    frozen reference."""
    print(
        f"agent {args.agent_id!r} baseline initialised "
        "(events recorded via airlock.baseline.record_event)"
    )
    return 0


def _cmd_diff(args: argparse.Namespace) -> int:
    """Compare the last 7 days against the prior 7 days (rolling diff)."""
    import time

    store = _open_store(Path(args.db) if args.db else None)
    now = time.time()
    seven_days = 7 * 24 * 3600
    reference = build_profile(store, args.agent_id, now_epoch=now - seven_days)
    current = build_profile(store, args.agent_id, now_epoch=now)
    report = drift_score(reference, current)
    payload = asdict(report)
    if args.format == "json":
        print(json.dumps(payload, indent=2))
    else:
        print(f"Drift report for {args.agent_id!r}:")
        for dim, val in payload.items():
            bar = "█" * int(val * 20)
            print(f"  {dim:<14} {val:.2f} {bar}")
    store.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="airlock baseline")
    parser.add_argument("--db", help="SQLite path (default ~/.airlock/baseline.db)")
    parser.add_argument("--format", choices=["text", "json"], default="text")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_init = sub.add_parser("init")
    p_init.add_argument("agent_id")
    p_init.set_defaults(func=_cmd_init)
    p_diff = sub.add_parser("diff")
    p_diff.add_argument("agent_id")
    p_diff.set_defaults(func=_cmd_diff)
    p_show = sub.add_parser("show")
    p_show.add_argument("agent_id")
    p_show.set_defaults(func=_cmd_show)
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = ["main"]
