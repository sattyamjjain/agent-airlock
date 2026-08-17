#!/usr/bin/env python3
"""Benchmark-claim freshness gate (v0.8.74+).

Why this exists
---------------
The README publishes five head-to-head benchmark rows, one of them a *competitive*
claim against a named third-party product at a pinned version. A competitive claim
against a moving target decays, and a stale one is worse for credibility than no claim
at all — the reader cannot tell "measured last week" from "measured in July and never
revisited".

Through v0.8.73 the only thing keeping those dates honest was a human remembering to
re-run. ``tests/test_numeric_claim_parity.py`` says it plainly: *"A human instruction is
exactly the thing that rots."* That file gates the numeric copies precisely because a
note telling a person to refresh them does not work. The dates had exactly the same
problem and none of the same protection — the 2026-07-16 gateway claim sat a month past
its run before anyone noticed.

Two modes, mirroring ``check_changelog.py``
-------------------------------------------
**Default (structural).** Every known benchmark row must carry *some* freshness marker.
This never flaps on a calendar boundary — it fails only when a row loses its date, which
is a real edit someone made. Safe to run on every commit.

**``--release`` (pre-tag).** Additionally fails when any marker is older than
:data:`MAX_AGE_DAYS`. This is deliberately a *release* gate rather than a CI-on-every-push
gate: a stale claim matters at the moment it is published, and failing every unrelated
commit for weeks is how a gate gets switched off. Wired into ``publish.yml`` next to the
stale-GitHub-description gate, which blocks for the same reason.

Exit codes: ``0`` pass, ``1`` fail.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import re
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_README = _ROOT / "README.md"

#: A row older than this fails ``--release``. Matches the 30-day rule the benchmark
#: table is maintained under.
MAX_AGE_DAYS = 30

#: ``identifier -> (human label, how to re-run it)``. The identifier is a string that
#: appears on the README line carrying that row's freshness marker.
BENCHMARKS: dict[str, tuple[str, str]] = {
    "benchmarks.blockrate": (
        "Cross-tool block-rate",
        "python -m benchmarks.blockrate",
    ),
    "benchmarks.toolprivbench": (
        "Least-privilege (ToolPrivBench)",
        "python -m benchmarks.toolprivbench",
    ),
    "benchmarks.agentdojo.run": (
        "Adaptive-attacker (AgentDojo)",
        "python -m benchmarks.agentdojo.run  (needs API keys; costs money)",
    ),
    "benchmarks.vs_gateway": (
        "Native MCP gateway head-to-head",
        "python -m benchmarks.vs_gateway.gateway_harness.regen  (needs a Docker daemon)",
    ),
    "benchmarks/mcp_conformance/RESULTS.md": (
        "MCP spec conformance",
        "python benchmarks/mcp_conformance/run.py",
    ),
}

#: The three shapes a freshness marker takes in the README.
_MARKER_RE = re.compile(
    r"_?(?:re-run|re-measured live|last verified)\s+(\d{4}-\d{2}-\d{2})",
)


def _today() -> _dt.date:
    return _dt.datetime.now(_dt.timezone.utc).date()


def _find_marker(readme: str, identifier: str) -> tuple[str, _dt.date] | None:
    """Return the first freshness marker on a line mentioning ``identifier``."""
    for line in readme.splitlines():
        if identifier not in line:
            continue
        match = _MARKER_RE.search(line)
        if match:
            return line, _dt.date.fromisoformat(match.group(1))
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--release",
        action="store_true",
        help=f"also fail when a marker is older than {MAX_AGE_DAYS} days (pre-tag gate)",
    )
    args = parser.parse_args(argv)

    readme = _README.read_text(encoding="utf-8")
    today = _today()
    undated: list[str] = []
    stale: list[tuple[str, _dt.date, int, str]] = []
    ok: list[tuple[str, _dt.date, int]] = []

    for identifier, (label, howto) in BENCHMARKS.items():
        found = _find_marker(readme, identifier)
        if found is None:
            undated.append(f"{label}  (looked for a line mentioning {identifier!r})")
            continue
        _line, date = found
        age = (today - date).days
        if args.release and age > MAX_AGE_DAYS:
            stale.append((label, date, age, howto))
        else:
            ok.append((label, date, age))

    for label, date, age in sorted(ok, key=lambda row: row[2], reverse=True):
        print(f"  ok    {label}: {date.isoformat()} ({age}d)")
    # Flush before touching stderr so a CI log shows the passing rows above the
    # failure rather than interleaved after it.
    sys.stdout.flush()

    if undated:
        print("\nFAIL: benchmark rows with no freshness marker in README.md:", file=sys.stderr)
        for item in undated:
            print(f"  - {item}", file=sys.stderr)
        print(
            "\nEvery published benchmark row must carry '_re-run YYYY-MM-DD_', "
            "'_re-measured live YYYY-MM-DD_', or '_last verified YYYY-MM-DD_'.",
            file=sys.stderr,
        )
        return 1

    if stale:
        print(
            f"\nFAIL: benchmark claims older than {MAX_AGE_DAYS} days are being released:",
            file=sys.stderr,
        )
        for label, date, age, howto in stale:
            print(f"  - {label}: last run {date.isoformat()} ({age}d ago)", file=sys.stderr)
            print(f"      re-run:  {howto}", file=sys.stderr)
        print(
            "\nRe-run it and update the date, or — if it genuinely cannot be re-run — say so "
            "in that benchmark's RESULTS.md naming the reason and the last date it actually "
            "ran, then move the README marker to '_last verified <that date>_'. Do not leave "
            "a dated claim standing without a fresh run behind it.",
            file=sys.stderr,
        )
        return 1

    scope = f"all within {MAX_AGE_DAYS}d" if args.release else "all present"
    print(f"\nOK ({len(ok)} benchmark rows, {scope})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
