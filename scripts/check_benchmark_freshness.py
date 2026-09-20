#!/usr/bin/env python3
"""Benchmark-claim freshness gate (v0.8.74+).

Why this exists
---------------
The README publishes seven head-to-head benchmark rows, one of them a *competitive*
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
    "benchmarks.harness_injection": (
        "Matched-pair multi-harness prompt injection",
        "python -m benchmarks.harness_injection --trials 18 --write "
        "--checkpoint ckpt.json  "
        "(drives third-party coding agents; ~100 min of real API budget — the "
        "checkpoint makes an interrupted run resumable instead of a total loss)",
    ),
    # Its own identifier, not the bare module path. The sandbox arm is published as a
    # separate README row but re-runs from the same command, so keying it on
    # "benchmarks.blockrate" would match the *first* line carrying that string and leave
    # this row's date ungated: it could silently lose its marker while the gate stayed
    # green. The results anchor appears only on this row.
    "RESULTS.md#sandboxtrue-dispatch-arm": (
        "`sandbox=True` dispatch parity",
        "python -m benchmarks.blockrate  (the arm runs inside the same command)",
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


#: Where the benchmark pages live, and the nav that has to reach all of them.
_DOCS_BENCHMARKS = _ROOT / "docs" / "benchmarks"
_MKDOCS_YML = _ROOT / "mkdocs.yml"
_BENCHMARK_INDEX = _DOCS_BENCHMARKS / "index.md"


def _nav_block(mkdocs_yml: str) -> str:
    """Return the text of the top-level ``nav:`` block.

    Parsed as text rather than with PyYAML on purpose. This script runs in
    ``publish.yml``, whose job installs only ``build`` and ``twine`` -- there is no
    guaranteed YAML parser there, and a gate that raises ImportError in the release
    workflow is worse than no gate. Nav entries are ``Title: path.md`` lines, so a
    block scan is enough and cannot fail on a config that mkdocs itself accepts.
    """
    lines = mkdocs_yml.splitlines()
    out: list[str] = []
    inside = False
    for line in lines:
        if not inside:
            if line.startswith("nav:"):
                inside = True
            continue
        # A non-indented, non-blank, non-comment line ends the block.
        if line.strip() and not line.startswith((" ", "\t", "#")):
            break
        out.append(line)
    return "\n".join(out)


def _nav_gaps() -> list[str]:
    """Every page under ``docs/benchmarks/`` must be reachable from the nav.

    mkdocs publishes a file whether or not nav references it, so a page can build,
    deploy and be reachable by direct URL while nothing on the site links to it.
    Three benchmark pages sat in exactly that state
    (``injection-multi-harness``, ``mcp-gateway-payload-gap``,
    ``vs-native-mcp-gateway``): they were live and invisible. A missing nav entry is
    indistinguishable from a working page unless something asserts the difference,
    which is what this does.
    """
    if not _DOCS_BENCHMARKS.is_dir():
        return []
    nav = _nav_block(_MKDOCS_YML.read_text(encoding="utf-8"))
    missing: list[str] = []
    for path in sorted(_DOCS_BENCHMARKS.rglob("*.md")):
        rel = path.relative_to(_ROOT / "docs").as_posix()
        if rel not in nav:
            missing.append(rel)
    return missing


def _index_date_mismatches(readme: str, readme_path: Path) -> list[str]:
    """The benchmarks landing page must date each row the same way README does.

    ``docs/benchmarks/index.md`` republishes the freshness dates that this gate reads
    out of README.md. Two copies of one date drift, and the drift is silent: both
    pages render fine while claiming a run happened on different days. The dates are
    checked against each other here so that a re-run which updates one and not the
    other fails the build.

    Only meaningful against this repository's own README. ``tests/`` drives
    :func:`main` with a synthetic README in ``tmp_path`` to exercise the date
    arithmetic; no landing page could agree with those invented dates, and asserting
    one would fail the date-logic tests on an unrelated concern.
    """
    if readme_path != _ROOT / "README.md":
        return []
    if not _BENCHMARK_INDEX.is_file():
        return []
    index = _BENCHMARK_INDEX.read_text(encoding="utf-8")
    problems: list[str] = []
    for identifier, (label, _howto) in BENCHMARKS.items():
        found = _find_marker(readme, identifier)
        if found is None:
            continue  # the undated check below already reports this
        _line, date = found
        if date.isoformat() not in index:
            problems.append(
                f"{label}: README says {date.isoformat()}, "
                f"which does not appear in docs/benchmarks/index.md"
            )
    return problems


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

    nav_gaps = _nav_gaps()
    if nav_gaps:
        print("\nFAIL: benchmark pages that mkdocs publishes but nav never links:", file=sys.stderr)
        for rel in nav_gaps:
            print(f"  - {rel}", file=sys.stderr)
        print(
            "\nmkdocs builds and deploys a page whether or not nav references it, so these "
            "are live on the site and reachable only by typing the URL. Add each one under "
            "the 'Benchmarks:' section of mkdocs.yml, or delete the file.",
            file=sys.stderr,
        )
        return 1

    index_gaps = _index_date_mismatches(readme, _README)
    if index_gaps:
        print(
            "\nFAIL: docs/benchmarks/index.md disagrees with README.md on a run date:",
            file=sys.stderr,
        )
        for item in index_gaps:
            print(f"  - {item}", file=sys.stderr)
        print(
            "\nThe landing page republishes these dates, so a re-run has to update both. "
            "Two dates for one run is worse than one stale date, because neither page "
            "looks wrong on its own.",
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
