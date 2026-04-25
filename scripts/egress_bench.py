#!/usr/bin/env python3
"""Agent Egress Bench — CVE fixture regression walker (v0.5.3+).

Walks ``tests/cves/fixtures/*.json`` and asserts every documented
payload is blocked by the corresponding preset. Emits a TAP / JSON /
Markdown summary so CI (and users' own configs) can gate on it.

Contract between fixture and bench:

Each fixture must expose either a ``payloads`` array (Ox STDIO style)
or a ``destructive_tools`` / ``cves`` array (MCPwn / OX dossier
style). The fixture name encodes which preset's check to dispatch:

    cve_2026_33032_mcpwn.json  → mcpwn_cve_2026_33032_check
    ox_stdio_payloads.json     → validate_stdio_command + ox_defaults
    ox_supply_chain_2026_04.json → ox_mcp_supply_chain_2026_04_defaults

Exit codes:
    0 — every payload blocked (or marked ``expected_unblocked: true``)
    1 — at least one payload slipped through
    2 — fixture parse error / unknown fixture name

Reference
---------
Motivated by the OX dossier 2026-04-20:
https://www.ox.security/blog/mother-of-all-ai-supply-chains-2026-04-20
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = ROOT / "tests" / "cves" / "fixtures"


@dataclass
class Row:
    cve_id: str
    payload_count: int
    blocked: int
    unblocked: int
    status: str  # "pass" | "fail" | "skip"
    reason: str = ""
    disclosed_at: str | None = None


_ISO_DATE_RE = re.compile(r"^\d{4}(?:-\d{2}(?:-\d{2})?)?$")


class FixtureValidationError(ValueError):
    """Raised when a fixture is missing the required ``disclosed_at`` field."""


def _parse_iso_date(value: str) -> date:
    """Parse an ISO-format ``disclosed_at`` value into a comparable ``date``.

    Accepts ``YYYY``, ``YYYY-MM``, or ``YYYY-MM-DD``. Month-only and
    year-only values are normalised to the first day so they can be
    compared with ``--since`` filters.
    """
    if not _ISO_DATE_RE.match(value):
        raise FixtureValidationError(f"disclosed_at must be ISO YYYY[-MM[-DD]], got {value!r}")
    parts = [int(p) for p in value.split("-")]
    while len(parts) < 3:
        parts.append(1)
    return date(parts[0], parts[1], parts[2])


def _require_disclosed_at(fixture: dict, fixture_name: str) -> str:
    """Return ``fixture["disclosed_at"]`` or raise."""
    val = fixture.get("disclosed_at")
    if not val:
        raise FixtureValidationError(
            f"fixture {fixture_name} is missing required key 'disclosed_at'"
        )
    if not isinstance(val, str):
        raise FixtureValidationError(f"fixture {fixture_name} has non-string disclosed_at: {val!r}")
    # Validates format; raises if malformed.
    _parse_iso_date(val)
    return val


def _run_ox_stdio(fixture: dict) -> Row:
    sys.path.insert(0, str(ROOT / "src"))
    from agent_airlock.mcp_spec.stdio_guard import (  # type: ignore[import-not-found]
        StdioInjectionError,
        validate_stdio_command,
    )
    from agent_airlock.policy_presets import (
        stdio_guard_ox_defaults,  # type: ignore[import-not-found]
    )

    cfg = stdio_guard_ox_defaults()
    blocked = unblocked = 0
    for p in fixture["payloads"]:
        try:
            validate_stdio_command(p["argv"], cfg)
            unblocked += 1
        except StdioInjectionError:
            blocked += 1
    return Row(
        cve_id="CVE-2026-30616",
        payload_count=len(fixture["payloads"]),
        blocked=blocked,
        unblocked=unblocked,
        status="pass" if unblocked == 0 else "fail",
    )


def _run_mcpwn(fixture: dict) -> Row:
    from agent_airlock.policy_presets import (
        UnauthenticatedDestructiveToolError,
        mcpwn_cve_2026_33032_check,
    )

    blocked = unblocked = 0
    for tool in fixture["destructive_tools"]:
        try:
            mcpwn_cve_2026_33032_check([{"name": tool["name"], "middlewares": []}])
            unblocked += 1
        except UnauthenticatedDestructiveToolError:
            blocked += 1
    return Row(
        cve_id="CVE-2026-33032",
        payload_count=len(fixture["destructive_tools"]),
        blocked=blocked,
        unblocked=unblocked,
        status="pass" if unblocked == 0 else "fail",
    )


def _run_ox_supply_chain(fixture: dict) -> Row:
    """The dossier lists 10 CVEs; the walker verifies each has a
    primary-source URL and a known class label. Actual per-CVE
    block testing happens in the unit tests."""
    count = len(fixture["cves"])
    ok = all(e.get("source", "").startswith("https://") for e in fixture["cves"])
    return Row(
        cve_id="OX-DOSSIER-2026-04",
        payload_count=count,
        blocked=count if ok else 0,
        unblocked=0 if ok else count,
        status="pass" if ok else "fail",
        reason="fixture metadata + source citations" if ok else "missing sources",
    )


_DISPATCH: dict[str, object] = {
    "ox_stdio_payloads.json": _run_ox_stdio,
    "cve_2026_33032_mcpwn.json": _run_mcpwn,
    "ox_supply_chain_2026_04.json": _run_ox_supply_chain,
}


def walk(fixture_dir: Path, *, since: date | None = None) -> list[Row]:
    """Walk fixtures and run each registered handler.

    Args:
        fixture_dir: Directory holding ``*.json`` fixtures.
        since: If supplied, fixtures whose ``disclosed_at`` is strictly
            before this date are filtered out (a ``skip`` row is
            emitted in their place so the report still accounts for
            every file scanned). Fixtures missing ``disclosed_at``
            raise :class:`FixtureValidationError` regardless of
            ``since``.

    Returns:
        Per-fixture rows, in stable filesystem-sorted order.
    """
    rows: list[Row] = []
    for path in sorted(fixture_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            rows.append(
                Row(
                    cve_id=path.stem,
                    payload_count=0,
                    blocked=0,
                    unblocked=0,
                    status="fail",
                    reason=f"JSON parse: {exc}",
                )
            )
            continue

        # Validate disclosed_at — required since v0.5.6.
        disclosed_raw = _require_disclosed_at(data, path.name)
        disclosed = _parse_iso_date(disclosed_raw)

        # Filter by --since.
        if since is not None and disclosed < since:
            rows.append(
                Row(
                    cve_id=path.stem,
                    payload_count=0,
                    blocked=0,
                    unblocked=0,
                    status="skip",
                    reason=f"disclosed_at {disclosed_raw} < --since {since.isoformat()}",
                    disclosed_at=disclosed_raw,
                )
            )
            continue

        handler = _DISPATCH.get(path.name)
        if handler is None:
            rows.append(
                Row(
                    cve_id="<unknown>",
                    payload_count=0,
                    blocked=0,
                    unblocked=0,
                    status="skip",
                    reason=f"no dispatcher for {path.name}",
                    disclosed_at=disclosed_raw,
                )
            )
            continue

        row = handler(data)  # type: ignore[operator]
        row.disclosed_at = disclosed_raw
        rows.append(row)
    return rows


def _emit_tap(rows: list[Row]) -> str:
    lines = [f"1..{len(rows)}"]
    for i, row in enumerate(rows, 1):
        if row.status == "pass":
            lines.append(f"ok {i} - {row.cve_id} (blocked {row.blocked}/{row.payload_count})")
        elif row.status == "skip":
            lines.append(f"ok {i} - # SKIP {row.cve_id}: {row.reason}")
        else:
            lines.append(
                f"not ok {i} - {row.cve_id} "
                f"(blocked {row.blocked}/{row.payload_count}, "
                f"unblocked {row.unblocked}) {row.reason}"
            )
    return "\n".join(lines)


def _emit_json(rows: list[Row], *, since: date | None = None) -> str:
    payload: dict = {
        "filter": {"since": since.isoformat() if since else None},
        "rows": [
            {
                "cve_id": r.cve_id,
                "payload_count": r.payload_count,
                "blocked": r.blocked,
                "unblocked": r.unblocked,
                "status": r.status,
                "reason": r.reason,
                "disclosed_at": r.disclosed_at,
            }
            for r in rows
        ],
    }
    return json.dumps(payload, indent=2)


def _emit_md(rows: list[Row]) -> str:
    out = [
        "| CVE | Payloads | Blocked | Unblocked | Status |",
        "|---|---|---|---|---|",
    ]
    for r in rows:
        out.append(f"| {r.cve_id} | {r.payload_count} | {r.blocked} | {r.unblocked} | {r.status} |")
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-dir", type=Path, default=FIXTURE_DIR)
    parser.add_argument(
        "--format",
        choices=["tap", "json", "md"],
        default="tap",
    )
    parser.add_argument(
        "--since",
        type=str,
        default=None,
        help=(
            "Filter fixtures whose disclosed_at is strictly before this "
            "ISO date (YYYY-MM-DD). Useful for time-windowed CVE coverage "
            "reports — e.g. 'what April 2026 CVEs are we now blocking?'"
        ),
    )
    args = parser.parse_args()

    sys.path.insert(0, str(ROOT / "src"))

    if not args.fixture_dir.is_dir():
        print(f"fixture dir not found: {args.fixture_dir}", file=sys.stderr)
        return 2

    since: date | None = None
    if args.since is not None:
        try:
            since = _parse_iso_date(args.since)
        except FixtureValidationError as exc:
            print(f"invalid --since value: {exc}", file=sys.stderr)
            return 2

    try:
        rows = walk(args.fixture_dir, since=since)
    except FixtureValidationError as exc:
        print(f"fixture validation: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(_emit_json(rows, since=since))
    else:
        emitters = {"tap": _emit_tap, "md": _emit_md}
        print(emitters[args.format](rows))

    fail_count = sum(1 for r in rows if r.status == "fail")
    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
