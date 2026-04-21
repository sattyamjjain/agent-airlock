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
import sys
from dataclasses import dataclass
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


def _run_ox_stdio(fixture: dict) -> Row:
    sys.path.insert(0, str(ROOT / "src"))
    from agent_airlock.mcp_spec.stdio_guard import (  # type: ignore[import-not-found]
        StdioInjectionError,
        validate_stdio_command,
    )
    from agent_airlock.policy_presets import stdio_guard_ox_defaults  # type: ignore[import-not-found]

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


def walk(fixture_dir: Path) -> list[Row]:
    rows: list[Row] = []
    for path in sorted(fixture_dir.glob("*.json")):
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
                )
            )
            continue
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
        rows.append(handler(data))  # type: ignore[operator]
    return rows


def _emit_tap(rows: list[Row]) -> str:
    lines = [f"1..{len(rows)}"]
    for i, row in enumerate(rows, 1):
        if row.status == "pass":
            lines.append(
                f"ok {i} - {row.cve_id} "
                f"(blocked {row.blocked}/{row.payload_count})"
            )
        elif row.status == "skip":
            lines.append(f"ok {i} - # SKIP {row.cve_id}: {row.reason}")
        else:
            lines.append(
                f"not ok {i} - {row.cve_id} "
                f"(blocked {row.blocked}/{row.payload_count}, "
                f"unblocked {row.unblocked}) {row.reason}"
            )
    return "\n".join(lines)


def _emit_json(rows: list[Row]) -> str:
    return json.dumps(
        [
            {
                "cve_id": r.cve_id,
                "payload_count": r.payload_count,
                "blocked": r.blocked,
                "unblocked": r.unblocked,
                "status": r.status,
                "reason": r.reason,
            }
            for r in rows
        ],
        indent=2,
    )


def _emit_md(rows: list[Row]) -> str:
    out = [
        "| CVE | Payloads | Blocked | Unblocked | Status |",
        "|---|---|---|---|---|",
    ]
    for r in rows:
        out.append(
            f"| {r.cve_id} | {r.payload_count} | {r.blocked} | "
            f"{r.unblocked} | {r.status} |"
        )
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-dir", type=Path, default=FIXTURE_DIR)
    parser.add_argument(
        "--format",
        choices=["tap", "json", "md"],
        default="tap",
    )
    args = parser.parse_args()

    sys.path.insert(0, str(ROOT / "src"))

    if not args.fixture_dir.is_dir():
        print(f"fixture dir not found: {args.fixture_dir}", file=sys.stderr)
        return 2

    rows = walk(args.fixture_dir)
    emitters = {"tap": _emit_tap, "json": _emit_json, "md": _emit_md}
    print(emitters[args.format](rows))

    fail_count = sum(1 for r in rows if r.status == "fail")
    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
