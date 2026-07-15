"""Join airlock's live decisions with the recorded gateway measurement.

Produces the head-to-head table and the single "contract-layer gap" number:
how many malformed payloads each layer blocks on the identical corpus.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from .airlock_runner import run_airlock
from .corpus import GatewayCall

_FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gateway_measurement.json")


@dataclass(frozen=True)
class Row:
    """One joined corpus item: airlock vs gateway decision."""

    call: GatewayCall
    airlock_blocked: bool
    gateway_blocked: bool
    airlock_latency_ms: float


@dataclass
class HeadToHead:
    """Aggregate head-to-head result over the corpus."""

    rows: list[Row]
    provenance: dict[str, object] = field(default_factory=dict)

    @property
    def malicious(self) -> list[Row]:
        return [r for r in self.rows if r.call.expected_block]

    @property
    def benign(self) -> list[Row]:
        return [r for r in self.rows if not r.call.expected_block]

    @property
    def airlock_blocked(self) -> int:
        return sum(1 for r in self.malicious if r.airlock_blocked)

    @property
    def gateway_blocked(self) -> int:
        return sum(1 for r in self.malicious if r.gateway_blocked)

    @property
    def airlock_fp(self) -> int:
        return sum(1 for r in self.benign if r.airlock_blocked)

    @property
    def gateway_fp(self) -> int:
        return sum(1 for r in self.benign if r.gateway_blocked)

    @property
    def malicious_total(self) -> int:
        return len(self.malicious)

    @property
    def benign_total(self) -> int:
        return len(self.benign)

    def airlock_p50_ms(self) -> float:
        lat = sorted(r.airlock_latency_ms for r in self.rows)
        return lat[len(lat) // 2] if lat else 0.0


def _load_fixture() -> dict[str, object]:
    with open(_FIXTURE, encoding="utf-8") as fh:
        data: dict[str, object] = json.load(fh)
    return data


def build_report() -> HeadToHead:
    """Run airlock live, join with the recorded gateway fixture."""
    fixture = _load_fixture()
    records = fixture.get("records", {})
    assert isinstance(records, dict)

    rows: list[Row] = []
    for call, airlock_blocked, latency in run_airlock():
        rec = records.get(call.item_id, {})
        decision = rec.get("gateway_decision", "PASS") if isinstance(rec, dict) else "PASS"
        rows.append(
            Row(
                call=call,
                airlock_blocked=airlock_blocked,
                gateway_blocked=(decision == "BLOCK"),
                airlock_latency_ms=latency,
            )
        )
    prov = fixture.get("provenance", {})
    return HeadToHead(rows=rows, provenance=prov if isinstance(prov, dict) else {})


def render(report: HeadToHead) -> str:
    """Render the head-to-head as a plain-text report."""
    prov = report.provenance
    gw_ver = prov.get("gateway_image_version", "?")
    gw_prod = prov.get("gateway_product", "native MCP gateway")
    date = prov.get("measured_utc_date", "?")

    lines: list[str] = []
    lines.append("=" * 74)
    lines.append("agent-airlock vs native MCP gateway — contract-layer head-to-head")
    lines.append("=" * 74)
    lines.append(
        f"Corpus: {report.malicious_total} malformed payloads + "
        f"{report.benign_total} benign controls (identical to both layers)"
    )
    lines.append(f"Gateway: {gw_prod} v{gw_ver} (recorded {date})")
    lines.append(
        f"Airlock: live, in-process (this run) — p50 {report.airlock_p50_ms():.3f} ms/decision"
    )
    lines.append("")
    header = f"{'payload class':24s} {'airlock':>9s} {'gateway':>9s}  note"
    lines.append(header)
    lines.append("-" * len(header))
    for r in report.rows:
        a = "BLOCK" if r.airlock_blocked else "allow"
        g = "BLOCK" if r.gateway_blocked else "allow"
        tag = "" if r.call.expected_block else "  (benign)"
        lines.append(f"{r.call.item_id:24s} {a:>9s} {g:>9s}  {r.call.note[:34]}{tag}")
    lines.append("-" * len(header))
    lines.append("")
    lines.append(
        f"MALFORMED blocked  — airlock {report.airlock_blocked}/{report.malicious_total}"
        f"   |   {gw_prod} {report.gateway_blocked}/{report.malicious_total}"
    )
    lines.append(
        f"BENIGN false-pos   — airlock {report.airlock_fp}/{report.benign_total}"
        f"   |   {gw_prod} {report.gateway_fp}/{report.benign_total}"
    )
    lines.append("")
    gap = report.airlock_blocked - report.gateway_blocked
    lines.append(
        f"CONTRACT-LAYER GAP: airlock blocks {report.airlock_blocked}/{report.malicious_total} "
        f"malformed tool-call payloads that the native gateway forwards "
        f"({gap}/{report.malicious_total} more)."
    )
    lines.append(
        "The gateway authenticates identity + transport and sandboxes the server; "
        "it does not validate the tool-call payload's argument contract."
    )
    lines.append("=" * 74)
    return "\n".join(lines)
