"""Guard: the published MCP conformance result stays true to the code.

``benchmarks/mcp_conformance/RESULTS.md`` publishes a transport-contract pass for
spec 2026-07-28. This ties that claim to the validators so an airlock transport /
stateless / routing regression fails here, not silently in a stale RESULTS.md.

The three 2026-08 divergence probes (#127/#128/#129) were resolved against the
ratified 2026-07-28 text on 2026-08-10 and are now scored contract cases.
"""

from __future__ import annotations

# Same source of truth the `airlock conformance --revision` CLI and the
# benchmarks/mcp_conformance harness use.
from benchmarks.mcp_conformance.run import build_report

from agent_airlock.mcp_spec.conformance import run_conformance


class TestMcpConformanceResultHolds:
    def test_all_contract_cases_pass(self) -> None:
        report = build_report()
        failed = [r.cid for r in report.results if not r.passed]
        assert not failed, f"2026-07-28 transport-contract regression: {failed}"
        assert report.passed == report.total == 22

    def test_resolved_divergences_reflect_ratified_reading(self) -> None:
        # #127/#128/#129, closed 2026-08-10 against the ratified 2026-07-28 clauses.
        report = run_conformance("2026-07-28")
        by_id = {r.cid: r.actual for r in report.results}
        # #128 — POST MUST list both application/json and text/event-stream.
        assert by_id["T-REJECT-ACCEPT-JSON-ONLY"] == "reject"
        # #129 — the GET stream endpoint was removed; GET at 2026-07-28 is 405.
        assert by_id["T-REJECT-GET-CURRENT"] == "reject"
        # #127 — Mcp-Name is required only for name-bearing methods (tools/list is not).
        assert by_id["H-ACCEPT-LIST-NO-NAME"] == "accept"
