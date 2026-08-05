"""Guard: the published MCP conformance result stays true to the code.

``benchmarks/mcp_conformance/RESULTS.md`` publishes an 18/18 transport-contract
pass and three named divergence-probe outcomes for spec 2026-07-28. This ties
those claims to the validators so an airlock transport / stateless / routing
regression fails here, not silently in a stale RESULTS.md.
"""

from __future__ import annotations

from benchmarks.mcp_conformance.run import build_report


class TestMcpConformanceResultHolds:
    def test_all_contract_cases_pass(self) -> None:
        report = build_report()
        failed = [o.cid for o in report.outcomes if not o.passed]
        assert not failed, f"2026-07-28 transport-contract regression: {failed}"
        assert report.passed == report.total == 18

    def test_divergence_probes_match_published(self) -> None:
        # RESULTS.md publishes these observed behaviours as the honest edges.
        # Lock them so the doc cannot drift from the code without this failing.
        report = build_report()
        observed = {p.pid: actual for p, actual, _ in report.probes}
        assert observed == {
            "D-PING-NAME": "reject",
            "D-ACCEPT-JSON-ONLY": "accept",
            "D-GET-NOVERSION": "reject",
        }, observed
