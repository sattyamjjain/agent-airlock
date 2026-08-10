"""Conformance run: agent-airlock's MCP 2026-07-28 transport validators.

    python -m benchmarks.mcp_conformance.run

Why this shape (read ``RESULTS.md`` first): the official suite,
``@modelcontextprotocol/conformance``, tests a running MCP **server** (``--url``)
or **client** (``--command``). agent-airlock is neither — it is the in-process
request-validation layer that sits *in front of* a server, so the official
server/client scenarios have no endpoint to drive here. What is measurable, and
what this reports, is whether airlock's validators enforce the 2026-07-28
normative Streamable-HTTP / stateless / routing requirements they each cite.

The cases now live in the shipped, single-source-of-truth runner
``agent_airlock.mcp_spec.conformance`` (so the ``airlock conformance --revision``
CLI and this benchmark cannot drift). The three divergence probes published in
2026-08 (``D-PING-NAME`` / ``D-ACCEPT-JSON-ONLY`` / ``D-GET-NOVERSION``, issues
#127/#128/#129) were resolved against the ratified 2026-07-28 text on 2026-08-10
and are now scored contract cases (``H-ACCEPT-LIST-NO-NAME`` /
``T-REJECT-ACCEPT-JSON-ONLY`` / ``T-REJECT-GET-CURRENT``).

Nothing here is tuned to pass; a failure is an airlock regression.
"""

from __future__ import annotations

from agent_airlock.mcp_spec.conformance import (
    CURRENT_VERSION,
    ConformanceReport,
    format_report,
    run_conformance,
)

# The official suite this run is scoped against (provenance for RESULTS.md).
OFFICIAL_SUITE = "@modelcontextprotocol/conformance"
OFFICIAL_SUITE_VERSION = "0.1.16"


def build_report() -> ConformanceReport:
    """Run the shipped conformance runner for the current ratified revision."""
    return run_conformance(CURRENT_VERSION)


def main() -> int:
    report = build_report()
    print(f"Official suite of record: {OFFICIAL_SUITE}@{OFFICIAL_SUITE_VERSION}\n")
    print(format_report(report))
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
