"""Conformance run: agent-airlock's MCP 2026-07-28 transport validators.

    python -m benchmarks.mcp_conformance.run

Why this shape (read ``RESULTS.md`` first): the official suite,
``@modelcontextprotocol/conformance``, tests a running MCP **server** (``--url``)
or **client** (``--command``). agent-airlock is neither — it is the in-process
request-validation layer that sits *in front of* a server. So the official
server/client scenarios have no endpoint to drive here. What is measurable, and
what this file measures, is whether airlock's validators actually enforce the
2026-07-28 normative Streamable-HTTP / stateless / routing requirements they
each cite.

Two buckets, kept apart on purpose:

1. **Contract cases** — a positive/negative case per normative rule airlock
   claims to enforce (protocol-version negotiation, no-token-in-query,
   content-type, Accept, bearer auth, SEP-2575 statelessness, SEP-2567 explicit
   state, SEP-2243 routing-header integrity). Expectation traces to the cited
   clause. A failure here is an airlock bug and is published as-is.
2. **Divergence probes** — inputs where airlock's strictness *might* differ from
   a lenient reading of the clause. These are reported as airlock's observed
   behaviour, not scored against the spec, because the exact 2026-07-28 clause
   text is the arbiter and we do not assert a reading we cannot verify. They are
   published so the gap is visible, not hidden.

Nothing here is tuned to pass. The harness prints every case and exits 0
(report-only, like the other ``benchmarks/*`` modules).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from agent_airlock.mcp_spec.header_integrity import validate_header_body_integrity
from agent_airlock.mcp_spec.statelessness import (
    validate_state_handle_declared,
    validate_stateless_request,
)
from agent_airlock.mcp_spec.transport import validate_streamable_http_request

CURRENT_VERSION = "2026-07-28"
LEGACY_VERSION = "2025-11-25"

# The official suite this run is scoped against (provenance for RESULTS.md).
OFFICIAL_SUITE = "@modelcontextprotocol/conformance"
OFFICIAL_SUITE_VERSION = "0.1.16"


def _headers(**over: str) -> dict[str, str]:
    """A minimal valid 2026-07-28 Streamable-HTTP header set."""
    h = {
        "MCP-Protocol-Version": CURRENT_VERSION,
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Authorization": "Bearer t0ken",
    }
    h.update(over)
    return h


def _post(url: str = "https://mcp.example/mcp", **over: str) -> Callable[[], object]:
    headers = _headers(**over)
    return lambda: validate_streamable_http_request(
        method="POST", url=url, headers=headers, body={"jsonrpc": "2.0"}
    )


def _sample_tool_with_cursor(cursor: str | None = None) -> str:  # noqa: ARG001
    """A tool that declares ``cursor`` as an explicit contract parameter."""
    return "ok"


def _sample_tool_no_state(query: str) -> str:  # noqa: ARG001
    """A tool that declares no state handle."""
    return "ok"


@dataclass(frozen=True)
class Case:
    cid: str
    layer: str
    clause: str
    description: str
    thunk: Callable[[], object]
    expected: str  # "accept" | "reject"


@dataclass(frozen=True)
class Probe:
    pid: str
    clause: str
    description: str
    thunk: Callable[[], object]
    note: str


@dataclass
class Outcome:
    cid: str
    layer: str
    clause: str
    description: str
    expected: str
    actual: str
    passed: bool
    detail: str = ""


def _run(thunk: Callable[[], object]) -> tuple[str, str]:
    """Return (verdict, detail): 'accept' if no raise, else 'reject' + message."""
    try:
        thunk()
    except Exception as exc:  # noqa: BLE001 - any raise is a reject on the wire
        return "reject", f"{type(exc).__name__}: {exc}"
    return "accept", ""


def contract_cases() -> list[Case]:
    return [
        # --- Streamable-HTTP transport (basic/transports) ---
        Case(
            "T-ACCEPT-CURRENT",
            "transport",
            "2026-07-28 basic/transports",
            "valid POST advertising MCP-Protocol-Version=2026-07-28",
            _post(),
            "accept",
        ),
        Case(
            "T-ACCEPT-LEGACY",
            "transport",
            "version negotiation (legacy interop)",
            "valid POST advertising legacy 2025-11-25 is still accepted",
            _post(**{"MCP-Protocol-Version": LEGACY_VERSION}),
            "accept",
        ),
        Case(
            "T-REJECT-NOVERSION",
            "transport",
            "MCP-Protocol-Version required",
            "POST with no MCP-Protocol-Version header",
            lambda: validate_streamable_http_request(
                method="POST",
                url="https://mcp.example/mcp",
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Authorization": "Bearer t",
                },
                body={"jsonrpc": "2.0"},
            ),
            "reject",
        ),
        Case(
            "T-REJECT-BADVERSION",
            "transport",
            "MCP-Protocol-Version must be supported",
            "POST advertising an unsupported version (2024-01-01)",
            _post(**{"MCP-Protocol-Version": "2024-01-01"}),
            "reject",
        ),
        Case(
            "T-REJECT-TOKEN-IN-QUERY",
            "transport",
            "Access Token Usage (token not in query)",
            "access_token in the URI query string",
            _post(url="https://mcp.example/mcp?access_token=leaked"),
            "reject",
        ),
        Case(
            "T-REJECT-CONTENT-TYPE",
            "transport",
            "JSON-RPC body Content-Type",
            "POST body with Content-Type: text/plain",
            _post(**{"Content-Type": "text/plain"}),
            "reject",
        ),
        Case(
            "T-REJECT-ACCEPT",
            "transport",
            "Accept must allow json or event-stream",
            "Accept: text/html only",
            _post(**{"Accept": "text/html"}),
            "reject",
        ),
        Case(
            "T-REJECT-NOAUTH",
            "transport",
            "Authorization: Bearer on protected endpoint",
            "no Authorization header, require_auth default",
            lambda: validate_streamable_http_request(
                method="POST",
                url="https://mcp.example/mcp",
                headers={
                    "MCP-Protocol-Version": CURRENT_VERSION,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                body={"jsonrpc": "2.0"},
            ),
            "reject",
        ),
        # --- SEP-2575: stateless lifecycle ---
        Case(
            "S-REJECT-SESSION-ID",
            "stateless",
            "SEP-2575 (session lifecycle removed)",
            "request still carrying Mcp-Session-Id",
            lambda: validate_stateless_request(
                {"method": "tools/call", "headers": {"Mcp-Session-Id": "abc"}}
            ),
            "reject",
        ),
        Case(
            "S-REJECT-INITIALIZE",
            "stateless",
            "SEP-2575 (no initialize handshake)",
            "method=initialize under the stateless model",
            lambda: validate_stateless_request({"method": "initialize"}),
            "reject",
        ),
        Case(
            "S-REJECT-INITIALIZED",
            "stateless",
            "SEP-2575 (no initialized notification)",
            "method=notifications/initialized under the stateless model",
            lambda: validate_stateless_request({"method": "notifications/initialized"}),
            "reject",
        ),
        Case(
            "S-ACCEPT-STATELESS",
            "stateless",
            "SEP-2575 (ordinary stateless call)",
            "tools/call carrying no session header",
            lambda: validate_stateless_request({"method": "tools/call"}),
            "accept",
        ),
        # --- SEP-2567: state passed as an explicit typed argument ---
        Case(
            "S-REJECT-GHOST-STATE",
            "stateless",
            "SEP-2567 (state is an explicit param)",
            "state handle 'cursor' smuggled to a tool that does not declare it",
            lambda: validate_state_handle_declared(
                _sample_tool_no_state, {"query": "x", "cursor": "opaque"}
            ),
            "reject",
        ),
        Case(
            "S-ACCEPT-DECLARED-STATE",
            "stateless",
            "SEP-2567 (declared state param)",
            "state handle 'cursor' passed to a tool that declares it",
            lambda: validate_state_handle_declared(_sample_tool_with_cursor, {"cursor": "opaque"}),
            "accept",
        ),
        # --- SEP-2243: routing-header / body integrity ---
        Case(
            "H-ACCEPT-MATCH",
            "routing",
            "SEP-2243 (headers agree with body)",
            "Mcp-Method / Mcp-Name present and matching the body",
            lambda: validate_header_body_integrity(
                {
                    "headers": {"Mcp-Method": "tools/call", "Mcp-Name": "search"},
                    "method": "tools/call",
                    "params": {"name": "search"},
                }
            ),
            "accept",
        ),
        Case(
            "H-REJECT-NO-METHOD-HEADER",
            "routing",
            "SEP-2243 (Mcp-Method required)",
            "Mcp-Method routing header absent",
            lambda: validate_header_body_integrity(
                {
                    "headers": {"Mcp-Name": "search"},
                    "method": "tools/call",
                    "params": {"name": "search"},
                }
            ),
            "reject",
        ),
        Case(
            "H-REJECT-METHOD-MISMATCH",
            "routing",
            "SEP-2243 (headers must agree with body)",
            "Mcp-Method disagrees with the body method",
            lambda: validate_header_body_integrity(
                {
                    "headers": {"Mcp-Method": "resources/read", "Mcp-Name": "search"},
                    "method": "tools/call",
                    "params": {"name": "search"},
                }
            ),
            "reject",
        ),
        Case(
            "H-REJECT-NAME-MISMATCH",
            "routing",
            "SEP-2243 (headers must agree with body)",
            "Mcp-Name disagrees with the body operation name",
            lambda: validate_header_body_integrity(
                {
                    "headers": {"Mcp-Method": "tools/call", "Mcp-Name": "delete"},
                    "method": "tools/call",
                    "params": {"name": "search"},
                }
            ),
            "reject",
        ),
    ]


def divergence_probes() -> list[Probe]:
    return [
        Probe(
            "D-PING-NAME",
            "SEP-2243 (Name header applicability)",
            "ping request with Mcp-Method=ping but no Mcp-Name",
            lambda: validate_header_body_integrity(
                {"headers": {"Mcp-Method": "ping"}, "method": "ping"}
            ),
            "airlock requires Mcp-Name on every request; a method with no "
            "operation name (ping) has nothing for it to carry. If the clause "
            "scopes Mcp-Name to named operations, airlock is stricter than spec "
            "here (a benign-request false-positive risk).",
        ),
        Probe(
            "D-ACCEPT-JSON-ONLY",
            "Streamable-HTTP Accept (both variants)",
            "Accept: application/json only, no text/event-stream",
            _post(**{"Accept": "application/json"}),
            "airlock accepts json-only. If 2026-07-28 requires the client to "
            "accept BOTH application/json and text/event-stream, airlock is more "
            "lenient than spec here.",
        ),
        Probe(
            "D-GET-NOVERSION",
            "MCP-Protocol-Version on GET (SSE) requests",
            "GET (SSE open) with no MCP-Protocol-Version header",
            lambda: validate_streamable_http_request(
                method="GET",
                url="https://mcp.example/mcp",
                headers={"Accept": "text/event-stream", "Authorization": "Bearer t"},
            ),
            "airlock requires the version header on GET too. Confirm the clause "
            "requires it on the SSE-open GET and not only on JSON-RPC POSTs.",
        ),
    ]


def evaluate() -> list[Outcome]:
    outs: list[Outcome] = []
    for c in contract_cases():
        actual, detail = _run(c.thunk)
        outs.append(
            Outcome(
                cid=c.cid,
                layer=c.layer,
                clause=c.clause,
                description=c.description,
                expected=c.expected,
                actual=actual,
                passed=(actual == c.expected),
                detail=detail,
            )
        )
    return outs


@dataclass
class Report:
    outcomes: list[Outcome]
    probes: list[tuple[Probe, str, str]] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.outcomes)

    @property
    def passed(self) -> int:
        return sum(1 for o in self.outcomes if o.passed)

    @property
    def failed(self) -> list[Outcome]:
        return [o for o in self.outcomes if not o.passed]


def build_report() -> Report:
    report = Report(outcomes=evaluate())
    for p in divergence_probes():
        actual, detail = _run(p.thunk)
        report.probes.append((p, actual, detail))
    return report


def main() -> int:
    report = build_report()
    print(f"MCP conformance — agent-airlock transport surface @ spec {CURRENT_VERSION}")
    print(f"Official suite of record: {OFFICIAL_SUITE}@{OFFICIAL_SUITE_VERSION}")
    print("Scope: airlock is a request validator, not a server/client; see RESULTS.md.\n")

    print("Contract cases (airlock vs the normative rule it cites):")
    print(f"  {'case':<26} {'layer':<10} {'exp':<7} {'got':<7} result")
    for o in report.outcomes:
        mark = "PASS" if o.passed else "FAIL"
        print(f"  {o.cid:<26} {o.layer:<10} {o.expected:<7} {o.actual:<7} {mark}")

    print(f"\n  contract cases: {report.passed}/{report.total} pass")
    if report.failed:
        print("\n  FAILURES (published as-is, not tuned away):")
        for o in report.failed:
            print(f"    - {o.cid} [{o.clause}] {o.description}")
            print(f"        expected {o.expected}, got {o.actual} :: {o.detail}")

    print("\nDivergence probes (airlock behaviour reported, not scored vs spec):")
    for p, actual, _detail in report.probes:
        print(f"  {p.pid:<20} {actual:<7} {p.description}")
        print(f"      note: {p.note}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
