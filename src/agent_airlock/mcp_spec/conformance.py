"""Shipped MCP transport-contract conformance runner (in-process, no server, no network).

agent-airlock is the request-validation layer that sits *in front of* an MCP server, not a
server or client, so the official ``@modelcontextprotocol/conformance`` suite (which drives a
running ``--url`` server or ``--command`` client) has no endpoint to drive here. What *is*
measurable, and what this runs, is whether airlock's own 2026-07-28 validators
(``transport`` / ``header_integrity`` / ``statelessness``) enforce the normative
Streamable-HTTP / stateless / routing rules they each cite.

This module is the **single source of truth** for those cases: it ships in the wheel so
``airlock conformance --revision`` works from an installed package, and
``benchmarks/mcp_conformance/run.py`` imports the same cases so the CLI and the benchmark
cannot drift. It makes **no** conformance *claim* — it is a reproducible regression baseline,
not a certification (see ``docs/interop/CONFORMANCE-SCOPE.md``).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ._versions import PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS
from .header_integrity import validate_header_body_integrity
from .statelessness import validate_state_handle_declared, validate_stateless_request
from .transport import validate_streamable_http_request

CURRENT_VERSION = PROTOCOL_VERSION
LEGACY_VERSION = "2025-11-25"

__all__ = [
    "CURRENT_VERSION",
    "LEGACY_VERSION",
    "CaseResult",
    "ConformanceCase",
    "ConformanceReport",
    "contract_cases",
    "format_report",
    "run_conformance",
]


@dataclass(frozen=True)
class ConformanceCase:
    """One normative case: a thunk that drives a real guard and its expected verdict."""

    cid: str
    layer: str
    clause: str
    description: str
    thunk: Callable[[], object]
    expected: str  # "accept" | "reject"


@dataclass(frozen=True)
class CaseResult:
    cid: str
    layer: str
    clause: str
    description: str
    expected: str
    actual: str
    passed: bool
    detail: str = ""


@dataclass(frozen=True)
class ConformanceReport:
    revision: str
    results: tuple[CaseResult, ...]

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def passed(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def ok(self) -> bool:
        return all(r.passed for r in self.results)


def _headers(**over: str) -> dict[str, str]:
    """A minimal valid 2026-07-28 Streamable-HTTP POST header set."""
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


def contract_cases() -> list[ConformanceCase]:
    """The normative cases airlock's validators are checked against.

    Includes the three cases that closed the 2026-08 divergence probes (#127/#128/#129),
    now scored against the ratified 2026-07-28 clause text rather than published as open
    divergences.
    """
    return [
        # --- Streamable-HTTP transport (basic/transports) ---
        ConformanceCase(
            "T-ACCEPT-CURRENT",
            "transport",
            "2026-07-28 basic/transports",
            "valid POST advertising MCP-Protocol-Version=2026-07-28",
            _post(),
            "accept",
        ),
        ConformanceCase(
            "T-ACCEPT-LEGACY",
            "transport",
            "version negotiation (legacy interop)",
            "valid POST advertising legacy 2025-11-25 is still accepted",
            _post(**{"MCP-Protocol-Version": LEGACY_VERSION}),
            "accept",
        ),
        ConformanceCase(
            "T-REJECT-NOVERSION",
            "transport",
            "MCP-Protocol-Version required",
            "POST with no MCP-Protocol-Version header",
            lambda: validate_streamable_http_request(
                method="POST",
                url="https://mcp.example/mcp",
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                    "Authorization": "Bearer t",
                },
                body={"jsonrpc": "2.0"},
            ),
            "reject",
        ),
        ConformanceCase(
            "T-REJECT-BADVERSION",
            "transport",
            "MCP-Protocol-Version must be supported",
            "POST advertising an unsupported version (2024-01-01)",
            _post(**{"MCP-Protocol-Version": "2024-01-01"}),
            "reject",
        ),
        ConformanceCase(
            "T-REJECT-TOKEN-IN-QUERY",
            "transport",
            "Access Token Usage (token not in query)",
            "access_token in the URI query string",
            _post(url="https://mcp.example/mcp?access_token=leaked"),
            "reject",
        ),
        ConformanceCase(
            "T-REJECT-CONTENT-TYPE",
            "transport",
            "JSON-RPC body Content-Type",
            "POST body with Content-Type: text/plain",
            _post(**{"Content-Type": "text/plain"}),
            "reject",
        ),
        ConformanceCase(
            "T-REJECT-ACCEPT",
            "transport",
            "Accept must allow the transport media types",
            "Accept: text/html only",
            _post(**{"Accept": "text/html"}),
            "reject",
        ),
        ConformanceCase(
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
                    "Accept": "application/json, text/event-stream",
                },
                body={"jsonrpc": "2.0"},
            ),
            "reject",
        ),
        # Resolved #128: a POST MUST list both application/json and text/event-stream.
        ConformanceCase(
            "T-REJECT-ACCEPT-JSON-ONLY",
            "transport",
            "Sending Messages (Accept lists BOTH types) [was divergence #128]",
            "POST with Accept: application/json only",
            _post(**{"Accept": "application/json"}),
            "reject",
        ),
        # Resolved #129: the GET stream endpoint was removed; GET at 2026-07-28 is 405.
        ConformanceCase(
            "T-REJECT-GET-CURRENT",
            "transport",
            "Backward Compatibility (GET -> 405 at 2026-07-28) [was divergence #129]",
            "GET to the MCP endpoint at 2026-07-28",
            lambda: validate_streamable_http_request(
                method="GET", url="https://mcp.example/mcp", headers=_headers()
            ),
            "reject",
        ),
        ConformanceCase(
            "T-ACCEPT-GET-LEGACY",
            "transport",
            "legacy 2025-11-25 kept the GET SSE-open",
            "GET to the MCP endpoint at legacy 2025-11-25",
            lambda: validate_streamable_http_request(
                method="GET",
                url="https://mcp.example/mcp",
                headers=_headers(**{"MCP-Protocol-Version": LEGACY_VERSION}),
            ),
            "accept",
        ),
        # --- SEP-2575: stateless lifecycle ---
        ConformanceCase(
            "S-REJECT-SESSION-ID",
            "stateless",
            "SEP-2575 (session lifecycle removed)",
            "request still carrying Mcp-Session-Id",
            lambda: validate_stateless_request(
                {"method": "tools/call", "headers": {"Mcp-Session-Id": "abc"}}
            ),
            "reject",
        ),
        ConformanceCase(
            "S-REJECT-INITIALIZE",
            "stateless",
            "SEP-2575 (no initialize handshake)",
            "method=initialize under the stateless model",
            lambda: validate_stateless_request({"method": "initialize"}),
            "reject",
        ),
        ConformanceCase(
            "S-REJECT-INITIALIZED",
            "stateless",
            "SEP-2575 (no initialized notification)",
            "method=notifications/initialized under the stateless model",
            lambda: validate_stateless_request({"method": "notifications/initialized"}),
            "reject",
        ),
        ConformanceCase(
            "S-ACCEPT-STATELESS",
            "stateless",
            "SEP-2575 (ordinary stateless call)",
            "tools/call carrying no session header",
            lambda: validate_stateless_request({"method": "tools/call"}),
            "accept",
        ),
        # --- SEP-2567: state passed as an explicit typed argument ---
        ConformanceCase(
            "S-REJECT-GHOST-STATE",
            "stateless",
            "SEP-2567 (state is an explicit param)",
            "state handle 'cursor' smuggled to a tool that does not declare it",
            lambda: validate_state_handle_declared(
                _sample_tool_no_state, {"query": "x", "cursor": "opaque"}
            ),
            "reject",
        ),
        ConformanceCase(
            "S-ACCEPT-DECLARED-STATE",
            "stateless",
            "SEP-2567 (declared state param)",
            "state handle 'cursor' passed to a tool that declares it",
            lambda: validate_state_handle_declared(_sample_tool_with_cursor, {"cursor": "opaque"}),
            "accept",
        ),
        # --- SEP-2243: routing-header / body integrity ---
        ConformanceCase(
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
        ConformanceCase(
            "H-REJECT-NO-METHOD-HEADER",
            "routing",
            "SEP-2243 (Mcp-Method required on all)",
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
        ConformanceCase(
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
        ConformanceCase(
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
        # Resolved #127: Mcp-Name is required only for name-bearing methods.
        ConformanceCase(
            "H-ACCEPT-LIST-NO-NAME",
            "routing",
            "SEP-2243 (Mcp-Name scoped to name-bearing methods) [was divergence #127]",
            "tools/list carries Mcp-Method but no Mcp-Name",
            lambda: validate_header_body_integrity(
                {"method": "tools/list", "headers": {"Mcp-Method": "tools/list"}}
            ),
            "accept",
        ),
    ]


def _run(thunk: Callable[[], object]) -> tuple[str, str]:
    """Return (verdict, detail): 'accept' if no raise, else 'reject' + message."""
    try:
        thunk()
    except Exception as exc:  # noqa: BLE001 - any raise is a reject on the wire
        return "reject", f"{type(exc).__name__}: {exc}"
    return "accept", ""


def run_conformance(revision: str = CURRENT_VERSION) -> ConformanceReport:
    """Run the transport-contract cases and return a structured report.

    Args:
        revision: the MCP revision to report against. Must be one of
            :data:`SUPPORTED_PROTOCOL_VERSIONS`. The case set exercises both the current
            2026-07-28 rules and the accepted legacy behaviour; ``revision`` labels the
            report and is validated as supported.

    Raises:
        ValueError: if ``revision`` is not a supported protocol version.
    """
    if revision not in SUPPORTED_PROTOCOL_VERSIONS:
        raise ValueError(
            f"unsupported MCP revision {revision!r}; "
            f"supported={list(SUPPORTED_PROTOCOL_VERSIONS)!r}"
        )
    results: list[CaseResult] = []
    for case in contract_cases():
        actual, detail = _run(case.thunk)
        results.append(
            CaseResult(
                cid=case.cid,
                layer=case.layer,
                clause=case.clause,
                description=case.description,
                expected=case.expected,
                actual=actual,
                passed=actual == case.expected,
                detail=detail,
            )
        )
    return ConformanceReport(revision=revision, results=tuple(results))


def format_report(report: ConformanceReport) -> str:
    """A compact text summary of a report for the CLI."""
    lines = [
        f"MCP transport-contract conformance (agent-airlock) — revision {report.revision}",
        f"{report.passed}/{report.total} normative cases pass"
        + ("" if report.ok else f"  ({report.total - report.passed} FAILED)"),
        "",
    ]
    for r in report.results:
        mark = "PASS" if r.passed else "FAIL"
        line = f"  [{mark}] {r.cid:<24} {r.layer:<9} expected={r.expected} actual={r.actual}"
        if not r.passed and r.detail:
            line += f"\n         {r.detail}"
        lines.append(line)
    lines.append("")
    lines.append(
        "Not a conformance claim: airlock is a request validator, not an MCP server or "
        "client. See docs/interop/CONFORMANCE-SCOPE.md."
    )
    return "\n".join(lines)
