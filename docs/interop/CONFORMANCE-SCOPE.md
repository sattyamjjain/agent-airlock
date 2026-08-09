# Conformance scope

agent-airlock **implements** validators and hardening that **target** the MCP `2026-07-28` (current) and `2025-11-25` (legacy) revisions. It makes **no conformance claim**: no MCP conformance suite has been run against agent-airlock.

The claim strength is therefore "implements" and "targets" — never "conformant". This is the same position the `CHANGELOG.md` `0.8.61` entry already takes: *"airlock still makes no conformance claim — no conformance suite has been run."* Keep that wording.

## Open divergence-resolution issues

The first conformance run ([`benchmarks/mcp_conformance/RESULTS.md`](https://github.com/sattyamjjain/agent-airlock/blob/main/benchmarks/mcp_conformance/RESULTS.md)) published three **divergence probes** — inputs where airlock's strictness may differ from a lenient reading of the clause. Each is now a tracked issue, so a divergence is closeable work instead of a line in a results file:

- [#127](https://github.com/sattyamjjain/agent-airlock/issues/127) — **D-PING-NAME**: airlock rejects `ping` (it requires `Mcp-Name` on every request). Stricter than spec *if* SEP-2243 scopes `Mcp-Name` to named operations — a benign-request false positive.
- [#128](https://github.com/sattyamjjain/agent-airlock/issues/128) — **D-ACCEPT-JSON-ONLY**: airlock accepts an `application/json`-only `Accept`. More lenient than spec *if* 2026-07-28 requires both `application/json` and `text/event-stream`.
- [#129](https://github.com/sattyamjjain/agent-airlock/issues/129) — **D-GET-NOVERSION**: airlock requires `MCP-Protocol-Version` on the SSE-open `GET`, not only on JSON-RPC `POST`s. Confirm the clause requires it on `GET`.

Each closes when the ratified 2026-07-28 clause is read and airlock is either confirmed conformant (the reading recorded) or adjusted (the probe flips and a regression case is added). Until then the probes stay published as-is; none is tuned away.

## If the OpenID AIIM interop event produces a result

This file is where a completed interop result lands. When one exists, record:

- the partner and their software / version,
- the MCP revision(s) exercised,
- the date and what was tested (at least one interop test is due by 2026-10-16),
- the outcome, linked to any artifact.

Until then there is no result to report, and the claim strength stays "implements" / "targets" — never "conformant".
