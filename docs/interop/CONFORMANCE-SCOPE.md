# Conformance scope

agent-airlock **implements** validators and hardening that **target** the MCP `2026-07-28` (current) and `2025-11-25` (legacy) revisions. It makes **no conformance claim**: no MCP conformance suite has been run against agent-airlock.

The claim strength is therefore "implements" and "targets" — never "conformant". This is the same position the `CHANGELOG.md` `0.8.61` entry already takes: *"airlock still makes no conformance claim — no conformance suite has been run."* Keep that wording.

## Divergence-resolution issues — resolved (2026-08-10)

The first conformance run published three **divergence probes** — inputs where airlock's
strictness might differ from a lenient reading of the clause — held open until the ratified
2026-07-28 text could be read. All three are now resolved against that text (verbatim clause
quotes in the guard source); each is a scored contract case in
[`benchmarks/mcp_conformance/RESULTS.md`](https://github.com/sattyamjjain/agent-airlock/blob/main/benchmarks/mcp_conformance/RESULTS.md)
("Resolved divergences"), and issues #127/#128/#129 are closed:

- [#127](https://github.com/sattyamjjain/agent-airlock/issues/127) — **D-PING-NAME**: the SEP-2243 header table scopes `Mcp-Name` to `tools/call` / `resources/read` / `prompts/get` (and `ping` was removed). airlock's `Mcp-Name` requirement is now scoped to those methods (`H-ACCEPT-LIST-NO-NAME`).
- [#128](https://github.com/sattyamjjain/agent-airlock/issues/128) — **D-ACCEPT-JSON-ONLY**: the spec requires a POST to list **both** `application/json` and `text/event-stream`; airlock now rejects a json-only `Accept` on a POST (`T-REJECT-ACCEPT-JSON-ONLY`).
- [#129](https://github.com/sattyamjjain/agent-airlock/issues/129) — **D-GET-NOVERSION**: the GET stream endpoint was removed (`405` at 2026-07-28); airlock rejects `GET`/`DELETE` to the protected MCP endpoint at 2026-07-28 while keeping legacy GET-SSE (`T-REJECT-GET-CURRENT`, `T-ACCEPT-GET-LEGACY`).

Reproduce from the installed wheel: `airlock conformance --revision 2026-07-28`.

## If the OpenID AIIM interop event produces a result

This file is where a completed interop result lands. When one exists, record:

- the partner and their software / version,
- the MCP revision(s) exercised,
- the date and what was tested (at least one interop test is due by 2026-10-16),
- the outcome, linked to any artifact.

Until then there is no result to report, and the claim strength stays "implements" / "targets" — never "conformant".
