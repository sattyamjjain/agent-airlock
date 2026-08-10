# MCP conformance — agent-airlock (spec 2026-07-28)

Last run: **2026-08-10** (the three 2026-08-05 divergence probes were resolved against the
ratified 2026-07-28 text and are now scored contract cases; see below). Official suite of
record: **`@modelcontextprotocol/conformance@0.1.16`**.

Reproduce (airlock transport surface, deterministic, no server, no network) — the harness and
the shipped `airlock` CLI share one source of truth, `agent_airlock.mcp_spec.conformance`:

```bash
python -m benchmarks.mcp_conformance.run
airlock conformance --revision 2026-07-28   # same cases, from the installed wheel
```

Reproduce (inspect the official suite this run is scoped against):

```bash
npx -y @modelcontextprotocol/conformance@0.1.16 list
npx -y @modelcontextprotocol/conformance@0.1.16 server --url <url> --spec-version 2026-07-28
```

## Headline

- agent-airlock transport-contract conformance: **20 / 20** normative cases pass, **0 failures**.
- The three divergence probes published on 2026-08-05 (`D-PING-NAME`, `D-ACCEPT-JSON-ONLY`,
  `D-GET-NOVERSION`, issues #127/#128/#129) were **resolved** on 2026-08-10 against the ratified
  2026-07-28 clause text and are now the scored cases `H-ACCEPT-LIST-NO-NAME`,
  `T-REJECT-ACCEPT-JSON-ONLY`, and `T-REJECT-GET-CURRENT` (resolution detail below). None tuned away.
- **This is not a full MCP server/client conformance pass-rate.** agent-airlock is an
  in-process request validator, not an MCP server or client, so the official suite —
  which drives a running server (`--url`) or client (`--command`) — has no endpoint to
  drive here. What is measured is airlock's transport / stateless / routing validators
  against the 2026-07-28 normative HTTP requirements they each cite.

## What this measures, and what it can't

The official [`@modelcontextprotocol/conformance`](https://github.com/modelcontextprotocol/conformance)
suite validates MCP implementations by connecting to a **server** as a client
(`server --url`), or by driving a **client** binary (`client --command`) against a
test server, then checking the captured protocol traffic against the spec. Every
scenario also runs a synthetic `wire-schema-valid` check against the spec JSON schema
for the negotiated version.

agent-airlock is neither a server nor a client. It is the request-validation layer that
sits **in front of** a server: `validate_streamable_http_request`, the SEP-2575
statelessness guard, the SEP-2567 explicit-state guard, and the SEP-2243 routing-header
integrity guard. There is no airlock endpoint for `server --url` or `client --command`
to drive, so the suite's server/client scenarios cannot produce a pass-rate for it.

Two further facts, both verified this run and both worth stating plainly:

1. **At `--spec-version 2026-07-28` the official suite currently ships very little that
   is 2026-07-28-specific.** Only three scenarios are tagged `[draft]`
   (`auth/resource-mismatch`, `auth/offline-access-scope`,
   `auth/offline-access-not-supported`) and all three are **client-side OAuth**
   scenarios. Everything else runs the latest *dated* set (`2025-11-25`) under the
   stateless lifecycle. There is no body of 2026-07-28 **server** scenarios yet.
2. **No SDK ships a 2026-07-28 server to host airlock.** The official Python SDK's
   `LATEST_PROTOCOL_VERSION` is `2025-11-25` (checked this run). So even a "wrap a real
   SDK server with airlock and run `server --url`" approach cannot be 2026-07-28 today —
   the baseline server would not speak 2026-07-28.

So the honest, reproducible thing to measure now is airlock's own 2026-07-28 transport
validators against the normative rules they cite. That is the run below. When an SDK
ships a 2026-07-28 server, the `server --url` path against an airlock-gated instance
becomes runnable and this file will grow a second result.

## Result — airlock transport-contract conformance (22/22)

Each case drives a real airlock validator with a request that the cited clause says must
be accepted or rejected. `accept` = validator returned; `reject` = validator raised.

| Case | Layer | Clause | Expected | airlock | Result |
|---|---|---|---|---|---|
| T-ACCEPT-CURRENT | transport | 2026-07-28 basic/transports | accept | accept | ✅ |
| T-ACCEPT-LEGACY | transport | version negotiation (legacy) | accept | accept | ✅ |
| T-REJECT-NOVERSION | transport | MCP-Protocol-Version required | reject | reject | ✅ |
| T-REJECT-BADVERSION | transport | version must be supported | reject | reject | ✅ |
| T-REJECT-TOKEN-IN-QUERY | transport | Access Token Usage | reject | reject | ✅ |
| T-REJECT-CONTENT-TYPE | transport | JSON-RPC body Content-Type | reject | reject | ✅ |
| T-REJECT-ACCEPT | transport | Accept allows json / event-stream | reject | reject | ✅ |
| T-REJECT-NOAUTH | transport | Authorization: Bearer required | reject | reject | ✅ |
| T-REJECT-ACCEPT-JSON-ONLY | transport | Accept lists BOTH types (resolved #128) | reject | reject | ✅ |
| T-REJECT-GET-CURRENT | transport | GET removed at 2026-07-28, 405 (resolved #129) | reject | reject | ✅ |
| T-ACCEPT-GET-LEGACY | transport | legacy 2025-11-25 GET SSE-open kept | accept | accept | ✅ |
| S-REJECT-SESSION-ID | stateless | SEP-2575 (session removed) | reject | reject | ✅ |
| S-REJECT-INITIALIZE | stateless | SEP-2575 (no handshake) | reject | reject | ✅ |
| S-REJECT-INITIALIZED | stateless | SEP-2575 (no initialized) | reject | reject | ✅ |
| S-ACCEPT-STATELESS | stateless | SEP-2575 (ordinary call) | accept | accept | ✅ |
| S-REJECT-GHOST-STATE | stateless | SEP-2567 (explicit state) | reject | reject | ✅ |
| S-ACCEPT-DECLARED-STATE | stateless | SEP-2567 (declared param) | accept | accept | ✅ |
| H-ACCEPT-MATCH | routing | SEP-2243 (headers agree) | accept | accept | ✅ |
| H-REJECT-NO-METHOD-HEADER | routing | SEP-2243 (Mcp-Method required) | reject | reject | ✅ |
| H-REJECT-METHOD-MISMATCH | routing | SEP-2243 (header/body agree) | reject | reject | ✅ |
| H-REJECT-NAME-MISMATCH | routing | SEP-2243 (header/body agree) | reject | reject | ✅ |
| H-ACCEPT-LIST-NO-NAME | routing | SEP-2243 Mcp-Name scoped to name-bearing (resolved #127) | accept | accept | ✅ |

**Contract failures: none.** If any case here ever flips, it is an airlock regression and
belongs in this section verbatim — the harness prints failures with the raised message.

## Resolved divergences (2026-08-10)

The three divergence probes published on 2026-08-05 were the honest edges where airlock's
strictness *might* differ from the clause, held open because we would not assert a reading we
could not verify from the ratified document. The ratified 2026-07-28 spec resolves all three;
each is now a scored contract case above, and the guard reflects the reading (verbatim clause
quotes are cited in the guard source).

| Was | Ratified reading (2026-07-28) | Resolution | Case |
|---|---|---|---|
| **D-PING-NAME** (#127) | Standard request headers table: `Mcp-Name` is "Required For: `tools/call`, `resources/read`, `prompts/get` requests" — **not** every request. `ping` was removed entirely (SEP-2575). | airlock's `Mcp-Name` requirement is now scoped to those name-bearing methods; requiring it on `tools/list` etc. was stricter than spec. | `H-ACCEPT-LIST-NO-NAME` (accept) |
| **D-ACCEPT-JSON-ONLY** (#128) | Sending Messages: "The client **MUST** include an `Accept` header listing both `application/json` and `text/event-stream`." | A POST with an `application/json`-only `Accept` is now **rejected** (airlock was too lenient). | `T-REJECT-ACCEPT-JSON-ONLY` (reject) |
| **D-GET-NOVERSION** (#129) | "Removal of the GET stream endpoint"; Backward Compatibility: "HTTP GET or DELETE to the MCP endpoint: respond with `405 Method Not Allowed`." | At 2026-07-28 the endpoint is POST-only, so a `GET`/`DELETE` to the protected MCP endpoint is **rejected** (405); the version-less `GET` was already rejected. Legacy 2025-11-25 `GET` SSE-open stays accepted. | `T-REJECT-GET-CURRENT` (reject), `T-ACCEPT-GET-LEGACY` (accept) |

Issues [#127](https://github.com/sattyamjjain/agent-airlock/issues/127),
[#128](https://github.com/sattyamjjain/agent-airlock/issues/128), and
[#129](https://github.com/sattyamjjain/agent-airlock/issues/129) are closed. See
[docs/interop/CONFORMANCE-SCOPE.md](../../docs/interop/CONFORMANCE-SCOPE.md).

## Official-suite scenario inventory at 2026-07-28, mapped to airlock's surface

From `npx @modelcontextprotocol/conformance@0.1.16 list`. This is where airlock's
validation surface lands against what the suite actually exercises — most of it is
application-server or client-OAuth behavior airlock does not implement, by design.

| Official scenario(s) | Spec tag | airlock surface |
|---|---|---|
| `server-initialize` | 2025-11-25 | Inverted under 2026-07-28: airlock's SEP-2575 guard **rejects** `initialize` (stateless). |
| `dns-rebinding-protection` | 2025-11-25 | `mcp_origin_host_guard`, `bind_address_guard` (Origin / bind-address validation). |
| `json-schema-2020-12` | 2025-11-25 | `schema_ref_guard` (`mcp_schema_2020_12_contract_defaults`). |
| `auth/resource-mismatch`, `auth/offline-access-*` | draft (2026-07-28) | Client-side OAuth flows. airlock has OAuth **validators** (`oauth`, `oauth_audit`, `step_up_scope_guard`) but is not an OAuth **client** — N/A here. |
| `tools-*`, `resources-*`, `prompts-*`, `completion-complete`, `logging-set-level`, `ping` | 2025-11-25 | Application-server methods. airlock is a validator, not a server — N/A. |

## Honest scope

> agent-airlock does not claim MCP server or client conformance, and this file does not
> assert one. It is the request-validation layer beneath a server. The **22/22** above is
> airlock's transport validators agreeing with the 2026-07-28 normative rules they cite —
> a real, reproducible regression baseline, **not** a leaderboard pass-rate, and **not**
> a substitute for running the official suite against a conformant server once one exists
> for this revision. The three 2026-08-05 divergence probes have been resolved against the
> ratified clause text (see "Resolved divergences" above) and folded into the scored cases;
> the guards now match the spec on `Mcp-Name` scoping, the dual-`Accept` requirement, and the
> removed `GET` endpoint. The README caveat ("no MCP conformance suite has been run against
> this package") is updated to point here.
