# agent-airlock — OpenID AIIM MCP interop

_Written for the [OpenID Foundation AIIM Community Group MCP interop event](https://openid.net/call-for-participation-demonstrate-mcp-based-ai-agent-security-with-open-identity-standards-2/). Commit-by: **2026-08-10** (end of day, Pacific). At least one interop test with a partner by **2026-10-16**. Participation is open to all, and free._

## What agent-airlock is

agent-airlock is an **in-process, deny-by-default contract layer that sits beneath an MCP gateway**: after the gateway authenticates the caller and routes the request, airlock validates the tool-call payload the model actually produced — argument types, ghost/hallucinated arguments, least-privilege tool and capability scope — and denies anything outside the contract.

## MCP revisions accepted

airlock accepts these `MCP-Protocol-Version` header values on the wire (read from `agent_airlock.mcp_spec.SUPPORTED_PROTOCOL_VERSIONS`, not typed by hand; a request naming any other version is denied):

| `MCP-Protocol-Version` | Status |
| --- | --- |
| `2026-07-28` | current |
| `2025-11-25` | legacy |

`2026-07-28` is the current ratified revision; `2025-11-25` is accepted for legacy interop. This table is tied to the code by `tests/test_interop_doc.py`, so it cannot drift.

## Scope on the identity axis — read this before the test

Be exact about the boundary; discovering it mid-test is far worse than reading it here.

- airlock **validates and constrains tool calls**. It enforces argument-type contracts (strict Pydantic, no coercion), strips or rejects ghost arguments, and applies deny-by-default tool and capability scope at the execution boundary.
- airlock is **not an OAuth authorization server**. It runs no `/authorize` or `/token` endpoint and issues no tokens.
- airlock **does not issue or verify identity tokens today**. At the transport check it reads the `Authorization: Bearer` header's presence and shape; it does not validate a token's signature, audience, or claims. Token issuance and verification are the gateway's and identity provider's job.

In interop terms: airlock is the party that decides *"this tool call is or is not within contract"*, not the party that decides *"this caller is or is not who they claim to be"*.

## The interop surface a partner can drive

**Entry point** — the Streamable HTTP request validator:

```python
from agent_airlock.mcp_spec import validate_streamable_http_request
```

**Expected request shape** — a conformant MCP Streamable HTTP request:

```
POST /mcp HTTP/1.1
MCP-Protocol-Version: 2026-07-28
Content-Type: application/json
Accept: application/json
Authorization: Bearer <token>

{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {...}}
```

A valid request returns a `StreamableHTTPValidation` result and proceeds.

**What a deny looks like on the wire** — a violation raises `MCPTransportError` with a message safe to place in a JSON-RPC `error.message`. Verbatim examples:

- Unsupported protocol version → `unsupported MCP-Protocol-Version='1999-01-01'; supported=['2026-07-28', '2025-11-25']` (mirrors the spec's `UnsupportedProtocolVersionError`, JSON-RPC code `-32022`).
- Missing version header → `missing required MCP-Protocol-Version header`.
- Access token in the query string → denied (tokens MUST NOT appear in the URI).

For the tool-call **payload** contract (argument types, ghost arguments, tool/capability scope), the seam is the `@Airlock` decorator around the tool function: a denied call returns a structured blocked response carrying the reason and a `fix_hints` retry, instead of executing the tool.

## Reproduce the gateway head-to-head

The most legible artifact to hand a partner: the same 12 malformed tool-call payloads pushed through a live **Docker MCP Gateway v2.0.1** and through airlock. The gateway forwarded **0 / 12** to the backend; airlock blocked **12 / 12**, with 0 / 3 false positives on benign controls.

```bash
python -m benchmarks.vs_gateway          # human-readable table
python -m benchmarks.vs_gateway --json   # machine-readable summary
```

Method, per-payload table, and the honest read of where a native gateway is already enough: [`benchmarks/vs_gateway/RESULTS.md`](https://github.com/sattyamjjain/agent-airlock/blob/main/benchmarks/vs_gateway/RESULTS.md).

## Conformance scope

See [`CONFORMANCE-SCOPE.md`](CONFORMANCE-SCOPE.md): no MCP conformance suite has been run against agent-airlock, so the claim strength is "implements" and "targets", never "conformant".
