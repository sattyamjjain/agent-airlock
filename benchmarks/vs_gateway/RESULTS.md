# agent-airlock vs native MCP gateway — contract-layer head-to-head

**Reproduce (no Docker needed):**

```bash
python -m benchmarks.vs_gateway          # human-readable table
python -m benchmarks.vs_gateway --json   # machine-readable summary
```

The airlock column is measured **live, in-process, on every run**. The gateway
column replays a **recorded live measurement** of a Docker MCP Gateway
(`benchmarks/vs_gateway/gateway_measurement.json`); regenerate it with
`benchmarks/vs_gateway/gateway_harness/` (needs a Docker daemon).

## The number (recorded 2026-07-16)

Identical corpus: **12 malformed tool-call payloads + 3 benign controls**, sent
through both layers.

| Layer | Malformed blocked | Benign false-positive |
|---|---|---|
| **agent-airlock** (in-process contract layer) | **12 / 12** | 0 / 3 |
| **Docker MCP Gateway v2.0.1** (native, transport/identity) | **0 / 12** | 0 / 3 |

**Contract-layer gap: airlock blocks 12/12 malformed payloads that the native
gateway forwards to the backend.** Airlock p50 ≈ 0.08 ms/decision.

Both layers are correct on the 3 benign controls (0 false positives) — the
gateway is not "blocking nothing because it's broken"; it forwards *everything*,
malformed or not, because payload-contract validation is not its job.

## Per-payload

| payload class | airlock | gateway | what it is |
|---|---|---|---|
| type_confusion | **BLOCK** | allow | `amount="100"` — string for an integer field |
| value_constraint | **BLOCK** | allow | `amount=-1` — type-valid int violating `amount>0` |
| ghost_argument | **BLOCK** | allow | `force=True` — hallucinated / ghost argument |
| path_traversal | **BLOCK** | allow | `../../../../etc/passwd` |
| url_ssrf | **BLOCK** | allow | SSRF to `169.254.169.254` cloud metadata |
| url_file_scheme | **BLOCK** | allow | `file:///etc/shadow` |
| arg_injection_eval | **BLOCK** | allow | eval/exec RCE payload |
| arg_injection_subproc | **BLOCK** | allow | subprocess command injection |
| arg_injection_env | **BLOCK** | allow | `LD_PRELOAD` code-loading env var |
| arg_injection_secret | **BLOCK** | allow | `${JWT_SECRET}` interpolation in a URL |
| arg_injection_codegen | **BLOCK** | allow | codegen triple-quote break-out |
| over_privileged | **BLOCK** | allow | over-privileged tool selected over a low-priv one |
| benign_transfer | allow | allow | well-typed transfer *(benign)* |
| benign_read | allow | allow | clean relative path *(benign)* |
| benign_fetch | allow | allow | plain public https URL *(benign)* |

## Method / provenance

- **Gateway:** Docker MCP Gateway image **v2.0.1**, `docker mcp` CLI **v0.42.1**,
  Docker engine **29.4.3**, MCP protocol `2025-06-18`, stdio transport.
- Each payload was sent as a **real MCP `tools/call`** through a running gateway
  to an echo-oracle backend that performs **no validation**. `PASS` (gateway
  allowed) = the backend received and echoed the args; `BLOCK` = the gateway
  returned a JSON-RPC error before the backend saw the call.
- The gateway ran with its **defaults**: `block-secrets` on (it scanned every
  call's args + response for known secret values and found none to block — the
  `${JWT_SECRET}` literal is not a stored secret), `no-new-privileges`, and
  cpu/memory caps. None of those inspect the argument contract.
- The airlock side runs the shipped code paths: `@Airlock` strict Pydantic
  validation + ghost-arg BLOCK, `SafePathValidator` / `SafeURLValidator`, the
  in-process argument-guard chain, and a deny-by-default `SecurityPolicy`.

## What this is and isn't

This is a **structural** result, not a "gateway is bad" result. A native MCP
gateway secures the *connection*: who may connect, over what transport, with
which token, in what sandbox. It does that well. It is not designed to check
that `transfer(amount=-1)` is contract-valid or that the agent picked the
least-privileged tool. **Use both** — gateway/OAuth for the connection, airlock
for the in-process call contract.
