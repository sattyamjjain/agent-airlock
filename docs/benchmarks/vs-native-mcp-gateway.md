# Reproduced head-to-head: agent-airlock vs a native MCP gateway

**TL;DR (recorded 2026-07-16):** on an identical corpus of **12 malformed
tool-call payloads**, a live **Docker MCP Gateway v2.0.1** forwarded **12/12** to
the backend; **agent-airlock blocked 12/12** at the contract layer. Both had
**0/3** false positives on the benign controls.

```bash
python -m benchmarks.vs_gateway        # reproduce (no Docker required)
```

## Why this benchmark exists

MCP gateways and platform firewalls — Docker MCP Gateway, Cloudflare, Azure API
Management, AWS, plus the MCP spec's OAuth resource-server mandate — secure the
**transport and identity** layer: who may connect, over what channel, with which
token, in what sandbox. That is necessary work and they do it well.

agent-airlock sits **one layer in**, at the execution boundary *after* auth: it
validates the **actual tool-call payload** the model produced. The two do
different jobs. This benchmark makes the difference concrete and measured instead
of asserted.

## What was measured

The **same 12 malformed payloads + 3 benign controls** were pushed through both
layers (`benchmarks/vs_gateway/corpus.py` is the single source of truth):

- **type confusion** — `transfer(amount="100")`, a string where an integer is
  declared (strict, no coercion).
- **value constraint** — `transfer(amount=-1)`, a type-valid integer that
  violates the tool's declared `amount > 0` contract.
- **ghost argument** — `transfer(..., force=True)`, an invented parameter.
- **path traversal / SSRF / file://** — `../../../../etc/passwd`,
  `http://169.254.169.254/…`, `file:///etc/shadow`.
- **argument injection** — eval/exec RCE, subprocess command + env (`LD_PRELOAD`)
  injection, `${JWT_SECRET}` interpolation, codegen triple-quote break-out.
- **over-privileged selection** — an `admin_execute` call when a low-privilege
  tool suffices.

### Gateway side (measured live, then recorded)

`benchmarks/vs_gateway/gateway_harness/` runs `docker mcp gateway run
--transport stdio` in front of an **echo-oracle** MCP server that does no
validation of its own. Each payload is sent as a real MCP `tools/call`. If the
oracle echoes the args back, the gateway **forwarded** the payload (`PASS`); a
JSON-RPC error from the gateway would be a `BLOCK`.

The gateway ran with its defaults, and its own logs confirm what it *does* do:

```
- Scanning tool call arguments for secrets...   > No secret found in arguments.
- Scanning tool call response for secrets...     > No secret found in response.
- Running airlock-bench/echo-mcp:latest with [run --rm -i --init
  --security-opt no-new-privileges --cpus 1 --memory 2Gb --pull never ...]
```

Secret-scanning, `no-new-privileges`, and resource caps all fired — none of them
inspects whether the argument contract is valid. Result: **0/12 malformed
blocked.** The recording (with gateway version, date, and method) lives in
`benchmarks/vs_gateway/gateway_measurement.json`; regenerate it with the harness
(needs Docker).

### Airlock side (measured live, every run)

The airlock column runs the shipped code — no lookup table:

| payload class | airlock mechanism |
|---|---|
| type_confusion, value_constraint | `@Airlock` strict Pydantic (`amount: int`, `> 0`) |
| ghost_argument | ghost-argument BLOCK mode |
| path_traversal | `SafePathValidator` |
| url_ssrf, url_file_scheme | `SafeURLValidator` |
| arg_injection_* | in-process guard chain (eval / subprocess / env / codegen) |
| over_privileged | deny-by-default `SecurityPolicy` |

Result: **12/12 malformed blocked, 0/3 benign false-positive**, p50 ≈ 0.08 ms per
decision.

## Result

| Layer | Malformed blocked | Benign FP |
|---|---|---|
| **agent-airlock** | **12 / 12** | 0 / 3 |
| **Docker MCP Gateway v2.0.1** | **0 / 12** | 0 / 3 |

The gateway is not failing — it is doing a *different job*. It authenticates and
sandboxes; it forwards the payload. Airlock validates the payload's contract.
**Use both.**

## Provenance

Docker MCP Gateway image **v2.0.1** · `docker mcp` CLI **v0.42.1** · Docker engine
**29.4.3** · MCP protocol `2025-06-18` · measured **2026-07-16**. Full method and
per-payload table: [`benchmarks/vs_gateway/RESULTS.md`](../../benchmarks/vs_gateway/RESULTS.md).
Regeneration harness: [`benchmarks/vs_gateway/gateway_harness/`](../../benchmarks/vs_gateway/gateway_harness/).
