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

## The number (re-measured live 2026-08-17)

Identical corpus: **12 malformed tool-call payloads + 3 benign controls**, sent
through both layers.

| Layer | Malformed blocked | Benign false-positive |
|---|---|---|
| **agent-airlock** (in-process contract layer) | **12 / 12** | 0 / 3 |
| **Docker MCP Gateway v2.0.1** (native, transport/identity) | **0 / 12** | 0 / 3 |

**Contract-layer gap: airlock blocks 12/12 malformed payloads that the native
gateway forwards to the backend.** Airlock p50 ≈ 0.08 ms/decision.

### Which gateway build this is, and what has moved since

Re-measured **2026-08-17** against a live gateway: `docker mcp` CLI plugin **v0.42.1**,
gateway image version **2.0.1**, Docker engine **29.4.3**. Same result as the 2026-07-16
run — **0 / 12** — so the finding is reproduced, not inherited.

Stated precisely, because a competitive claim against a moving target decays: **v2.0.1 is
what the currently-installed `docker mcp` plugin runs**, not necessarily the newest build
in existence. Docker Hub's `docker/mcp-gateway` moving tags `v2` and `latest` were rebuilt
**2026-07-23**, and the highest pinned tag there is `v0.43.3` (2026-07-16) against the
local plugin's `v0.42.1`. A newer gateway therefore exists that this run did not measure.

That gap is deliberate and disclosed rather than papered over: the number above is exactly
what a user on the current shipped Docker toolchain gets today. Re-measuring against a
bumped plugin is a one-command job — `python -m benchmarks.vs_gateway.gateway_harness.regen`
— and this section should be rewritten, not appended to, when someone does it.

Both layers are correct on the 3 benign controls (0 false positives) — the
gateway is not "blocking nothing because it's broken"; it forwards *everything*,
malformed or not, because payload-contract validation is not its job.

## 2026-09-12 — re-measured successfully. The 2026-09-08 diagnosis was wrong.

**Result: unchanged.** Gateway 0/12 malformed payloads blocked, airlock 12/12, 0/3
benign false positives on both — identical to 2026-08-17, now on a newer CLI.

| | 2026-08-17 | 2026-09-12 |
|---|---|---|
| `docker mcp` CLI | v0.42.1 | **v0.43.3** |
| Docker engine | 29.4.3 | **29.7.2** |
| Gateway image | 2.0.1 | 2.0.1 |
| gateway blocked | 0/12 | **0/12** |
| airlock blocked | 12/12 | **12/12** |

The only diff in `gateway_measurement.json` is the date and the two version strings.
All 15 corpus records still read `PASS`.

### What actually broke on 2026-09-08, since the entry below gets it wrong

Not a schema migration. The `version: 3` catalog is fine and loads on v0.43.3.

`docker mcp gateway run --catalog` documents its argument as *"Catalog paths must
resolve under `~/.docker/mcp/catalogs/`"*. The harness passed an **absolute path into
the repo**. Older plugin versions accepted that; v0.43.x resolves it to nothing, and
the failure is silent in the worst way — the gateway starts, reports
`Those servers are enabled: echo`, and then lists `0 tools`. It looks like a catalog
the gateway read and found empty, which is what led to "the v3 schema is legacy".

Staging that same unmodified file under `~/.docker/mcp/catalogs/` and passing its bare
name lists all ten tools:

```
- Reading catalog from [airlock-bench-catalog.yaml]
- Those servers are enabled: echo
  > echo: (10 tools)
> 10 tools listed in 339.441333ms
```

`regen.py` now stages the catalog itself on every run, so the harness is reproducible
on a fresh machine and cannot silently measure a stale copy someone left behind.

The lesson worth keeping: **a plugin flag quietly narrowed what it accepts, and the
failure mode was an empty result rather than an error.** An empty result reads as a
finding. The 2026-09-08 entry was right to refuse to re-date the row on it, and wrong
about why it happened — both are left standing below rather than edited away.

## 2026-09-08 — attempted re-run, FAILED to measure. Nothing here was updated.

Recorded because a benchmark that silently stops being re-runnable is how a stale
competitive claim survives.

`docker mcp` has moved from **v0.42.1** (the version behind the 2026-08-17 numbers
below) to **v0.43.3**. Against v0.43.3 the harness's catalog
(`gateway_harness/airlock-bench-catalog.yaml`, `version: 3`) still loads and the
gateway still starts — but it discovers nothing:

```
- Reading catalog from [benchmarks/vs_gateway/gateway_harness/airlock-bench-catalog.yaml]
- Those servers are enabled: echo
- Listing MCP tools...
> 0 tools listed in 19.125µs
```

With zero tools there is no `tools/call` surface to push the corpus at, so
`regen.py` times out waiting on `initialize`. `docker mcp catalog create` in
v0.43.3 now describes a v3 file as a *legacy* catalog, so this is a schema
migration on Docker's side, not a broken environment: the daemon, the plugin and
the `airlock-bench/echo-mcp:latest` oracle image all built and ran fine.

**Consequences, stated rather than smoothed over:**

- `gateway_measurement.json` was **not** rewritten — verified byte-identical after
  the failed attempt. The published 12/12 figure is still the real 2026-08-17
  recording it always was.
- The README marker was **not** advanced to 2026-09-08. Nothing was measured, so
  dating it today would be the exact dishonesty the freshness gate exists to catch.
  It therefore still ages, and will trip `check_benchmark_freshness --release` on
  **2026-09-16**.
- Re-enabling this row means migrating the catalog to v0.43.x and re-validating the
  head-to-head. That is a new measurement against a **newer gateway build**, not a
  refresh, and it may well return a different number — which would be the finding.
  The 2026-08-17 entry below already warned that the `v2` tag had been rebuilt after
  the image it measured.

  **Resolved 2026-09-12 — and the diagnosis above is wrong.** No schema migration was
  needed. `--catalog` on v0.43.x only resolves paths under `~/.docker/mcp/catalogs/`,
  and an absolute repo path silently yields zero tools instead of an error. See the
  2026-09-12 entry above. The row was re-measured, not re-dated, and the number did
  not change.

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
