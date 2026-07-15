# Gateway harness — regenerate the measurement fixture

This directory reproduces `../gateway_measurement.json` by measuring a **live**
Docker MCP Gateway. The shipped bench (`python -m benchmarks.vs_gateway`) replays
that recorded fixture, so it needs **no Docker daemon**. You only need this
harness to re-measure the gateway yourself.

## What's here

- `echo_server.py` — a dependency-free MCP stdio server that echoes the args it
  receives. It does **no validation** — it is a receipt oracle, so any block we
  observe is the *gateway's*, never the backend's.
- `Dockerfile` — packages the echo oracle.
- `airlock-bench-catalog.yaml` — a one-server Docker MCP catalog pointing at the
  locally built image.
- `regen.py` — spawns `docker mcp gateway run --transport stdio` in front of the
  oracle, pushes the corpus (imported from `benchmarks/vs_gateway/corpus.py` —
  single source of truth) through it as real `tools/call` requests, classifies
  each as PASS (forwarded) / BLOCK (rejected), and rewrites the fixture with
  provenance (gateway version, date, method).

## Prerequisites

- Docker Desktop running (`docker info` succeeds)
- The Docker MCP plugin (`docker mcp version`)

## Reproduce

From the repo root:

```bash
docker build -t airlock-bench/echo-mcp:latest benchmarks/vs_gateway/gateway_harness
python -m benchmarks.vs_gateway.gateway_harness.regen
```

That overwrites `../gateway_measurement.json`. Then run the head-to-head:

```bash
python -m benchmarks.vs_gateway
```

## Why an echo backend?

The claim under test is *"the gateway forwards the tool-call payload without
validating its argument contract"* — not *"the backend is exploitable"*. An echo
oracle isolates the gateway's behaviour: if the oracle receives the malformed
args, the gateway forwarded them. The airlock side is measured separately and
live, against the shipped `@Airlock` decorator, `SafePath`/`SafeURL` validators,
the in-process guard chain, and a deny-by-default `SecurityPolicy`.
