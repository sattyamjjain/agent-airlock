# scan-tools × MCPTox bench

A deterministic, offline bench that runs `airlock scan-tools` (the static
contract / type-checker) over tool-poisoning fixtures reconstructed from the
technique studied in **MCPTox** (Wang et al., "MCPTox: A Benchmark for Tool
Poisoning Attack on Real-World MCP Servers", [arXiv:2508.14925](https://arxiv.org/abs/2508.14925)).

```bash
python -m benchmarks.scantools_mcptox
```

- **`corpus.py`** — labeled fixtures (`poisoned` / `benign`), tagged by injection
  *shape*. These are representative reconstructions of the metadata-injection
  technique, **not** the paper's 1,312-case live corpus.
- **`runner.py`** — scores detection rate (coverage) and precision under the
  permissive policy so only the trust-boundary check bites.
- **`report.py` / `__main__.py`** — rendering + CLI.
- **`RESULTS.md`** — the current numbers, reported as-is.

See `RESULTS.md` for the honest framing: this measures *static contract-checking
coverage*, not MCPTox's model-in-the-loop Attack Success Rate, and is explicitly
differentiated from content-signature poisoning scanners (MCP-Scan, eSentire
MCP-Scanner).
