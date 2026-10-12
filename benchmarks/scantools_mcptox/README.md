# scan-tools × MCPTox bench

A deterministic, offline bench that runs `airlock scan-tools` (the static
contract / type-checker) over tool-poisoning fixtures reconstructed from the
technique studied in **MCPTox** (Wang et al., "MCPTox: A Benchmark for Tool
Poisoning Attack on Real-World MCP Servers", [arXiv:2508.14925](https://arxiv.org/abs/2508.14925)),
and, on request, over MCPTox's real tool descriptions.

```bash
python -m benchmarks.scantools_mcptox                                 # the 23 fixtures
python -m benchmarks.scantools_mcptox --mcptox-data --fetch           # + the real corpus
python -m benchmarks.scantools_mcptox --mcptox-data --fetch --write   # rewrite RESULTS.md
```

- **`corpus.py`** — labeled fixtures (`poisoned` / `benign`), tagged by injection
  *shape*. These are representative reconstructions of the metadata-injection
  technique, **not** MCPTox's corpus (45 live servers, 353 tools; 1,348 cases in the
  released `response_all.json`, 1,312 in the paper's version 1).
- **`real_corpus.py`** — the same check over MCPTox's 1,338 unique real poisoned
  descriptions (and a per-case rate over all 1,348) and its 362 clean tool blocks,
  from a pinned, sha256-verified download that is never committed.
- **`runner.py`** — scores detection rate (coverage) and precision under the
  permissive policy so only the trust-boundary check bites.
- **`report.py` / `__main__.py`** — rendering + CLI. The default run (and the tests CI
  runs) use the fixtures only.
- **`RESULTS.md`** — the current numbers, reported as-is.

See `RESULTS.md` for the honest framing: this measures *static contract-checking
coverage*, not MCPTox's model-in-the-loop Attack Success Rate (top reported 72.8%,
o1-mini), and the fixture rate is not the real-corpus rate. It is explicitly
differentiated from content-signature poisoning scanners (MCP-Scan, eSentire
MCP-Scanner).
