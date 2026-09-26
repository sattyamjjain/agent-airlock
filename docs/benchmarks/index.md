# Benchmarks

Seven published measurements. Each one carries the date it was last re-run, and each
date is machine-checked: `scripts/check_benchmark_freshness.py` fails the release if any
row is missing its marker, and `--release` fails if any row is older than 30 days.

Two conventions are worth knowing before reading any number here.

**A null result is published as a null result.** The multi-harness prompt-injection row
is a zero, and the page says at length why that zero is *not* evidence of injection
resistance. A benchmark that only ever reports wins is not a benchmark.

**Scope is stated, not implied.** Where a comparison is against a system this harness
does not execute, the incumbent's coverage is marked *scope-claimed, not re-run* rather
than given a fabricated number. Where a slot has no samples, it is shown as `n=0` rather
than omitted — four of the ten OWASP Agentic slots are in that state.

## The seven published rows

| Benchmark | Headline result | Last re-run | Full results |
|---|---|---|---|
| **Cross-tool block rate** · 210 tool calls | 100% blocked · 0% false-positive · p50 ~2µs · _6 of 10 OWASP ASI slots measured; ASI07–ASI10 are n=0_ | 2026-09-16 | [Cross-tool block rate results](blockrate.md) |
| **`sandbox=True` dispatch** · contract parity | 4/4 annotated-contract probes refused on the sandbox path (0/4 before v0.10.6) · 204/204 verdicts agree with the local path | 2026-09-16 | [Sandbox dispatch parity arm](blockrate.md#sandboxtrue-dispatch-arm) |
| **Least-privilege** · ToolPrivBench, 100 scenarios | 100% over-privileged blocked · 100% low-privileged allowed · OPUR 100% → 0% | 2026-09-08 | [ToolPrivBench results on GitHub](https://github.com/sattyamjjain/agent-airlock/blob/main/benchmarks/toolprivbench/RESULTS.md) |
| **Adaptive attacker** · AgentDojo, all 4 suites | 86.0% of injection→target tool-calls blocked (524/609, deterministic bound). Model-in-the-loop ASR 45% → 10% (model pass of 2026-08-08), but that is one model family on a 60-pair subset | 2026-09-08 | [AgentDojo results on GitHub](https://github.com/sattyamjjain/agent-airlock/blob/main/benchmarks/agentdojo/RESULTS.md) |
| **vs. native MCP gateway** · 12 malformed payloads | airlock 12/12 blocked · Docker MCP Gateway 0/12 · 0% false-positive on both | 2026-09-12 | [Native MCP gateway head-to-head](vs-native-mcp-gateway.md) |
| **Prompt injection across agent harnesses** | A null result, published as one. `claude-code` and `codex` each acted on the planted script 0/36, and ignored the benign twin just as completely, so this is indifference to the channel, not detection. Weaker than the 2026-08-26 run: the one benign action that made `codex`'s zero a choice did not reproduce, and `codex` finished only 52/72 cells | 2026-09-20 | [Multi-harness prompt injection](injection-multi-harness.md) |
| **MCP spec conformance** · `@modelcontextprotocol/conformance` | Run against the wire-path validators, outcome published in full. Not a full MCP server/client conformance pass — airlock is a request validator, not a server, so it does not claim one | 2026-09-08 | [MCP conformance results on GitHub](https://github.com/sattyamjjain/agent-airlock/blob/main/benchmarks/mcp_conformance/RESULTS.md) |

The **Last re-run** column is the same date the freshness gate reads out of `README.md`,
and `check_benchmark_freshness.py` asserts the two agree. If a row here disagrees with
the README, the build fails rather than publishing two different dates for one run.

## Pages on this site

- [Cross-tool block rate](blockrate.md) — the flagship corpus: 210 tool calls, 106
  malicious and 104 benign, with the per-OWASP-ASI breakdown and the `sandbox=True`
  dispatch arm.
- [Guard-suite corpus](full-corpus.md) — the full per-class, false-positive-aware table
  over the versioned exploit corpus. A self-corpus, and labelled as one.
- [Multi-harness prompt injection](injection-multi-harness.md) — the matched-pair design,
  and why the benign control is the only reason the injected column means anything.
- [Native MCP gateway head-to-head](vs-native-mcp-gateway.md) — airlock against Docker's
  MCP Gateway on the same malformed payloads.
- [MCP gateway payload gap](mcp-gateway-payload-gap.md) — what the gateway comparison
  does and does not establish.

Four of the seven rows have their full results in the benchmark packages rather than on
this site; those link to GitHub in the table above.

## Re-running them

Every row is reproducible from the repository. The deterministic ones need nothing but a
checkout:

```bash
python -m benchmarks.blockrate          # block rate, latency, sandbox dispatch arm
python -m benchmarks.toolprivbench      # least-privilege
make benchmark                          # regenerate BENCHMARK.md from the corpus
```

Three are not free. `benchmarks.agentdojo.run` and `benchmarks.harness_injection` spend
real API budget, and `benchmarks.vs_gateway` needs a Docker daemon. The multi-harness run
is roughly 100 minutes of paid API time for a full `--trials 18` matrix, which is why it
takes a `--checkpoint` flag and refuses to do anything without an explicit `--run`:

```bash
python -m benchmarks.harness_injection --trials 18 --write --checkpoint ckpt.json --run
```

`python -m benchmarks.harness_injection` on its own is a dry run. It prints the cells it
would execute and the statistical power that many trials would buy, so the cost is known
before it is spent.
