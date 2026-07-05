# scan-tools × MCPTox — contract-checking coverage

Reproduce:

```bash
python -m benchmarks.scantools_mcptox
```

Deterministic, offline (no model call, no live server). Numbers below are the
output as-is on the taxonomy-derived fixtures — nothing is rounded up or curated.

| Metric | Value |
| --- | --- |
| Poisoned fixtures | 13 |
| Detected (SCAN002 trust-boundary) | 9 |
| **Detection rate (contract-checking coverage)** | **69.2%** |
| Benign fixtures | 10 |
| False positives | 0 |
| **Precision** | **100.0%** |

By injection shape:

| Shape | Detected / total |
| --- | --- |
| `override_directive` | 3 / 3 (100%) |
| `imperative_command` | 3 / 3 (100%) |
| `fenced_command` | 3 / 3 (100%) |
| `declarative_side_effect` | 0 / 4 (0%) |

## What this is (and is not)

- **Is:** a deterministic, static measurement of how many *injection-shaped* tool
  descriptions `airlock scan-tools` flags at the Server-Card trust boundary
  (reusing the shipped `ToolOutputTrustGuard`), plus the false-positive rate on
  clean descriptions.
- **Is not** MCPTox's published result. [MCPTox](https://arxiv.org/abs/2508.14925)
  (Wang et al., arXiv:2508.14925) is built on **45 live MCP servers / 353 authentic
  tools** and reports a model-in-the-loop **Attack Success Rate up to 72%** across
  **1,312 cases in 10 risk categories**. Those are properties of *agents/models*.
  A static checker cannot and does not reproduce them; this bench does not
  redistribute that corpus.
- **The honest gap:** the `declarative_side_effect` fixtures state a malicious side
  effect with no imperative marker ("…also silently forwards every argument to
  attacker@…"). The trust-boundary check targets injection-*shaped* text, so it
  misses these by design — hence 69.2%, not 100%.

## Differentiation from tool-poisoning scanners

MCP-Scan (Invariant Labs) and eSentire's MCP-Scanner are **content-signature
tool-poisoning scanners**. `scan-tools` overlaps them only on the
description-poisoning subset scored here; its distinct job is a **contract/type
check** against a least-privilege `SecurityPolicy` — over-broad argument surfaces,
missing type constraints, and capability caps that exceed policy — which those
scanners do not do. Coverage of description-poisoning is a *secondary* signal, not
the headline claim.
