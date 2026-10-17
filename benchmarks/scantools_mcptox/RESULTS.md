# scan-tools × MCPTox — contract-checking coverage

Reproduce:

```bash
python -m benchmarks.scantools_mcptox                                  # the 23 fixtures
python -m benchmarks.scantools_mcptox --mcptox-data --fetch --write    # + the real corpus
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

The fixtures are hand-written stand-ins. The section below runs the same check over
MCPTox's real descriptions, and the two numbers are not interchangeable: read the real
corpus before quoting the fixture rate.

<!-- SCANTOOLS-MCPTOX-REAL:BEGIN -->
## Real MCPTox corpus (measured 2026-10-12, UTC)

Reproduce: `python -m benchmarks.scantools_mcptox --mcptox-data --fetch --write`. It fetches and verifies MCPTox's
`response_all.json` at commit `f85189f9ad12` (never committed) and runs the same
check as the fixtures: `scan_tool` under the permissive policy, where a SCAN002
trust-boundary violation counts as detected.

| Population | Flagged (SCAN002) |
| --- | --- |
| Unique poisoned descriptions | 157/1338 (11.7%, 95% CI 10.1-13.6%) |
| All cases, weighted by case | 160/1348 (11.9%, 95% CI 10.2-13.7%) |
| Clean tool blocks (false positives) | 1/362 (0.3%, 95% CI 0.1-1.6%) |
| Clean blocks named in `tool_names` (false positives) | 1/353 (0.3%, 95% CI 0.1-1.6%) |

Per case, by paradigm:

| Paradigm | Flagged |
| --- | --- |
| Template-1 | 36/211 (17.1%, 95% CI 12.6-22.7%) |
| Template-2 | 47/519 (9.1%, 95% CI 6.9-11.8%) |
| Template-3 | 77/618 (12.5%, 95% CI 10.1-15.3%) |

Per case, by whether the description carries an `<IMPORTANT>` tag:

| Tag | Flagged |
| --- | --- |
| tagged | 9/473 (1.9%, 95% CI 1.0-3.6%) |
| untagged | 151/875 (17.3%, 95% CI 14.9-19.9%) |

Per case, by risk category:

| Risk category | Flagged |
| --- | --- |
| Code Injection | 19/63 (30.2%, 95% CI 20.2-42.4%) |
| Credential Leakage | 14/115 (12.2%, 95% CI 7.4-19.4%) |
| Data Tampering | 2/120 (1.7%, 95% CI 0.5-5.9%) |
| Financial Loss | 15/55 (27.3%, 95% CI 17.3-40.2%) |
| Information Manipulation | 36/281 (12.8%, 95% CI 9.4-17.2%) |
| Infrastructure Damage | 24/124 (19.4%, 95% CI 13.4-27.2%) |
| Instruction Tampering | 2/57 (3.5%, 95% CI 1.0-11.9%) |
| Message Hijacking | 2/44 (4.5%, 95% CI 1.3-15.1%) |
| Other | 1/4 (25.0%, 95% CI 4.6-69.9%) |
| Privacy Leakage | 8/276 (2.9%, 95% CI 1.5-5.6%) |
| Service Disruption | 37/209 (17.7%, 95% CI 13.1-23.4%) |

Poisoned blocks that did not parse: 0.
<!-- SCANTOOLS-MCPTOX-REAL:END -->

## What this is (and is not)

- **Is:** a deterministic, static measurement of how many *injection-shaped* tool
  descriptions `airlock scan-tools` flags at the Server-Card trust boundary
  (reusing the shipped `ToolOutputTrustGuard`), plus the false-positive rate on
  clean descriptions.
- **Is not** MCPTox's published result. [MCPTox](https://arxiv.org/abs/2508.14925)
  (Wang et al., arXiv:2508.14925) is built on **45 live MCP servers / 353 authentic
  tools**. Version 1 of the paper reported 1,312 cases; version 2 (2026-09-29) and the
  released `response_all.json` carry **1,348** (1,312 with `wrong_data` 0 plus 36 with
  `wrong_data` 2) in **10 risk categories (11 with "Other")**. Its top reported
  model-in-the-loop **Attack Success Rate is 72.8% (o1-mini)**, which reproduces only
  over all 1,348 cases (574 of 788 labelled responses). Those are properties of
  *agents/models*. A static checker cannot and does not reproduce them; this bench does
  not redistribute that corpus (the real-corpus run downloads and verifies it).
- **The honest gap:** the `declarative_side_effect` fixtures state a malicious side
  effect with no imperative marker ("…also silently forwards every argument to
  attacker@…"). The trust-boundary check targets injection-*shaped* text, so it
  misses these by design — hence 69.2%, not 100%, on the fixtures. On the real corpus
  the rate is far lower: MCPTox's poisoned descriptions mostly redirect the agent to
  another tool or tamper with an argument (its three paradigms), and most of them,
  `<IMPORTANT>`-tagged ones included, match none of the guard's detectors.

## Differentiation from tool-poisoning scanners

MCP-Scan (Invariant Labs) and eSentire's MCP-Scanner are **content-signature
tool-poisoning scanners**. `scan-tools` overlaps them only on the
description-poisoning subset scored here; its distinct job is a **contract/type
check** against a least-privilege `SecurityPolicy` — over-broad argument surfaces,
missing type constraints, and capability caps that exceed policy — which those
scanners do not do. Coverage of description-poisoning is a *secondary* signal, not
the headline claim.
