# Metis-inspired corpus block-rate regression (v0.8.2+)

`agent_airlock.regression_corpus.MetisInspiredCorpusBlockRateGuard` is
a release-gate primitive that runs a fixed corpus of exploit-shape
prompts through agent-airlock's guard chain and asserts that the
fraction blocked has not regressed below an operator-set baseline.

## What this is NOT

This is **not** the Metis attacker.

The Metis paper ([arXiv:2605.10067][metis], ICML 2026) is an **adaptive
POMDP attacker** that targets a closed-loop LLM and measures
response-level **Attack Success Rate (ASR)** — i.e. did the model
emit harmful content. The paper's headline result (89.2% avg ASR on
frontier models) is a property of the *model's* refusal behaviour,
not of any middleware.

agent-airlock is a **tool-call argument validator**. It sits in front
of the tool, validates the argument dict against a guard chain, and
never sees the model's response. The two threat surfaces don't
compose: you can't reproduce Metis ASR through agent-airlock because
agent-airlock isn't on Metis's attack path.

[metis]: https://arxiv.org/abs/2605.10067

## What this primitive does

The inverse of ASR: it measures **block rate** on a deterministic
exploit-shape corpus, and fires the release gate when block rate
drifts downward.

```
block_rate = blocked_count / total_prompts
gate fires when block_rate < baseline_block_rate - drift_threshold
```

A guard chain that becomes more lenient (catches fewer exploits)
lowers block rate; the gate catches that drift. A guard chain that
catches *more* (block rate rises) is fine — the gate is one-sided
downward.

## The corpus

`tests/cves/corpora/metis_inspired_corpus_2026_05_18.json` —
25 entries:

| Anchor | Entries | What it exercises |
|---|---|---|
| `CVE-2026-44717` (eval RCE class) | 12 | `eval(`, `exec(`, `compile(`, `__import__(`, `getattr(`, `parse_expr(` (unpinned), namespace-prefixed `parse_expr`, vulnerable-package denylist (`mcp-calculate-server` 0.0.8 / 0.0.9 / 0.1.0), patched-version safe form (0.1.1) |
| `MCP-STDIO-injection-2026-05-05` | 5 | Shell metachars: `;`, `\|`, `$(`, backtick, `&&` |
| `benign-math` / `benign-pkg` / etc. | 8 | False-positive sentinels (must NOT be blocked) |

The Metis citation is motivational: the paper's *taxonomy* of failure
modes (closed-loop reasoning trajectories, semantic-gradient
refinement, metacognitive policy optimisation) shaped which
categories we chose to cover. The paper's **prompts** are NOT reused.

## Quickstart

```python
import json
from pathlib import Path

from agent_airlock import (
    CorpusEntry,
    MetisInspiredCorpusBlockRateGuard,
)

raw = json.loads(Path("tests/cves/corpora/metis_inspired_corpus_2026_05_18.json").read_text())
entries = [CorpusEntry(**e) for e in raw["entries"]]

guard = MetisInspiredCorpusBlockRateGuard(
    corpus=entries,
    baseline_block_rate=raw["baseline_block_rate"],   # 0.68 locked first-run
    drift_threshold=raw["drift_threshold"],           # 0.05
)
decision = guard.evaluate()
assert decision.allowed, decision.detail
```

## CLI: `airlock corpus-bench`

```bash
python -m agent_airlock.cli.corpus_bench \
    --corpus-path tests/cves/corpora/metis_inspired_corpus_2026_05_18.json \
    --report json
```

Reports: `text` (default, one line), `json` (machine-readable),
`md` (markdown table with per-prompt outcomes).

Exit codes: `0` gate pass, `1` generic error, `2` argparse usage,
`3` gate FAILED.

`structlog` output is routed to **stderr** so stdout stays clean for
machine parsing — pipe `airlock corpus-bench --report json` directly
into `jq`.

## Custom guard chain

The default chain is `EvalRCEGuard + StdioCommandInjectionGuard`.
Operators can pass a custom callable:

```python
def my_chain(entry: CorpusEntry) -> bool:
    # Return True iff the chain refuses this entry.
    return any_of_my_guards_blocks(entry.args)

guard = MetisInspiredCorpusBlockRateGuard(
    corpus=entries,
    baseline_block_rate=0.95,
    drift_threshold=0.05,
    guard_chain=my_chain,
)
```

## Honest scope

- **Fixed corpus, not adaptive attacker.** This catches *regressions
  on a known set of exploit shapes*. A novel exploit shape outside
  the corpus is invisible to this gate.
- **One-sided downward gate.** A guard that becomes overzealous (false
  positives) is NOT caught by this metric. The `expected_block` field
  per-entry lets reports flag false-positive drift, but the gate
  itself only fires on regression downward.
- **Block rate is not ASR.** Don't quote this number alongside Metis
  paper figures — they measure different surfaces.

## Factory

```python
from agent_airlock.policy_presets import (
    metis_inspired_corpus_block_rate_regression_defaults_2026_05_18,
)

cfg = metis_inspired_corpus_block_rate_regression_defaults_2026_05_18()
# {
#   'preset_id': 'metis_inspired_corpus_block_rate_regression_2026_05_18',
#   'severity': 'high',
#   'default_action': 'fail_release_gate',
#   'advisory_url': 'https://arxiv.org/abs/2605.10067',
#   'baseline_block_rate': 0.68,
#   'drift_threshold': 0.05,
#   ...
# }
```

## Related

- [`EvalRCEGuard`](eval-rce-cve-2026-44717.md) (v0.8.0) — the
  primary detector exercised by the corpus.
- [`StdioCommandInjectionGuard`](mcp-stdio-command-injection-guard.md)
  (v0.7.6) — the secondary detector.
- [`OpenAPIDriftGuard`](openapi-drift-guard.md) (v0.8.1) — payload-shape
  drift detector one layer above the exploit-shape guards.
