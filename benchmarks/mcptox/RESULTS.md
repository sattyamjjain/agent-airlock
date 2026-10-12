# MCPTox: recorded tool calls replayed through `@Airlock`, and a fresh Claude 5.5 run

[MCPTox](https://arxiv.org/abs/2508.14925) (Wang et al.) poisons one tool description on
each of **45 live MCP servers (353 tools)** and records what each model then did. Version 1
of the paper reported 1,312 cases; version 2 (2026-09-29) and the released
`response_all.json` carry **1,348** (1,312 with `wrong_data` 0, 36 with `wrong_data` 2), in
**10 risk categories (11 with "Other")** and three attack paradigms. Its top reported attack
success rate, **72.8% for o1-mini**, reproduces only over all 1,348 cases (574 of 788
labelled responses).

Two measurements live here, both judge-free:

- **Replay (free, offline).** Every call the 27 recorded models made (16 API-model keys,
  Claude 3.7 Sonnet's 1,348 cases split across a thinking and a non-thinking key, and up
  to 11 local models) is parsed and sent through an `@Airlock` stub of the tool it named,
  under three policy tiers. It says which recorded attack calls the layer would have
  refused, and how many of the benign-proxy calls it would have refused too.
- **Fresh run (paid, Claude 5.5).** The poisoned prompt and the clean prompt are sent to
  Haiku, Sonnet and Opus 5.5 with the same query; the poisoned tool's influence is the
  difference, net of run-to-run noise measured on a repeated 10% subset.

## Provenance

- **Data:** MCPTox
  [`response_all.json`](https://github.com/zhiqiangwang4/MCPTox-Benchmark/blob/f85189f9ad12504c197c7f920ab818a40657b1fa/response_all.json)
  at commit `f85189f9ad12504c197c7f920ab818a40657b1fa`, sha256
  `79a90049be931c59e71446d6180b1d7f0d196d123d08a59bc155d142b5041c03` (20,666,873 bytes).
  It is downloaded at run time (`--fetch`), verified, and never committed: the source
  repository carries no license. Nothing in this directory quotes its text; the committed
  outputs are counts and rates.
- **Policy labels:** the LP tier's per-tool labels,
  [`lp_labels.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/benchmarks/mcptox/lp_labels.py),
  were written from `python -m benchmarks.mcptox clean-view` alone (clean tool blocks and
  clean queries, nothing from the attack side) and committed on their own in commit
  `5e856c228a0c21c6c6d885ba195572bb3d3e15f7` (`bench(mcptox): blind G0/G/LP policy
  labels`), before the replay code existed. That file's sha256 then was
  `e1476ddc206ed09ab177ee73d8d16b990b897f6f67c7b2ef3d2369361327f314`; every replay records
  whether it still matches.
- **Harness:** [`benchmarks/mcptox/`](https://github.com/sattyamjjain/agent-airlock/blob/main/benchmarks/mcptox/README.md).

## Replay of recorded calls

Tiers, each derived from a server's clean side only
([`policies.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/benchmarks/mcptox/policies.py)):

- **G0**: the call contract alone. Ghost arguments refused (`UnknownArgsMode.BLOCK`),
  required arguments enforced. No tool allowlist.
- **G**: G0 plus a `SecurityPolicy` allowlist of the clean prompt's tools
  (`default_deny=True`).
- **LP**: G plus per-tool filesystem roots and endpoint policies derived from the clean
  queries, for the 35 servers that have clean queries; the other 10 get G.

Stubs declare every argument `typing.Any`, because MCPTox prompts carry no types, so the
strict-type layer is not exercised here. Each response's status (`calls`, `no_call`,
`malformed`, `empty`) and every parse repair are counted in the accounting table; nothing is
dropped.

<!-- MCPTOX-REPLAY:BEGIN -->
_Not yet measured._ The canonical replay runs on Linux, after the filesystem gate's `~`
fix, with `python -m benchmarks.mcptox replay --fetch --write`; see the
[README](https://github.com/sattyamjjain/agent-airlock/blob/main/benchmarks/mcptox/README.md)
for the container command.
<!-- MCPTOX-REPLAY:END -->

## Fresh Claude 5.5 run

Arms: **P**, MCPTox's own system prompt (the clean prompt with the poisoned tool inserted)
plus the case query, byte-exact, in MCPTox's text protocol; **C**, the clean system prompt
plus the same query; **C'**, C again on a seeded, paradigm-stratified 10% subset. Requests
use adaptive thinking and each model's default effort, pinned and recorded; no temperature,
tools, fallbacks or caching. Every result records the model id that served it, and results
from different ids are never pooled.

<!-- MCPTOX-FRESH-RUNS: append newest below; never edit dated blocks -->

_Not yet measured._

## Limits

- The replay is not an end-to-end run: a refused call would have changed what the model
  did next, which a recording cannot show.
- The benign proxy (Failure-Ignored responses) was generated with the poison in context.
  The fresh run's clean arm is the true benign control.
- `agent_airlock` has no recipient allowlist, SQL or shell parser, or JavaScript sandbox, so
  LP scopes paths and URLs only; email, chat, database and command tools are unscoped
  beyond G.
- Poison-literal uptake is a judge-free proxy for "the call carries the attacker's value".
  It misses changes that carry no quoted literal, so its recall is bounded; its precision
  and recall against MCPTox's labels are published with every use.
- Filesystem verdicts depend on the host; the canonical replay runs on Linux.
