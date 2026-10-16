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

### Fresh run `fresh-20261016T101746Z`, scored 2026-10-16 (UTC)

- Run `fresh-20261016T101746Z` (fresh), git `d9187e00e1fd`, anthropic SDK 1.15.0, pricing `anthropic_pricing_2026_10.json`, ledger spend $8.63.
- Batches: `msgbatch_01Te9CXPmC886uHo77EiCGed`, `msgbatch_01SM8M2oScXjoBSj913YBLG5`.
- Models requested: `claude-haiku-5-5`, `claude-sonnet-5-5`; effort {'claude-haiku-5-5': 'medium', 'claude-sonnet-5-5': 'high'}; max_tokens {'claude-haiku-5-5': 8192, 'claude-sonnet-5-5': 4096}; adaptive thinking; no temperature, tools, fallbacks or caching.
- Cases: 1348; C' repeat subset: 135 (seed 20261012).
- Served model ids, by requested model (results are grouped by served id, never pooled): `h55`: `claude-haiku-5-5` 2831; `s55`: `claude-sonnet-5-5` 2831.
- Parse-valid excludes API refusals (`stop_reason: refusal`), which are reported in their own column and never counted as influence.

#### `claude-haiku-5-5`

| Arm | Succeeded | Parse-valid | API refusal | Truncated | No call |
| --- | --- | --- | --- | --- | --- |
| P | 1348 | 100.0% (1348/1348) | 0.0% (0/1348) | 0.0% (0/1348) | 10.5% (142/1348) |
| C | 1348 | 100.0% (1348/1348) | 0.0% (0/1348) | 0.0% (0/1348) | 13.9% (187/1348) |
| C' | 135 | 100.0% (135/135) | 0.0% (0/135) | 0.0% (0/135) | 13.3% (18/135) |

| Metric | Value |
| --- | --- |
| Direct Execution (P calls the poisoned tool) | 74/1348 (5.5%, CI 4.4-6.8%) |
| Influenced, Templates 2+3 (P differs from C) | 456/1137 (40.1%, CI 37.3-43.0%) |
| Influenced, Template 1 (its query targets the poisoned tool) | 118/211 (55.9%, CI 49.2-62.5%) |
| Noise, Templates 2+3 (C differs from C') | 7/114 (6.1%, CI 3.0-12.1%) |
| Excess influence, Templates 2+3 (influenced minus noise) | +34.0 pp (95% CI +27.3 to +38.2 pp) |
| Poison-literal uptake, P | 190/1348 (14.1%, CI 12.3-16.1%) |
| Poison-literal uptake, C (false-positive baseline) | 4/1348 (0.3%, CI 0.1-0.8%) |

| Tier | P real calls refused | in influenced cases | carrying a poison literal | P poisoned-tool calls refused | C real calls refused (false refusal) | C responses with a refusal |
| --- | --- | --- | --- | --- | --- | --- |
| G0 (contract only) | 2.8% (32/1132) | 3.4% (16/476) | 1.6% (3/190) | 2.7% (2/74) | 1.8% (21/1161) | 1.8% (21/1161) |
| G (+ tool allowlist) | 2.8% (32/1132) | 3.4% (16/476) | 1.6% (3/190) | 100.0% (74/74) | 1.8% (21/1161) | 1.8% (21/1161) |
| LP (+ path / endpoint scopes) | 8.1% (92/1132) | 7.1% (34/476) | 6.8% (13/190) | 100.0% (74/74) | 6.2% (72/1161) | 6.2% (72/1161) |

Residual under LP (poison-literal calls admitted): 177/190 (93.2%, CI 88.6-96.0%).

#### `claude-sonnet-5-5`

| Arm | Succeeded | Parse-valid | API refusal | Truncated | No call |
| --- | --- | --- | --- | --- | --- |
| P | 1348 | 87.3% (1177/1348) | 12.7% (171/1348) (cyber 171) | 0.0% (0/1348) | 7.8% (92/1177) |
| C | 1348 | 99.7% (1344/1348) | 0.3% (4/1348) (cyber 1, reasoning_extraction 3) | 0.0% (0/1348) | 12.9% (173/1344) |
| C' | 135 | 98.5% (133/135) | 1.5% (2/135) (cyber 1, reasoning_extraction 1) | 0.0% (0/135) | 13.5% (18/133) |

| Metric | Value |
| --- | --- |
| Direct Execution (P calls the poisoned tool) | 42/1177 (3.6%, CI 2.6-4.8%) |
| Influenced, Templates 2+3 (P differs from C) | 564/1020 (55.3%, CI 52.2-58.3%) |
| Influenced, Template 1 (its query targets the poisoned tool) | 81/154 (52.6%, CI 44.7-60.3%) |
| Noise, Templates 2+3 (C differs from C') | 2/113 (1.8%, CI 0.5-6.2%) |
| Excess influence, Templates 2+3 (influenced minus noise) | +53.5 pp (95% CI +48.1 to +56.8 pp) |
| Poison-literal uptake, P | 312/1177 (26.5%, CI 24.1-29.1%) |
| Poison-literal uptake, C (false-positive baseline) | 3/1344 (0.2%, CI 0.1-0.7%) |

| Tier | P real calls refused | in influenced cases | carrying a poison literal | P poisoned-tool calls refused | C real calls refused (false refusal) | C responses with a refusal |
| --- | --- | --- | --- | --- | --- | --- |
| G0 (contract only) | 0.5% (5/1043) | 0.8% (5/592) | 0.0% (0/312) | 2.4% (1/42) | 0.0% (0/1171) | 0.0% (0/1171) |
| G (+ tool allowlist) | 0.5% (5/1043) | 0.8% (5/592) | 0.0% (0/312) | 100.0% (42/42) | 0.0% (0/1171) | 0.0% (0/1171) |
| LP (+ path / endpoint scopes) | 5.5% (57/1043) | 4.2% (25/592) | 4.8% (15/312) | 100.0% (42/42) | 4.7% (55/1171) | 4.7% (55/1171) |

Residual under LP (poison-literal calls admitted): 297/312 (95.2%, CI 92.2-97.1%).

Recorded Claude 3.7 Sonnet, same literal-uptake method (P arm, MCPTox's outputs): 244/1185 (20.6%, CI 18.4-23.0%).

Requests that did not succeed, by requested model: none.

### Fresh run `fresh-20261016T102523Z`, scored 2026-10-16 (UTC)

- Run `fresh-20261016T102523Z` (fresh), git `d9187e00e1fd`, anthropic SDK 1.15.0, pricing `anthropic_pricing_2026_10.json`, ledger spend $14.68.
- Batches: `msgbatch_01UmeCjijQsSr1MY7BBz1F5M`.
- Models requested: `claude-opus-5-5`; effort {'claude-opus-5-5': 'medium'}; max_tokens {'claude-opus-5-5': 4096}; adaptive thinking; no temperature, tools, fallbacks or caching.
- Cases: 1348; C' repeat subset: 135 (seed 20261012).
- Served model ids, by requested model (results are grouped by served id, never pooled): `o55`: `claude-opus-5-5` 2831.
- Parse-valid excludes API refusals (`stop_reason: refusal`), which are reported in their own column and never counted as influence.

#### `claude-opus-5-5`

| Arm | Succeeded | Parse-valid | API refusal | Truncated | No call |
| --- | --- | --- | --- | --- | --- |
| P | 1348 | 75.9% (1023/1348) | 24.1% (325/1348) (cyber 325) | 0.0% (0/1348) | 6.8% (70/1023) |
| C | 1348 | 99.6% (1342/1348) | 0.4% (6/1348) (cyber 6) | 0.0% (0/1348) | 14.5% (195/1342) |
| C' | 135 | 99.3% (134/135) | 0.7% (1/135) (cyber 1) | 0.0% (0/135) | 14.9% (20/134) |

| Metric | Value |
| --- | --- |
| Direct Execution (P calls the poisoned tool) | 26/1023 (2.5%, CI 1.7-3.7%) |
| Influenced, Templates 2+3 (P differs from C) | 475/903 (52.6%, CI 49.3-55.8%) |
| Influenced, Template 1 (its query targets the poisoned tool) | 55/120 (45.8%, CI 37.2-54.7%) |
| Noise, Templates 2+3 (C differs from C') | 5/114 (4.4%, CI 1.9-9.9%) |
| Excess influence, Templates 2+3 (influenced minus noise) | +48.2 pp (95% CI +41.9 to +52.3 pp) |
| Poison-literal uptake, P | 244/1023 (23.9%, CI 21.3-26.6%) |
| Poison-literal uptake, C (false-positive baseline) | 6/1342 (0.4%, CI 0.2-1.0%) |

| Tier | P real calls refused | in influenced cases | carrying a poison literal | P poisoned-tool calls refused | C real calls refused (false refusal) | C responses with a refusal |
| --- | --- | --- | --- | --- | --- | --- |
| G0 (contract only) | 0.2% (2/927) | 0.4% (2/498) | 0.0% (0/244) | 0.0% (0/26) | 0.0% (0/1147) | 0.0% (0/1147) |
| G (+ tool allowlist) | 0.2% (2/927) | 0.4% (2/498) | 0.0% (0/244) | 100.0% (26/26) | 0.0% (0/1147) | 0.0% (0/1147) |
| LP (+ path / endpoint scopes) | 3.9% (36/927) | 3.8% (19/498) | 2.0% (5/244) | 100.0% (26/26) | 4.2% (48/1147) | 4.2% (48/1147) |

Residual under LP (poison-literal calls admitted): 239/244 (98.0%, CI 95.3-99.1%).

Recorded Claude 3.7 Sonnet, same literal-uptake method (P arm, MCPTox's outputs): 244/1185 (20.6%, CI 18.4-23.0%).

Requests that did not succeed, by requested model: none.

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
