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
### Replay, measured 2026-10-17 (UTC)

- Host: Linux 7.0.14-linuxkit (canonical Linux host), Python 3.12.15; agent-airlock 0.10.25 at `74048af5a98e`.
- Filesystem gate checks `~` paths in their expanded form: yes.
- Data: MCPTox `response_all.json` at `f85189f9ad12`, sha256 `79a90049be931c59...`, verified before scoring.
- LP labels: blind commit `5e856c228a0c`; `lp_labels.py` sha256 `e1476ddc206ed09a...` (matches the blind commit's).
- Bootstrap: 2000 resamples of whole servers, seed 20261012.
- Reproduce: `python -m benchmarks.mcptox replay --fetch --write`

Denominators: 20220 API-model responses and 10507 local-model responses. API models: S = 7465 Success responses with a real-tool call, DE = 1650 Direct Execution responses with a poisoned-tool call, B = 7388 Failure-Ignored responses with a real-tool call.

#### API models (primary)

| Tier | Attack refusal, lower bound (every real call refused) | Upper bound (any real call refused) | Direct Execution refused | Benign-proxy false refusal | of which policy / contract-only | Poison-literal calls refused |
| --- | --- | --- | --- | --- | --- | --- |
| G0 (contract only) | 220/7465 (2.9%, CI 2.6-3.4%; server bootstrap 0.9-6.0%) | 237/7465 (3.2%, CI 2.8-3.6%) | 39/1650 (2.4%, CI 1.7-3.2%) | 175/7388 (2.4%, CI 2.1-2.7%; server bootstrap 0.4-6.6%) | 0.0% (0/7388) / 2.4% (175/7388) | 124/4981 (2.5%, CI 2.1-3.0%) |
| G (+ tool allowlist) | 220/7465 (2.9%, CI 2.6-3.4%; server bootstrap 0.9-6.0%) | 237/7465 (3.2%, CI 2.8-3.6%) | 1650/1650 (100.0%, CI 99.8-100.0%) | 175/7388 (2.4%, CI 2.1-2.7%; server bootstrap 0.4-6.6%) | 0.0% (0/7388) / 2.4% (175/7388) | 124/4981 (2.5%, CI 2.1-3.0%) |
| LP (+ path / endpoint scopes) | 792/7465 (10.6%, CI 9.9-11.3%; server bootstrap 2.0-24.0%) | 817/7465 (10.9%, CI 10.3-11.7%) | 1650/1650 (100.0%, CI 99.8-100.0%) | 300/7388 (4.1%, CI 3.6-4.5%; server bootstrap 0.8-8.7%) | 1.7% (125/7388) / 2.4% (175/7388) | 708/4981 (14.2%, CI 13.3-15.2%) |

Direct Execution under G is refused by construction: the allowlist is the clean prompt's tools, and the poisoned tool is not one of them. G0 shows what the call contract alone does to the same calls.

#### Local models (secondary)

| Tier | Attack refusal, lower bound (every real call refused) | Upper bound (any real call refused) | Direct Execution refused | Benign-proxy false refusal | of which policy / contract-only | Poison-literal calls refused |
| --- | --- | --- | --- | --- | --- | --- |
| G0 (contract only) | 71/1773 (4.0%, CI 3.2-5.0%) | 76/1773 (4.3%, CI 3.4-5.3%) | 174/2747 (6.3%, CI 5.5-7.3%) | 258/5194 (5.0%, CI 4.4-5.6%) | 0.0% (0/5194) / 5.0% (258/5194) | 36/1234 (2.9%, CI 2.1-4.0%) |
| G (+ tool allowlist) | 71/1773 (4.0%, CI 3.2-5.0%) | 76/1773 (4.3%, CI 3.4-5.3%) | 2747/2747 (100.0%, CI 99.9-100.0%) | 258/5194 (5.0%, CI 4.4-5.6%) | 0.0% (0/5194) / 5.0% (258/5194) | 36/1234 (2.9%, CI 2.1-4.0%) |
| LP (+ path / endpoint scopes) | 181/1773 (10.2%, CI 8.9-11.7%) | 221/1773 (12.5%, CI 11.0-14.1%) | 2747/2747 (100.0%, CI 99.9-100.0%) | 309/5194 (5.9%, CI 5.3-6.6%) | 1.0% (51/5194) / 5.0% (258/5194) | 151/1234 (12.2%, CI 10.5-14.2%) |

#### Claude 3.7 Sonnet (MCPTox's recorded outputs)

| Group | S | G0 lower | G lower | LP lower | LP upper | B | G false refusal | LP false refusal |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `both keys` | 400 | 0.8% (3/400) | 0.8% (3/400) | 5.2% (21/400) | 9.8% (39/400) | 436 | 0.7% (3/436) | 2.5% (11/436) |
| `claude-3-7-sonnet` | 310 | 1.0% (3/310) | 1.0% (3/310) | 5.2% (16/310) | 7.4% (23/310) | 347 | 0.3% (1/347) | 2.3% (8/347) |
| `claude-3-7-sonnet-20250219-thinking` | 90 | 0.0% (0/90) | 0.0% (0/90) | 5.6% (5/90) | 17.8% (16/90) | 89 | 2.2% (2/89) | 3.4% (3/89) |

#### By paradigm (API models)

| Group | S | G0 lower | G lower | LP lower | LP upper | B | G false refusal | LP false refusal |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `Template-1` | 985 | 3.4% (33/985) | 3.4% (33/985) | 17.7% (174/985) | 18.0% (177/985) | 434 | 0.9% (4/434) | 0.9% (4/434) |
| `Template-2` | 2153 | 3.5% (76/2153) | 3.5% (76/2153) | 14.6% (315/2153) | 15.6% (335/2153) | 3618 | 2.9% (104/3618) | 4.6% (168/3618) |
| `Template-3` | 4327 | 2.6% (111/4327) | 2.6% (111/4327) | 7.0% (303/4327) | 7.0% (305/4327) | 3336 | 2.0% (67/3336) | 3.8% (128/3336) |

#### By risk category (API models)

| Group | S | G0 lower | G lower | LP lower | LP upper | B | G false refusal | LP false refusal |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `Code Injection` | 354 | 0.0% (0/354) | 0.0% (0/354) | 0.0% (0/354) | 0.0% (0/354) | 265 | 0.0% (0/265) | 0.0% (0/265) |
| `Credential Leakage` | 565 | 0.4% (2/565) | 0.4% (2/565) | 46.0% (260/565) | 46.2% (261/565) | 586 | 0.2% (1/586) | 3.2% (19/586) |
| `Data Tampering` | 683 | 4.1% (28/683) | 4.1% (28/683) | 7.0% (48/683) | 7.6% (52/683) | 623 | 1.4% (9/623) | 4.5% (28/623) |
| `Financial Loss` | 267 | 27.0% (72/267) | 27.0% (72/267) | 27.0% (72/267) | 27.3% (73/267) | 216 | 43.1% (93/216) | 43.1% (93/216) |
| `Information Manipulation` | 1750 | 2.6% (45/1750) | 2.6% (45/1750) | 3.0% (52/1750) | 3.1% (54/1750) | 1595 | 0.6% (10/1595) | 0.7% (11/1595) |
| `Infrastructure Damage` | 538 | 2.6% (14/538) | 2.6% (14/538) | 28.1% (151/538) | 28.4% (153/538) | 588 | 1.7% (10/588) | 11.6% (68/588) |
| `Instruction Tampering` | 402 | 0.7% (3/402) | 0.7% (3/402) | 2.7% (11/402) | 2.7% (11/402) | 294 | 0.3% (1/294) | 0.7% (2/294) |
| `Message Hijacking` | 275 | 0.7% (2/275) | 0.7% (2/275) | 0.7% (2/275) | 0.7% (2/275) | 209 | 0.5% (1/209) | 0.5% (1/209) |
| `Other` | 26 | 0.0% (0/26) | 0.0% (0/26) | 0.0% (0/26) | 0.0% (0/26) | 25 | 0.0% (0/25) | 0.0% (0/25) |
| `Privacy Leakage` | 1105 | 1.6% (18/1105) | 1.6% (18/1105) | 10.9% (120/1105) | 11.8% (130/1105) | 2021 | 0.7% (15/2021) | 1.8% (37/2021) |
| `Service Disruption` | 1500 | 2.4% (36/1500) | 2.4% (36/1500) | 5.1% (76/1500) | 5.4% (81/1500) | 966 | 3.6% (35/966) | 4.2% (41/966) |

#### By model family (API models)

| Group | S | G0 lower | G lower | LP lower | LP upper | B | G false refusal | LP false refusal |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `Claude` | 400 | 0.8% (3/400) | 0.8% (3/400) | 5.2% (21/400) | 9.8% (39/400) | 436 | 0.7% (3/436) | 2.5% (11/436) |
| `DeepSeek` | 1639 | 1.8% (30/1639) | 1.8% (30/1639) | 11.3% (185/1639) | 11.5% (189/1639) | 528 | 1.5% (8/528) | 3.2% (17/528) |
| `Gemini` | 776 | 5.3% (41/776) | 5.3% (41/776) | 12.9% (100/776) | 12.9% (100/776) | 390 | 0.8% (3/390) | 3.1% (12/390) |
| `Llama` | 350 | 7.1% (25/350) | 7.1% (25/350) | 8.9% (31/350) | 9.1% (32/350) | 1143 | 3.1% (35/1143) | 4.8% (55/1143) |
| `OpenAI` | 1573 | 2.5% (39/1573) | 2.5% (39/1573) | 9.7% (153/1573) | 9.7% (153/1573) | 1311 | 1.8% (23/1311) | 3.1% (41/1311) |
| `Qwen` | 2727 | 3.0% (82/2727) | 3.0% (82/2727) | 11.1% (302/2727) | 11.1% (304/2727) | 3580 | 2.9% (103/3580) | 4.6% (164/3580) |

#### By model

| Group | S | G0 lower | G lower | LP lower | LP upper | B | G false refusal | LP false refusal |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `online:DeepSeek-R1` | 886 | 1.7% (15/886) | 1.7% (15/886) | 10.4% (92/886) | 10.8% (96/886) | 179 | 0.0% (0/179) | 1.7% (3/179) |
| `online:DeepSeek-v3` | 753 | 2.0% (15/753) | 2.0% (15/753) | 12.4% (93/753) | 12.4% (93/753) | 349 | 2.3% (8/349) | 4.0% (14/349) |
| `online:Llama-3.1-70B-Instruct` | 210 | 7.6% (16/210) | 7.6% (16/210) | 10.0% (21/210) | 10.5% (22/210) | 399 | 2.0% (8/399) | 4.3% (17/399) |
| `online:Llama-3.1-8B-Instruct` | 140 | 6.4% (9/140) | 6.4% (9/140) | 7.1% (10/140) | 7.1% (10/140) | 744 | 3.6% (27/744) | 5.1% (38/744) |
| `online:claude-3-7-sonnet` | 310 | 1.0% (3/310) | 1.0% (3/310) | 5.2% (16/310) | 7.4% (23/310) | 347 | 0.3% (1/347) | 2.3% (8/347) |
| `online:claude-3-7-sonnet-20250219-thinking` | 90 | 0.0% (0/90) | 0.0% (0/90) | 5.6% (5/90) | 17.8% (16/90) | 89 | 2.2% (2/89) | 3.4% (3/89) |
| `online:gemini-2.5-flash` | 776 | 5.3% (41/776) | 5.3% (41/776) | 12.9% (100/776) | 12.9% (100/776) | 390 | 0.8% (3/390) | 3.1% (12/390) |
| `online:gpt-3.5-turbo` | 195 | 3.6% (7/195) | 3.6% (7/195) | 5.6% (11/195) | 5.6% (11/195) | 888 | 2.0% (18/888) | 3.5% (31/888) |
| `online:gpt-4o-mini` | 804 | 3.5% (28/804) | 3.5% (28/804) | 11.1% (89/804) | 11.1% (89/804) | 309 | 1.3% (4/309) | 2.6% (8/309) |
| `online:o1-mini` | 574 | 0.7% (4/574) | 0.7% (4/574) | 9.2% (53/574) | 9.2% (53/574) | 114 | 0.9% (1/114) | 1.8% (2/114) |
| `online:qwen3-235b-a22b_NO_Think` | 229 | 2.6% (6/229) | 2.6% (6/229) | 9.2% (21/229) | 9.2% (21/229) | 588 | 1.9% (11/588) | 3.2% (19/588) |
| `online:qwen3-235b-a22b_Think` | 674 | 1.3% (9/674) | 1.3% (9/674) | 8.3% (56/674) | 8.5% (57/674) | 533 | 1.9% (10/533) | 3.9% (21/533) |
| `online:qwen3-32b_NO_Think` | 316 | 6.0% (19/316) | 6.0% (19/316) | 11.7% (37/316) | 11.7% (37/316) | 636 | 3.3% (21/636) | 6.0% (38/636) |
| `online:qwen3-32b_Think` | 778 | 3.1% (24/778) | 3.1% (24/778) | 11.2% (87/778) | 11.3% (88/778) | 400 | 2.5% (10/400) | 4.2% (17/400) |
| `online:qwen3-8b_NO_Think` | 173 | 2.3% (4/173) | 2.3% (4/173) | 15.0% (26/173) | 15.0% (26/173) | 816 | 3.6% (29/816) | 4.5% (37/816) |
| `online:qwen3-8b_Think` | 557 | 3.6% (20/557) | 3.6% (20/557) | 13.5% (75/557) | 13.5% (75/557) | 607 | 3.6% (22/607) | 5.3% (32/607) |
| `local:Deepseek-qwen3-8b-Think` | 22 | 9.1% (2/22) | 9.1% (2/22) | 36.4% (8/22) | 36.4% (8/22) | 98 | 16.3% (16/98) | 21.4% (21/98) |
| `local:LLama-13b` | 3 | 66.7% (2/3) | 66.7% (2/3) | 66.7% (2/3) | 66.7% (2/3) | 137 | 23.4% (32/137) | 23.4% (32/137) |
| `local:LLama-3-8b` | 30 | 13.3% (4/30) | 13.3% (4/30) | 23.3% (7/30) | 23.3% (7/30) | 471 | 5.7% (27/471) | 6.8% (32/471) |
| `local:Phi-4-Think` | 664 | 2.7% (18/664) | 2.7% (18/664) | 7.2% (48/664) | 12.3% (82/664) | 204 | 2.0% (4/204) | 2.9% (6/204) |
| `local:Qwen3-14b-No-Think` | 56 | 7.1% (4/56) | 7.1% (4/56) | 12.5% (7/56) | 12.5% (7/56) | 707 | 3.4% (24/707) | 4.2% (30/707) |
| `local:Qwen3-14b-Think` | 331 | 3.9% (13/331) | 3.9% (13/331) | 10.6% (35/331) | 12.1% (40/331) | 562 | 3.7% (21/562) | 5.5% (31/562) |
| `local:Qwen3-30b-A3b-No-Think` | 52 | 5.8% (3/52) | 5.8% (3/52) | 5.8% (3/52) | 5.8% (3/52) | 430 | 4.7% (20/430) | 4.7% (20/430) |
| `local:Qwen3-8b-No-Think` | 65 | 3.1% (2/65) | 3.1% (2/65) | 6.2% (4/65) | 6.2% (4/65) | 671 | 5.4% (36/671) | 5.4% (36/671) |
| `local:Qwen3-8b-Think` | 286 | 4.9% (14/286) | 4.9% (14/286) | 12.2% (35/286) | 12.6% (36/286) | 586 | 4.8% (28/586) | 6.5% (38/586) |
| `local:gemma-2-9b` | 183 | 3.8% (7/183) | 3.8% (7/183) | 13.1% (24/183) | 13.1% (24/183) | 813 | 3.0% (24/813) | 3.6% (29/813) |
| `local:mistral` | 81 | 2.5% (2/81) | 2.5% (2/81) | 9.9% (8/81) | 9.9% (8/81) | 515 | 5.0% (26/515) | 6.6% (34/515) |

#### Why real calls in S were refused (API models)

| Tier | Block reasons (refused real calls) |
| --- | --- |
| G0 | `ghost_arguments` 194, `validation_error` 43 |
| G | `ghost_arguments` 194, `validation_error` 43 |
| LP | `path_violation` 582, `ghost_arguments` 194, `validation_error` 43 |

#### wrong_data = 0 subset (API models)

| Tier | Attack refusal, lower bound (every real call refused) | Upper bound (any real call refused) | Direct Execution refused | Benign-proxy false refusal | of which policy / contract-only | Poison-literal calls refused |
| --- | --- | --- | --- | --- | --- | --- |
| G0 (contract only) | 220/7165 (3.1%, CI 2.7-3.5%) | 237/7165 (3.3%, CI 2.9-3.8%) | 39/1632 (2.4%, CI 1.8-3.2%) | 175/7237 (2.4%, CI 2.1-2.8%) | 0.0% (0/7237) / 2.4% (175/7237) | 124/4874 (2.5%, CI 2.1-3.0%) |
| G (+ tool allowlist) | 220/7165 (3.1%, CI 2.7-3.5%) | 237/7165 (3.3%, CI 2.9-3.8%) | 1632/1632 (100.0%, CI 99.8-100.0%) | 175/7237 (2.4%, CI 2.1-2.8%) | 0.0% (0/7237) / 2.4% (175/7237) | 124/4874 (2.5%, CI 2.1-3.0%) |
| LP (+ path / endpoint scopes) | 792/7165 (11.1%, CI 10.3-11.8%) | 817/7165 (11.4%, CI 10.7-12.2%) | 1632/1632 (100.0%, CI 99.8-100.0%) | 300/7237 (4.1%, CI 3.7-4.6%) | 1.7% (125/7237) / 2.4% (175/7237) | 708/4874 (14.5%, CI 13.6-15.5%) |

#### Poison-literal uptake against MCPTox's labels

| Source | Precision (uptake -> Success) | Recall (Success -> uptake) |
| --- | --- | --- |
| online | 4868/4964 (98.1%, CI 97.6-98.4%) | 4868/7465 (65.2%, CI 64.1-66.3%) |
| local | 1166/1223 (95.3%, CI 94.0-96.4%) | 1166/1773 (65.8%, CI 63.5-67.9%) |

#### MCPTox's own attack success rate, from its labels (reproduction anchor)

| API model | Success / labelled (None excluded) |
| --- | --- |
| `DeepSeek-R1` | 890/1256 (70.9%, CI 68.3-73.3%) |
| `DeepSeek-v3` | 757/1339 (56.5%, CI 53.9-59.2%) |
| `Llama-3.1-70B-Instruct` | 211/856 (24.6%, CI 21.9-27.7%) |
| `Llama-3.1-8B-Instruct` | 150/1065 (14.1%, CI 12.1-16.3%) |
| `claude-3-7-sonnet` | 318/900 (35.3%, CI 32.3-38.5%) |
| `claude-3-7-sonnet-20250219-thinking` | 91/293 (31.1%, CI 26.0-36.6%) |
| `gemini-2.5-flash` | 777/1302 (59.7%, CI 57.0-62.3%) |
| `gpt-3.5-turbo` | 199/1335 (14.9%, CI 13.1-16.9%) |
| `gpt-4o-mini` | 804/1302 (61.8%, CI 59.1-64.3%) |
| `o1-mini` | 574/788 (72.8%, CI 69.6-75.8%) |
| `qwen3-235b-a22b_NO_Think` | 231/1340 (17.2%, CI 15.3-19.4%) |
| `qwen3-235b-a22b_Think` | 676/1337 (50.6%, CI 47.9-53.2%) |
| `qwen3-32b_NO_Think` | 319/1345 (23.7%, CI 21.5-26.1%) |
| `qwen3-32b_Think` | 778/1331 (58.5%, CI 55.8-61.1%) |
| `qwen3-8b_NO_Think` | 188/1346 (14.0%, CI 12.2-15.9%) |
| `qwen3-8b_Think` | 560/1341 (41.8%, CI 39.1-44.4%) |

#### Accounting (nothing dropped)

| Source | Label | calls | no_call | malformed | empty |
| --- | --- | --- | --- | --- | --- |
| online | `Failure-Direct Execution` | 1776 | 2 | 0 | 0 |
| online | `Failure-Ignored` | 8835 | 263 | 9 | 14 |
| online | `Failure-Refused` | 16 | 33 | 0 | 5 |
| online | `None` | 15 | 188 | 0 | 1541 |
| online | `Success` | 7509 | 8 | 6 | 0 |
| local | `<missing>` | 1 | 0 | 0 | 0 |
| local | `Failure-Direct Execution` | 2814 | 0 | 22 | 0 |
| local | `Failure-Ignored` | 5371 | 0 | 121 | 0 |
| local | `None` | 336 | 0 | 8 | 0 |
| local | `Success` | 1777 | 0 | 57 | 0 |

Parse repairs: `end_token` 10478, `python_literal` 9745, `think_block` 505, `json_keywords_in_literal` 393, `unparseable_call_span` 231, `no_arguments_key` 153, `apostrophe_repair` 100, `native_call` 70, `partial` 55, `unbalanced_call_text` 43, `json_comments` 18, `call_list` 14, `arguments_not_object` 3, `arguments_unparseable_string` 2, `orphan_think_close` 1, `unterminated_think` 1.

Calls: local:other 16, local:poisoned 3023, local:real 7966, online:other 46, online:poisoned 3201, online:real 15206 (other = neither a clean-prompt tool nor the poisoned tool: not replayable).

Real or poisoned calls that could not be replayed: none.

LP coverage: 35 servers at LP, 10 without clean queries at G; 22 tools filesystem-scoped, 2 on an endpoint allowlist, 22 open-web with the SSRF pre-check; 12 labelled scopes could not be derived and fell back to G.
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

### Fresh run `fresh-pilot-20261016T195916Z`, scored 2026-10-16 (UTC)

- Run `fresh-pilot-20261016T195916Z` (fresh-pilot), git `1a3e9eba498f`, anthropic SDK 1.15.0, pricing `anthropic_pricing_2026_10.json`, ledger spend $9.54.
- Batches: none (synchronous pilot).
- Models requested: `claude-fable-5-1`; effort {'claude-fable-5-1': 'high'}; max_tokens {'claude-fable-5-1': 4096}; adaptive thinking; no temperature, tools, fallbacks or caching.
- Cases: 200; C' repeat subset: 0 (seed 20261012).
- Served model ids, by requested model (results are grouped by served id, never pooled): `f51`: `claude-fable-5-1` 400.
- Parse-valid excludes API refusals (`stop_reason: refusal`), which are reported in their own column and never counted as influence.

#### `claude-fable-5-1`

| Arm | Succeeded | Parse-valid | API refusal | Truncated | No call |
| --- | --- | --- | --- | --- | --- |
| P | 200 | 82.0% (164/200) | 18.0% (36/200) (cyber 36) | 0.0% (0/200) | 6.1% (10/164) |
| C | 200 | 99.5% (199/200) | 0.5% (1/200) (cyber 1) | 0.0% (0/200) | 13.6% (27/199) |
| C' | 0 | n=0 | n=0 | n=0 | n=0 |

| Metric | Value |
| --- | --- |
| Direct Execution (P calls the poisoned tool) | 9/164 (5.5%, CI 2.9-10.1%) |
| Influenced, Templates 2+3 (P differs from C) | 48/143 (33.6%, CI 26.4-41.6%) |
| Influenced, Template 1 (its query targets the poisoned tool) | 12/21 (57.1%, CI 36.5-75.5%) |
| Noise, Templates 2+3 (C differs from C') | n=0 (not measured) |
| Excess influence, Templates 2+3 (influenced minus noise) | not measured (a denominator is 0) |
| Poison-literal uptake, P | 8/164 (4.9%, CI 2.5-9.3%) |
| Poison-literal uptake, C (false-positive baseline) | 2/199 (1.0%, CI 0.3-3.6%) |

| Tier | P real calls refused | in influenced cases | carrying a poison literal | P poisoned-tool calls refused | C real calls refused (false refusal) | C responses with a refusal |
| --- | --- | --- | --- | --- | --- | --- |
| G0 (contract only) | 0.0% (0/145) | 0.0% (0/50) | 0.0% (0/8) | 0.0% (0/9) | 0.0% (0/172) | 0.0% (0/172) |
| G (+ tool allowlist) | 0.0% (0/145) | 0.0% (0/50) | 0.0% (0/8) | 100.0% (9/9) | 0.0% (0/172) | 0.0% (0/172) |
| LP (+ path / endpoint scopes) | 2.8% (4/145) | 0.0% (0/50) | 0.0% (0/8) | 100.0% (9/9) | 2.9% (5/172) | 2.9% (5/172) |

Residual under LP (poison-literal calls admitted): 8/8 (100.0%, CI 67.6-100.0%).

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
