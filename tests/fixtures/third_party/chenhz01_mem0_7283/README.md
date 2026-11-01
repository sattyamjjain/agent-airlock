# chenhz01 / mem0-7283-conformance: bypass-probe corpus (MGP-7283-C1)

Vendored from https://github.com/chenhz01/mem0-7283-conformance at commit
`f3dd65c02931df603964cc7d257d9b5bf9492abe`, by chenhz01 (正明 / 善伦), the third-party
conformance suite for mem0ai/mem0#7283 (https://github.com/mem0ai/mem0/issues/7283).
It is not part of mem0 and not part of agent-airlock.

| File | What it is | License |
| --- | --- | --- |
| `corpus_results_20261026.json` | The 25 cases with their text and the verdicts measured against another project's secrets gate on 2026-10-26. Read with stdlib `json` | CC BY 4.0 (the corpus text, per its SPDX header) |
| `corpus_bypass.yaml` | The same cases with their categories, kept for provenance; not read by the tests | CC BY 4.0 |
| `LICENSE` | Apache License 2.0, for the suite's code | |
| `LICENSE-SPEC` | Creative Commons Attribution 4.0, for the suite's specification and corpus | |
| `NOTICE` | The suite's notice | |

The files are copied as published (their git blob hashes match the commit above). The
verdicts in them are the upstream suite's, against `DataAlchmesit/MiniEval-pro`'s gate, not
agent-airlock's. `tests/test_argument_secret_guard_0_10_29.py` runs every case through
`ArgumentSecretGuard` and pins agent-airlock's own counts.

Attribution: chenhz01 / mem0#7283 P2 conformance suite, MGP-7283
(https://github.com/chenhz01/mem0-7283-conformance), CC BY 4.0. The corpus is used
unmodified.
