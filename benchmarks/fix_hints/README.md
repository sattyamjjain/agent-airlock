# fix_hints recovery benchmark

Does airlock's refusal help a Claude model repair its own tool call? Method and results:
[`RESULTS.md`](RESULTS.md) (also published at `docs/benchmarks/fix-hints-recovery.md`).

## Run it

From the repo root. Without `--run` nothing is sent: every command below except the
ones marked *paid* prints request counts, the worst-case cost and the expected cost at 0
and 1,000 thinking tokens per request.

```bash
python -m benchmarks.fix_hints                    # R1 plan: corpus, counts, cost
python -m benchmarks.fix_hints --pilot            # the 5-request pilot plan

# paid: the key is read for this command only, never exported
ANTHROPIC_API_KEY="$(security find-generic-password -s anthropic-credits -w)" \
  python -m benchmarks.fix_hints --pilot --run --budget-usd 1
ANTHROPIC_API_KEY="$(security find-generic-password -s anthropic-credits -w)" \
  python -m benchmarks.fix_hints --round r1 --run --budget-usd 60 --no-wait
ANTHROPIC_API_KEY="$(security find-generic-password -s anthropic-credits -w)" \
  python -m benchmarks.fix_hints --collect fh-r1-20261014T101500Z

# free: re-score stored results, then append the round block
python -m benchmarks.fix_hints --score fh-r1-20261014T101500Z
python -m benchmarks.fix_hints --score fh-r1-20261014T101500Z --write --date 2026-10-14
```

A paid run is refused before anything is submitted when the whole round's worst case does
not fit the budget. To stage a round instead (say, one model per run), pass `--models`
per run and score the runs together; they must share the corpus, protocol and hint code:

```bash
python -m benchmarks.fix_hints --score fh-r1-20261014T101500Z,fh-r1-20261014T143000Z --write
```

R2 runs after the hint fixes land, against R1 (`--r1-run ID[,ID]`, else the newest R1 run
plus every other R1 run of the same hint code):

```bash
python -m benchmarks.fix_hints --round r2                     # which scenarios changed
ANTHROPIC_API_KEY="..." python -m benchmarks.fix_hints --round r2 --run --budget-usd 60
```

Options: `--models h55,s55,o55` (aliases or ids), `--arms h,n,s` (add `g` for the
generic-error arm), `--protocol tool|text`, `--seed 20261012`, `--no-wait`, `--force`
(append a second block under a used heading), `--force-resubmit` (resubmit over a
dangling submit intent; check the Console's batch list first).

## Guardrails

- A paid run needs `--run` **and** a positive `--budget-usd`, refuses a dirty git tree,
  and goes through `benchmarks._claude`: the key only from `ANTHROPIC_API_KEY`, every
  request priced by exact model id, every dollar in the shared ledger, each batch
  admitted only if its worst case fits under `--budget-usd` and the cumulative hard cap.
- One batch per model per round; the submit intent is recorded before the batch is
  created, so a crash cannot double-spend.
- No fallbacks, no temperature, no `tool_choice`, effort pinned per model: what a block
  reports is what the named model did at the recorded settings.
- Raw outputs stay in `~/.cache/agent-airlock-bench/runs/fix_hints/<run_id>/` (manifest,
  requests, scenarios, payload hashes, batch results, scores). The repository gets only
  `RESULTS.md` and `summary.json`, both written by `--write`.

## Layout

| Module | What it does |
|---|---|
| [`catalogue.py`](catalogue.py) | the synthetic tools, their `@Airlock` stubs and JSON schemas |
| [`scenarios.py`](scenarios.py) | the 500 scenarios, each self-checked at generation |
| [`payloads.py`](payloads.py) | arms H, N, S, G from the live refusal |
| [`protocol.py`](protocol.py) | request params, custom ids, token estimates, the pilot |
| [`score.py`](score.py) | outcomes and oracles |
| [`report.py`](report.py) | aggregation, Wilson intervals, McNemar, the round block |
| [`__main__.py`](__main__.py) | the CLI |

Tests: `tests/test_fix_hints_bench.py` (no network, no SDK).
