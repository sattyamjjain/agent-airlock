# MCPTox bench

Replays [MCPTox](https://arxiv.org/abs/2508.14925)'s recorded tool calls through
`@Airlock`, and runs Claude 5.5 on it fresh. Results:
[`RESULTS.md`](https://github.com/sattyamjjain/agent-airlock/blob/main/benchmarks/mcptox/RESULTS.md).

The data (`response_all.json`, pinned commit and sha256 in `data.py`) is downloaded only
when you pass `--fetch`, verified, and cached under `~/.cache/agent-airlock-bench/mcptox/`
(or `$AIRLOCK_BENCH_DATA`). It is never committed: the source repository has no license.

```bash
python -m benchmarks.mcptox clean-view --fetch          # clean tool blocks and queries only
python -m benchmarks.mcptox replay --fetch              # free; prints the summary
python -m benchmarks.mcptox replay --fetch --write      # canonical (Linux) run only
```

The canonical replay runs on Linux, because macOS's `/etc`, `/tmp` and `/var` are
symlinks into `/private` and change filesystem verdicts. From the repository root, with
Docker:

```bash
docker run --rm -v "$PWD":/src -w /src \
  -v "$HOME/.cache/agent-airlock-bench":/root/.cache/agent-airlock-bench \
  -e AIRLOCK_BENCH_GIT_SHA="$(git rev-parse HEAD)" \
  -e AIRLOCK_BENCH_GIT_DIRTY="$(test -z "$(git status --porcelain --untracked-files=no)" && echo 0 || echo 1)" \
  python:3.12-slim sh -c 'pip install -q -e . && python -m benchmarks.mcptox replay --fetch --write'
```

`--write` refuses a non-Linux host unless `--non-canonical-host`, and a filesystem gate
that takes `~` literally unless `--allow-unexpanded-tilde`; either override is printed in
the published block.

## Fresh Claude 5.5 run (paid)

Every paid path is a dry run unless `--run` and `--budget-usd` are both given. The dry run
prints request counts and the worst-case and expected cost and needs neither a key nor the
`anthropic` SDK.

```bash
python -m benchmarks.mcptox fresh --fetch                 # dry run: P + C + C' x 3 models
python -m benchmarks.mcptox fresh --pilot 40              # dry run of the 40-case pilot

# Paid: the key is supplied for the one command, never exported.
ANTHROPIC_API_KEY="$(security find-generic-password -s anthropic-credits -w)" \
  python -m benchmarks.mcptox fresh --pilot 40 --run --budget-usd 6
ANTHROPIC_API_KEY="$(security find-generic-password -s anthropic-credits -w)" \
  python -m benchmarks.mcptox fresh --models h55 --run --budget-usd 10 --no-wait
ANTHROPIC_API_KEY="$(security find-generic-password -s anthropic-credits -w)" \
  python -m benchmarks.mcptox fresh --collect <RUN_ID>

python -m benchmarks.mcptox fresh --score <RUN_ID> --write   # free; appends a dated block
```

Submit one model per command: the budget guard reserves each batch's worst case
(`max_tokens` all spent), and Sonnet's and Opus's together exceed the $180 hard cap.
`--max-tokens`, `--no-repeat` (drop C') and `--paradigms Template-2,Template-3` are the
plan's cost cuts; the pilot and repeat subsets are drawn from all 1,348 cases either way, so
a cut changes what is sent, never what a custom id means. A paid run refuses a dirty tree
and records its manifest, requests, batch ids and raw outputs under
`~/.cache/agent-airlock-bench/runs/mcptox/<run_id>/`, outside git.

## Files

- `data.py` - pinned download (HTTPS, 50 MB cap, temp file, sha256, atomic rename), cache,
  case iteration keyed by server and instance position.
- `clean.py` - clean-prompt `Tool:` blocks to tool contracts; `CleanServer` holds the
  clean fields only.
- `lp_labels.py` - the blind per-tool LP labels (written from `clean-view` alone,
  committed before any replay code).
- `policies.py` - G0, G and LP derived from a `CleanServer` (pure).
- `parse.py` - recorded responses to calls, with status and repair notes for every one.
- `stubs.py` - `@Airlock`-wrapped stubs (`typing.Any` parameters, BLOCK mode, no honeypot)
  and the verdict of one call.
- `literals.py` - poison-literal uptake (judge-free).
- `replay.py`, `metrics.py`, `report.py` - the replay, its aggregates and their rendering.
- `fresh.py` - the paid two-arm run: request building, dry-run pricing, Batch submission
  through `benchmarks/_claude/`, collection and judge-free scoring.
- `replay_summary.json`, `fresh_summary.json` - written by `--write` only; aggregates, no
  MCPTox text.

## Blind labelling protocol

`clean-view` prints each server's clean tool blocks and clean queries and nothing from the
attack side. The LP labels were written from that output alone and committed on their own
(commit `5e856c2`, `bench(mcptox): blind G0/G/LP policy labels`) before `replay.py`
existed. `replay.py` pins the file's sha256 from that commit, and every replay records
whether `lp_labels.py` still matches it.
