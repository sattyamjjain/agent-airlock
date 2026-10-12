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
- `replay_summary.json` - written by `replay --write` only; aggregates, no MCPTox text.

## Blind labelling protocol

`clean-view` prints each server's clean tool blocks and clean queries and nothing from the
attack side. The LP labels were written from that output alone and committed on their own
(commit `5e856c2`, `bench(mcptox): blind G0/G/LP policy labels`) before `replay.py`
existed. `replay.py` pins the file's sha256 from that commit, and every replay records
whether `lp_labels.py` still matches it.
