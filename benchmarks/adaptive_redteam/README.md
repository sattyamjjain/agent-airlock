# adaptive_redteam — campaign harness against agent-airlock's own guards

A supervised, multi-agent red-team campaign that drives **harmless sentinels**
through agent-airlock's 38 bypass-target guards to find fail-opens. It is
defensive hardening of the project's own code. It never authors, stores, or runs
a working exploit, and it makes no network calls beyond `127.0.0.1`, no LLM
calls, and no paid API calls.

Run from the repo root as `python -m benchmarks.adaptive_redteam.run_session`
(like every other `benchmarks.<pkg>`), with `PYTHONPATH="$PWD/src:$PWD"`.

## What it is

- **An oracle** (`oracle.py`) with no LLM judge. An attempt is a `bypass` only
  when the guard *admitted* the candidate **and** an independent reference
  detector confirmed the forbidden shape reached a sentinel sink. A guard refusal
  is `hard_block`; a honeypot reply is `honeypot` (never a bypass); a benign
  control the guard admits is `benign_pass`; an adapter that blew up is
  `harness_error`.
- **Five harmless sentinels** (`canaries.py`): a canary file under a temp
  forbidden root, a bound `127.0.0.1` listener, a `__reduce__` that only appends a
  marker to an in-process list, a spawn-argv recorder, and a generic in-process
  marker list. Each run points `AIRLOCK_AUDIT_LOG_PATH` at a temp file, never the
  checkout.
- **41 adapters** (`adapters/`): the 38 bypass targets plus three value-gate
  adapters the oracle anchors on (`deserialization_guard`, `filesystem`,
  `endpoint`). Modes A (policy field), B (config gate), C (standalone). The map is
  [`adapters_table.md`](adapters_table.md); the executable truth is
  `adapters/registry.py`.
- **A resumable, append-only ledger** (`ledger.py`, schema 1): one JSON file per
  `(guard, seed[, nohints])` at `ledger/<guard>/<guard>.seed<NN>[.nohints].json`.
  A paused wave resumes by skipping candidate ids already recorded.
- **Statistics** (`stats.py`): a rule-of-three 95% upper bound on the bypass rate
  for a null (`0/n → ≤ 3/n`), a Wilson upper bound for a non-null, outcome
  histograms, and queries-to-plateau.

## Running one attack session

```bash
export PYTHONPATH="$PWD/src:$PWD"
PY=/path/to/.venv/bin/python   # hypothesis / rfc3986 / yarl / httpx installed

# 1. See the targets and their seed counts.
$PY -m benchmarks.adaptive_redteam.run_session --list-guards

# 2. Bootstrap a candidate file from the adapter's own controls.
$PY -m benchmarks.adaptive_redteam.run_session \
    --guard ssrf_egress_guard --seed 0 --emit-controls > cands.json

# 3. (An attacker agent appends ~100 CallSpec candidates to cands.json,
#     reading each transcript line to refine the next.)

# 4. Run the session (resumable; re-running skips completed candidate ids).
$PY -m benchmarks.adaptive_redteam.run_session \
    --guard ssrf_egress_guard --seed 0 --candidates cands.json
```

Add `--nohints` for the fix-hints-off ablation arm (the transcript then omits the
guard's `fix_hints`, and the ledger lands at `...seed00.nohints.json`).

## Candidate file format

A JSON list, or `{"candidates": [...]}`. Each candidate:

```json
{
  "candidate_id": "ssrf-0007",
  "intent": "attack",
  "call": {"args": [], "kwargs": {"url": "http://169.254.169.254/"}, "sequence": []}
}
```

`guard`, `seed` and `candidate_id` default from the CLI if omitted. `intent` is
`"attack"` (default) or `"benign"` (a control the guard must admit). `sequence`
is for the stateful guards (`sequence_guard`, `action_contradiction_gate`): each
entry is a prior `CallSpec` replayed before the scored call.

## What a run proves, and what it does not

A clean seed — `0/n` bypasses — publishes as `0/n (≤ 3/n at 95%)`, never as "the
guard is safe". An automated null leaves room for a bypass a human could find.
See [`RESULTS.md`](RESULTS.md) (waves 1–3 run at seed 0 on 2026-10-15; the full
multi-seed campaign continues after the merge) and the dated page at
`docs/benchmarks/adaptive-redteam.md`.

The campaign plan (waves, seeds, severity rubric) is
[`waves.json`](waves.json); the attack-session prompt skeleton is
[`prompts/attacker.md`](prompts/attacker.md).
