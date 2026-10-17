# Module: benchmarks/adaptive_redteam

Subtree conventions for the adaptive red-team campaign. These extend
`benchmarks/CLAUDE.md`; where they differ, the stricter rule wins.

## Scope and safety (load-bearing)

- **Harmless sentinels only.** The campaign drives a canary file, a 127.0.0.1
  listener, a `__reduce__` that appends a marker to an in-process list, and a
  spawn-argv recorder. Never author, commit, or run a working exploit, a real
  reverse shell, a real credential, or a payload that would do harm if the guard
  let it through. A blocked candidate is a *shape* the guard refuses, not a live
  attack.
- **No LLM judge, ever.** Ground truth is a sentinel reaching a sink plus an
  independent reference detector — not a model's opinion. Do not add a scoring
  path that asks a model whether something was a bypass.
- **No network beyond 127.0.0.1, no paid API, no secrets.** The attack agents
  that author candidate files run on the Max plan out of band; this package only
  executes and scores the JSON they produce.
- **Audit logs stay out of the checkout.** Every canary run sets its own
  `AIRLOCK_AUDIT_LOG_PATH` under a temp dir (`canaries.canary_env`). Never let a
  run write `airlock_audit.json` into the tree.

## Reporting conventions

- **Nulls ship as nulls.** A clean seed is `0/n (≤ 3/n at 95%)`, never "safe" and
  never `0%`. An unrun arm is "not yet run" / `n=0`, never `0`. `RESULTS.md` lists
  only the waves and seeds the coordinator actually ran, and every published
  number carries its denominator and run date (UTC).
- **State the scope inline.** Say in the same sentence that an automated null
  leaves room for a human-found bypass, that a symbolic-sink finding needs human
  triage, and which seeds / candidate budget produced a number.
- **A finding stays on the record beside its fix.** If a wave finds a real
  bypass, it becomes a failing regression test then a `fix(security):`; the old
  figure stays next to the correction (the `benchmarks/CLAUDE.md` "nothing is
  dropped" rule).
- **Symbolic vs physical sinks.** A bypass on a physical-sink adapter
  (filesystem, egress, deserialization, spawn) is ground truth. A bypass on a
  symbolic-sink adapter (the pure validators) is a candidate finding that an
  independent reference detector flagged — record it, but triage it by hand before
  claiming it.

## Resume and determinism

- The ledger is append-only and resumable: a re-run skips candidate ids already
  recorded (`Ledger.completed_ids`). A 5-hour or weekly limit pausing a wave must
  lose nothing — never truncate or rewrite a ledger's `attempts`.
- Per-seed ledgers are raw output and are **gitignored** (`.gitignore` here). Only
  aggregates (`RESULTS.md` and any summary JSON) are committed.
- Adapter control shapes (`known_blocked` / `benign_control`) must come from the
  guard's own behaviour — a shape its tests prove refused, and a benign shape it
  admits. `tests/test_adaptive_redteam_adapters.py` enforces this for all 41.

## Layout

- `oracle.py` — `Outcome`, `Intent`, `ForbiddenEffect`, `CallSpec`, `Candidate`,
  `Canary`, `Attempt`, `classify`.
- `canaries.py` — the five sentinel sinks + `canary_env` / `read_audit`.
- `adapters/` — `base.py` (protocol), `standalone.py` (C), `config_gate.py` (B),
  `policy_field.py` (A), `registry.py` (all 41), `adapters_table.md` is the map.
- `run_session.py` / `__main__.py` — the resumable CLI.
- `ledger.py` — schema-1 append-only ledger.
- `stats.py` — rule-of-three, histograms, plateau.
- `waves.json` — the wave plan and seed counts.
- `prompts/attacker.md` — the attack-session prompt skeleton.
- `RESULTS.md` — dated aggregate output: status, results table, per-wave sections,
  Findings. A wave or seed that has not run stays "not yet run" (`n=0`).

## Notes

Add module-specific notes here.
