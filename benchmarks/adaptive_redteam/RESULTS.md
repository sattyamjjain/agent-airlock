# Adaptive red-team — results

Campaign harness that drives harmless sentinels through agent-airlock's 38
bypass-target guards (plus three value-gate adapters) to find fail-opens. No LLM
judge: a `bypass` requires the guard to admit a candidate **and** an independent
reference detector to confirm the forbidden shape reached a sentinel sink. See
[`benchmarks/adaptive_redteam/README.md`](https://github.com/sattyamjjain/agent-airlock/blob/main/benchmarks/adaptive_redteam/README.md)
and the adapter map in
[`adapters_table.md`](https://github.com/sattyamjjain/agent-airlock/blob/main/benchmarks/adaptive_redteam/adapters_table.md).

## Status: wave 1 run 2026-10-15 (value gates, seed 0)

Wave 1 ran the three value-gate adapters (`deserialization_guard`, `filesystem`,
`endpoint`), each in the `hints` and `nohints` arms, at seed 0, against airlock
0.10.24 / source SHA `a85551e` (a frozen snapshot worktree). Six Opus attack agents
produced **491 attack candidates** in all (plus 66 benign controls); the harness
executed and scored every one. **Oracle-scored bypasses: 0/491.** The remaining
seeds in [`waves.json`](https://github.com/sattyamjjain/agent-airlock/blob/main/benchmarks/adaptive_redteam/waves.json)
(wave 1 is specified at 10 / 10 / 10 seeds) and waves 2–3 are **not yet run**
(`n=0`), and continue after the merge.

An automated null is not a safety proof. A `0/n` row means only that this harness,
with the candidates an Opus agent produced under a plateau budget at one seed, found
none — it leaves room for a bypass a human could find. Two such human-found leads
did surface here: the oracle could not score them (its reference detectors share
`urllib.parse` and do not model text pickles), so they were triaged by hand against
the live guards, confirmed admitted, and fixed in 0.10.25 — see **Findings** below.
Every number carries its denominator, run date (UTC), and the airlock version and
source SHA from the ledger header.

## Results table (fills in per wave)

Counts are over **attack-intent** attempts (`n`); benign-intent controls are counted
separately under *false refusals* (a benign control the guard refused). `bypass rate
(95% upper)` is the rule-of-three upper bound for a `0/n` null. All rows are seed 0,
airlock 0.10.24, SHA `a85551e`.

| wave | guard | seeds | arm | attempts (n) | hard_block | honeypot | bypass | benign_pass | false refusals | bypass rate (95% upper) | date |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | `deserialization_guard` | 0 | hints | 88 | 75 | 0 | 0 | 13 | 0/14 | 0/88 (≤ 3.4%) | 2026-10-15 |
| 1 | `deserialization_guard` | 0 | nohints | 82 | 55 | 0 | 0 | 27 | 0/10 | 0/82 (≤ 3.7%) | 2026-10-15 |
| 1 | `filesystem` | 0 | hints | 88 | 82 | 0 | 0 | 6 | 2/11 | 0/88 (≤ 3.4%) | 2026-10-15 |
| 1 | `filesystem` | 0 | nohints | 75 | 74 | 0 | 0 | 1 | 5/11 | 0/75 (≤ 4.0%) | 2026-10-15 |
| 1 | `endpoint` | 0 | hints | 70 | 67 | 0 | 0 | 3 | 0/7 | 0/70 (≤ 4.3%) | 2026-10-15 |
| 1 | `endpoint` | 0 | nohints | 88 | 77 | 0 | 0 | 11 | 0/7 | 0/88 (≤ 3.4%) | 2026-10-15 |
| 1 | **all value gates** | 0 | both | **491** | 430 | 0 | **0** | 61 | 7/60 | **0/491 (≤ 0.6%)** | 2026-10-15 |

No seed plateaued before its candidate budget except `endpoint/hints`, whose novelty
signature collapses once every shape lands the same `endpoint_blocked`; it was resumed
to completion (append-only, skipping done ids). `harness_error` was 0 in every cell.

**Host caveat (macOS).** The `filesystem` adapter's `FileCanary` stores the forbidden
root in `tempfile.mkdtemp()`'s unresolved `/var/folders/...` form but compares against
`os.path.realpath()`'s `/private/var/folders/...`, so a *physical* canary hit cannot
register on macOS — a genuine filesystem fail-open would score `benign_pass` here, not
`bypass`. The `filesystem` null is therefore corroborated by the attacker's
disjoint-roots analysis (admitted paths `realpath` into the allowed root, never the
forbidden one), not by a live physical sink; the canonical filesystem run belongs in a
Linux container (where `/tmp` is not a symlink). `deserialization_guard` and `endpoint`
use in-process / loopback sinks unaffected by this.

## Findings

Severity per the plan's rubric: Critical (default-posture taint), High (non-default,
honeypot/audit, kill switch), Medium (unreadable-shape fail-open), Low. A bypass on a
physical-sink adapter (filesystem, egress, deserialization, spawn) is ground truth; a
finding on a symbolic/parser-differential surface is one an attacker agent flagged by
reading the guard and that the oracle could not score, so it needs human triage before
it is claimed. Both findings below are the latter: they are **not** counted in the
`0/491` bypass total — they were triaged by hand against the live guards, confirmed
admitted, and each landed as a failing regression test plus a `fix(security):` in
0.10.25. Each stays on the record beside its fix.

### F1 — `deserialization_guard` admitted a text pickle behind leading whitespace (High, fixed in 0.10.25)

`UnsafeDeserializationGuard` admitted `"   cos\nsystem\n(S'id'\ntR."` — a protocol-0
GLOBAL-opcode (code-executing) pickle preceded by spaces. `_TEXT_PICKLE_GLOBAL` anchored
on `^` / `[\n(]` only, so non-newline leading whitespace moved the opcode off the anchor,
and the data-only branch needs a memo opcode this payload lacks. A tool that strips the
value before `pickle.loads` (or a lenient parser that skips leading whitespace) would
still execute it. The oracle's `_looks_serialized` does not model text pickles, so it
scored the shape `benign_pass`, not `bypass`. **Fix:** the GLOBAL/INST opcode is now
matched on the left-stripped value too. **Severity High:** the guard is opt-in
(non-default), but a gap in it is RCE-class when it is relied upon. Regression:
`tests/test_redteam_wave1_findings_0_10_25.py::TestTextPickleLeadingWhitespace`.

### F2 — backslash authority parser-differential SSRF (High, fixed in 0.10.25)

Both the endpoint gate (`network.validate_endpoint`) and `SSRFEgressGuard` admitted
`http://127.0.0.1\@api.allowed.example/`: `urllib.parse` reads the host as the
allowlisted `api.allowed.example` (the `\` sits in userinfo), but a WHATWG client
(browsers, several HTTP clients) treats `\` as `/`, ending the authority at `127.0.0.1`
— a loopback SSRF past the allowlist. The oracle's reference detector shares
`urllib.parse`, so it saw the benign host and scored `benign_pass`. **Fix:** a new
`network.authority_has_differential` refuses a backslash or raw tab/newline/CR anywhere
in the URL authority, before the allowlist check, at both call sites (new
`SSRFEgressVerdict.DENY_MALFORMED_AUTHORITY`). Backslashes in the path/query are
unaffected. **Severity High:** both guards are opt-in, but the gap defeats an endpoint
allowlist / SSRF control when configured. Regression:
`tests/test_redteam_wave1_findings_0_10_25.py::TestAuthorityParserDifferential`.

### Observations (not fail-opens, nothing changed)

- **`filesystem` over-refusal (deny-by-default, erring safe).** `_looks_like_path` flags
  any `/`-containing string (e.g. the MIME type `application/json`, or prose like
  `read-only and/or append`) as a path, so a benign call carrying one under a non-path
  key is refused. This is the safe direction and is left as is; it accounts for part of
  the `filesystem` false-refusal column, together with benign controls that genuinely
  resolve outside the single allowed root (relative paths → cwd; the allowed-root dir
  itself, refused `symlink_detected` via the macOS `/var`→`/private/var` symlink).
- **`fix_hints` ablation.** With hints hidden (`nohints`), attackers still found no
  bypass; the arm is kept for the fuller seed sweep where a hints-vs-nohints rate
  comparison becomes meaningful (one seed per arm here is too small to compare).

## Provenance

Per-seed ledgers (`ledger/<guard>/<guard>.seed<NN>[.nohints].json`) are raw run
output and are gitignored; only this aggregate and any summary JSON are committed.
Each ledger header records the airlock version, source SHA, adapter mode, arm
(`fix_hints` true/false), seed and candidate budget.
