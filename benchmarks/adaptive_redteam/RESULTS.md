# Adaptive red-team — results

Campaign harness that drives harmless sentinels through agent-airlock's 38
bypass-target guards (plus three value-gate adapters) to find fail-opens. No LLM
judge: a `bypass` requires the guard to admit a candidate **and** an independent
reference detector to confirm the forbidden shape reached a sentinel sink. See
[`benchmarks/adaptive_redteam/README.md`](https://github.com/sattyamjjain/agent-airlock/blob/main/benchmarks/adaptive_redteam/README.md)
and the adapter map in
[`adapters_table.md`](https://github.com/sattyamjjain/agent-airlock/blob/main/benchmarks/adaptive_redteam/adapters_table.md).

## Status: waves 1–3 run 2026-10-15 (seed 0)

Wave 1 ran the three value-gate adapters (`deserialization_guard`, `filesystem`,
`endpoint`), each in the `hints` and `nohints` arms, at seed 0, against airlock
0.10.24 / source SHA `a85551e` (a frozen snapshot worktree). Six Opus attack agents
produced **491 attack candidates** in all (plus 66 benign controls); the harness
executed and scored every one. **Oracle-scored bypasses: 0/491.** Wave 2 (11 SSRF /
eval-RCE / path / spawn / stdio guards) and wave 3 (a control baseline across the 27
lower-surface guards plus a focused differential probe) have since run at seed 0 — see
their sections below. The remaining seeds in
[`waves.json`](https://github.com/sattyamjjain/agent-airlock/blob/main/benchmarks/adaptive_redteam/waves.json)
(wave 1 is specified at 10 / 10 / 10 seeds) and the full multi-seed wave-3 attack
matrix are **not yet run** (`n=0`), and continue after the merge.

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

## Wave 2 — 2026-10-15 (SSRF / eval-RCE / path / spawn / stdio guards, seed 0, hints arm)

Wave 2 ran 11 guards against airlock 0.10.24 / SHA `7582b68` (the snapshot including the
wave-1 fixes). Eleven Opus attack agents produced **496 attack candidates** (plus benign
controls).

**Harness-fidelity caveat — read before any count.** Most mode-C adapters are wired with
the `StandaloneAdapter` default `reference=lambda _call: True` and a *symbolic* in-process
sink, so the oracle scores **every admitted attack-intent candidate as a "bypass" with no
independent confirmation** that the admitted value is actually the forbidden shape. Only
`eval_rce_guard` (a `\b`-boundary sink reference) and `ssrf_egress_guard` (a stdlib
`ipaddress` reference) carry a real independent detector. So the raw tally — **338 admits
over 496 attack candidates** — is *"the guard admitted an attack-labelled probe,"* **not**
338 confirmed fail-opens, and must not be published as one. Each admit was triaged by hand
against the guard's own code; the genuine fail-opens are below, and a harness follow-up
(give each mode-C adapter a real reference detector, or flip the default to fail-safe so an
unconfirmed admit scores `benign_pass`, not `bypass`) is **F17**, fixed in 0.10.25.

Two findings were **oracle-anchored** (confirmed by the real reference detectors) and are
fixed:

| ID | guard | finding | severity | status |
|---|---|---|---|---|
| F3 | `ssrf_egress_guard` | IETF-reserved / unallocated IP space (IPv6 `200::/7`…`fe00::/9`, IPv4 `240/4`) admitted — no `is_reserved` catch | High | **fixed 0.10.25** (`020a3b7`) |
| F4 | `eval_rce_guard` | eval-family call on a non-identifier receiver (`get_evaluator().eval(`, `.eval(`) — sink regex excluded `.` from its boundary | High | **fixed 0.10.25** (`020a3b7`) |

The rest are **hand-triaged genuine fail-opens** (confirmed by reading the guard, not by the
over-reporting oracle); each landed as a failing regression test + `fix(security):` in 0.10.25
(all in `tests/test_redteam_wave2_findings_0_10_25.py`):

| ID | guard | finding | severity | status |
|---|---|---|---|---|
| F5 | `config_path_guard` | `~` not `expanduser`'d in `command`/`args`/`env` (only `workingDirectory` is); env `/`-prefilter skips a bare `..`/`~` | High | **fixed 0.10.25** |
| F6 | `stdio_meta_guard` | `evaluate()` never inspects `env`, so `env={"LD_PRELOAD":…}` (DYLD_*, BASH_ENV, NODE_OPTIONS, …) → allow → RCE at spawn | High | **fixed 0.10.25** |
| F7 | `subprocess_arg_guard` | only top-level keys checked, so a nested `{"mcpServers":{"x":{"command":"bash",…}}}` config is not recursed | — | **RETRACTED on triage** — intentional scope boundary (see below) |
| F8 | `subprocess_arg_guard` | dangerous-env **denylist** missed LD_AUDIT, GCONV_PATH, RUBYLIB, PERL5OPT, CLASSPATH, JAVA_TOOL_OPTIONS, PYTHONHOME, DYLD_FALLBACK_* | High | **fixed 0.10.25** (broadened set) |
| F9 | `stdio_guard` | joined `-cCODE` defeats the `^-c$` deny (Python reads `-cXXX` as `-c XXX`) — inline RCE even under the shipped OX preset | High | **fixed 0.10.25** |
| F10 | `stdio_guard` / `mcp_proxy_guard` | relative `argv[0]` matched by `basename` only, no traversal check (`../python`, `evil/python`) — planted binary admitted | High | **fixed 0.10.25** |
| F11 | `stdio_guard` | U+2028/U+2029 line terminators + directional marks (LRM/RLM/ALM) pass the newline / Trojan-Source model the docstring claims | Medium | **fixed 0.10.25** |
| F12 | `stdio_command_injection_guard` | `DEFAULT_SHELL_METACHARS` omits single `&` (separator), `<`/`>` redirection, `<(`/`>(` process substitution | Medium | **fixed 0.10.25** |
| F13 | `loopback_spawn_guard` | wrapper option-arg consumption (`env -u python bash` latches `python`, execs `bash`); also 3 false refusals on legit `env -u FOO python` | High | **fixed 0.10.25** |
| F14 | `mcp_proxy_guard` | attached/combined `-cCODE`/`-Ic` and `-m` module-exec defeat the preset's `^-c$` (overlaps F9) | Medium | **fixed 0.10.25** |
| F15 | `filter_eval_rce_guard` | lambda param-list regex `[\w\s,*]*` misses default args / positional-only `/` (CVE-2026-25592 class); C# `Expression . Lambda` whitespace; Razor `@(eval(…))` never implemented despite docstring | High | **fixed 0.10.25** |
| F16 | `argv_guard` | single-token flag injection (`--kubeconfig=/etc/shadow`) admitted — guard blocks space-concatenation only (CVE-2026-39884 class) | High | **fixed 0.10.25** |
| F17 | *harness* | most mode-C adapters lacked an independent reference detector, so admits over-reported as bypasses | n/a (harness) | **fixed 0.10.25** (fail-safe default) |

**F7 retracted (intentional scope boundary).** The wave-2 agent read `subprocess_arg_guard`
not recursing into a nested `mcpServers` map as a fail-open. On human triage it is a
*deliberate, documented* design decision: the guard validates **one** spawn config, and the
integration contract is that the caller iterates a nested server map and checks each entry.
Auto-recursing would both contradict that contract and read arbitrary nested data as spawn
configs (false positives). The boundary is pinned by
`tests/cves/test_cve_2026_42271_kev_regression.py::TestScopeBoundary` and
`test_cve_2026_90898_bifrost_stdio_registration.py` (e.g. "passing the whole request body
protects nothing"). The recursion added in the first pass was reverted; F8 (the env-denylist
breadth, an independent improvement) stands.

**Excluded — not guard defects** (recorded so they are not re-raised): `eval_rce` `parse_expr`
with a pinned `local_dict=`/`global_dict=` is the CVE-2026-44717 *safe* form and is
correctly admitted; `argv_guard` skipping non-string slots is documented by-design;
`config_path` admitting a `\`-path under `platform=auto` on a POSIX host is arguable (the
risk is cross-platform); and several `mcp_proxy` / `subprocess_arg` admits are closed by the
shipped preset or are an operator allowlist choice (allowlisting an interpreter). An
automated run at one seed with an over-reporting oracle is not a safety proof; these are the
fail-opens a careful read of the guards confirmed, and the list may not be exhaustive.

## Wave 3 — 2026-10-15 (lower-surface inspection guards, seed 0, hints arm)

Wave 3 covers the 27 lower-surface guards. A control baseline ran every one of them at
seed 0 (each adapter's `known_blocked` shape and its benign control): all 27 `hard_block`
their blocked shape and `benign_pass` their control — **0 bypasses, 0 harness errors** —
which proves the adapters are wired to a real refusal and a real admit. One harness bug
surfaced and was fixed first: `run_session._fix_hints_of` crashed on
`description_manifest_guard`, whose decision object exposes `fix_hints` as a *method*, not
an attribute (`890b4bd`).

Most wave-3 adapters have no independent reference detector (the F17 fail-safe default), so
the harness cannot auto-confirm a fail-open on them; candidates are triaged by hand against
the guard's logic and, where there is a physical effect, against ground truth. A focused
parser-differential probe of the network-binding guards — the class that produced wave-1 F2
and wave-2 F3 — found one genuine fail-open, confirmed against the OS socket parser rather
than the harness oracle:

| wave | guard | finding | severity | status |
|---|---|---|---|---|
| 3 | `bind_address_guard` | every kernel-lenient spelling of `0.0.0.0` admitted — `0`, `0x0`, `00.00.00.00`, `000.000.000.000`, `0x0.0x0.0x0.0x0`, `0.0.0`, `0.00.0.0` (all `inet_aton` → `0.0.0.0`); `_is_public_bind` checked only the literal set + a strict `ipaddress` parse | High | **fixed 0.10.25** |

### F18 — `bind_address_guard` kernel-lenient all-interfaces spellings (High, fixed in 0.10.25)

The guard refuses binding to all interfaces (CVE-2026-23744). `_is_public_bind` matched a
literal blocklist (`0.0.0.0`, `::`, `[::]`, `0:0:0:0:0:0:0:0`) and a strict `ipaddress`
parse, but the socket layer's own IPv4 parser (`inet_aton`) also accepts octal, hex,
bare-integer and short-dotted forms. A server handed `0`, `0x0`, `00.00.00.00` or `0.0.0`
binds to `0.0.0.0` on every NIC — the exact surface the guard exists to refuse — and
`ipaddress` rejected every one of them, so the guard let them through. Confirmed against
ground truth with `socket.getaddrinfo` / `inet_aton` (resolution only, never a live bind):
each maps to `0.0.0.0`. `_is_public_bind` now adds an `inet_aton` layer; a real address
(`127.0.0.1`, `2130706433` → loopback, `1` → `0.0.0.1`) still passes, so no false positives.
The sibling `lan_unauth_rce_guard` was checked and needs no change — its `_is_lan_bound`
treats an `ipaddress`-unparseable address as LAN-bound, so the lenient spellings are blocked
there already (fail-safe, not fail-open).

### Also probed, no fail-open found

Three more guards got a focused differential probe at this pass and were clean **within
their documented threat model** (recorded so the negative result is not re-derived):

- `mcp_origin_host_guard` and `ws_origin_guard` (the DNS-rebinding / cross-origin class,
  CVE-2026-11624): exact normalized set-membership with port stripping. Every adversarial
  authority shape tried — suffix (`ok.example.evil.com`), prefix (`xok.example`), `\`,
  `%00`, CR/LF/TAB injection, trailing dot, `wss://`, scheme/port mismatch — is correctly
  denied. `Host: ok.example:8080@evil.com` is admitted (its `_strip_port` reads the host as
  `ok.example`), but that is **not** a browser-reachable rebinding bypass: a browser derives
  `Host` from the URL authority, and in `http://ok.example:8080@evil.com/` the host the
  browser dials and sends is `evil.com`, which is denied. Noted, not fixed.
- `env_interpolation_guard` (secret-exfil via env interpolation, CVE-2026-32625): every
  named-variable form in scope is denied — `${VAR}`, `${VAR:-x}`, `${VAR#x}`, `${ VAR }`,
  `$VAR`, `%VAR%`. The admitted shapes (`$(cmd)`, backticks, `$$VAR`, `${!VAR}`) are outside
  the guard's stated shell-style named-interpolation scope: `$(…)`/backticks are command
  substitution (an RCE class, not this guard's), `$$VAR` is a PID in shell (not a leak), and
  `${!VAR}` is indirect expansion that does not resolve the named secret directly.

### Scope of this pass

This was a control baseline across all 27 guards plus a focused differential probe of the
binding, origin/host and env-interpolation guards, **not** the full ~100-candidate attack
session on every guard at every seed. The full multi-seed wave-3 campaign continues after
the merge (`waves.json`), run by Opus attack agents out of band. A `0/n` control baseline is
not a safety proof, and a careful human read of the remaining low-surface guards may still
find fail-opens.

## Provenance

Per-seed ledgers (`ledger/<guard>/<guard>.seed<NN>[.nohints].json`) are raw run
output and are gitignored; only this aggregate and any summary JSON are committed.
Each ledger header records the airlock version, source SHA, adapter mode, arm
(`fix_hints` true/false), seed and candidate budget.
