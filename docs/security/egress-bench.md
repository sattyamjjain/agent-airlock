# Agent Egress Bench

The egress bench walks `tests/cves/fixtures/*.json` and asserts every
documented payload is blocked by the corresponding preset. It runs in
three surfaces:

1. **Local dev loop** — `make egress-bench`
2. **Programmatic** — `python3 -c "from agent_airlock.cli import egress_bench; egress_bench()"`
3. **CI** — a GitHub Actions job (sample at
   [`docs/security/egress-bench-ci.yml.sample`](egress-bench-ci.yml.sample);
   a maintainer with `workflow` scope must copy it into
   `.github/workflows/`)

## Output formats

```bash
python3 scripts/egress_bench.py --format tap    # TAP protocol
python3 scripts/egress_bench.py --format json   # machine-readable
python3 scripts/egress_bench.py --format md     # Markdown table for PR bodies
```

## Coverage

The walker emits one TAP line per fixture in `tests/cves/fixtures/`. Fixtures without a
dispatcher are reported as `SKIP` rather than silently dropped, so the plan line counts
every fixture on disk while only the dispatched ones are graded:

```
1..12
...
ok 6 - CVE-2026-33032 (blocked 12/12)
...
ok 11 - CVE-2026-30616 (blocked 10/10)
ok 12 - OX-DOSSIER-2026-04 (blocked 10/10)
```

Three graded fixture categories, 32 payloads, zero slips. The remaining fixtures are
carried for other guards and have no egress dispatcher yet — a `SKIP` is an honest "not
measured here", not a pass.

These three numbers are re-derived from a live walk by
`tests/test_numeric_claim_parity.py::TestEgressBenchDocClaims`, so they fail CI if a
fixture change moves them.

## Fixture contract

Every fixture under `tests/cves/fixtures/*.json` must carry:

- A `$schema` top-level note explaining what the file documents.
- Either a `payloads` / `destructive_tools` / `cves` array.
- A `source` per payload citing the primary CVE or write-up URL.

The bench refuses to run (exit 2) on malformed fixtures — this keeps
the dossier honest.

## Adding a new fixture

1. Drop the JSON into `tests/cves/fixtures/`.
2. Add a dispatcher entry to `_DISPATCH` in
   [`scripts/egress_bench.py`](https://github.com/sattyamjjain/agent-airlock/blob/main/scripts/egress_bench.py) that
   knows how to unpack the fixture shape and call the matching preset.
3. Run `make egress-bench` locally.
4. Commit both the fixture and the dispatcher update together.

## Motivating incident

OX Security published the ["Mother of All AI Supply Chains"
dossier](https://www.ox.security/blog/mother-of-all-ai-supply-chains-2026-04-20)
on **2026-04-20** — 10+ coordinated MCP-ecosystem CVEs in a single
report. Without a fixture walker, a silent regression in any one
preset could un-catch a previously-covered CVE. The bench makes that
impossible.
