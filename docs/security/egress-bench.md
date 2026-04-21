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

## Coverage as of v0.5.3

```
1..3
ok 1 - CVE-2026-33032 (blocked 12/12)
ok 2 - CVE-2026-30616 (blocked 10/10)
ok 3 - OX-DOSSIER-2026-04 (blocked 10/10)
```

Three fixture categories, 32 payloads, zero slips.

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
   [`scripts/egress_bench.py`](../../scripts/egress_bench.py) that
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
