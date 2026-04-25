# `airlock egress-bench` — CVE fixture regression walker

**Script:** `scripts/egress_bench.py`
**CLI:** `airlock egress-bench` (also exposed as `agent_airlock.cli.egress_bench:egress_bench`)

The walker iterates `tests/cves/fixtures/*.json` and asserts every
documented attack payload is blocked by the corresponding agent-
airlock preset. CI gates on it; you can run it locally for a fast
"are we still covered?" check.

See `docs/security/egress-bench.md` for the original v0.5.3 contract.
This page documents the **v0.5.6+ additions**:

- `--since YYYY-MM-DD` flag for time-windowed coverage reports
- Required `disclosed_at` field on every fixture
- `--format json` filter metadata in output

## `--since YYYY-MM-DD` — time-windowed coverage

Filters fixtures to those whose `disclosed_at` is on or after the
given ISO date. Useful for security-team reporting along the lines of
"what April 2026 CVEs are we now blocking?".

```bash
# Only April-2026 CVEs:
airlock egress-bench --since 2026-04-01

# Only the OX dossier wave (2026-04-20):
airlock egress-bench --since 2026-04-20

# JSON output with filter metadata:
airlock egress-bench --since 2026-04-20 --format json
```

Sample TAP output, `--since 2026-04-20`:

```
1..8
ok 1 - # SKIP archived_mcp_servers_2026_04: disclosed_at 2026-04 < --since 2026-04-20
ok 2 - # SKIP cve_2026_23744_mcpjam: disclosed_at 2026-04 < --since 2026-04-20
ok 3 - # SKIP cve_2026_33032_mcpwn: disclosed_at 2026-04-09 < --since 2026-04-20
ok 4 - # SKIP cve_2026_39884_kubectl_argv: disclosed_at 2026-04-14 < --since 2026-04-20
ok 5 - # SKIP cve_2026_41349_consent_bypass: disclosed_at 2026-04-23 ...
ok 6 - # SKIP cve_2026_5023_codebase_mcp: disclosed_at 2026-04-15 < --since 2026-04-20
ok 7 - # SKIP ox_stdio_payloads: disclosed_at 2026-04-16 < --since 2026-04-20
ok 8 - OX-DOSSIER-2026-04 (blocked 10/10)
```

## ISO-date format

`--since` and `disclosed_at` accept three precisions:

| Format | Normalised to |
|---|---|
| `2026` | `2026-01-01` |
| `2026-04` | `2026-04-01` |
| `2026-04-25` | `2026-04-25` |

Anything else (`2026/04/25`, `April 25 2026`, `2026-4-25` without a
leading zero) raises `FixtureValidationError` and exits 2.

## Required fixture field — `disclosed_at`

Every fixture under `tests/cves/fixtures/` must carry a top-level
`disclosed_at` string. Missing it raises `FixtureValidationError` at
parse time, even when `--since` isn't passed — the walker won't
silently skip a malformed fixture.

```json
{
  "cve": "CVE-2026-XYZAB",
  "disclosed_at": "2026-04-25",
  "primary_source": "https://example.com/...",
  "payloads": [ ... ]
}
```

For umbrella fixtures (e.g. `ox_supply_chain_2026_04.json`, which
covers 10 distinct CVEs at once), each sub-entry can also carry its
own `disclosed_at` — useful when the umbrella publication date and
the per-CVE NVD entry differ.

## JSON output

`--format json` produces a payload that includes filter metadata so
downstream report generators can render the filter context:

```json
{
  "filter": {
    "since": "2026-04-20"
  },
  "rows": [
    {
      "cve_id": "OX-DOSSIER-2026-04",
      "payload_count": 10,
      "blocked": 10,
      "unblocked": 0,
      "status": "pass",
      "reason": "fixture metadata + source citations",
      "disclosed_at": "2026-04-20"
    }
  ]
}
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | every payload blocked (or marked `expected_unblocked: true`) |
| `1` | at least one payload slipped through |
| `2` | fixture parse / validation error, or invalid `--since` value |

## Primary source

- v0.5.5 commit [17478448](https://github.com/sattyamjjain/agent-airlock/commit/17478448b7025688ded72382c8aae7d528273563)
  introduced the bench skeleton; v0.5.6 adds `--since`.
