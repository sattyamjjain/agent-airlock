# Module: tests/cves

<!-- AUTO-MANAGED: module-description -->
## Purpose

Regression tests that replay a disclosed CVE's or advisory's tool-call shape and assert an
airlock primitive refuses it — a **second defence** at the argument seam, not the upstream
fix. The commit-message and catalog rules for this directory are in the root `CLAUDE.md`;
what counts as in scope is in `docs/cve-triage.md`.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: architecture -->
## Module Architecture

- **The filename decides catalog membership.** `scripts/gen_cve_catalog.py` globs
  `test_cve_*.py` only, so a CVE module named any other way gets no row in
  `docs/cves/index.md`. Name them `test_cve_<yyyy>_<n>_<slug>.py` (`<n>` unpadded);
  advisories with no CVE id of their own take a descriptive `test_<slug>.py`.
- **`fixtures/*.json`** hold per-advisory payloads. Shapes vary, but every file needs an ISO
  `disclosed_at` or `scripts/egress_bench.py` exits 2; the walker grades only fixtures in its
  `_DISPATCH` table and prints `# SKIP` for the rest. **`corpora/*.json`** are block-rate
  corpora, one of which feeds `BENCHMARK.md`.
  `grep -rlE 'cves.{0,6}(fixtures|corpora)' tests scripts src` finds every outside reader.
- **Nothing here ships** — the sdist and wheel take `src/` only — so no preset may load data
  from `fixtures/`. One did, and failed open for every `pip install` user; its block-list
  now lives inline in `policy_presets.py`.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Module-Specific Conventions

- **Docstring header.** The canonical format is the module docstring of
  `scripts/gen_cve_catalog.py`. The opening `"""` line must be the CVE id then a title;
  labelled fields (`Advisory:`, `NVD:`, `CVSS:`, `Airlock fit:`) must start at column 0 —
  an indented field is silently dropped. `--write` only warns about an unparseable module;
  `--check`, the CI gate, fails on it.
- **Presets.** A module that adds a preset pins that preset's `cves` tuple and its
  `list_active()` entry. A second-defence module that reuses an existing guard asserts the
  reverse — the preset does *not* claim the CVE — plus the watcher signal that admitted it;
  copy `TestScopeBoundary` and `TestWatcherAdmittedThisOn*` from
  `test_cve_2026_77521_maxkb_sandbox_shell.py`.
- **No mocks.** The only `unittest.mock.patch` fakes `socket.getaddrinfo`
  (`test_ox_supply_chain_2026_04.py`); everything else runs against real fixtures. Tests on
  the allow path resolve real public hosts, so a few of them fail offline.
- **A refusal needs no module**: one `docs/cve-triage.md` disposition on the triage issue
  and one row in the out-of-scope table in `tests/cves/README.md`.
- **Any real CVE id written in a `.py` or `.md` here — this file included — marks that CVE
  as tracked** for `scripts/cve_watcher.py`, which then never files it. Use placeholders
  such as `CVE-YYYY-NNNNN` in examples.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: dependencies -->
## Key Dependencies

- **Nothing optional.** No module imports an extra or carries `importorskip`, a skip mark
  or a `docker` mark, so every test here runs in CI's `test` job.
- **Count gates.** `tests/test_cve_catalog_gate.py` pins literal module and distinct-CVE
  totals, and the README's ASI04 row and `.claude-plugin/marketplace.json` repeat them.
  Adding or removing a module means editing all three, unless it is listed in
  `_NON_DISCLOSURE_CVE_MODULES` (`tests/test_marketplace_metadata.py`).
- **Fixture gates.** CI exercises the fixtures through `tests/cli/test_egress_bench_since.py`
  and `tests/test_numeric_claim_parity.py`; no workflow runs `make egress-bench`. Fixtures
  are not hash-pinned; per `AGENTS.md`, removing one cites its advisory and adds a successor.

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Notes

Add module-specific notes here — this section is never auto-modified.

<!-- END MANUAL -->
