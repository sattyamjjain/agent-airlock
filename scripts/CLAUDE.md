# Module: scripts

<!-- AUTO-MANAGED: module-description -->
## Purpose

The repo's claim gates and generators, run through `make` and CI: `check_*` claim gates,
the generators behind `make benchmark` / `test-badge` / `check-cve-catalog`, `smoke_*`
end-to-end drivers, `cve_watcher.py`, and `egress_bench.py` / `verify_corpus_manifest.py`
behind `make egress-bench` / `verify-corpus`. Nothing here ships. A gate exists so that a
claim drifting from the code fails CI instead of shipping (root `CLAUDE.md`, Git Insights).

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: architecture -->
## Module Architecture

Repo-specific claim gates. `make help` lists every target, and
`tests/test_makefile_help.py` fails if a target is missing from it or from `.PHONY`:

```bash
make benchmark               # regenerate BENCHMARK.md (guard-suite block-rate corpus)
make test-badge              # regenerate the TEST-BADGE block in README.md
make egress-bench            # CVE egress walker over tests/cves/fixtures/ (checkout only)
make verify-corpus           # verify wild_payload_corpus MANIFEST.sha256
make check-links             # dead relative links; docs/ pages must link inside docs/
make check-docs-api          # docs and example code use agent_airlock API that exists
make check-cve-catalog       # docs/cves/index.md matches the tests/cves/ suite
make check-docs              # mkdocs build --strict, built OUTSIDE the tree (see below)
make check-changelog         # drift: [Unreleased] must be empty while the version is released
make check-changelog-release # [Unreleased] must be NON-empty; this repo's flow never turns it green
make check-benchmark-freshness          # dated README rows, each paired by title with its
                                        # docs/benchmarks/index.md twin; every page in nav
make check-benchmark-freshness-release  # pre-tag: no benchmark claim older than 30 days
make check-registry-parity              # declared version must not outrun PyPI
make check-registry-parity-distance     # release-only: refuse to skip a version
```

What CI runs — `ci.yml` jobs, on PRs and pushes to `main`:

- `test` (full Python matrix) — installs `.[dev,redis,mcp,crypto]`, imports the redis,
  FastMCP and cryptography extras, then runs the five extra-backed test files and fails
  unless their summary is passes only (a skip, xfail, error or failure fails it); ruff
  check, mypy, pytest with the coverage floor; on 3.11 only, `generate_benchmark.py
  --check` and a pytest-benchmark smoke run that asserts the suite executes (deliberately
  not a latency threshold). Why those extras: `tests/CLAUDE.md`.
- `lint` — `ruff format --check` only.
- `docs` — `mkdocs build --strict`, `check_links.py`, `gen_cve_catalog.py --check`, and the
  **default** modes of `check_benchmark_freshness.py` and `check_changelog.py`.
- `bare-install` — `check_core_deps.py` against a no-extras install, an import of the
  package root, `agent_airlock.audit` and `policy_presets.list_active()` through the shim,
  then `check_bare_imports.py`, which imports every module under the package (what that
  enforces: `src/agent_airlock/CLAUDE.md`, Key Dependencies).
- `docker-sandbox` — the docker-marked tests, matched for an exact passed-count
  (`tests/CLAUDE.md`).
- `security` — bandit (`-c pyproject.toml`) and a CycloneDX SBOM; `safety` runs with
  `continue-on-error`, so it is advisory only.
- `version-tag-guard` (pushes to `main` only) — `check_version_tagged.py`,
  `check_changelog_heading.py`, `check_registry_parity.py`.

`publish.yml` (on a published release) adds `check_benchmark_freshness.py --release`,
`check_registry_parity.py --distance-only`, a GitHub-description drift check and
`twine check`. The upload authenticates through PyPI Trusted Publishing (OIDC), so the job
needs `id-token: write` and there is no PyPI token to add back. Its gate steps run before
it installs anything (it later installs only `build` and `twine`), so any script it runs
must stay stdlib-only. `cve-watcher.yml` polls NVD on a schedule, diffs against the ledger
and files triage issues; it is not a merge gate.

**Docs site.** The site is served from the `gh-pages` branch, which `docs.yml` rebuilds with
`mkdocs gh-deploy --force` on pushes to `main` that touch `docs/`, `mkdocs.yml`,
`src/agent_airlock/` or the workflow itself (or on `workflow_dispatch`). No
snippet-included file is a trigger path (no `benchmarks/**` path is), so a push that changes
only them redeploys nothing. The committed `site/` was a stale duplicate of the gh-pages
build (#151). `make check-docs` builds to `$TMPDIR/agent-airlock-mkdocs-check`, not
`./site/`, because even gitignored HTML in the working tree made project-classifying tooling
read this library as a web app. Generated files stay where their generator writes them:
`BENCHMARK.md` and the `RESULTS.md` files of `blockrate`,
`mcptox`, `fix_hints` and `adaptive_redteam` reach the site through `pymdownx.snippets`
includes under `docs/benchmarks/` (`grep -rn -- '--8<--' docs/` lists them; `check_paths` is
on, so a moved file fails the strict build); keep cross-tree links inside them absolute.
All are generated except `adaptive_redteam/RESULTS.md`, which is hand-written, so there the
absolute-link rule is an authoring rule.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Module-Specific Conventions

- **`make check-changelog-release` runs in no workflow, and this repo's release flow never
  turns it green**: release PRs write notes straight under the new `## [X.Y.Z]` heading, so
  `[Unreleased]` is already empty at the tagged commit. Do not satisfy it by leaving entries
  under `[Unreleased]`: once the version is bumped, the `docs` job's default-mode
  `check_changelog.py` fails on them.
- **`scripts/check_docs_api.py`** imports the package and skips a module whose extra is missing, so
  it runs in `test` as `tests/test_docs_api_gate.py`, where `[dev,redis,mcp,crypto]` are
  installed, rather than in `docs`, which installs the package with only `[docs]`. It checks
  names imported from `agent_airlock` in each Python fence of every authored markdown file
  (README included; `CHANGELOG.md` and `.github/` excepted) and in each `examples/` script:
  the import resolves, keywords match the signature, attributes exist. A fence that names
  `agent_airlock` but does not parse is a failure, not a skip.
- **Release checklist (version bumps).** Move every surface a test pins —
  `pyproject.toml` + `__version__`, `.claude-plugin/plugin.json`, `CITATION.cff` (the newest
  *published* version and its CHANGELOG date: a patch bump leaves it one behind, the most
  `test_version_consistency.py` allows, and an X.Y.0 bump must cite X.Y.0), the supported
  minor line in `SECURITY.md`, the README badge (`make test-badge`) — and add a dated
  `## [X.Y.Z] - YYYY-MM-DD` CHANGELOG heading (`test_changelog_headings.py`, and
  `check_changelog_heading.py` in `version-tag-guard`). Tag `vX.Y.Z` within one commit of
  the bump, or `version-tag-guard` turns `main` red. Push the tag as soon as the squash
  merge lands: the merge's own push run also runs `check_registry_parity.py`, which fails on
  a dated CHANGELOG section with no tag yet (re-run that job once the tag exists).
- **`make test-badge`** rewrites only the README badge (test count, coverage, version). The
  hand-written copies must match it in the same commit: every count and `(vX.Y.Z = N)` pair
  under `docs/distribution/` (`test_numeric_claim_parity.py`) and the `N tests` proof point
  in `.claude-plugin/marketplace.json` (`test_marketplace_metadata.py`).
- **Benchmark pages.** A new page under `docs/benchmarks/` must be added to the `mkdocs.yml`
  nav, and each README benchmark row's date must match its own row in
  `docs/benchmarks/index.md`, paired by title, so a row retitled on one page only fails too.
  `check_benchmark_freshness.py` fails on either gap in both modes; only the 30-day age
  check is `--release`-only.
- **README gates.** The README was cut by roughly nine-tenths and its size gated
  (`tests/test_readme_shape.py`, #180: line and word ceilings, code in the first screenful,
  no table of contents), and its framework and version-pin claims are gated too; long-form
  material belongs in `docs/`.
- **`smoke_*.py`** build the wheel, install it into a throwaway `.smoke-<name>-venv/`
  (network needed) and drive one guard or preset through the installed package (in
  `smoke_explain.py`, the `airlock-explain` console script), which an editable-tree unit
  test cannot show. No workflow runs them; a failed run leaves its `.smoke-*` directory
  behind (gitignored). Add one only when a unit test is not enough. `smoke_frameworks.py`
  is different: a framework matrix with one venv per framework under
  `.smoke-frameworks-venv/<key>/`, whose `--run --budget-usd N` makes paid Claude calls with
  `ANTHROPIC_API_KEY` (ask first) and whose `--write` rewrites the SMOKE-MATRIX block in
  `docs/COMPATIBILITY.md`.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: dependencies -->
## Key Dependencies

The scripts `publish.yml` runs before it installs anything must stay stdlib-only (see
above). `check_docs_api.py` imports the package, so it needs the extras the `test` job
installs. `generate_benchmark.py` imports the package and, inside a function,
`benchmarks.blockrate`.

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Notes

Add module-specific notes here — this section is never auto-modified.

<!-- END MANUAL -->
