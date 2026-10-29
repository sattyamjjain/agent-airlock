# agent-airlock

<!-- AUTO-MANAGED: project-description -->
## Overview

**agent-airlock** — an in-process, deny-by-default contract layer and type-checker for AI
agent tool calls. It intercepts calls into MCP (Model Context Protocol) servers and agent
frameworks, validates arguments strictly, applies policy, and sandboxes dangerous execution.
The wedge is argument validation at the call boundary; every other layer wraps it.

**The installed core is Pydantic-only** (plus `tomli` on Python 3.10); everything else,
structlog included, is an extra (`src/agent_airlock/_log.py` falls back to a stdlib shim).
`scripts/check_core_deps.py` enforces it as an exhaustive allowlist: add no core dependency.

**Detail lives next to the code** and loads when you touch that tree; read the one for an
area before changing it. `src/agent_airlock/CLAUDE.md`: what ships, the module map, every
step of the call path, package patterns. `src/agent_airlock/mcp_spec/` and
`src/agent_airlock/integrations/`: guards and adapters. `tests/`: test layout and the CI jobs
that couple to tests. `tests/cves/`: the signed CVE suite and triage. `scripts/`: claim gates,
CI jobs, the release checklist. `benchmarks/` and, hand-written to extend it,
`benchmarks/adaptive_redteam/`. `**/CLAUDE.md` is excluded from the sdist and wheel
(`[tool.hatch.build.targets.*]`), so the ones under `src/` never reach site-packages.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: build-commands -->
## Build & Development Commands

```bash
pip install -e ".[dev]"            # editable install with dev deps
# Optional extras — install only what you need. Full set:
#   logging bench sandbox modal mcp claude-agent model-armor console
#   redis crypto attested pydantic-ai crewai google-adk all dev docs
pip install -e ".[all]"            # runtime extras EXCEPT modal, bench, attested (and dev/docs)

make test          # pytest tests/ -v --no-cov
make lint          # ruff check + ruff format --check + mypy src/
make format        # ruff format + ruff check --fix
make coverage      # pytest with coverage (floor enforced; see [tool.coverage.report])
make bench         # pytest-benchmark suite (tests/benchmarks/, --ignore'd by default addopts)
make test-live     # tests/live against the real API: needs ANTHROPIC_API_KEY, spends credit
make help          # every target, the claim gates included (scripts/CLAUDE.md)
```

Docker integration tests are **opt-in** (default `addopts` carries `-m 'not docker'`; run
them with `pytest -m docker`). CI is `ci.yml` (`test`, `lint`, `docs`, `bare-install`,
`docker-sandbox`, `security`, `version-tag-guard`) on PRs and pushes to `main`, plus
`publish.yml` on a published release. None is a required check (`main` has no branch
protection; its one ruleset is disabled), so red blocks a merge by convention only.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: architecture -->
## Architecture

`src/` layout, single package, hatchling build. The `airlock` console script is one
dispatcher over every `agent_airlock.cli.<name>:main(argv)`. Repo-level directories outside
the package: `tests/`, `benchmarks/`, `scripts/`, `docs/` (mkdocs source), `examples/`,
`demo/` (runnable live demo), `presets/`, `schemas/`, `tools/`, `.claude-plugin/` (plugin
and marketplace manifests).

**Call flow through `@Airlock`** (`core.py`): `_pre_execution` gates, then execute, then
`_post_execution`. The numbers match the `# Step N` comments in `core.py`:

0. Kill switch → 0.5 startup-hook self-check → 0.6 OAuth token audience (both off until
   configured)
1. Ghost arguments (BLOCK / STRIP_AND_LOG / STRIP_SILENT)
2. Policy and caller identity → 2.5 tool-call sequence guard → 2.6 action-time
   contradiction gate → 2.7 unsafe-deserialization guard → 2.8 per-run amplification budget
3. Filesystem paths → 4. capability requirements → 5. endpoint policy → 6. per-model-tier
   budget
7. Execute: Pydantic strict validation, then run locally or in the sandbox
8. `_post_execution`: sanitize output, audit log, mark untrusted output, reconcile cost

A blocked call, validation failures included, returns `AirlockResponse.to_dict()` rather than
raising: a plain dict (`success: False`, `block_reason`, `error`, `fix_hints` for the model
to retry against). A configured honeypot may answer with fake success instead; its audit
record still says `blocked: true` and `honeypot: true`. Every step's reads and refusals, and
every CI job and gate, are in `src/agent_airlock/CLAUDE.md` and `scripts/CLAUDE.md`.

**There is no committed `site/`**: `docs.yml` rebuilds the `gh-pages` branch; `site/` is
gitignored, do not add it back. `BENCHMARK.md` and four benchmark `RESULTS.md` files reach the
site through `pymdownx.snippets` includes under `docs/benchmarks/`: never copy them into `docs/`.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Code Conventions

- **Python 3.10+**, `from __future__ import annotations` first (every module but the
  `__init__.py` files). Use `X | Y`, not `Optional`.
- **mypy strict** (`disallow_untyped_defs`, `warn_return_any`, pydantic plugin): type every
  signature; `TypeVar` / `ParamSpec` / `@overload` for generics; `TYPE_CHECKING` guards for
  type-only imports.
- **ruff**, line length 100, target `py310` (selected E, W, F, I, B, C4, UP, ARG, SIM;
  ignored E501, SIM102, SIM103, B027). Keep `py310`: at `py311`, UP017, UP035, UP036 and
  UP042 fire, and `make format`'s `ruff check --fix` would apply UP017 (`datetime.UTC`) and
  UP035 (`typing.NotRequired`), both 3.11+, breaking 3.10
  (`ruff check src/ --target-version py311 --select UP --statistics` shows them). Per-file
  `ARG` ignores (top-level `integrations/*.py`, `cli/*.py`, `anomaly.py`, tests with
  `SIM117`, examples with `F841`) cover interface signatures (callbacks, test stubs, demo
  tools, a reserved `anomaly.py` parameter): do not "fix" them.
- **bandit** reads `[tool.bandit]` in `pyproject.toml` (CI passes `-c pyproject.toml`).
  B101 (`assert`) is deliberately not skipped — it caught narrowing asserts on a security
  path. Where an assert is genuinely fine, use a scoped `# nosec B101 - <reason>`.
- **Pydantic V2 strict mode** for validation; `@dataclass` with `field(default_factory=...)`
  for structured data over plain dicts. **Enums** extend `str, Enum` so they serialize to
  JSON (`Capability` is a `Flag`, the one exception).
- **Logging** through `agent_airlock._log`: `from ._log import structlog`, then
  `logger = structlog.get_logger("agent-airlock.<dotted.module.path>")`. Never
  `import structlog` directly. Structured kwargs, never f-strings.
- **Exceptions** live in the module that raises them; new ones subclass
  `exceptions.AirlockError`, store details as attributes and call `super().__init__()`.
  Several keep other bases on purpose; do not rebase any in a patch release (the list is in
  `src/agent_airlock/CLAUDE.md`).
- Imports stdlib → third-party → first-party (`known-first-party = ["agent_airlock"]`).
  snake_case functions, PascalCase classes, UPPER_SNAKE constants, `_` private. Google-style
  docstrings (Args / Returns / Raises).
- **Tests**: almost all are `Test<Feature>` classes with `test_<scenario>` methods; keep
  each under ~5s.
- **Commits**: conventional — `feat:` `fix:` `docs:` `chore:` `ci:` `security:` `bench:`
  `test:` (`test(cves):` for a second-defence CVE fixture); branches `<type>/<short>`;
  squash-merge into `main`, which stays tag-able. GitHub's squash subject defaults to the PR
  title (multi-commit PR) or the commit's own message (single commit): write both that way.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: patterns -->
## Detected Patterns

- **Deny-by-default** — unknown tier, unregistered manifest, unpinned spec revision and an
  input shape a guard cannot read all fail closed: refused rather than skipped. New
  branches should preserve that direction.
- **Lazy optional imports** — anything from an extra is imported inside the function that
  needs it, behind `try/except ImportError`: an entry point raises an error naming the extra,
  a probe returns False so its caller refuses. `bare-install` imports every module bare.
- **No silent config no-ops** — a stored `AirlockConfig` field that nothing applies is listed
  in `config._NOT_APPLIED` and warns when set. Never add a setting that quietly does nothing.
- The decorator entrypoint, guard + preset pairs, context propagation, declarative presets
  and dated snapshots are described in `src/agent_airlock/CLAUDE.md`.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: git-insights -->
## Git Insights

History is dominated by `feat:` and `fix:`, with steady `docs:`, `chore:` and `bench:` work
(`git log --format=%s | sed -E 's/^([a-z]+)[(!:].*/\1/' | sort | uniq -c | sort -rn`
recounts it with scopes folded in). Four themes drive it: per-CVE guards and CVE triage
(`tests/cves/CLAUDE.md`), claims integrity, benchmark honesty (`benchmarks/CLAUDE.md`), and
fail-closed fixes on the call path, each release's in its own regression modules
(`tests/CLAUDE.md`).

**Claims integrity** is a commit class of its own: `fix(meta):` / `fix:` commits that stop
the README/docs/registry over-claiming ("ten places the repo claimed something the code
contradicted", #175; #215 extended it to the version `SECURITY.md` and `CITATION.cff`
state), and machine-checked gates (`scripts/check_*.py`, the badge, changelog, version and
README-shape tests) so drift fails CI instead of shipping. **Do not add a capability claim to
README, docs, or a preset description unless code and a test back it.** A benchmark number
is a claim too: report the run you got, zero included. Counts in these CLAUDE.md files rot
and nothing gates them, so prefer the structural fact plus the command that recounts it.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: best-practices -->
## Best Practices

- Read `AGENTS.md` first — it holds the load-bearing contributor contract.
- Default safety posture:
  `@Airlock(policy=STRICT_POLICY, sandbox=True, sandbox_required=True)`. Anything weaker
  needs a one-line justification in the docstring. `STRICT_POLICY` requires an agent
  identity (`src/agent_airlock/CLAUDE.md` says where one is read from).
- **Forbidden:** `subprocess.run(..., shell=True)` anywhere in `src/`; raw `eval()` /
  `exec()`; mocking fixtures in CVE regression tests.
- **CVE fixtures are signed history.** A commit touching `corpus/wild_payload_corpus/` or
  `tests/cves/` names a primary-source URL in its message (AGENTS.md's rule; no gate checks
  it, and history is uneven), and the same PR regenerates `docs/cves/index.md` with
  `python3 scripts/gen_cve_catalog.py --write` (with no flag it only prints) — never
  hand-edit it. Never remove a check without naming the CVE that motivated it.
- Every `feat:` needs at least one regression test. Run `make lint` and
  `pytest -m "not docker"` before committing.
- **`[Unreleased]` in `CHANGELOG.md` stays the placeholder between releases.** The `docs`
  job's default-mode `check_changelog.py` fails any PR that adds an entry there while the
  version is a released one; the release PR writes its notes under the new dated heading.
- A snippet or subprocess run from the checkout writes `airlock_audit.json` into its cwd: set
  `AIRLOCK_AUDIT_LOG_PATH` (or run it from a temp dir) to keep the log out of the tree.
- The README is gated (shape, framework and version-pin claims): do not grow it; use `docs/`.
- Before a version bump, read the release checklist in `scripts/CLAUDE.md`: every surface a
  test pins moves together, and the tag follows the merge at once.

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Custom Notes

Add project-specific notes here. This section is never auto-modified. The shipped-phase
checklist that used to live here is in `ROADMAP.md` under "Shipped history".

<!-- END MANUAL -->
