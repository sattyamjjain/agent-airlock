# agent-airlock

<!-- AUTO-MANAGED: project-description -->
## Overview

**agent-airlock** — an in-process, deny-by-default contract layer and type-checker for AI
agent tool calls. It intercepts calls into MCP (Model Context Protocol) servers and agent
frameworks, validates arguments strictly, applies policy, and sandboxes dangerous execution.

The wedge is argument validation at the call boundary; every other layer wraps it.

- Ghost-argument stripping/rejection (parameters the LLM invented)
- Pydantic V2 strict validation, no type coercion; self-healing errors carrying `fix_hints`
- Policy engine: RBAC, token-bucket rate limits, time windows, per-model-tier cost budgets,
  per-run resource-amplification budgets
- PII/secret detection and masking; Indic PII is opt-in (`pii_locales=["in"]`)
- Sandboxed execution: `@Airlock(sandbox=True)` dispatches only to E2B Firecracker. The
  Docker, Modal and local backends in `sandbox_backend.py` are used directly:
  `get_default_backend()` picks E2B, then Docker, and returns the local backend only with
  `allow_unsafe_local=True`; `ModalBackend` is only ever constructed by the caller. The
  beta, opt-in Anthropic Managed Agents backend runs nothing: its `execute()` returns a
  failed `SandboxResult` by design
- `mcp_spec/` guards mapped to specific named CVEs and MCP spec clauses — stdio injection,
  OAuth, DNS rebinding, SSRF (`$ref` dereference, through `ssrf_egress_guard`), eval-RCE,
  WebSocket origin hijack, task lifecycle, handle trust
- Framework adapters (the README's gated list, `_ADAPTER_SHIPPED_MODULES` in
  `tests/test_readme_framework_claims.py`): FastMCP, LangChain/LangGraph, Anthropic Messages
  and Claude Agent SDK, OpenAI, Gemini, PydanticAI, CrewAI, smolagents, Google ADK; plus two
  user-invoked gates that wrap no tool, the Managed Agents `ManagedAgentToolGate` and the
  Model Armor scanner
- Fleet-wide kill switch, checked before any other gate: one signed broadcast freezes; a
  reset needs votes from an M-of-N quorum of signer keys (`kill_switch/broadcast.py`)
- Two checks before the arguments, both inert until configured: the OAuth token audience
  of each call (`expected_token_audience`, CVE-2026-115413) and a startup-hook self-check
  of the interpreter (`startup_hook_check`, `runtime/startup_hooks.py`)
- `airlock` CLI — one dispatcher fronting every `cli/<name>.py`; the `_COMMANDS` table in
  `cli/__main__.py` (or `airlock --help`) is the authoritative subcommand list

**The installed core is Pydantic-only** (plus `tomli` on Python 3.10). Everything else —
structlog included — lives in an extra. `src/agent_airlock/_log.py` falls back to a
stdlib-logging shim when structlog is absent. `scripts/check_core_deps.py` enforces this as
an exhaustive allowlist; do not add a core dependency.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: build-commands -->
## Build & Development Commands

```bash
pip install -e ".[dev]"            # editable install with dev deps

# Optional extras — install only what you need. Full set:
#   logging bench sandbox modal mcp claude-agent model-armor console
#   redis crypto attested pydantic-ai crewai google-adk all dev docs
pip install -e ".[sandbox]"        # E2B Firecracker micro-VM execution
pip install -e ".[redis]"          # distributed rate limiter
pip install -e ".[all]"            # runtime extras EXCEPT modal, bench, attested (and dev/docs)

make test          # pytest tests/ -v --no-cov
make test-live     # tests/live against the real API: needs ANTHROPIC_API_KEY, spends credit
make coverage      # pytest with coverage (floor enforced; see [tool.coverage.report])
make lint          # ruff check + ruff format --check + mypy src/
make format        # ruff format + ruff check --fix
make bench         # pytest-benchmark suite (tests/benchmarks/, --ignore'd by default addopts)
```

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
make check-docs              # mkdocs build --strict, built OUTSIDE the tree (see Architecture)
make check-changelog         # post-release drift: [Unreleased] must be empty after a release
make check-changelog-release # [Unreleased] must be NON-empty; this repo's flow never turns it green
make check-benchmark-freshness          # dated README rows, each paired by title with its
                                        # docs/benchmarks/index.md twin; every page in nav
make check-benchmark-freshness-release  # pre-tag: no benchmark claim older than 30 days
make check-registry-parity              # declared version must not outrun PyPI
make check-registry-parity-distance     # release-only: refuse to skip a version
```

What CI runs — `ci.yml` jobs, on PRs and pushes to `main`. None is a required check (`main`
has no branch protection or ruleset), so a red job blocks a merge by convention only:

- `test` (full Python matrix) — installs `.[dev,redis,mcp,crypto]` and asserts the redis,
  FastMCP and cryptography extras import (a `--collect-only` step); ruff check, mypy, pytest
  with the coverage floor;
  on 3.11 only, `generate_benchmark.py --check` and a pytest-benchmark smoke run that asserts
  the suite executes (deliberately not a latency threshold).
- `lint` — `ruff format --check` only.
- `docs` — `mkdocs build --strict`, `check_links.py`, `gen_cve_catalog.py --check`, and the
  **default** modes of `check_benchmark_freshness.py` and `check_changelog.py`.
- `bare-install` — `check_core_deps.py` against a no-extras install, an import of the
  package root, `agent_airlock.audit` and `policy_presets.list_active()` through the shim,
  then `check_bare_imports.py`, which imports every module under the package.
- `docker-sandbox` — builds the repo `Dockerfile`, runs `pytest -m docker` over only the
  files that hold docker-marked tests (collecting all of `tests/` adds collection-time skips
  of modules whose extras the job lacks), and matches the log's pytest summary line,
  anchored, for an exact passed-count: adding or removing a
  docker-marked test means editing that count and the cases in
  `tests/test_tooling_honesty_0_10_24.py` that run it against real pytest output, and a
  skipped one turns the job red.
- `security` — bandit (`-c pyproject.toml`) and a CycloneDX SBOM; `safety` runs with
  `continue-on-error`, so it is advisory only.
- `version-tag-guard` (pushes to `main` only) — `check_version_tagged.py`,
  `check_changelog_heading.py`, `check_registry_parity.py`.

`publish.yml` (on a published release) adds `check_benchmark_freshness.py --release`,
`check_registry_parity.py --distance-only`, a GitHub-description drift check and
`twine check`. The upload authenticates through PyPI Trusted Publishing (OIDC), so the job
needs `id-token: write` and there is no PyPI token to add back. Its gate steps run before
it installs anything (it later installs only `build` and `twine`), so any script it runs
must stay stdlib-only.
`make check-changelog-release` runs in no workflow, and this repo's release flow never turns
it green: release PRs write notes straight under the new `## [X.Y.Z]` heading, so
`[Unreleased]` is already empty at the tagged commit. Do not satisfy it by leaving entries
under `[Unreleased]`: once the version is bumped, the `docs` job's default-mode
`check_changelog.py` fails on them.

`scripts/check_docs_api.py` imports the package and skips a module whose extra is missing,
so it runs in `test` as `tests/test_docs_api_gate.py`, where `[dev,redis,mcp,crypto]`
are installed, rather than in `docs`, which installs the package with only `[docs]`. It checks
names imported from `agent_airlock` in each Python fence of every authored markdown file
(README included; `CHANGELOG.md` and `.github/` excepted) and in each `examples/` script:
the import resolves, keywords match the signature, attributes exist.

`test` installs the `[redis]`, `[mcp]` and `[crypto]` extras because the redis-backed,
FastMCP-backed, Ed25519-identity and attested-admission modules skip without them
(`pytest.importorskip`), and a skipped module reads like a passing one in the summary line.
`[crypto]` joined in 0.10.26: `cryptography` had arrived only transitively, through `mcp`'s
`pyjwt[crypto]` and FastMCP's `authlib`. `[mcp]` resolves to the newest FastMCP the pin
allows, so a FastMCP major that breaks the integration fails CI rather than a user. If you
add an `importorskip`, add its dependency to a CI job in the same PR. Several existing ones
break that rule: the real-SDK tests for google-adk, crewai, smolagents, anthropic,
llama_index, autogen and agentdojo import SDKs no CI job installs, so they skip in every
run (`grep -rn importorskip tests/ --include='*.py'`).

Docker integration tests are **opt-in** — default `addopts` carries `-m 'not docker'`; run
them with `pytest -m docker`. `cve-watcher.yml` polls NVD on a schedule, diffs against the
ledger and files triage issues; it is not a merge gate.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: architecture -->
## Architecture

`src/` layout, single package, hatchling build. The `airlock` console script dispatches to
every `agent_airlock.cli.<name>:main(argv)` in space-form (`airlock scan-tools`), so flags
are identical to the `python -m agent_airlock.cli.<name>` long form. Three pre-dispatcher
scripts (`airlock-explain`, `airlock-conformance`, `airlock-scan-tools`) survive as stable
aliases. Subtree `CLAUDE.md` files live in `src/agent_airlock/mcp_spec/`,
`src/agent_airlock/integrations/`, `tests/cves/`, `benchmarks/` and, hand-written to extend
`benchmarks/CLAUDE.md`, `benchmarks/adaptive_redteam/`; `**/CLAUDE.md` is excluded from
the sdist and wheel (`[tool.hatch.build.targets.*]`), so the two under `src/` never reach a
user's site-packages.

Repo-level directories outside the package: `tests/` (mostly mirrors the package's
subpackages; `tests/cves/` is the signed CVE regression suite), `benchmarks/` (agentdojo,
adaptive_redteam, blockrate, fix_hints, harness_injection, mcp_conformance, mcptox,
scantools_mcptox, toolprivbench, vs_gateway, and `_claude` shared paid-run plumbing),
`scripts/` (`check_*` claim gates, the generators behind `make benchmark` / `test-badge` /
`check-cve-catalog`, `smoke_*` end-to-end drivers, `cve_watcher.py`, and `egress_bench.py` /
`verify_corpus_manifest.py` behind `make egress-bench` / `verify-corpus`), `docs/` (mkdocs
source), `examples/`, `demo/` (runnable live demo), `presets/`, `schemas/`, `tools/`, and
`.claude-plugin/` (plugin and marketplace manifests).

`tests/fuzz/` holds the Hypothesis property and differential suites; `HYPOTHESIS_PROFILE`
(`tests/fuzz/conftest.py`) picks `ci`, the derandomized default that CI runs, or `deep`
(5,000 examples, no deadline) for a manual run; nothing in the repo invokes `deep`.
`tests/live/` calls the Anthropic API and spends
credit, so default `addopts` ignores it and each test also skips without `AIRLOCK_LIVE=1`
and `ANTHROPIC_API_KEY`: no workflow runs it, `make test-live` does (recipe in
`tests/live/README.md`), and `make test-badge` counts it as a third excluded bucket beside
`tests/benchmarks/` and the docker-marked tests.

**There is no committed `site/`.** The docs site is served from the `gh-pages` branch,
which `docs.yml` rebuilds with `mkdocs gh-deploy --force` on pushes to `main` that touch
`docs/`, `mkdocs.yml`, `src/agent_airlock/` or the workflow itself (or on
`workflow_dispatch`). No snippet-included file is a trigger path (no `benchmarks/**` path
is), so a push that changes only them redeploys nothing. `site/` is gitignored — do not
add it back: the committed copy was a stale duplicate of the gh-pages build (#151).
`make check-docs` builds to `$TMPDIR/agent-airlock-mkdocs-check`, not `./site/`, because
even gitignored HTML in the working tree made project-classifying tooling read this
library as a web app.

Generated files stay where their generator writes them. `BENCHMARK.md` and the
`RESULTS.md` files of `blockrate`, `mcptox`, `fix_hints` and `adaptive_redteam` reach the
site through `pymdownx.snippets` includes under `docs/benchmarks/`
(`grep -rn -- '--8<--' docs/` lists them; `check_paths` is on, so a moved file fails the
strict build). Never copy them into `docs/`, and keep cross-tree links inside them absolute.

```
src/agent_airlock/
├── core.py            @Airlock decorator — the entrypoint; sync + async
├── __init__.py        public API surface (large, explicit __all__)
├── config.py          AirlockConfig; some env vars override the constructor, others only
│                      fill gaps (see its docstring); airlock.toml is read only by the
│                      explicit from_toml() / from_toml_if_exists(), never implicitly
├── exceptions.py      AirlockError base only; exception classes live where they're raised
├── testing.py         state-reset helpers for test isolation
├── _log.py            structlog-or-stdlib logging shim
├── _sandbox_errors.py sandbox exception classes shared by core.py and sandbox.py, so
│                      core.py can raise them without importing agent_airlock.sandbox
├── _arg_walk.py       names positional arguments by parameter and walks what they hold
│                      (containers, the tool's own models) for the value gates (2.7, 3, 5)
│
├── VALIDATION   validator.py, unknown_args.py, safe_types.py, self_heal.py, handles.py
├── POLICY       policy.py, policy_presets.py, preset_loader.py, capabilities.py,
│                oversight.py, identity.py, redis_rate_limit.py, amplification.py,
│                capability_caps/, policy_compiler/, budget/
├── EXECUTION    sandbox.py, sandbox_backend.py, streaming.py, context.py,
│                conversation.py, runtime/; circuit_breaker.py and retry.py are
│                exported helpers, not part of the @Airlock call path. In runtime/, only
│                startup_hooks.py is on it (step 0.5)
├── SANITIZE     sanitizer.py, audit.py, audit_otel.py, observability.py,
│                cost_tracking.py, trace_redaction.py
├── VACCINE      filesystem.py, network.py, honeypot.py, vaccine.py,
│                camouflage_resistant.py, ssrf_egress_guard.py, sequence_guard.py,
│                action_contradiction_gate.py, tool_output_trust_guard.py,
│                done_receipt_guard.py
├── mcp_spec/    per-CVE / per-spec-revision MCP guards — largest subpackage, own CLAUDE.md
├── mcp/         FastMCP integration (MCPAirlock, secure_tool, create_secure_mcp_server) —
│                a refusal raises FastMCP's ToolError (error result whatever the return
│                type); plus cimd.py — pinned CIMD trust anchor, denies on drift
├── kill_switch/ fleet freeze: one signed broadcast freezes, an M-of-N quorum of signer keys
│                resets — registry, signer, quorum, broadcast, transports/
├── data/        dated snapshots (model pricing, advisory blast radius)
├── fixtures/    dated pattern files (redaction patterns)
├── ADVERSARIAL  anomaly.py, regression_corpus.py, sdk_provenance.py, a2a.py,
│                mcp_proxy_guard.py, negotiation_bench.py, corpus/wild_payload_corpus/
├── ATTEST       attest/, conformance/, baseline/, pack/, packs/, scan/, graph/, studio/,
│                owasp_agentic_coverage/
├── integrations/  every other framework adapter, plus adapters/ (commerce caps) and
│                  scanners/ (pluggable IDE-scanner protocol) — own CLAUDE.md
└── cli/           subcommands behind the unified dispatcher; a new one needs a row in
                   `_COMMANDS` (`cli/__main__.py`) and in the `EXPECTED` map in
                   `tests/test_cli_dispatcher.py`, and an argparse `main(argv) -> int` so
                   `--help` parity holds. `egress-bench` needs a source checkout
```

**Call flow through `@Airlock`** — `_pre_execution` gates, then execute, then
`_post_execution`. Steps 0–6 match the `# Step N` comments in `core.py`:

0. Kill switch — a fleet freeze refuses before any gate looks at the arguments (the call's
   context is extracted and the call logged first; no gate runs)
   - 0.5 startup-hook self-check (`startup_hook_check`, off by default): the walk
     (`runtime/startup_hooks.py`) runs once per process, on the first call admitted with it
     on; `deny` refuses every guarded call while a hook is not on `startup_hook_allowlist`
   - 0.6 OAuth token audience (`expected_token_audience`, inert until set, `warn` by
     default): the `aud` of the claims the host put on context metadata under
     `access_token_claims` (`_call_metadata`), never a tool argument; `deny` also refuses a
     call with no claims
1. Ghost arguments (BLOCK / STRIP_AND_LOG / STRIP_SILENT)
2. Resolve policy (static, or `Callable[[AirlockContext], SecurityPolicy | None]`; a
   resolver that returns None refuses the call) and check it against the caller's identity
   (one a first argument carries at a `ContextExtractor.CONTEXT_ATTRS` name such as
   `.context` / `.ctx`, else the one set around the call). Every call gets a fresh
   `AirlockContext`: it takes the agent id and roles of the context set around the call when
   it has none of its own, and that context's session, workspace and user ids whenever it
   lacks them, unless that context names a different agent (`_inherit_ambient_identity`).
   `_share_run_state` points its untrusted-output counts and `authorize_once` grants at the
   run's context (an `AirlockContext` the first argument carries, else the one set around
   the call unless it names a different agent than the call does) and merges that context's
   metadata under its own, so a policy with `reauth_on_untrusted_reinvocation` refuses a
   call that belongs to no run
   - 2.5 behavioral tool-call sequence guard
   - 2.6 action-time contradiction gate
   - 2.7 unsafe-deserialization content guard
   - 2.8 per-run resource-amplification budget, keyed by the call's `session_id` (one
     anonymous ledger when there is none) — after the gates above, so a call they refuse
     is never charged to the run's ledger (one that steps 3–7 refuse already has been)
3. Filesystem path validation. A violation is refused under `BlockStrategy.HONEYPOT` too
   (the wrapper then answers with honeypot data); only `SOFT_BLOCK` logs and proceeds
4. Capability requirements, read from the wrapper `@Airlock` returned and the
   `__wrapped__` chain beneath it and combined, so `@requires` counts above or below
   `@Airlock`
5. Endpoint policy validation

   Steps 2.7, 3 and 5 read every argument the call passes (`_arg_walk`): positional ones
   by parameter name (`*args` under the parameter's own name), down through mappings (keys
   included), sequences, sets and mapping views, and into pydantic models and dataclasses
   the tool's author defined. The run wrapper the context came from and objects from agent
   frameworks (`_arg_walk.FRAMEWORK_PACKAGES`) are not walked. A top-level string is a path
   by `_looks_like_path`: a path-named key, the absolute / drive-rooted / home-relative /
   traversing shape (`_is_absolute_or_escaping`, shared with the nested test), a separator,
   or a file extension; a nested one (`_looks_like_nested_path`) only by that shape or by a
   separator and a file extension, either one being enough under a path-named key, so a
   MIME type is not; bytes only under a path-named key and shaped like a path; a `file:`
   URI always. A URL is any `scheme://` in any case, or a value under a URL-named key.
   Input nested deeper than 32 levels, or a container that contains itself, is refused by
   whichever of the three gates reads it, in words that say so
6. Per-model-tier budget check — the tier, token count and model id come from context
   metadata (`_call_metadata`), never from the tool's arguments, which the model writes.
   The worst case is priced at `model_id`'s row (a dated snapshot, `<key>-YYYYMMDD`, at
   its model's), an unlisted model at the table's dearest row, and no `model_id` at the
   tracker's own model
7. Execute (unnumbered in code) — Pydantic strict validation, reaching inside model,
   dataclass and TypedDict arguments passed as dicts (`validator._nested_strict_check`; an
   instance the caller already built is accepted as-is), then run locally or
   in the sandbox, inside the network airgap when one is configured. Sandbox mode validates in
   the parent (`validate_sandbox_args`) before dispatch, so both paths fail the same way, and a
   tool that raises in the sandbox gets the answer it gets locally; a sandbox that fails is
   refused as `sandbox_error`. E2B, Docker and Modal run one payload (`generate_execution_code`)
   whose outcome comes back as JSON: never unpickle anything a sandbox printed
8. `_post_execution` — when `sanitize_output` is on, sanitize output via
   `_sanitize_tool_output` (a string is masked and truncated; a dict, list, tuple, set or
   frozenset is masked value by value and keeps its type; any other object is returned
   as-is and its detections reported as not masked) → audit log → mark untrusted output
   (when the resolved policy sets `reauth_on_untrusted_reinvocation`) → reconcile actual vs
   estimated cost against the resolved policy's budget (it records nothing on the
   `CostTracker`). A generator result is wrapped instead (`_guard_stream`): its body runs
   when iterated, after the call returns, so each step re-enters the call's airgap and
   context and each item is sanitized as it is yielded; the call's audit record, written
   at return, counts none of its items

A blocked call, validation failures included, returns `AirlockResponse.to_dict()` rather than
raising: a plain dict (`success: False`, `block_reason`, `error`, `fix_hints` for the model
to retry against). With a honeypot configured, the caller may get fake success instead;
its audit record still says `blocked: true` and `honeypot: true`.

A new `BlockReason` (`self_heal.py`) fails `test_every_block_reason_is_covered` until
`tests/test_fix_hints_0_10_25.py` has a `_REFUSALS` row whose call is refused with it
(each row is checked for the `AIRLOCK_BLOCK` prefix and non-empty `fix_hints`), or lists
it in `_NOT_ON_THE_CALL_PATH` with a reason.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Code Conventions

- **Python 3.10+**, `from __future__ import annotations` first (every module but the
  `__init__.py` files). Use `X | Y`, not `Optional`.
- **mypy strict** (`disallow_untyped_defs`, `warn_return_any`, pydantic plugin). Type every
  signature. `TypeVar` / `ParamSpec` / `@overload` for generics.
- **ruff**, line length 100, target `py310`. Selected: E, W, F, I, B, C4, UP, ARG, SIM;
  globally ignored: E501, SIM102, SIM103, B027. The `py310` target is deliberate: at
  `py311`, UP017, UP035, UP036 and UP042 fire, and `make format`'s `ruff check --fix` would
  apply UP017 (`datetime.UTC`) and UP035 (`typing.NotRequired`), both 3.11+, unasked, which
  breaks 3.10. Do not raise it
  (`ruff check src/ --target-version py311 --select UP --statistics` shows what fires).
  Per-file `ARG` ignores exist for top-level `integrations/*.py`, `cli/*.py`, `anomaly.py`,
  tests (which also ignore `SIM117`) and examples (also `F841`) — those unused args are
  interface signatures (callbacks, test stubs, demo tools, a reserved `anomaly.py`
  parameter), so do not "fix" them.
- **bandit** reads `[tool.bandit]` in `pyproject.toml` (CI passes `-c pyproject.toml`).
  B101 (`assert`) is deliberately not skipped — it caught narrowing asserts on a security
  path. Where an assert is genuinely fine, use a scoped `# nosec B101 - <reason>`.
- **Pydantic V2 strict mode** for validation. `@dataclass` with `field(default_factory=...)`
  for structured data; prefer it over plain dicts.
- **Enums** extend `str, Enum` so they serialize to JSON (`Capability` is a `Flag`, the one
  exception).
- **Logging** through `agent_airlock._log` (structlog when installed, stdlib shim otherwise):
  `from ._log import structlog` (`from .._log` one package down) then
  `logger = structlog.get_logger("agent-airlock.<dotted.module.path>")` (`core.py` alone
  uses the bare root name). Never
  `import structlog` directly — in `src/` the shim is the only module that does.
  Structured kwargs, never f-strings.
- **Imports** stdlib → third-party → first-party (`known-first-party = ["agent_airlock"]`).
- **Naming**: snake_case functions, PascalCase classes, UPPER_SNAKE constants, `_` private.
- **Docstrings** Google-style (Args / Returns / Raises).
- **Exceptions** live in the module that raises them; new ones subclass
  `exceptions.AirlockError`, store details as attributes and call `super().__init__()`.
  Pre-v0.5.1 ones keep their `Exception` / `ValueError` bases on purpose (`exceptions.py`
  docstring), two later ones do too (`OversightDeniedError`, `OpenAPIDriftViolation`), and
  `SequenceViolation` / `ActionContradictionViolation` subclass `PolicyViolation` by design,
  so `except AirlockError` does not catch `PolicyViolation`, `PathValidationError` and the
  like; do not rebase any of them in a patch release.
- `TYPE_CHECKING` guards for type-only imports.
- **Tests**: almost all are `Test<Feature>` classes with `test_<scenario>` methods; keep
  each under ~5s.
- **Commits**: conventional — `feat:` `fix:` `docs:` `chore:` `ci:` `security:` `bench:`
  `test:` (`test(cves):` for a second-defence CVE fixture).
  Branches `<type>/<short>` with the same vocabulary (`fix/`, `test/`, `docs/`, `ci/`, ...).
  Squash-merge into `main`, which stays tag-able at all times. GitHub defaults the squash
  subject to the PR title for a multi-commit PR and to the commit's own message for a
  single-commit one, so write both in conventional form — prose PR titles are how
  unprefixed subjects reached `main`.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: patterns -->
## Detected Patterns

- **Decorator entrypoint** — `@Airlock()` wraps a function with the full layer stack, and
  preserves `__signature__` / `__annotations__` so framework introspection still works.
- **Defense-in-depth** — kill switch → startup hooks → token audience → ghost arguments →
  policy (and the 2.5–2.8 gates) → filesystem → capability → network → budget → strict
  validation and sandbox at execute (the `# Step N` order in `core.py`). Most guard layers
  trace to a named advisory; the kill switch, the startup-hook check and the budgets are
  operational controls.
- **Guard + preset pairs** — `mcp_spec/` guards come in three shapes (see
  `mcp_spec/CLAUDE.md`); a guard's preset factory, usually `*_defaults()`, lives in
  `policy_presets.py`. Register it with `@preset` **and** list it in
  `policy_presets.__all__`, and any `policy_presets.<name>` named in README or `docs/` must
  resolve to a registered factory (`tests/presets/test_registry_parity.py`). An
  unregistered preset never shows up in `list_active()`. Many guards are re-exported from
  the package root (`agent_airlock.__all__`); `mcp_spec/__init__.py` exports no per-CVE
  guard — its `__all__` is the protocol surface only.
- **Lazy optional imports** — anything from an extra (`e2b`, `redis`, `cryptography`,
  framework SDKs) is imported inside the function that needs it, behind
  `try/except ImportError`, raising an error that names the extra to install. `structlog` is
  the exception: `_log.py` tries it once at import and falls back to the stdlib shim instead
  of raising. This is what keeps the `bare-install` job green, where
  `scripts/check_bare_imports.py` imports every module under the package.
- **Deny-by-default** — unknown tier, unregistered manifest, and unpinned spec revision all
  fail closed, and so does an input shape a guard cannot read, such as a list where a string
  was expected: it is refused rather than skipped (see `mcp_spec/CLAUDE.md`). The core
  value-reading gates, when one of them is on (`_reads_argument_values`), refuse input too
  deep or self-containing to read, and a resolver that returns no policy refuses the call.
  New branches should preserve that direction.
- **Context propagation** — `contextvars`-backed `AirlockContext`; `get_current_context()`
  is available inside the wrapped tool, and a policy may be a callable over that context
  for per-tenant / per-workspace rules.
- **Declarative presets** — `presets/*.yaml` use a restricted YAML dialect
  (`schema_version: 1`) that `preset_loader` parses without PyYAML. Every `factory:`
  value, even on an `enabled: false` entry, must name a preset registered in
  `policy_presets.list_active()` — `tests/presets/test_ox_mcp_yaml.py` checks this
  against every file under `presets/`, not just the one it's named for.
- **No silent config no-ops** — a stored `AirlockConfig` field that nothing applies must
  be listed in `config._NOT_APPLIED` (field name → what to use instead), or documented in
  its field comment as a carrier for a named consumer (`credential_scopes` →
  `MCPProxyConfig(tool_scopes=...)` is the one such field), so
  `_warn_on_settings_not_applied` emits a `FutureWarning` (deprecated, removal in v1.0.0)
  when it's set away from its default. `FutureWarning`, because Python hides
  `DeprecationWarning` outside `__main__`. Never add a setting that quietly does nothing.
- **Dated snapshots** — pricing tables, advisory blast-radius data and redaction patterns
  ship as dated files under `data/` and `fixtures/`; a refresh is a new dated file, not an
  edit to the old one, plus a repoint of the one constant naming the current file
  (`grep -rnE '_20[0-9]{2}_[0-9]{2}[^"]*\.(json|txt)"' src/agent_airlock`; the grep also
  lists the kept June pricing loader and one preset's provenance path). Superseded
  snapshots stay in `data/`, the 2026-06 pricing one with a loader, the 2026-09 one without.
  `cost_tracking.DEFAULT_PRICING` is the undated in-process fallback, so a price refresh
  edits it too; `tests/test_budget_pricing_0_10_24.py` fails when it lacks a model the
  current snapshot prices.
- **Also by name** — `airlock attest` receipts (identity plus assume/guarantee
  `LayerContract`); `SandboxPool` of single-use sandboxes, one pool per config, hiding cold
  starts; `vaccinate()` monkeypatching
  third-party `@tool` decorators; honeypot deception returning plausible fake success.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: git-insights -->
## Git Insights

History is dominated by `feat:` and `fix:`, with steady `docs:`, `chore:` and `bench:`
work (`git log --format=%s | sed -E 's/^([a-z]+)[(!:].*/\1/' | sort | uniq -c | sort -rn`
recounts it with scopes folded in). Four themes drive most recent development:

1. **Per-CVE guards.** The recurring guard commit, `feat:` or `fix(...)` alike, adds one
   guard for one named advisory (`mcp_spec/*_guard.py`), its preset defaults, and a
   regression test. AGENTS.md asks for the primary-source URL in the commit message, but
   history is uneven: the test module's docstring header is where to look (an `Advisory:` /
   `NVD:` line in the canonical shape, a bare URL in older modules).
   `cve-watcher.yml` files triage issues for argument-shaped CVEs; each gets a disposition
   from the vocabulary in `docs/cve-triage.md`
   (`in-scope-and-scheduled`, `in-scope-and-deferred-until-<DATE>`,
   `out-of-scope-because-<clause>`), and the queue closes with a fixture or a public,
   reasoned refusal (#177). An in-scope CVE that an existing guard already refuses lands as
   a second-defence fixture, not a new guard (#226). A fixture PR is titled
   `test(cves): ...`; a refusal is `docs(triage): ...` and adds only a row to the
   out-of-scope table in `tests/cves/README.md` (#312). A CVE can be both, an out-of-scope
   half whose primitive an existing guard already refuses (`docs/cve-triage.md`): that one
   still gets a fixture (#289, #301).
2. **Claims integrity.** A distinct class of `fix(meta):` / `fix:` commits exists purely
   to stop the README/docs/registry over-claiming — "ten places the repo claimed something
   the code contradicted" (#175) is the archetype, and #215 extended it to the version
   `SECURITY.md` and `CITATION.cff` state. Machine-checked gates (`scripts/check_*.py`, the
   badge, changelog, version and README-shape tests) exist so this drift fails CI instead
   of shipping. The README was cut by roughly nine-tenths and its size gated
   (`tests/test_readme_shape.py`, #180); long-form material belongs in `docs/`.
3. **Benchmark honesty.** `bench(...)` commits publish adversarial results under
   `benchmarks/` and are written to survive a hostile read: a null result ships as a null
   result, a re-run that comes back weaker ships weaker, a broken harness is fixed before
   its output is quoted, an expiring row is re-measured rather than re-dated and a wrong
   diagnosis stays on the record beside its correction (#179), and the sample scope is
   stated inline rather than rounded up. Match this register when touching `benchmarks/`
   or `BENCHMARK.md`.
4. **Fail-closed fixes on the call path.** `fix(security):` and `fix(<area>):` commits close
   a path where a check was skipped or a refusal failed open; since 0.10.16 each release's
   fixes land in regression modules named for it
   (`ls tests | grep -E '_[0-9]+_[0-9]+_[0-9]+\.py$'` lists them).

Practical consequence: **do not add a capability claim to README, docs, or a preset
description unless code and a test back it.** There is tooling that will fail the build on it.
A benchmark number is a claim too — report the run you actually got, including a zero.

The same rule applies to this file. Counts of modules, classes or commits rot on every
merge and are not gated by anything, so prefer the structural fact plus the command that
recounts it over a number pasted into prose.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: best-practices -->
## Best Practices

- Read `AGENTS.md` first — it holds the load-bearing contributor contract.
- Default safety posture:
  `@Airlock(policy=STRICT_POLICY, sandbox=True, sandbox_required=True)`.
  Anything weaker needs a one-line justification in the docstring. `STRICT_POLICY`
  requires an agent identity: a first argument that carries one at `.context` / `.ctx`
  (`ContextExtractor.CONTEXT_ATTRS` lists what is read; a bare `AirlockContext` passed as
  the first argument is not read), or `with AirlockContext(agent_id=...)` around the call
  (`_caller_identity` in `core.py`).
- **Forbidden:** `subprocess.run(..., shell=True)` anywhere in `src/`; raw `eval()` /
  `exec()`; mocking fixtures in CVE regression tests. `mcp_spec/manifest_only_mode.py` is
  the only `subprocess` importer in `src/` and does not use `shell=True`; the `shell=True`
  grep hits in `capabilities.py` (a docstring) and `cli/doctor.py` (a detection regex) are
  text, not calls.
- **CVE fixtures are signed history.** Files under `corpus/wild_payload_corpus/` and
  `tests/cves/` require a primary-source URL in the commit message, and the same PR
  regenerates `docs/cves/index.md` with `python3 scripts/gen_cve_catalog.py --write` (with
  no flag it only prints) — it is built from the `tests/cves/` docstring headers, so never
  hand-edit it. Never remove a check without naming the CVE that motivated it.
- Every `feat:` needs at least one regression test.
- Run `make lint` and `pytest -m "not docker"` before committing.
- `tests/conftest.py` redirects the default `airlock_audit.json` path to a temp file, but
  only inside that pytest process — a test that runs an example or script in a subprocess
  must pass `cwd=tmp_path` (or set `AIRLOCK_AUDIT_LOG_PATH` for the child) itself, or the
  child writes its audit log into the checkout. The same variable keeps an ad-hoc
  snippet's log out of the checkout.
- `bare-install` is the job that enforces the Pydantic-only core: `check_core_deps.py` fails
  on a new core dependency, its import step fails on a module-level import of an extra in
  the modules it loads (the package root, `audit`, `policy_presets` and what they import:
  about three fifths of the package, not `sequence_guard`, `action_contradiction_gate`,
  `sandbox`, `cli/` or most of `integrations/`), and since 0.10.26 `check_bare_imports.py`
  imports every module under the package, so such an import anywhere fails there.
- A new `mcp_spec/*guard*.py` module also needs a red-team adapter
  (`tests/test_adaptive_redteam_registry_parity.py` fails until it is in
  `benchmarks/adaptive_redteam/adapters/registry.py`; `mcp_spec/CLAUDE.md` has the recipe).
- **Version bumps** must move every surface a test pins — `pyproject.toml` + `__version__`,
  `.claude-plugin/plugin.json`, `CITATION.cff` (the newest *published* version and its
  CHANGELOG date: a patch bump leaves it one behind, the most `test_version_consistency.py`
  allows, and an X.Y.0 bump must cite X.Y.0), the supported minor line in `SECURITY.md`,
  the README badge (`make test-badge`) — and need a dated `## [X.Y.Z] - YYYY-MM-DD`
  CHANGELOG heading (`test_changelog_headings.py`, and `check_changelog_heading.py` in
  `version-tag-guard`). Tag `vX.Y.Z` within one commit of the bump, or
  `version-tag-guard` turns `main` red. Push the tag as soon as the squash merge lands: the
  merge's own push run also runs `check_registry_parity.py`, which fails on a dated
  CHANGELOG section with no tag yet (re-run that job once the tag exists).
- `make test-badge` rewrites only the README badge (test count, coverage, version). The
  hand-written copies must match it in the same commit: every count and `(vX.Y.Z = N)` pair
  under `docs/distribution/` (`test_numeric_claim_parity.py`) and the `N tests` proof point
  in `.claude-plugin/marketplace.json` (`test_marketplace_metadata.py`).
- A new page under `docs/benchmarks/` must be added to the `mkdocs.yml` nav, and each README
  benchmark row's date must match its own row in `docs/benchmarks/index.md`, paired by
  title, so a row retitled on one page only fails too. `check_benchmark_freshness.py` fails
  on either gap in both modes; only the 30-day age check is `--release`-only.
- The README is gated on shape (`tests/test_readme_shape.py`: line and word ceilings, code
  in the first screenful, no table of contents) and on its framework and version-pin
  claims. Put new material in `docs/` and link it; do not grow the README.
- `scripts/smoke_*.py` build the wheel, install it into a throwaway `.smoke-<name>-venv/`
  (network needed) and drive one guard or preset through the installed package (in
  `smoke_explain.py`, the `airlock-explain` console script), which an editable-tree unit
  test cannot show. No workflow runs them; a failed run leaves its `.smoke-*` directory
  behind (gitignored). Add one only when a unit test is not enough.
- New modules follow the layered structure: validation → policy → execution → sanitization.
- Keep security-relevant decisions observable via structured logging.

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Project Notes

### Phase 1: Core Validator
- [x] Ghost argument stripping
- [x] Pydantic strict validation
- [x] Self-healing responses
- [x] Configuration system

### Phase 2: E2B Sandbox
- [x] Warm sandbox pool (SandboxPool class)
- [x] Function serialization (cloudpickle)
- [x] E2B integration (execute_in_sandbox)
- [x] File mounting (`sandbox.mount_files()`)

### Phase 3: Policy Engine
- [x] SecurityPolicy class with allow/deny lists
- [x] Time-based restrictions (TimeWindow)
- [x] Rate limiting (token bucket algorithm)
- [x] Agent identity and role-based access control
- [x] Predefined policies (PERMISSIVE, STRICT, READ_ONLY, BUSINESS_HOURS)

### Phase 4: Output Sanitization
- [x] PII detection and masking (email, phone, SSN, credit card, IP)
- [x] Secret detection and masking (API keys, passwords, AWS keys, JWT, connection strings)
- [x] Token/character truncation with configurable limits
- [x] Masking strategies (FULL, PARTIAL, TYPE_ONLY, HASH)
- [x] Audit logging (JSON Lines format, thread-safe)

### Phase 5: FastMCP Integration
- [x] MCPAirlock decorator for MCP-specific features
- [x] secure_tool convenience decorator
- [x] create_secure_mcp_server factory function
- [x] MCP context extraction utilities
- [x] Progress reporting support
- [x] Comprehensive example (fastmcp_integration.py)

### Phase 0: Production Readiness (Added 2026-01-31)
- [x] Audit logging implementation (was config-only, now fully working)
- [x] Async function support (proper async/await wrapper)
- [x] Coverage verification (99%, enforced 80% in CI)
- [x] 647 tests total (includes context, streaming, audit, async, edge cases)

### Production Phase 1: Core Missing Features (Added 2026-01-31)
- [x] P1.1: Streaming/generator support (StreamingAirlock class)
  - Per-chunk PII/secret sanitization
  - Cumulative output truncation
  - Sync and async generator wrapping
- [x] P1.2: RunContext preservation (AirlockContext)
  - contextvars for request-scoped state
  - ContextExtractor for RunContextWrapper pattern
  - get_current_context() available inside tools
- [x] P1.3: Dynamic policy resolution
  - Policy can be SecurityPolicy or Callable[[AirlockContext], SecurityPolicy]
  - Enables workspace/tenant-specific policies
  - Context extracted from first arg with .context/.ctx attribute

### Phase 6: Launch
- [x] PyPI release v0.1.3, v0.1.4
- [x] README with manifesto-style copy
- [x] Security scan and fixes
- [ ] Outreach

### Framework Integrations (Tested 2026-02-01)
All major AI frameworks tested and working:
- [x] LangChain - `@tool` + `@Airlock()` pattern, `.invoke()` for tool calls
- [x] LangGraph - ToolNode integration, state graphs with security
- [x] PydanticAI - `output_type` param, RunContext preservation
- [x] OpenAI Agents SDK - `@function_tool` + `@Airlock()`, Agent.run()
- [x] Anthropic - `@Airlock()` with tool_use blocks, Messages API
- [x] AutoGen - FunctionTool with airlocked functions
- [x] CrewAI - `@tool` decorator pattern (Tool object wrapper)
- [x] LlamaIndex - FunctionTool.from_defaults(), ToolOutput.raw_output
- [x] smolagents - `@tool` + `@Airlock()` with proper Args docstrings

### Enterprise Production Roadmap (Added 2026-02-01)

The `PRODUCTION_ROADMAP.md` this line used to point at was deleted in v0.4.0 (8a3939e;
`git show 4b5fe16:PRODUCTION_ROADMAP.md` recovers it). The live plan is
[`ROADMAP.md`](ROADMAP.md); the checklist below is a record of what shipped, not a
tracker.

**Already Implemented (v0.1.5):**
- [x] Async function support (proper async/await)
- [x] Streaming support (StreamingAirlock)
- [x] Context propagation (AirlockContext)
- [x] Dynamic policy resolution (PolicyResolver callable)
- [x] Audit logging (JSON Lines, thread-safe)
- [x] Workspace PII config (per-tenant rules)
- [x] Conversation tracking (multi-turn state)

**V0.3.0 "Vaccine" Features (COMPLETED):**
- [x] Filesystem path validation (CVE-resistant)
- [x] Network egress control (socket monkeypatch)
- [x] Honeypot deception protocol
- [x] Framework vaccination (LangChain, OpenAI SDK auto-wrap)

**V0.4.0 "Enterprise" Features (COMPLETED):**
- [x] UnknownArgsMode (BLOCK/STRIP_AND_LOG/STRIP_SILENT)
- [x] SafePath/SafeURL safe types
- [x] Capability gating (@requires decorator)
- [x] Pluggable sandbox backends (E2B/Docker/Local)
- [x] OpenTelemetry observability
- [x] Circuit breaker pattern
- [x] Cost tracking with budget limits
- [x] Retry policies with exponential backoff
- [x] MCP Proxy Guard
- [x] India-specific PII (Aadhaar, PAN, UPI, IFSC)

**Future Roadmap:**
- [x] Redis-backed distributed rate limiting (`redis_rate_limit.py`, `[redis]` extra)
- [x] Performance benchmarks in CI (smoke run, not a latency gate — v0.8.80)
- [ ] Additional framework integrations

**Current Version:** see `pyproject.toml` / `agent_airlock.__version__` — this line is
not gated, so it is a pointer rather than a number that can rot (it read v0.5.0 while
the package was v0.8.79).

<!-- END MANUAL -->
