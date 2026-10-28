# Module: tests

<!-- AUTO-MANAGED: module-description -->
## Purpose

The pytest suite. It mostly mirrors the package's subpackages; `tests/cves/` is the signed
CVE regression suite and has its own `CLAUDE.md`. Default `addopts` leave out three buckets,
which `make test-badge` also counts as excluded: the docker-marked tests, `tests/live/` and
`tests/benchmarks/` (the pytest-benchmark latency suite, `make bench`).

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: architecture -->
## Module Architecture

- **`tests/fuzz/`** holds the Hypothesis property and differential suites;
  `HYPOTHESIS_PROFILE` (`tests/fuzz/conftest.py`) picks `ci`, the derandomized default that
  CI runs, or `deep` (5,000 examples, no deadline) for a manual run; nothing in the repo
  invokes `deep`.
- **`tests/live/`** calls the Anthropic API and spends credit, so default `addopts` ignores
  it and each test also skips without `AIRLOCK_LIVE=1` and `ANTHROPIC_API_KEY`: no workflow
  runs it, `make test-live` does (recipe in `tests/live/README.md`).
- **Docker-marked tests** are opt-in (`-m 'not docker'` in default `addopts`; run them with
  `pytest -m docker`). CI's `docker-sandbox` job builds the repo `Dockerfile`, runs
  `pytest -m docker` over only the files that hold docker-marked tests (collecting all of
  `tests/` adds collection-time skips of modules whose extras the job lacks), and matches
  the log's pytest summary line, anchored, for an exact passed-count: adding or removing a
  docker-marked test means editing that count and the cases in
  `tests/test_tooling_honesty_0_10_24.py` that run it against real pytest output, and a
  skipped one turns the job red.
- **Release regression modules.** `fix(security):` and `fix(<area>):` commits close a path
  where a check was skipped or a refusal failed open; since 0.10.16 most releases' fixes
  land in regression modules named for the release
  (`ls tests | grep -E '_[0-9]+_[0-9]+_[0-9]+\.py$'` lists them). 0.10.27 is the exception:
  its tests are in `tests/mcp_spec/test_oauth.py` and `tests/test_token_audience_call_path.py`.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Module-Specific Conventions

- **Keep audit logs out of the checkout.** `tests/conftest.py` redirects the default
  `airlock_audit.json` path to a temp file, but only inside that pytest process — a test that
  runs an example or script in a subprocess must pass `cwd=tmp_path` (or set
  `AIRLOCK_AUDIT_LOG_PATH` for the child) itself, or the child writes its audit log into the
  checkout. The same variable keeps an ad-hoc snippet's log out of the checkout.
- **An `importorskip` needs a CI job that installs its dependency**, added in the same PR,
  and an extra-backed file joins the `test` job's step that runs those files and fails on
  any skip: a skipped module reads like a passing one in the summary line.
- **Test framework verification against a fake distribution, not an SDK.** The `framework`
  fixture in `tests/test_review_runtime_0_10_28.py` lays out a `smolagents` distribution,
  RECORD included, under `tmp_path` in a `file-symlink`, `package-symlink` or `copy` layout:
  `framework(layout)` returns its `tools` module, so `_arg_walk.is_framework_object` and
  run-wrapper identity need no SDK. It is local to that module and resets
  `_arg_walk._distribution_files` (a `@cache`) on each install and at teardown: copy that too.
- **Count Airlock layers by what they do**: a one-call-per-hour rate limit (a second layer
  spends the only token) or audit records per call. Never walk `__wrapped__`:
  `named_tool_proxy` sets none, so a helper that did reported one layer on a tool wrapped
  twice (`tests/test_crewai_double_wrap_0_10_25.py` until the 0.10.28 review).
- **A wall-clock p99 assertion is the best of five 100-sample batches** (the `min` across
  batches of each sorted batch's 99th value), not one batch's p99 and not the median of
  them: one batch's p99 is its second-worst sample, so a single scheduler hiccup set it, and
  a median tracked the host's load rather than the code. The ceiling widens under
  `sys.gettrace()`, since coverage inflates per-call cost several-fold in CI.
  `grep -rln batch_p99s tests --include='*.py'` lists the tests that do this; copy one.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: dependencies -->
## Key Dependencies

CI's `test` job installs `.[dev,redis,mcp,crypto]`, because the redis-backed,
FastMCP-backed, Ed25519-identity and attested-admission modules skip without them
(`pytest.importorskip`). `[crypto]` joined in 0.10.26: `cryptography` had arrived only
transitively, through `mcp`'s `pyjwt[crypto]` and FastMCP's `authlib`. `[mcp]` resolves to
the newest FastMCP the pin allows (`<5.0`), so a FastMCP release inside the pin that breaks
the integration fails CI rather than a user; one past the pin, installed directly, is outside
that net.

Several existing `importorskip`s break the rule above: the real-SDK tests for google-adk,
crewai, smolagents, anthropic, llama_index, autogen, agentdojo and openai-agents import SDKs
no CI job installs, so they skip in every run (`grep -rn importorskip tests/ --include='*.py'`).
The openai-agents one (`TestTheOpenAIAgentsSDK` in `tests/test_call_path_0_10_28.py`) has a
CI-run twin: the same module calls each tool positionally, which is what that SDK does. The
E2B tests in `tests/test_remaining_coverage.py` skip in every run too, through an inline
`pytest.skip` that grep misses: no job installs `[sandbox]`.

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Notes

Add module-specific notes here — this section is never auto-modified.

<!-- END MANUAL -->
