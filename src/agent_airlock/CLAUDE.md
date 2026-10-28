# Module: agent_airlock

<!-- AUTO-MANAGED: module-description -->
## Purpose

The installed package: `@Airlock` (`core.py`, sync and async) and every layer it runs.
`mcp_spec/` and `integrations/` carry their own `CLAUDE.md`. What ships:

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
  `cli/__main__.py` (or `airlock --help`) is the authoritative subcommand list. It
  dispatches in space-form (`airlock scan-tools`), so flags are identical to the
  `python -m agent_airlock.cli.<name>` long form; three pre-dispatcher scripts
  (`airlock-explain`, `airlock-conformance`, `airlock-scan-tools`) survive as stable aliases

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: architecture -->
## Module Architecture

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
     on; `deny` refuses every call guarded by a config that sets it while a hook is not on
     `startup_hook_allowlist`, whose entries pin a hook file's bytes, not the modules its
     `import` lines load
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

The order is defense-in-depth — kill switch → startup hooks → token audience → ghost
arguments → policy (and the 2.5–2.8 gates) → filesystem → capability → network → budget →
strict validation and sandbox at execute. Most guard layers trace to a named advisory; the
kill switch, the startup-hook check and the budgets are operational controls.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Module-Specific Conventions

- **Decorator entrypoint.** `@Airlock()` wraps a function with the full layer stack and
  preserves `__signature__` / `__annotations__` so framework introspection still works.
- **Caller identity.** `STRICT_POLICY` requires an agent identity: a first argument that
  carries one at `.context` / `.ctx` (`ContextExtractor.CONTEXT_ATTRS` lists what is read; a
  bare `AirlockContext` passed as the first argument is not read), or
  `with AirlockContext(agent_id=...)` around the call (`_caller_identity` in `core.py`).
- **Context propagation.** `contextvars`-backed `AirlockContext`; `get_current_context()` is
  available inside the wrapped tool, and a policy may be a callable over that context for
  per-tenant / per-workspace rules.
- **A new `BlockReason`** (`self_heal.py`) fails `test_every_block_reason_is_covered` until
  `tests/test_fix_hints_0_10_25.py` has a `_REFUSALS` row whose call is refused with it
  (each row is checked for the `AIRLOCK_BLOCK` prefix and non-empty `fix_hints`), or lists
  it in `_NOT_ON_THE_CALL_PATH` with a reason.
- **Deny-by-default, in detail.** Unknown tier, unregistered manifest and unpinned spec
  revision fail closed, and so does an input shape a guard cannot read, such as a list where
  a string was expected: it is refused rather than skipped (see `mcp_spec/CLAUDE.md`). The
  core value-reading gates, when one of them is on (`_reads_argument_values`), refuse input
  too deep or self-containing to read, and a resolver that returns no policy refuses the
  call.
- **Guard + preset pairs.** `mcp_spec/` guards come in three shapes (see
  `mcp_spec/CLAUDE.md`); a guard's preset factory, usually `*_defaults()`, lives in
  `policy_presets.py`. Register it with `@preset` **and** list it in
  `policy_presets.__all__`, and any `policy_presets.<name>` named in README or `docs/` must
  resolve to a registered factory (`tests/presets/test_registry_parity.py`). An
  unregistered preset never shows up in `list_active()`. Many guards are re-exported from
  the package root (`agent_airlock.__all__`); `mcp_spec/__init__.py` exports no per-CVE
  guard — its `__all__` is the protocol surface only.
- **Declarative presets.** `presets/*.yaml` use a restricted YAML dialect
  (`schema_version: 1`) that `preset_loader` parses without PyYAML. Every `factory:` value,
  even on an `enabled: false` entry, must name a preset registered in
  `policy_presets.list_active()` — `tests/presets/test_ox_mcp_yaml.py` checks this against
  every file under `presets/`, not just the one it's named for.
- **No silent config no-ops, in detail.** A stored `AirlockConfig` field that nothing applies
  must be listed in `config._NOT_APPLIED` (field name → what to use instead), or documented
  in its field comment as a carrier for a named consumer (`credential_scopes` →
  `MCPProxyConfig(tool_scopes=...)` is the one such field), so
  `_warn_on_settings_not_applied` emits a `FutureWarning` (deprecated, removal in v1.0.0)
  when it's set away from its default. `FutureWarning`, because Python hides
  `DeprecationWarning` outside `__main__`.
- **Dated snapshots.** Pricing tables, advisory blast-radius data and redaction patterns
  ship as dated files under `data/` and `fixtures/`; a refresh is a new dated file, not an
  edit to the old one, plus a repoint of the one constant naming the current file
  (`grep -rnE '_20[0-9]{2}_[0-9]{2}[^"]*\.(json|txt)"' src/agent_airlock`; the grep also
  lists the kept June pricing loader and one preset's provenance path). Superseded
  snapshots stay in `data/`, the 2026-06 pricing one with a loader, the 2026-09 one without.
  `cost_tracking.DEFAULT_PRICING` is the undated in-process fallback, so a price refresh
  edits it too; `tests/test_budget_pricing_0_10_24.py` fails when it lacks a model the
  current snapshot prices.
- **Exceptions with other bases on purpose.** Pre-v0.5.1 exceptions keep their `Exception` /
  `ValueError` bases (`exceptions.py` docstring), two later ones do too
  (`OversightDeniedError`, `OpenAPIDriftViolation`), and `SequenceViolation` /
  `ActionContradictionViolation` subclass `PolicyViolation` by design, so
  `except AirlockError` does not catch `PolicyViolation`, `PathValidationError` and the
  like; do not rebase any of them in a patch release.
- **Logger names.** `from .._log import structlog` one package down; `core.py` alone uses the
  bare root name (`tests/test_tooling_honesty_0_10_28.py` checks every `get_logger` call). In
  `src/` the shim is the only module that imports `structlog`.
- **Forbidden-pattern greps.** `mcp_spec/manifest_only_mode.py` is the only `subprocess`
  importer in `src/` and does not use `shell=True`; the `shell=True` grep hits in
  `capabilities.py` (a docstring) and `cli/doctor.py` (a detection regex) are text, not
  calls.
- **Also by name** — `airlock attest` receipts (identity plus assume/guarantee
  `LayerContract`); `SandboxPool` of single-use sandboxes, one pool per config, hiding cold
  starts; `vaccinate()` monkeypatching third-party `@tool` decorators; honeypot deception
  returning plausible fake success.
- New modules follow the layered structure: validation → policy → execution → sanitization.
  Keep security-relevant decisions observable via structured logging.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: dependencies -->
## Key Dependencies

**External: Pydantic only** (plus `tomli` on Python 3.10; root `CLAUDE.md`). Anything from an
extra (`e2b`, `redis`, `cryptography`, framework SDKs) is imported inside the function that
needs it, behind `try/except ImportError`, raising an error that names the extra to install —
`pip install -e ".[sandbox]"` for E2B Firecracker micro-VM execution, `pip install -e
".[redis]"` for the distributed rate limiter. `structlog` is the exception: `_log.py` tries it
once at import and falls back to the stdlib shim instead of raising.

**Enforced by `bare-install`:** `check_core_deps.py` fails on a new core dependency, its
import step fails on a module-level import of an extra in the modules it loads (the package
root, `audit`, `policy_presets` and what they import: about three fifths of the package, not
`sequence_guard`, `action_contradiction_gate`, `sandbox`, `cli/` or most of
`integrations/`), and since 0.10.26 `check_bare_imports.py` imports every module under the
package, so such an import anywhere fails there.

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Notes

Add module-specific notes here — this section is never auto-modified.

<!-- END MANUAL -->
