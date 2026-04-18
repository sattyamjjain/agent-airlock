# Agent-Airlock — Deep Codebase Analysis

**Version scanned:** v0.4.0 "Enterprise" (with v0.4.1 anomaly-detection / CVE-2026-26118 hardening visible in `anomaly.py`, `CHANGELOG.md`)
**Language / stack:** Python 3.10+ · Pydantic V2 (strict) · structlog · Hatch · mypy `--strict` · ruff
**Report date:** 2026-04-18
**Audience:** Platform & security engineers evaluating fitness for production use

---

## 1. Executive summary

Agent-Airlock is a **defense-in-depth middleware that sits between an AI agent and its tools**. It intercepts the kwargs an LLM passes to an MCP tool, strips hallucinated "ghost" arguments, re-validates with a strict Pydantic schema, enforces an RBAC / rate-limit / capability / filesystem / network policy stack, optionally executes inside an E2B Firecracker MicroVM, sanitizes the output for PII & secrets, and emits a structured audit trail (JSON Lines plus optional OpenTelemetry spans).

The repository is in **good shape**: src/ layout with ~14.8K LOC across 36 modules, 42 test files and ~16.4K LOC of tests, mypy strict, ruff-enforced formatting, CI matrix across Python 3.10/3.11/3.12 with bandit + safety + CycloneDX SBOM generation. Coverage gate is 79 % (CI enforces 80 % in the config). The public API exported from `src/agent_airlock/__init__.py` is large (~200 symbols) which makes semver maintenance harder than it needs to be.

The architecture is **sound**, but its biggest production risks come from three places that are inherent to the design rather than from sloppy coding: **(1)** monkey-patching third-party framework decorators (`vaccine.py`) and the stdlib socket module (`network.py`) — both are fragile across dependency upgrades; **(2)** a cloudpickle round-trip for remote sandbox execution, which is only safe as long as deserialization never happens on the host; and **(3)** regex-based PII detection running on untrusted output, which needs a timeout or a budget to be fully ReDoS-safe.

---

## 2. Repository layout

```
agent-airlock/
├── pyproject.toml           Hatch build, 3.10+, pydantic>=2 <3, structlog, tomli (py<3.11)
├── README.md                ~21 KB marketing/feature overview
├── SECURITY.md              Responsible disclosure, defense-in-depth summary, ReDoS analysis
├── CHANGELOG.md             v0.4.1 CVE-2026-26118 defense, v0.4.0 Enterprise, v0.3 Vaccine
├── LICENSE                  MIT
├── .github/workflows/ci.yml Test matrix (3.10/3.11/3.12) + lint + security + SBOM
├── Dockerfile               (present)
├── src/agent_airlock/       36 modules, ~14,850 LOC (see §3)
├── tests/                   42 test files, ~16,444 LOC
├── examples/                21 runnable integration examples (LangChain, CrewAI, etc.)
└── docs/                    MkDocs site (getting-started, guide, changelog)
```

The **src/ layout** is correct — nothing leaks into the import path when the package is installed editable. Entry points for the two CLI commands (`airlock doctor`, `airlock verify`) are declared as console scripts.

---

## 3. Module-by-module architecture

The package is organized into five conceptual layers. The table below records the real LOC and key exports observed in the source.

### 3.1 Validation layer

| Module | LOC | Key exports | Notes |
|---|---|---|---|
| `core.py` | 1,216 | `Airlock` decorator, `airlock()` helper | Five-gate pipeline. Sync/async dispatch decided at decoration time via `asyncio.iscoroutinefunction`. Signature preservation so LangChain / CrewAI can still introspect schemas. |
| `validator.py` | 187 | `create_strict_validator`, `strip_ghost_arguments` | Builds a Pydantic V2 model from the wrapped function's signature and runs in strict mode (no coercion). |
| `unknown_args.py` | 195 | `UnknownArgsMode` (`BLOCK` / `STRIP_AND_LOG` / `STRIP_SILENT`) | V0.4 replacement for the older boolean `strict_mode`. |
| `safe_types.py` | 547 | `SafePath`, `SafeURL` (+ variants) | Pydantic V2 validators — directory-traversal prevention, metadata-URL blocking, regex validation. Three `# nosec` comments are in assertion-style checks, not real binds (see §5). |

### 3.2 Policy layer

| Module | LOC | Key exports | Notes |
|---|---|---|---|
| `policy.py` | 527 | `SecurityPolicy`, `RateLimit` (token bucket), `TimeWindow` | Predefined: `PERMISSIVE_POLICY`, `STRICT_POLICY`, `READ_ONLY_POLICY`, `BUSINESS_HOURS_POLICY`. |
| `capabilities.py` | 350 | `Capability` enum (22 capabilities), `CapabilityPolicy`, `@requires()` decorator | Per-tool capability gate; granular (`filesystem.read`, `network.http`, `sandbox.execute`, etc.). |
| `filesystem.py` | 295 | `validate_path`, `FilesystemPolicy` | Uses `os.path.commonpath` + symlink resolution; root allowlist driven. |
| `network.py` | 713 | `validate_endpoint`, `network_airgap` context manager, `EndpointPolicy` | Socket monkey-patch (connect / connect_ex / getaddrinfo) with reference-counted install/uninstall and thread-local policy. |

### 3.3 Execution layer

| Module | LOC | Key exports | Notes |
|---|---|---|---|
| `sandbox.py` | 862 | `execute_in_sandbox`, `SandboxPool` | Warm pool of E2B MicroVMs for sub-200 ms startup. Explicit `sandbox_required=True` guard to prevent silent local fallback. |
| `sandbox_backend.py` | 538 | `E2BBackend`, `DockerBackend`, `LocalBackend` | Pluggable. cloudpickle payload serialized, base64 over stdin; the untrusted side never runs on the host. |
| `streaming.py` | 365 | `StreamingAirlock`, `create_streaming_wrapper` | Per-chunk PII/secret sanitization with cumulative output truncation. |
| `context.py` | 333 | `AirlockContext`, `ContextExtractor` | `contextvars`-backed — async-safe request scope. |
| `conversation.py` | 425 | `ConversationTracker`, `ConversationState` | Multi-turn call graph; prevents loops. |

### 3.4 Post-processing & ops layer

| Module | LOC | Key exports | Notes |
|---|---|---|---|
| `sanitizer.py` | 731 | `detect_sensitive_data`, `mask_sensitive_data`, `sanitize_output` | 14 detectors including India-specific PII (Aadhaar / PAN / UPI / IFSC). Four masking strategies: FULL / PARTIAL / TYPE_ONLY / HASH. |
| `audit.py` | 318 | `AuditLogger`, `AuditRecord` | JSON Lines, thread-safe Lock. Option to SHA-256-hash args instead of logging them. |
| `audit_otel.py` | 330 | `OTelAuditExporter`, `EnhancedAuditRecord` | OpenTelemetry bridge (OTLP). |
| `observability.py` | 375 | `OpenTelemetryProvider`, `track_event`, `record_metric` | No-op provider when disabled. |
| `circuit_breaker.py` | 346 | `CircuitBreaker`, `CircuitState` (CLOSED/OPEN/HALF_OPEN) | Per-tool breakers. |
| `cost_tracking.py` | 487 | `CostTracker`, `BudgetConfig`, `TokenUsage` | Callback hooks, cumulative cost. |
| `retry.py` | 372 | `@retry`, `RetryPolicy` (6 presets) | Exponential backoff + jitter. |
| `self_heal.py` | 377 | `AirlockResponse`, `BlockReason` | The "self-healing" JSON block returned on failure, with `fix_hints` for the LLM to retry. |

### 3.5 Framework-vaccine & v0.4.1 hardening

| Module | LOC | Notes |
|---|---|---|
| `vaccine.py` | 384 | Monkeypatches `@tool` decorators in LangChain / OpenAI SDK / CrewAI / smolagents / AutoGen. `FRAMEWORK_DECORATORS` is a hard-coded registry — fragile to upstream API changes (see §8 Risk 1). |
| `honeypot.py` | 397 | Soft-block strategy — return fake success data so the LLM doesn't enter a retry loop against the policy boundary. |
| `mcp.py` / `mcp_proxy_guard.py` | 361 / 626 | FastMCP integration; v0.4 MCP Proxy Guard prevents credential passthrough (session binding, per-tool `CredentialScope`). |
| `anomaly.py` | 412 | v0.4.1 addition — sliding-window call-rate monitor, endpoint diversity, error rate, consecutive-block tracking. Lock-guarded `deque`. |
| `integrations/` | 977 | LangChain `@tool` wrapper, Anthropic SDK `ToolRegistry`, OpenAI Agents SDK guardrails bridge. |

---

## 4. The @Airlock decorator — real control flow

From `core.py`, the ordered sequence when a wrapped tool is called:

1. **Pre-execution** (`_pre_execution`), five sequential gates:
   1. **Ghost argument handling** — `validator.strip_ghost_arguments()` diffs kwargs against `inspect.signature(func)`. `BLOCK` raises; `STRIP_AND_LOG` strips with a structlog event; `STRIP_SILENT` strips without logging.
   2. **Security policy** — policy can be a static `SecurityPolicy` or a `Callable[[AirlockContext], SecurityPolicy]`. Checks rate-limit bucket, tool allow/deny, RBAC role, `TimeWindow`.
   3. **Filesystem validation** — any param whose name matches `(path|file|dir|source|destination)` is pushed through `FilesystemPolicy` (root allowlist, symlink resolution, traversal prevention).
   4. **Capability gating** — `CapabilityPolicy` verifies the tool has been granted every `@requires(Capability.*)` it declares.
   5. **Endpoint policies (v0.4.1)** — any URL-shaped param is routed through `EndpointPolicy` (blocked IPs, allowed hosts, cloud-metadata-URL blocking).
2. **Context binding** — `AirlockContext` (session/agent/user id) is bound into `contextvars` for the duration of the call.
3. **Network airgap** — if `network_policy.allow_egress=False`, `network_airgap()` installs the socket interceptors via a reference-counted context manager (safe to nest).
4. **Execution dispatch** — either `validated_func(**kwargs)` (local strict Pydantic wrapper) or `_execute_in_sandbox()` (cloudpickle → E2B/Docker/Local backend). Sync vs. async branch decided at decoration time.
5. **Exception handling** — known exceptions (`NetworkBlockedError`, `ValidationError`, `CapabilityDeniedError`, `PathValidationError`, `PolicyViolation`, `SandboxUnavailableError`, `SandboxExecutionError`) are caught and converted into `AirlockResponse.blocked_response()` with `fix_hints`. Unknown exceptions are logged and re-wrapped.
6. **Post-execution** — `sanitize_output()` runs if enabled, truncating to `max_output_chars` and masking per strategy.
7. **Audit** — one JSON-Lines record per call (tool_name, blocked flag, duration_ms, sanitized_count, optional args-hash, result preview) under a per-file lock.
8. **Return** — raw value on success, or the self-healing dict when blocked / `return_dict=True`.

Documented lock order in `core.py:39–44` is `_pool_lock → audit._file_lock → _patch_lock`, which is internally consistent — no circular acquisitions were found.

---

## 5. Security posture

| Area | Observation | Verdict |
|---|---|---|
| `eval` / `exec` in production | None. The two occurrences are in docstrings. | ✅ Clean |
| `subprocess` with `shell=True` | None — `sandbox_backend.py` uses argv-style invocation for Docker. | ✅ Clean |
| Monkey-patching | `network.py` patches `socket.connect/connect_ex/getaddrinfo`; `vaccine.py` patches framework `@tool` decorators. | ⚠️ Intentional but fragile — see Risk 1 |
| Pickle / cloudpickle | Only in `sandbox_backend.py`, and only the *serialize* side runs on the host. Deserialize runs inside the sandbox. | ✅ As long as `sandbox_required=True` on dangerous tools |
| `# nosec` markers | 6 total. `sanitizer.py:38` (B105 enum name, not password), `filesystem.py:290` (B108 `/tmp` paths — intentional sandbox paths), `safe_types.py:411/424` (B104 — *checking* bind addresses, not binding), `honeypot.py:90/174` (B105/B311 — deliberately fake data), `retry.py:86` (B311 — jitter, not crypto). All are justified. | ✅ |
| PII / secret detectors | 14 patterns: email, phone, SSN, credit card, IP, Aadhaar, PAN, UPI, IFSC, OpenAI `sk-`, Anthropic `sk-ant-`, GitHub `ghp_`, AWS `AKIA/ASIA/...`, JWT, PEM private key, Slack `xox`, Mongo/Postgres/MySQL/Redis/AMQP URIs. `SECURITY.md` includes a ReDoS analysis per pattern. | ✅ Analysis documented |
| Crypto | stdlib `hashlib` for args-hash only. No custom TLS, no HMAC. Network traffic is in-process; TLS is the caller's responsibility. | ℹ️ In scope |
| Thread safety | `audit` (Lock), `network` (ref-counted install + thread-local policy), `sandbox` pool (`_pool_lock`), `anomaly` (Lock + `deque`), `context` (`contextvars`). | ✅ |

---

## 6. Testing & CI

- **42 test files, ~16.4K LOC.** File map mirrors the src/ layout: `test_core.py`, `test_async.py`, `test_sandbox.py`, `test_network.py`, `test_honeypot.py`, `test_policy.py`, `test_capabilities.py`, `test_anomaly.py`, `test_streaming.py`, `test_vaccine.py`, `test_mcp.py`, etc., plus "full" integration variants (`test_core_full.py`, `test_sandbox_integration.py`, `test_framework_integration.py`, `test_remaining_coverage.py`).
- **Coverage gate** — `pyproject.toml` declares 79 % minimum; the CI step uses `--cov-fail-under=80`. Anything below 80 breaks the build.
- **CI (`.github/workflows/ci.yml`)** runs in three jobs:
  1. **Test** — matrix over Python 3.10 / 3.11 / 3.12, runs ruff check, mypy, pytest with coverage, uploads to Codecov.
  2. **Lint** — `ruff format --check` on 3.11.
  3. **Security** — `bandit -r src/` (skips B101 assert), `safety check` (continue-on-error), `cyclonedx-py` SBOM artifact.

### Potential test gaps

Integration-style files like `test_remaining_coverage.py` are what keep the coverage gate green for smaller modules (`context.py`, `unknown_args.py`, `retry.py`, `cost_tracking.py`). That's a legitimate pattern, but it means regressions in one of those modules can be harder to localize from a coverage-drop signal alone. Nothing critical is untested.

---

## 7. Dependencies & public surface

**Required** (pyproject.toml lines 40-44): `pydantic>=2,<3`, `structlog>=24`, `tomli>=2; python_version<'3.11'`. That's it — the core has a genuinely small footprint.

**Optional extras**:
- `sandbox` — `e2b>=1,<2`, `cloudpickle>=3`
- `mcp` — `mcp>=1`, `fastmcp>=2,<3`
- `dev` — pytest, mypy, ruff, bandit, safety, cyclonedx-bom
- `docs` — mkdocs, mkdocs-material, mkdocstrings

Everything is upper-bounded, which is responsible for a security-middleware library.

**Public API surface** (from `__init__.py`): ~200 symbols. The entire v0.4.1 feature set is re-exported (anomaly detector, EndpointPolicy, CredentialScope, MCPProxyGuard, etc.). A smaller curated surface would reduce the risk of accidental breakage, but given the number of integrations, the breadth is understandable.

---

## 8. Top risks & improvement opportunities

1. **Framework-vaccine coupling** — `vaccine.py`'s `FRAMEWORK_DECORATORS` hard-codes module paths like `langchain_core.tools.tool`. A breaking rename on the upstream side silently falls through the `try/except ImportError` and the tool becomes un-vaccinated with only a warning. Recommendation: add a CI job that pins each supported framework to its minimum / maximum tested version and fails if a monkey-patch target has moved.
2. **Socket interceptor reference counting** — `network.py`'s `_install_interceptor` / `_uninstall_interceptor` are ref-counted; `network_airgap()` is safe because it's a context manager, but any direct call that throws between install and uninstall leaks a reference. Recommendation: make the private install/uninstall non-public, or wrap them in `try/finally` internally.
3. **Local sandbox fallback** — `core.py:774-787` will fall back to local execution when `E2B_API_KEY` is missing *unless* `sandbox_required=True` was passed at decoration time. For a security-middleware library, the safer default is the opposite — require an explicit opt-in (`allow_local_fallback=True`) before ever running sandboxed-declared code on the host.
4. **ReDoS budget on untrusted output** — the 14 PII/secret patterns are individually ReDoS-analyzed in `SECURITY.md`, but the cumulative cost on a 100 MB output with many near-matches has no wall-clock budget. Recommendation: add a `max_sanitize_ms` per call or wrap the regex sweep in `signal.alarm` / `asyncio.wait_for`.
5. **Cloudpickle on the host** — the sandbox-backend serializes on the host and deserializes in the VM, which is fine. But the comment in `sandbox.py:7-9` is the only load-bearing assurance here; an accidental change that caused a host-side `cloudpickle.loads` on returned data would be a sandbox escape. Recommendation: pin a lint rule (`grep -R "cloudpickle.loads"` in a CI gate) that blocks any new `.loads` outside the sandbox subprocess.
6. **Public-API inflation** — ~200 symbols re-exported means consumers can rely on internals. Consider a leaner, documented `__all__` and moving niche helpers into submodules users import explicitly.

---

## 9. Bottom line

Agent-Airlock is one of the more thoughtfully engineered security-middleware projects for the MCP ecosystem. Its architecture is layered, its tests and CI are strong, and its enterprise features (capability gates, circuit breaker, OpenTelemetry, cost tracking, anomaly detector) are implemented, not stubbed. The legitimate concerns are all design-boundary issues: the cost of monkey-patching third-party frameworks, the cost of cloudpickle for remote execution, and the cost of regex-based PII on untrusted output. Each one is manageable with the mitigations above; none of them are show-stoppers.
