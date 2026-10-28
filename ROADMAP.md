# Roadmap

Every item here comes from a caveat this repo's own [README](README.md) already states in
public. Nothing on this list is invented: it is the set of gaps agent-airlock names about
itself, promoted to tracked work.

**How this list is tracked.** Previously this file said "each item is a GitHub issue with the
`roadmap` label" and linked #122 / #123 / #124. All three are closed and the repo has **zero
open issues**, so that sentence pointed at nothing — a reader clicking through found closed
tickets and no way to tell which work had actually landed. The issues are kept below as
*history*, labelled with what shipped and what did not. The plan itself now lives here, in
this file, because a one-maintainer repo with no open issues does not need an issue tracker
to be the source of truth — it needs the source of truth to be somewhere that is actually
maintained.

Shape is Now / Next / Later, ordered by how bounded the work is, not by importance.

## Shipped since this file was last accurate

- **OWASP ASI04 answered rather than raised (v0.8.84).** The question was whether ASI04 is
  Partial because coverage is incomplete or because part of it is out of scope for an
  in-process argument validator. Enumerated against the codebase, the answer is both.

  Uncovered but in scope, now implemented: **tool-definition rug-pull**. A tool approved once
  could be re-served under the same name with a changed description or `inputSchema`.
  `attested_admission` gates on tool *names*, so nothing refused that call.
  `mcp_spec/tool_definition_pin_guard.py` pins the contract and denies on drift.

  Out of scope by architecture, now stated in the legend rather than left as an open gap:
  model checkpoint compromise, on-disk package compromise, and AIBOM/SCA inventory. Each names
  the layer that covers it.

  The row also under-credited three guards already in the tree
  (`description_manifest_guard`, `schema_ref_guard`, `attested_admission`). The coverage label
  is still Partial. Issue [#124](https://github.com/sattyamjjain/agent-airlock/issues/124) was
  closed 2026-08-06 without the coverage being raised, and this is the work that closed it.

- **The `sandbox=True` validation gap is closed (v0.10.6).** The README's first line
  promises a deny-by-default contract layer; on the sandbox dispatch path that contract did
  not run at all. With a real backend available, `@Airlock` serialised the *undecorated*
  function into the micro-VM instead of calling the Pydantic-validated wrapper, so no
  `Annotated` validator ran: `SafePath`, `SafeURL` and `HandleField` alike. Ghost-argument
  stripping was the only part still in effect, because `cleaned_kwargs` is computed upstream
  of the branch. An operator who wrote `@Airlock(sandbox=True)` for a *dangerous* tool, which
  is exactly when the sandbox is reached for, got isolation and no argument contract.

  The wrapper could not simply be shipped into the VM: it is a closure, the backend is not
  assumed to carry it, and the handle ledger is in-process by design. So validation is split
  from execution. All four dispatch sites (sync and async, airgapped and not) now validate in
  the parent through `validator.create_argument_validator` and hand the sandbox the
  already-validated values. A refusal returns the same `AirlockResponse`, `BlockReason` and
  `fix_hints` as the local path, so audit records from the two paths agree.

  **What still does not hold:** the ledger is still in-process and still does not travel into
  the VM. Validation happens on the parent side of the boundary, before dispatch. Nothing
  inside the sandbox can consult the ledger, mint a handle, or observe a rejection, and a
  tool that needs to issue handles from inside the sandbox remains outside what this
  expresses. `TestSandboxDispatchSkipsTheCheck` is now
  `TestSandboxDispatchValidatesFirst` and pins the fix, one case per annotated type and one
  per dispatch site.

- **An MCP conformance suite is run and the result is published.**
  ([#122](https://github.com/sattyamjjain/agent-airlock/issues/122), closed 2026-08-05.)
  The README no longer says "no MCP conformance suite has been run against this package";
  `@modelcontextprotocol/conformance@0.1.16` runs against the wire-path validators and the
  outcome is published in
  [`benchmarks/mcp_conformance/RESULTS.md`](benchmarks/mcp_conformance/RESULTS.md), with the
  date owned by `scripts/check_benchmark_freshness.py` so it cannot silently rot.
- **A second AgentDojo model was added.**
  ([#123](https://github.com/sattyamjjain/agent-airlock/issues/123), closed 2026-08-12.)
  The 2026-08-08 run put gpt-4o-2024-05-13 (ASR 72% → 22%) next to gpt-4o-mini
  (42% → 12%). This closed the *narrowest* reading of that issue and **not** the gap the
  README still describes — see Now, below.

## Now

**Widen the AgentDojo model-in-the-loop run past a single model family.**

The [AgentDojo results](benchmarks/agentdojo/RESULTS.md) publish a deterministic **86.0%
(524/609)** upper bound alongside a much smaller *realised* reduction (the 2026-07-31 pass
put the gap at +51pp, the 2026-08-08 pass at +46pp). Two OpenAI models is still **one family**,
and ActBench ([arXiv:2608.09476](https://arxiv.org/abs/2608.09476)) measured ASR spanning
10.1%–94.4% *across* models under a fixed harness — so a single family cannot speak for the
defense no matter how many of its members are sampled.

The harness is already built for this: the model-registry shim carries current Claude ids and
Together is wired. What remains is a keyed run over OpenAI + Anthropic + Together at the
power-calc-sized **163 pairs/arm** documented under "Widening plan" in
[`benchmarks/agentdojo/RESULTS.md`](benchmarks/agentdojo/RESULTS.md). That would replace a
scoped point estimate with a real cross-family number.

**Correction, 2026-09-09: "It is gated on API budget, not on code" was false, and
"Together is wired" was half true.** agentdojo's `together` provider, the price table and
the OpenAI-SDK cost hook were all in place — but the registry shim, the one component that
has to put an id into agentdojo's tables, had no Together branch. `_infer()` returned
`("anthropic", "Claude")` for every `org/model` slug, and `ensure_registered()` only
auto-registered ids starting with `claude`, so `--model meta-llama/…` registered nothing
and `ModelsEnum(...)` raised. Forced through `--register-model`, the arm would have been
built against `anthropic.Anthropic()` with the attack addressing a Llama model as "Claude"
— a number that looks like a result and means nothing. Fixed in v0.8.91 with eight
regression tests and a verified negative control.

So the item is unchanged in substance but honest in status: **the code blocker is now
removed, and it is genuinely gated on API budget alone.** No pilot arm has run — see
"Cross-family widening" in [`benchmarks/agentdojo/RESULTS.md`](benchmarks/agentdojo/RESULTS.md)
for exactly which arms did not run and why.

**Status as of 2026-10-10: unscheduled.** It waits on an API-budget decision, and no date is
committed until that decision is made. Read it as an open question, not a promise.

**~~Give the matched-pair injection null enough sample to mean something.~~ Done 2026-08-26.**

Run at `--trials 18` — 144 cells, n = 36 per harness per arm. The injected arm is **0/36** for
both harnesses, 95% Wilson **[0.0%, 9.6%]** and pooled **[0.0%, 5.1%]**, meeting the n = 35
target this item was written to name. It also produced the first live benign control in four
runs (`codex` 1/36), which does *not* establish discrimination — Fisher exact p = 1.00.
Numbers: [`benchmarks/harness_injection/RESULTS.md`](benchmarks/harness_injection/RESULTS.md).

What is left here is a *different* item, and it is worth stating rather than closing quietly:
at n = 36 a true **2%** action rate still escapes this run about half the time, and `codex`
demonstrated a real behaviour at 1-in-36. Bounding rare behaviour needs n ≈ 74
(`--trials 37`, 296 cells), which is again gated on API budget rather than code.
**Status as of 2026-10-10: unscheduled**, for the same reason: no date is committed until the
API budget is decided.

## Next

_The ASI04 item that sat here was resolved in v0.8.84. It is recorded under
"Shipped since this file was last accurate" rather than deleted, because a roadmap that
quietly drops items reads the same as one that never had them._

## Later

**~~Write the seven missing feature doc pages.~~ Done 2026-09-12 (v0.10.2).**

Fixing the README's dead links in v0.8.80 surfaced this rather than created it: shipped
features with no documentation page at all, whose README rows pointed at files that had
never been written.

The count was wrong twice, in both directions, which is its own small lesson about
untracked prose. It said **seven**; two of those (`policy_bundle.lock`, `kill-switch`)
already had real pages written on 2026-09-04, five days before this file was last edited,
so it was **five**. All five are now written:

| Feature | Code | Doc |
|---|---|---|
| `airlock attest receipt` | `attest/` | `docs/cli/attest-receipt.md` |
| `airlock console` | `cli/console.py` | `docs/cli/console.md` |
| `policy_bundle.lock` | `pack/` | `docs/cli/policy-bundle-lock.md` |
| `airlock studio` | `studio/` | `docs/cli/studio.md` |
| `airlock graph serve` | `cli/graph.py` | `docs/cli/graph-serve.md` |
| `airlock policy compile / explain` | `policy_compiler/` | `docs/cli/policy-compile-explain.md` |
| `airlock kill-switch` | `kill_switch/` | `docs/cli/kill-switch.md` |

Each was written by running the command and documenting what it did, not by reading the
source and describing what it should do. That surfaced a defect in the process:
`airlock policy compile` defaults to a keyword-matching stub and printed authoritative
YAML unrelated to the request, with no indication. It now says so. Each page also carries
an "Honest scope" section naming what the feature does **not** do — the HMAC-only signers
behind `attest receipt`, the 5-second poll behind `graph serve`, the unauthenticated bind
on `studio` and `graph serve`.

`scripts/check_links.py` prevents the 404s from coming back; writing the pages is what
this item was actually for.

## Shipped history

Moved verbatim from the MANUAL section of `CLAUDE.md` on 2026-10-28 (UTC), where it had grown
into a record of shipped work rather than instructions; "this line" and "the checklist
below" inside it refer to that file's layout.

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

---

Have a gap we should be honest about that is not on this list?
[Open an issue.](https://github.com/sattyamjjain/agent-airlock/issues/new)
