# Module: integrations

<!-- AUTO-MANAGED: module-description -->
## Purpose

Adapters that put `@Airlock` in front of third-party agent SDKs' tools and normalise vendor
tool-call payloads, plus helpers that sit beside them: the Managed Agents tool gate (reviews
session events, wraps nothing), Messages API task budgets, Claude runtime hooks, commerce
caps, log redaction, an IDE-scanner bridge. The FastMCP integration lives in
`../mcp/__init__.py` and framework vaccination in `../vaccine.py`; neither imports from here.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: architecture -->
## Module Architecture

- **Walkers** (`crewai`, `pydantic_ai`, `google_adk`, `anthropic_claude_agent_sdk`) take an
  agent, find its tools, and replace in place the callable the framework actually invokes,
  which is not always the obvious attribute: PydanticAI runs
  `tool.function_schema.function`, and a CrewAI `@tool` runs `func`, not `_run`. Prove
  interception with a stub that mirrors the SDK's real call path. A walker is idempotent
  per tool: `crewai` marks each shim with `_GUARDED_MARKER` and skips a tool that carries it
  on itself or its `func` / `_run`, because `Task(agent=a)` shares the agent's `tools` list
  and `wrap_crew` walks it twice (until 0.10.25 every allowed call wrote two audit
  records); copy that check into a new walker. The Claude SDK adapter's
  `wrap_tools` returns guarded copies instead (only `wrap_agent` mutates in place), so wrap
  before `create_sdk_mcp_server`, which keeps its own references. `langchain`, `anthropic`
  and `openai_guardrails` are the older decorator style. `smolagents_wrapper` runs
  caller-supplied `PolicyBundle` guards and never builds an `Airlock`. The `gpt5_5_*` /
  `gemini3_*` shape adapters normalise vendor payloads. `langgraph_toolnode_compat` only
  unwraps ToolNode output, and `model_armor`'s `ModelArmorScanner` is called by the user,
  never by `@Airlock`; neither wraps tools.
- **`@Airlock` enforces only the signature it is handed.** Re-tag a tool with
  `_tool_proxy.named_tool_proxy`, which carries the tool's signature (annotations resolved)
  and is async when the tool is; pass framework-injected context parameters as
  `relaxed_params`, as `pydantic_ai._run_context_params` does for a `RunContext`;
  `google_adk` predates the proxy and relaxes ADK's with its own `_relax_injected_params`.
  A Claude SDK `SdkMcpTool` handler takes one `args` dict, so `_claude_sdk_tools` builds the
  signature from its `input_schema` instead and spreads the dict into it; the per-field
  contract (strict types, ghost arguments) would otherwise see one opaque parameter. Test
  every walker with a
  wrong-typed and a ghost argument through the SDK's real call path; async handling is
  pinned once, in `tests/integrations/test_tool_proxy.py`.
- **`claude_managed_agents` reviews, it does not wrap.** A Managed Agents built-in tool runs
  in Anthropic's container; the client sees a call before it runs only when the tool is
  `always_ask`. `ManagedAgentToolGate.review()` checks, in order, the kill switch, that the
  tool is known (an MCP tool by its allowlisted `(server, tool)` pair), `allowed_tools`, the
  input (`RemotePathPolicy`: lexical `normpath` / `commonpath`, never `realpath`; `~`,
  `$var`, `\`, NUL and non-strings refused; `glob` patterns checked on their static prefix
  and full path; `web_fetch` through `validate_endpoint`; `bash` refused unless a
  `command_check` returns True), then `policy.check`; a check that raises refuses.
  `ToolUseDecision.confirmation` is the `user.tool_confirmation` to send (`result`
  allow / deny, `deny_message` = `refusal_text`, capped) and is None for an event the server
  already allowed, which logs `managed_agent_tool_not_enforced` with `enforced=False`.
  `build_agent_toolset()` lists every toolset tool under `always_ask`;
  `check_agent_toolset()` refuses `auto` / `always_allow`, the API's bare-toolset default
  and an unpinned toolset type, and passes `custom` entries (the client runs those: guard
  them with `@Airlock`). The deny message reaches the model, so it carries the refusal's
  error and hints, never its metadata.
- **The Messages adapter's schema is the contract.** `anthropic.ToolRegistry` builds each
  `input_schema` from resolved type hints through `TypeAdapter(TypedDict)`, so `int` is
  `integer`, a `Literal` an `enum`, an `Optional` an `anyOf`, a nested model lands in
  `$defs`, and `additionalProperties` is false unless the tool takes `**kwargs`; an
  annotation that cannot be resolved, or a positional-only parameter, raises `AirlockError`
  at registration. `process_tool_use` returns `is_error: True` for a refusal
  (`refusal_text`), an unknown tool, unreadable input, a tool that raised (its message stays
  in the log) and an async tool on the sync path (closed, never run);
  `aprocess_tool_use` / `aprocess_message_tools` await. The `anthropic` package is never
  imported: blocks are read by attribute or key.
- **`claude_task_budget`** builds the `output_config.task_budget` object the Messages API
  reads: `{"type": "tokens", "total": N[, "remaining": M]}`, `total` at least
  `MIN_TASK_BUDGET_TOKENS`, `InvalidTaskBudgetError` for anything the API would reject,
  `TaskBudgetExhausted` only under `soft=False` (a client-side stop; the API has no hard
  mode). `CostTracker.to_task_budget` and the SDK adapter's `task_budget_request_kit`
  delegate to it. Not the Managed Agents session budget, a dollar cap set at session
  creation.
- **`adapters/`** holds the commerce adapters, which satisfy the `CommerceAdapter` Protocol in
  `agent_commerce_caps.py` (contract in `docs/adapters.md`). **`scanners/`** defines a
  `Scanner` Protocol and registry; nothing under `src/` registers a scanner.
- **Exports.** `__init__.py` imports nothing, and its `__all__` is a partial list, not an
  index. The package root imports several modules here eagerly
  (`grep -n 'from .integrations' src/agent_airlock/__init__.py`), and they pull in
  `_claude_sdk_tools`, `_tool_proxy` and `claude_task_budget`; the rest (`anthropic`,
  `langchain`, `openai_guardrails`, `model_armor`, the shape adapters, ...) load only when
  a test imports them. A module-level SDK import anywhere here fails the `bare-install`
  job, which imports every module (`scripts/check_bare_imports.py`, 0.10.26).

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Module-Specific Conventions

- **SDK imports are function-local** — none is at module level. CI's `test` job installs
  `.[dev,redis,mcp,crypto]`. That brings no agent SDK, but `[mcp]`'s FastMCP pulls in
  `opentelemetry-api` on the 4.x line CI resolves to (the 2.x line the pin also allows does
  not), so `claude_auto_memory`'s OTel span path runs in CI. `bare-install` imports every
  module.
- **Missing SDK.** Each walker raises a `<X>MissingError(AirlockError)` built from a module
  `_INSTALL_HINT` that names the `agent-airlock[<extra>]` to install. Its `_maybe_check_sdk`
  imports the SDK only when `type(obj).__module__` belongs to it — local stubs never trigger
  the import — and warns on versions outside `SUPPORTED_*_VERSIONS` (the Claude SDK adapter
  does both in a module-level `_check_sdk`, shared with `wrap_tools`). `langchain` differs:
  one entry point returns the tool unwrapped when `langchain_core` is missing, another
  raises `ImportError`.
- **A setting nothing reads warns.** The SDK adapter's `managed_audit` / `auto_memory_policy`
  (its `_NOT_APPLIED`), `SecureAnthropicClient(auto_process_tools=...)` and
  `audit_managed_agent_invocation` each emit a `FutureWarning` (removal in v1.0.0) and
  still behave as before; the rule is `config._NOT_APPLIED`'s: a setting that quietly does
  nothing reads as protection. Add a new field to the matching map, or apply it.
- **Typing and lint.** mypy runs with no SDK installed, so each imported SDK needs an
  `ignore_missing_imports` entry in `pyproject.toml`; the `disallow_untyped_calls = false`
  override for `integrations.langchain` is load-bearing. The ruff `ARG001`/`ARG002` ignore
  exists for callback-interface signatures;
  `ruff check --isolated --select ARG src/agent_airlock/integrations/` lists what it hides.
- **Tests** live in `tests/integrations/test_<module>*.py`, with these exceptions:
  `langchain` / `anthropic` / `openai_guardrails` in `tests/test_new_features.py` (and
  `tests/integrations/test_openai_guardrails.py`), `_claude_sdk_tools` in
  `tests/integrations/test_anthropic_claude_agent_sdk_tools.py`, Model
  Armor in `tests/test_model_armor_integration.py`, `agent_commerce_caps` also in
  `tests/capability_caps/`, and the 0.10.25 contract pins in
  `tests/test_anthropic_contracts_0_10_25.py` (Messages adapter, SDK tools, auto-memory,
  the gate) and `tests/test_crewai_double_wrap_0_10_25.py`. `tests/live/` drives the
  Messages, Agent SDK and Managed Agents paths against the real API (`AIRLOCK_LIVE=1`; the
  default `addopts` ignore it).
  Drive adapters with stub objects instead of installing the SDK; simulate a missing SDK by
  setting its `sys.modules` entry to `None`, and fake an installed one with stub modules,
  seeding the parent of a dotted package (`google`) as well. No CI job installs an agent
  SDK, so an `importorskip` on one is a skipped test there.
- **A new framework adapter** also needs a row in `_ADAPTER_SHIPPED_MODULES`
  (`tests/test_readme_framework_claims.py`, kept by hand), the module named in the README's
  `Adapter-shipped (N)` paragraph with N bumped, and its doc page added to the `mkdocs.yml`
  nav by hand — only `docs/benchmarks/` has a nav gate.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: dependencies -->
## Key Dependencies

**External:** `claude_agent_sdk`, `crewai`, `pydantic_ai`, `google.adk` and `google.cloud`
(Model Armor) each have a pyproject extra; `langchain_core` and `opentelemetry` have no
extra of their own (`opentelemetry-api` arrives transitively through `[mcp]`'s FastMCP).
The OpenAI Agents SDK, `anthropic`, `langgraph` and `smolagents` are never imported: those
modules use duck typing, `importlib.util.find_spec` or `importlib.metadata` probes instead.
The grep hits for `from anthropic import` and `from agents import` in this tree are
`Usage:` docstrings; the one real lazy `import anthropic` in the package is
`sandbox_backend.ManagedSandboxBackend.is_available`.

**Internal:** `.._log` and `..exceptions` almost everywhere; `..core` / `..policy` wherever
an `Airlock` is built (the decorator-style adapters import them as `agent_airlock.*`), and
`..core` again in `claude_managed_agents` for `PATH_PARAM_NAMES` / `URL_PARAM_NAMES`;
`..self_heal` in the three modules that render a refusal for a model (`anthropic`,
`_claude_sdk_tools`, `claude_managed_agents`); `..filesystem`, `..kill_switch.registry` and
`..network` only in `claude_managed_agents`, whose `..observability` import is
function-local; `..sanitizer` and `..config` in a few modules each, `..capabilities` in
`model_tier` (`grep -rnE 'from (\.\.|agent_airlock\.)[a-z_]+' src/agent_airlock/integrations/*.py`
recounts). `../policy_presets.py` imports from here only inside preset factories. Sibling
imports are acyclic (`grep -rn '^\s*from \.[a-z_]' src/agent_airlock/integrations/`).

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Notes

Add module-specific notes here — this section is never auto-modified.

<!-- END MANUAL -->
