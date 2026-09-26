# Module: integrations

<!-- AUTO-MANAGED: module-description -->
## Purpose

Adapters that put `@Airlock` in front of third-party agent SDKs' tools and normalise vendor
tool-call payloads, plus helpers that sit beside them (Claude runtime hooks, commerce caps,
log redaction, an IDE-scanner bridge). The FastMCP integration lives in `../mcp/__init__.py`
and framework vaccination in `../vaccine.py`; neither imports from here.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: architecture -->
## Module Architecture

- **Walkers** (`crewai`, `pydantic_ai`, `google_adk`, `anthropic_claude_agent_sdk`) take an
  agent, find its tools, and replace in place the callable the framework actually invokes,
  which is not always the obvious attribute: PydanticAI runs
  `tool.function_schema.function`, and a CrewAI `@tool` runs `func`, not `_run`. Prove
  interception with a stub that mirrors the SDK's real call path. `langchain`, `anthropic`
  and `openai_guardrails` are the older decorator style. `smolagents_wrapper` runs
  caller-supplied `PolicyBundle` guards and never builds an `Airlock`. The `gpt5_5_*` /
  `gemini3_*` shape adapters normalise vendor payloads.
- **`@Airlock` enforces only the signature it is handed.** Re-tag a tool with
  `_tool_proxy.named_tool_proxy`, which carries the tool's signature (annotations resolved)
  and is async when the tool is; pass framework-injected context parameters as
  `relaxed_params`, as `google_adk._relax_injected_params` does for ADK. A Claude SDK
  `SdkMcpTool` handler takes one `args` dict, so `_claude_sdk_tools` builds the signature
  from its `input_schema` instead and spreads the dict into it; gates that read keyword
  arguments would otherwise see one opaque parameter. Test every walker with a
  wrong-typed and a ghost argument through the SDK's real call path; async handling is
  pinned once, in `tests/integrations/test_tool_proxy.py`.
- **`adapters/`** holds the commerce adapters, which satisfy the `CommerceAdapter` Protocol in
  `agent_commerce_caps.py` (contract in `docs/adapters.md`). **`scanners/`** defines a
  `Scanner` Protocol and registry; nothing under `src/` registers a scanner.
- **Exports.** `__init__.py` imports nothing, and its `__all__` is a partial list, not an
  index. The package root imports several modules here eagerly
  (`grep -n 'from .integrations' src/agent_airlock/__init__.py`), which is why a
  module-level SDK import in one of them breaks the `bare-install` job.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Module-Specific Conventions

- **SDK imports are function-local** — none is at module level. CI's `test` job installs
  `.[dev,redis]`, which carries no SDK, and `bare-install` imports the package root.
- **Missing SDK.** Each walker raises a `<X>MissingError(AirlockError)` built from a module
  `_INSTALL_HINT` that names the `agent-airlock[<extra>]` to install. Its `_maybe_check_sdk`
  imports the SDK only when `type(obj).__module__` belongs to it — local stubs never trigger
  the import — and warns on versions outside `SUPPORTED_*_VERSIONS` (the Claude SDK adapter
  does both in a module-level `_check_sdk`, shared with `wrap_tools`). `langchain` differs:
  one entry point returns the tool unwrapped when `langchain_core` is missing, another
  raises `ImportError`.
- **Typing and lint.** mypy runs with no SDK installed, so each imported SDK needs an
  `ignore_missing_imports` entry in `pyproject.toml`; the `disallow_untyped_calls = false`
  override for `integrations.langchain` is load-bearing. The ruff `ARG001`/`ARG002` ignore
  exists for callback-interface signatures;
  `ruff check --isolated --select ARG src/agent_airlock/integrations/` lists what it hides.
- **Tests** live in `tests/integrations/test_<module>*.py`, except `langchain` / `anthropic`
  (`tests/test_new_features.py`) and Model Armor (`tests/test_model_armor_integration.py`).
  Drive adapters with stub objects instead of installing the SDK; simulate a missing SDK by
  patching `sys.modules`, seeding the parent of a dotted package (`google`) as well. No CI
  job installs an SDK, so an `importorskip` test is a skipped test there.
- **A new framework adapter** also needs a row in `_ADAPTER_SHIPPED_MODULES`
  (`tests/test_readme_framework_claims.py`, kept by hand), the module named in the README's
  `Adapter-shipped (N)` paragraph with N bumped, and its doc page added to the `mkdocs.yml`
  nav by hand — only `docs/benchmarks/` has a nav gate.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: dependencies -->
## Key Dependencies

**External:** `claude_agent_sdk`, `crewai`, `pydantic_ai`, `google.adk` and `google.cloud`
(Model Armor) each have a pyproject extra; `langchain_core` and `opentelemetry` have none.
The OpenAI Agents SDK, `anthropic`, `langgraph` and `smolagents` are never imported: those
modules use duck typing, `importlib.util.find_spec` or `importlib.metadata` probes instead.

**Internal:** `.._log`, `..exceptions`, and `..core` / `..policy` wherever an `Airlock` is
built. `../policy_presets.py` imports from here only inside preset factories. Sibling
imports are acyclic (`grep -rn '^\s*from \.[a-z_]' src/agent_airlock/integrations/`).

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Notes

Add module-specific notes here — this section is never auto-modified.

<!-- END MANUAL -->
