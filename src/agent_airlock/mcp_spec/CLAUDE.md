# Module: mcp_spec

<!-- AUTO-MANAGED: module-description -->
## Purpose

Per-CVE and per-spec-revision guards for the MCP wire path — the largest subpackage in
`agent_airlock`. Most modules map to a named advisory or to clauses (SEPs) of a pinned MCP
spec revision — some to several — and name that source in the module docstring.

This is the layer that fails closed. An unregistered manifest, an unpinned spec revision
and a field shape a guard cannot read are all denials, not warnings — preserve that
direction in new branches.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: architecture -->
## Module Architecture

- **`_versions.py`** — a leaf (its only import is `from __future__ import annotations`) and
  the single source of `PROTOCOL_VERSION` and `SUPPORTED_PROTOCOL_VERSIONS`. `transport.py`
  (which enforces them on the wire), `conformance.py`, `cli/conformance.py` and the package
  `__init__` import them, so the enforced set and the public constant are the same object.
  Two places still
  spell the literals — `conformance.LEGACY_VERSION` and the `SPEC_REVISIONS` keys in
  `__init__.py`, which record provenance, not a conformance claim. Do not add a third.
- **Three guard shapes coexist**; match the neighbours a new guard will be read next to:
  1. Class triples — `*Guard` + frozen-dataclass `*Decision` + `*Verdict(str, enum.Enum)`.
     The Guard's name stem does not always match (`CodegenDelimiterInjectionGuard`).
  2. Inspection style — a `*Guard` class returning an `*Inspection` dataclass, with
     `Verdict = Literal[...]` (`config_path_guard`, `elicitation_guard`).
  3. Function style, no `*Guard` class — `validate_*` / `audit_*` / `check_*` /
     `enforce_*` / `verify_*` / `admit_*`. This covers `transport`, `oauth` and the
     2026-07-28 spec validators (`meta_trust`, `statelessness`, `header_integrity`,
     `elicitation_provenance`, …), which the package docstring calls guards: they are
     guards, just not triples. `tasks` holds only task-state models and `conformance` the
     case runner. Four modules fit none of the three: `LANUnauthRCEGuard` and
     `StdioMetaGuard` return frozen-dataclass verdicts (`Verdict`, `MetaVerdict`) with no
     `*Decision`, `PRMetadataGuard.sanitize()` returns a `SanitizedField`, and
     `manifest_only_mode` is a registry plus `launch_from_manifest`.
- **Sibling imports** exist and must stay acyclic — e.g. `transport` / `tasks` → `oauth`,
  `tasks_admission_guard` → `tasks_lifecycle_guard` → `step_up_scope_guard`
  (`grep -n '^from \.[a-z_]' src/agent_airlock/mcp_spec/*.py` lists them all).
- **`conformance.py`** is the single source of the conformance cases that
  `cli/conformance.py` and `benchmarks/mcp_conformance/run.py` both run.

**Exports.** `__init__.py`'s `__all__` is the protocol surface only — the `_versions`
constants, `SPEC_REVISIONS`, and the OAuth/task/transport helpers. Import a guard from its
own module (`from agent_airlock.mcp_spec.stdio_guard import validate_stdio_command`) or from
the package root, whose `agent_airlock.__all__` re-exports many `*Guard` classes.

**Presets live one level up.** A guard's preset factory — usually `*_defaults()`, not
always — is in `../policy_presets.py` and `@preset`-registered; an unregistered factory
never appears in `list_active()`. Not every guard has one: `reasoning_replay_guard`,
`session_guard`, `transcript_ingest_guard` and the `transport` validators ship without a
preset, and
`manifest_only_mode` is opted into in code (`ManifestRegistry` + `launch_from_manifest`).

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Module-Specific Conventions

- **Name the primary source.** A new guard's docstring cites its `CVE-` / `GHSA-` /
  `arXiv:` / `SEP-` id where one exists, with the primary-source URL. Coverage is uneven —
  some older modules cite only a blog or bulletin URL, several SEP-based modules give the
  SEP id with no URL, and `tool_definition_pin_guard` (an OWASP ASI04 answer) gives
  neither — so do not copy an uncited neighbour.
- **Read every shape a field can take, or refuse it.** A guard that inspects `command`,
  `args` or `env` handles a string and a sequence for each (a mapping for `env`), and
  refuses any other shape, non-string items included. Skipping a shape it did not expect is
  fail-open: until v0.10.21 a list `command` walked past both spawn guards, and until
  v0.10.24 six more guards skipped shapes (`ConfigPathGuard`, `McpConfigPinSet`, both eval
  guards, `StdioCommandInjectionGuard`'s non-string argv items, the env-interpolation guard).
  A guard that walks nested values refuses input deeper than 32 levels or containing
  itself, as `DENY_UNINSPECTABLE` where it has a verdict enum
  (`tests/test_spawn_guards_fail_closed_0_10_21.py`,
  `tests/test_guard_shapes_fail_closed_0_10_24.py`).
- `*Decision` is a frozen `@dataclass`; `*Verdict` is `class X(str, enum.Enum)` so it
  serializes as its own string value. Two `*Verdict`s that are frozen dataclasses and the
  inspection-style `Literal[...]` aliases are exceptions, not shapes to spread.
- Logger names are `agent-airlock.mcp_spec.<module>`. Pure validators may have no logger
  (`tool_definition_pin_guard` hands back `Decision.audit_event()` instead).
- Exceptions subclass `..exceptions.AirlockError`, except the `ValueError` subclasses in
  `oauth`, `transport` and the 2026-07-28 spec validators, and
  `openapi_drift_guard.OpenAPIDriftViolation`, which subclasses bare `Exception`.
- **Tests:** CVE-numbered guards go in `tests/cves/test_cve_<yyyy>_<n>_<slug>.py`, guards
  for an advisory with no CVE id in `tests/cves/test_<slug>.py`, other guards in
  `tests/mcp_spec/test_<module>.py`, and the 2026-07-28 validators in
  `tests/test_mcp_*_preset.py` (a few older CVE guards are tested only under
  `tests/mcp_spec/`). `tests/cves/CLAUDE.md` holds the fixture and no-mock rules.
- A guard whose behaviour a unit test cannot show may also get a `scripts/smoke_*.py`
  driver, as `attested_admission` and the Flowise stdio preset have.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: dependencies -->
## Key Dependencies

**External: only `oauth.py` and `tasks.py` import a third-party package (`pydantic`) at
module level.** Importing any submodule still loads pydantic through the root package. The
one other third-party use is `attested_admission.py`, which imports `cryptography`
*lazily* inside its verifier functions behind the `[attested]` extra and raises a
`RuntimeError` naming the extra when it is missing. That is the pattern to copy.
`bare-install`'s import step loads this subpackage through the package root and
`policy_presets`, so it catches a module-level third-party import in most modules here —
but not in `attested_admission`, `conformance`, `supply_chain` or
`transcript_ingest_guard`, which it never loads.

**Internal:** `.._log` and `..exceptions` in most modules, `..observability` in a few; every
other parent-package import (`..policy`, `..attest.receipt`, `..scan.schema`,
`..ssrf_egress_guard`, `..validator`, `..cost_tracking`, `..sanitizer`, `..audit`) is used
by one or two modules, several of them function-local or `TYPE_CHECKING`-only
(`grep -n 'from \.\.' src/agent_airlock/mcp_spec/*.py` recounts them).

**Nothing here imports `..policy_presets`**, at module level or inside a function — the
`from agent_airlock.policy_presets import ..._defaults` lines in docstrings are `Usage::`
examples. The dependency runs one way (presets import guards), and `_versions.py` stays a
leaf so that never becomes a cycle. Keep both true.

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Notes

Add module-specific notes here — this section is never auto-modified.

<!-- END MANUAL -->
