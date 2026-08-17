# Module: mcp_spec

<!-- AUTO-MANAGED: module-description -->
## Purpose

Per-CVE and per-spec-revision guards for the MCP wire path — the largest subpackage
(47 modules, ~13.8k lines). Each module maps to one named advisory or one clause of a
pinned MCP spec revision; 28 distinct `CVE-` / `GHSA-` / `arXiv:` references are cited
across module docstrings.

This is the layer that fails closed. Unknown tier, unregistered manifest, and unpinned
spec revision are all denials, not warnings — preserve that direction in new branches.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: architecture -->
## Module Architecture

- **`_versions.py`** — dependency-free leaf (imports nothing from `agent_airlock`).
  Single source of truth for protocol versions: `PROTOCOL_VERSION = "2026-07-28"`,
  `SUPPORTED_PROTOCOL_VERSIONS = (PROTOCOL_VERSION, "2025-11-25")`. Both `transport.py`
  (which enforces them on the wire) and the package `__init__` import from here, so the
  enforced set and the public constant are the *same object* and cannot drift. Never
  re-declare these literals elsewhere.
- **Guard modules** — 22 `*Guard` classes, 16 `*Decision`, 16 `*Verdict`, surfaced through
  the 22-entry `__all__` in `__init__.py`.
- **Protocol helpers** — `transport`, `oauth`, `tasks`, `conformance`, `statelessness`,
  `supply_chain`, `meta_trust`, `handle_trust`, `header_audit`. Validators, *not* guard
  triples — do not force the triple shape onto them.

**The guard triple is split across two files.** The `*Guard` / `*Decision` / `*Verdict`
classes live here; the matching `*_defaults()` preset factory lives in
`../policy_presets.py` (51 factories, all 51 `@preset`-registered). A new guard is not
wired up until both halves exist — a guard class with no registered preset will not
appear in `list_active()`.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Module-Specific Conventions

- **Name the advisory.** Every guard module cites its `CVE-` / `GHSA-` / `arXiv:` id in
  the module docstring with a primary-source URL. The same PR updates `docs/cves/index.md`.
  Never remove a check without naming the CVE that motivated it.
- **`manifest_only_mode.py` is the only module importing `subprocess`**, and the only
  place `shell=True` is permitted repo-wide. It currently does not use `shell=True` at
  all — keep that true.
- `@dataclass` is the default carrier for structured data (63 uses). Enums are rare here
  (2) — most decisions are dataclasses, not enum states.
- Logging via `from .._log import get_logger` (38 of 47 modules). Structured kwargs only.
- No mocking fixtures in the CVE regression tests that cover these guards.
- Each guard needs at least one regression test; a handful also carry a
  `scripts/smoke_*.py` end-to-end driver when unit tests alone don't show the behaviour.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: dependencies -->
## Key Dependencies

**External: stdlib + Pydantic only.** Only `oauth.py` and `tasks.py` import `pydantic`;
every other module is pure stdlib. This keeps the subpackage importable under a bare
`pip install agent-airlock`, which the `bare-install` CI job enforces — adding any other
third-party import here fails that job, not the test suite.

**Internal:** `.._log` (38 modules), `..exceptions` (26), `..observability` (6), `..policy`
(2), plus single uses of `..validator`, `..sanitizer`, `..cost_tracking`,
`..ssrf_egress_guard`, `..scan.schema`. Four modules import back into `..policy_presets`;
`_versions.py` is a dependency-free leaf specifically so that relationship never becomes
an import cycle. Keep it that way.

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Notes

Add module-specific notes here — this section is never auto-modified.

<!-- END MANUAL -->
