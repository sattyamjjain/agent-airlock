# Module: mcp_spec

<!-- AUTO-MANAGED: module-description -->
## Purpose

Per-CVE and per-spec-revision guards for the MCP wire path — the largest subpackage in
`agent_airlock`. Each module maps to one named advisory or one clause of a pinned MCP
spec revision, and cites its `CVE-` / `GHSA-` / `arXiv:` id in the module docstring.

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
- **Guard modules** — one `*Guard` class per advisory, most paired with a `*Decision`
  dataclass and a `*Verdict` enum.
- **Protocol helpers** — `transport`, `oauth`, `tasks`, `conformance`, `statelessness`,
  `supply_chain`, `meta_trust`, `handle_trust`, `header_audit`. Validators, *not* guard
  triples — do not force the triple shape onto them.

**`__init__.py` exports the protocol surface, not the guards** — its `__all__` is the
`_versions` constants plus OAuth/task/transport helpers. Import a guard from its own
module (`from agent_airlock.mcp_spec.stdio_guard import validate_stdio_command`), the
form the module docstrings demonstrate.

**The guard triple spans two files.** `*Guard` / `*Decision` / `*Verdict` live here; the
matching `*_defaults()` preset factory lives in `../policy_presets.py` and is
`@preset`-registered. A guard with no registered preset never appears in `list_active()`.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Module-Specific Conventions

- **Name the advisory.** Every guard module cites its `CVE-` / `GHSA-` / `arXiv:` id in
  the module docstring with a primary-source URL. The same PR updates `docs/cves/index.md`.
  Never remove a check without naming the CVE that motivated it.
- **`manifest_only_mode.py` is the only module importing `subprocess`**, and the only
  place `shell=True` is permitted repo-wide. It currently does not use `shell=True` at
  all — keep that true.
- `@dataclass` carries structured data, including every `*Decision`. `*Verdict` goes the
  other way — `class X(str, enum.Enum)`, so it serializes as its own string value. Match
  that split rather than inventing a third shape.
- Logging via `from .._log import get_logger` in most modules. Structured kwargs, never
  f-strings.
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

**Internal:** `.._log` in most modules, then `..exceptions`, `..observability` and
`..policy`, plus single uses of `..validator`, `..sanitizer`, `..cost_tracking`,
`..ssrf_egress_guard` and `..scan.schema`.

**Nothing here imports `..policy_presets` at runtime.** The
`from agent_airlock.policy_presets import ..._defaults` lines in module docstrings are
`Usage::` examples, not imports. The dependency runs one way — presets import guards — and
`_versions.py` is a dependency-free leaf so that never becomes a cycle. Keep both true.

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Notes

Add module-specific notes here — this section is never auto-modified.

<!-- END MANUAL -->
