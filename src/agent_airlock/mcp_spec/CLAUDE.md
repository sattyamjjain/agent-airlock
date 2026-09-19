# Module: mcp_spec

<!-- AUTO-MANAGED: module-description -->
## Purpose

Per-CVE and per-spec-revision guards for the MCP wire path — the largest subpackage in
`agent_airlock`. Each module maps to one named advisory or one clause (SEP) of a pinned
MCP spec revision, and cites its `CVE-` / `GHSA-` / `arXiv:` / `SEP-` id in the module
docstring.

This is the layer that fails closed. Unknown tier, unregistered manifest, and unpinned
spec revision are all denials, not warnings — preserve that direction in new branches.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: architecture -->
## Module Architecture

- **`_versions.py`** — dependency-free leaf (imports nothing, not even from
  `agent_airlock`). Single source of truth for `PROTOCOL_VERSION` and
  `SUPPORTED_PROTOCOL_VERSIONS`. Both `transport.py` (which enforces them on the wire) and
  the package `__init__` import from here, so the enforced set and the public constant are
  the *same object* and cannot drift. Never re-declare these literals elsewhere. The
  `SPEC_REVISIONS` legacy/current labelling lives in `__init__.py` and records provenance
  only — it is not a conformance claim.
- **Two guard shapes coexist.** Class-style triples — a `<Name>Guard` with a
  `@dataclass <Name>Decision` and a `<Name>Verdict(str, enum.Enum)` — and function-style
  validators (`validate_*`, `audit_*`, `check_*`, `enforce_*`) with no `*Guard` class at
  all. Roughly a third of the modules are full triples; do not force one shape onto the
  other when adding a guard, match the neighbours it will be read next to.
- **Protocol helpers, not guards** — `transport`, `oauth`, `tasks`, `conformance`,
  `statelessness`, `supply_chain`, `meta_trust`, `handle_trust`, `header_audit`,
  `header_integrity`, `elicitation_provenance`, `attested_admission`, `manifest_only_mode`.
  Validators and conformance runners; do not force the triple shape onto them either.

**`__init__.py` exports the protocol surface, not the guards** — its `__all__` is the
`_versions` constants plus `SPEC_REVISIONS` and the OAuth/task/transport helpers. Import a
guard from its own module (`from agent_airlock.mcp_spec.stdio_guard import
validate_stdio_command`), the form the module docstrings demonstrate.

**The guard triple spans two files.** `*Guard` / `*Decision` / `*Verdict` live here; the
matching `*_defaults()` preset factory lives in `../policy_presets.py` and is
`@preset`-registered. A guard with no registered preset never appears in `list_active()`.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: conventions -->
## Module-Specific Conventions

- **Name the advisory.** Every guard module cites its `CVE-` / `GHSA-` / `arXiv:` / `SEP-`
  id in the module docstring with a primary-source URL. The same PR updates
  `docs/cves/index.md`. Never remove a check without naming the CVE that motivated it.
- **`manifest_only_mode.py` is the only module importing `subprocess`**, and nothing in
  this subpackage — including it — uses `shell=True`. Keep both true.
- `@dataclass` carries structured data, including every `*Decision`. `*Verdict` is a
  `class X(str, enum.Enum)` so it serializes as its own string value; the two
  `*Verdict`s that are frozen dataclasses instead are the exception, not a third shape to
  copy.
- Logging is `from .._log import structlog` then
  `logger = structlog.get_logger("agent-airlock.mcp_spec.<module>")` — one logger per
  module, dotted after the file name. Structured kwargs, never f-strings.
- No mocking fixtures in the CVE regression tests that cover these guards.
- Each guard needs at least one regression test; a handful also carry a
  `scripts/smoke_*.py` end-to-end driver when unit tests alone don't show the behaviour.

<!-- END AUTO-MANAGED -->

<!-- AUTO-MANAGED: dependencies -->
## Key Dependencies

**External, at import time: stdlib + Pydantic only.** Only `oauth.py` and `tasks.py`
import `pydantic`; every other module is pure stdlib at import. The one third-party
exception is `attested_admission.py`, which imports `cryptography` *lazily* inside its
verifier functions behind the `[attested]` extra and raises a `RuntimeError` naming the
extra when it is missing. That is the pattern to copy — a module-level third-party import
here breaks the `bare-install` CI job, not the test suite.

**Internal:** `.._log` in nearly every module, then `..exceptions` and `..observability`,
`..policy` in the two stdio guards, plus single uses of `..attest.receipt`, `..audit`,
`..cost_tracking`, `..sanitizer`, `..scan.schema`, `..ssrf_egress_guard` and
`..validator`.

**Nothing here imports `..policy_presets` at runtime.** The
`from agent_airlock.policy_presets import ..._defaults` lines in module docstrings are
`Usage::` examples, not imports. The dependency runs one way — presets import guards — and
`_versions.py` is a dependency-free leaf so that never becomes a cycle. Keep both true.

<!-- END AUTO-MANAGED -->

<!-- MANUAL -->
## Notes

Add module-specific notes here — this section is never auto-modified.

<!-- END MANUAL -->
