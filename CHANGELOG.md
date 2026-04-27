# Changelog

All notable changes to Agent-Airlock are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

(no entries yet)

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
