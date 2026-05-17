"""2026 policy presets for Agent-Airlock.

Named policy factories that map public incidents, standards, and regulations
to a concrete `SecurityPolicy` + `CapabilityPolicy` configuration. Each preset
cites its primary source so reviewers can trace why a block fires.

Presets:

- `gtg_1002_defense_policy()` - Anthropic's GTG-1002 disclosure (Nov 2025):
  first largely-autonomous AI-orchestrated cyber-espionage. Blocks the
  reconnaissance + privilege-escalation + exfiltration tool patterns.

- `mex_gov_2026_policy()` - Mexican-government breach (Feb 2026, ~150 GB
  exfiltration via persistent-jailbreak prompt engineering). Blocks the
  unbounded-output-loop and unrestricted-egress patterns that made the
  leak possible.

- `owasp_mcp_top_10_2026_policy()` - OWASP MCP Top 10 (beta, Dec 2025).
  Covers MCP01 token mismanagement, MCP02 excessive permissions, MCP03
  tool poisoning, MCP04 supply chain, MCP05 command injection, MCP07
  insufficient authentication, MCP10 context oversharing.

- `eu_ai_act_article_15_policy()` - EU AI Act Article 15 (applies
  Aug 2, 2026). Cybersecurity controls for high-risk systems against
  data poisoning, model poisoning, adversarial examples, and
  confidentiality attacks.

- `india_dpdp_2023_policy()` - India Digital Personal Data Protection
  Act 2023 (notified Nov 13, 2025 by MeitY). Enforces purpose limitation,
  data minimization, and the India PII pack (Aadhaar / PAN / UPI / IFSC)
  at the sanitizer layer.

Each preset is documented, linked to its source, and paired with at least
one blocking test and one allow test in `tests/test_policy_presets.py`.

Usage:

    from agent_airlock import Airlock
    from agent_airlock.policy_presets import gtg_1002_defense_policy

    @Airlock(policy=gtg_1002_defense_policy())
    def run_shell(cmd: str) -> str:
        ...

Primary sources (retrieved 2026-04-18):

- Anthropic GTG-1002 disclosure: https://www.anthropic.com/news/detecting-countering-misuse-aug-2025
- Mexican government breach reporting: public press coverage Feb 2026
- OWASP MCP Top 10: https://owasp.org/www-project-mcp-top-10/
- OWASP Top 10 for Agentic Applications 2026:
  https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
- EU AI Act Article 15: https://artificialintelligenceact.eu/article/15/
- India DPDP Act 2023: https://www.meity.gov.in/static/uploads/2024/06/2bf1f0e9f04e6fb4f8fef35e82c42aa5.pdf
"""

from __future__ import annotations

import re
import shlex as _shlex_for_gitpilot
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path as _Path_for_gitpilot
from typing import TYPE_CHECKING, Any

from .exceptions import AirlockError
from .policy import SecurityPolicy, StdioGuardConfig

if TYPE_CHECKING:
    from .capabilities import CapabilityPolicy
    from .mcp_spec.header_audit import ResponseHeaderAuditConfig
    from .mcp_spec.oauth_audit import OAuthAppAuditConfig
    from .mcp_spec.sampling_guard import SamplingGuardConfig


def _capabilities(granted: int | None = None, denied: int | None = None) -> CapabilityPolicy | None:
    """Build a CapabilityPolicy, returning None if the module isn't importable.

    Mirrors the private helpers in `policy.py` so capability gating remains
    optional.
    """
    try:
        from .capabilities import Capability, CapabilityPolicy

        return CapabilityPolicy(
            granted=Capability(granted) if granted is not None else Capability.NONE,
            denied=Capability(denied) if denied is not None else Capability.NONE,
            require_sandbox_for=Capability.DANGEROUS,
        )
    except ImportError:
        return None


# -----------------------------------------------------------------------------
# GTG-1002 defense
# -----------------------------------------------------------------------------


def gtg_1002_defense_policy() -> SecurityPolicy:
    """Defensive policy against the GTG-1002 tool-call pattern.

    GTG-1002 is the actor-code Anthropic assigned to the first largely-
    autonomous AI-orchestrated cyber-espionage campaign, publicly disclosed
    in late 2025. The operator used Claude as the orchestration brain plus
    an MCP-style tool harness to run reconnaissance, credential collection,
    lateral movement, and exfiltration against roughly 30 targets.

    What this preset does:

    - Requires agent identity (no anonymous invocations).
    - Applies a very low global rate limit (10/hour) - the campaign's tell
      was high-fan-out tool invocation; normal developer workloads stay
      well under this cap.
    - Blocks shell/exec tools by default (the observed attack path used
      arbitrary shell commands for recon and implant installation).
    - Requires sandbox execution for every `DANGEROUS` capability.
    - Denies filesystem delete and arbitrary network.

    Mitigates (mapped to public reporting):

    - Tool-call floods for reconnaissance/enumeration -> rate limit
    - Shell-based post-exploitation -> denied PROCESS_SHELL capability
    - Credential/data exfiltration -> denied NETWORK_ARBITRARY, sandbox
      required for any filesystem write

    Reference: Anthropic threat-intelligence disclosure (2025).
    Retrieved 2026-04-18.
    """
    try:
        from .capabilities import Capability

        cap_policy = _capabilities(
            granted=(Capability.FILESYSTEM_READ | Capability.NETWORK_HTTPS).value,
            denied=(
                Capability.PROCESS_SHELL
                | Capability.PROCESS_EXEC
                | Capability.FILESYSTEM_DELETE
                | Capability.NETWORK_ARBITRARY
            ).value,
        )
    except ImportError:
        cap_policy = None

    return SecurityPolicy(
        require_agent_id=True,
        denied_tools=[
            "exec_*",
            "shell_*",
            "run_shell",
            "spawn_*",
            "system_*",
        ],
        rate_limits={"*": "10/hour"},
        capability_policy=cap_policy,
    )


# -----------------------------------------------------------------------------
# Mexican government breach defense (Feb 2026)
# -----------------------------------------------------------------------------


def mex_gov_2026_policy() -> SecurityPolicy:
    """Defensive policy modeled on the Feb 2026 Mexican-government breach.

    Public reporting indicates ~150 GB of government data was exfiltrated
    through persistent-jailbreak prompt engineering against an agentic
    system with over-broad tool access. The load-bearing weaknesses: no
    per-session output cap, no egress allowlist, tools able to iterate
    across arbitrary document stores.

    What this preset does:

    - Allows ONLY explicit read operations matching tight tool-name
      patterns (`read_*`, `get_*`, `search_*`). Everything else is denied.
    - Requires agent identity.
    - Rate limit: 50/hour (tight; force the attacker to run slow).
    - Denies database write, filesystem write/delete, arbitrary network.
    - Sandboxes every `DANGEROUS` capability.

    Operators should additionally:

    1. Configure `max_output_chars` on `AirlockConfig` to cap per-call
       output size (this policy does NOT change that knob).
    2. Add a `ConversationTracker` with strict per-session budgets.

    Reference: public press coverage, Feb 2026. Retrieved 2026-04-18.
    """
    try:
        from .capabilities import Capability

        cap_policy = _capabilities(
            granted=(Capability.FILESYSTEM_READ | Capability.DATABASE_READ).value,
            denied=(
                Capability.FILESYSTEM_WRITE
                | Capability.FILESYSTEM_DELETE
                | Capability.DATABASE_WRITE
                | Capability.NETWORK_ARBITRARY
                | Capability.PROCESS_SHELL
            ).value,
        )
    except ImportError:
        cap_policy = None

    return SecurityPolicy(
        require_agent_id=True,
        allowed_tools=["read_*", "get_*", "search_*", "list_*", "describe_*"],
        denied_tools=[
            "dump_*",
            "export_*",
            "backup_*",
            "replicate_*",
            "bulk_*",
        ],
        rate_limits={"*": "50/hour"},
        capability_policy=cap_policy,
    )


# -----------------------------------------------------------------------------
# OWASP MCP Top 10 (beta, Dec 2025)
# -----------------------------------------------------------------------------


def owasp_mcp_top_10_2026_policy() -> SecurityPolicy:
    """Defensive policy aligned to the OWASP MCP Top 10 (2026 beta).

    The OWASP MCP Top 10 enumerates the most critical security risks in
    MCP-enabled systems. As of retrieval the live categories include:

    - MCP01 Token mismanagement & secret exposure
    - MCP02 Excessive permissions / scope creep
    - MCP03 Tool poisoning
    - MCP04 Software supply chain attacks
    - MCP05 Command injection
    - MCP06 (reserved)
    - MCP07 Insufficient authentication
    - MCP08 (reserved)
    - MCP09 Shadow MCP servers
    - MCP10 Context over-sharing

    What this preset does:

    - MCP02 / MCP07: `require_agent_id=True` + global rate limit blocks
      anonymous or unbounded use.
    - MCP05: denies tool-name patterns commonly used to construct shell
      commands (`exec_*`, `run_*`, `system_*`).
    - MCP03 / MCP04: denies `install_*`, `download_*`, `fetch_plugin_*`
      tool-name patterns that are typical supply-chain vectors.
    - Capability gating: denies PROCESS_SHELL, FILESYSTEM_DELETE,
      NETWORK_ARBITRARY; requires sandbox for DANGEROUS.

    This preset does NOT fix:

    - MCP01 (tokens in payload) - use the sanitizer (secrets masking
      is on by default in `SanitizationConfig`).
    - MCP10 (context oversharing) - use per-tenant
      `WorkspacePIIConfig` and a `ConversationTracker`.
    - MCP07 transport-level auth (use OAuth 2.1 on the MCP server).

    Reference: https://owasp.org/www-project-mcp-top-10/ (retrieved 2026-04-18).
    """
    try:
        from .capabilities import Capability

        cap_policy = _capabilities(
            granted=(
                Capability.FILESYSTEM_READ | Capability.NETWORK_HTTPS | Capability.DATABASE_READ
            ).value,
            denied=(
                Capability.PROCESS_SHELL
                | Capability.FILESYSTEM_DELETE
                | Capability.NETWORK_ARBITRARY
            ).value,
        )
    except ImportError:
        cap_policy = None

    return SecurityPolicy(
        require_agent_id=True,
        denied_tools=[
            # MCP05 Command injection
            "exec_*",
            "run_*",
            "system_*",
            "shell_*",
            # MCP03 / MCP04 Tool poisoning + supply chain
            "install_*",
            "download_plugin_*",
            "fetch_plugin_*",
            "load_extension_*",
            # MCP02 Excessive permissions (destructive verbs)
            "delete_all_*",
            "drop_*",
            "truncate_*",
        ],
        rate_limits={"*": "200/hour"},
        capability_policy=cap_policy,
    )


# -----------------------------------------------------------------------------
# EU AI Act Article 15 (cybersecurity, Aug 2, 2026)
# -----------------------------------------------------------------------------


def eu_ai_act_article_15_policy() -> SecurityPolicy:
    """Defensive policy mapping to EU AI Act Article 15 cybersecurity.

    Article 15 requires providers of high-risk AI systems to implement
    technical measures to prevent, detect, respond to, resolve, and
    control for attacks attempting to:

    - alter the system's use, outputs, or performance;
    - manipulate training or pre-trained components (data / model
      poisoning);
    - supply inputs designed to cause model errors (adversarial
      examples, evasion);
    - exfiltrate confidential information (confidentiality attacks).

    These obligations become applicable on 2 August 2026 for high-risk
    systems falling under Annex III.

    What this preset does (Article 15 mapping in parentheses):

    - Requires agent identity (15(4) monitoring). Every call attributable.
    - Rate-limits to 500/hour/tool (15(1) resilience against floods).
    - Denies `NETWORK_ARBITRARY` and requires sandbox for `DANGEROUS`
      (15(5) confidentiality and integrity of the system).
    - Denies filesystem delete (15(5) integrity).
    - Caller is also expected to enable `OTelAuditExporter` and a
      `ConversationTracker` - those are configuration, not policy.

    Note: this preset is a *starting point*. Compliance with Article 15
    is a process, not a config setting. Pair with the Article 12
    (record-keeping) and Article 14 (human oversight) controls on the
    application layer.

    Reference: https://artificialintelligenceact.eu/article/15/
    (retrieved 2026-04-18).
    """
    try:
        from .capabilities import Capability

        cap_policy = _capabilities(
            granted=(
                Capability.FILESYSTEM_READ | Capability.NETWORK_HTTPS | Capability.DATABASE_READ
            ).value,
            denied=(
                Capability.NETWORK_ARBITRARY
                | Capability.FILESYSTEM_DELETE
                | Capability.PROCESS_SHELL
            ).value,
        )
    except ImportError:
        cap_policy = None

    return SecurityPolicy(
        require_agent_id=True,
        rate_limits={"*": "500/hour"},
        capability_policy=cap_policy,
    )


# -----------------------------------------------------------------------------
# India DPDP Act 2023
# -----------------------------------------------------------------------------


def india_dpdp_2023_policy() -> SecurityPolicy:
    """Defensive policy aligned to India's DPDP Act 2023.

    The Digital Personal Data Protection Act, 2023 (notified by MeitY on
    Nov 13, 2025) applies to the processing of digital personal data
    within India or of data principals in India. Core principles:
    consent, purpose limitation, data minimization, accountability.

    What this preset does:

    - Requires agent identity (accountability: every processing
      attributable to a named fiduciary/processor).
    - Allows only read and list tool-name patterns by default (data
      minimization: no unnecessary writes without explicit policy
      override).
    - Denies bulk export tool-name patterns that typically breach
      purpose limitation.
    - Denies capabilities that process sensitive data unsafely
      (`DATA_PII` and `DATA_SECRETS` are denied unless granted by a
      caller-supplied override).
    - Rate-limits to 300/hour/tool.

    Operators should additionally enable:

    1. The sanitizer with India PII detectors (Aadhaar, PAN, UPI, IFSC)
       - these are on by default in `SensitiveDataType`.
    2. `WorkspacePIIConfig` for per-tenant masking rules.
    3. Audit export via `OTelAuditExporter` for DPB (Data Protection
       Board) audit trail.

    Reference:
    https://www.meity.gov.in/static/uploads/2024/06/2bf1f0e9f04e6fb4f8fef35e82c42aa5.pdf
    (retrieved 2026-04-18).
    """
    try:
        from .capabilities import Capability

        cap_policy = _capabilities(
            granted=(
                Capability.FILESYSTEM_READ | Capability.DATABASE_READ | Capability.NETWORK_HTTPS
            ).value,
            denied=(
                Capability.DATA_PII
                | Capability.DATA_SECRETS
                | Capability.FILESYSTEM_DELETE
                | Capability.DATABASE_WRITE
                | Capability.NETWORK_ARBITRARY
            ).value,
        )
    except ImportError:
        cap_policy = None

    return SecurityPolicy(
        require_agent_id=True,
        allowed_tools=["read_*", "get_*", "list_*", "search_*", "describe_*"],
        denied_tools=[
            "bulk_export_*",
            "dump_database_*",
            "download_personal_data_*",
            "export_all_*",
        ],
        rate_limits={"*": "300/hour"},
        capability_policy=cap_policy,
    )


# -----------------------------------------------------------------------------
# Module-level eager instances for readability
# -----------------------------------------------------------------------------
# NOTE: these are constructed at import time. Each policy instance is
# immutable data (no live state) so sharing is safe. If you need a
# per-process fresh instance - e.g. to apply dynamic rate-limit overrides
# - call the factory function instead of using the constant.


def stdio_guard_ox_defaults() -> StdioGuardConfig:
    """Ox Security advisory defaults for the MCP STDIO sanitizer (v0.5.1+).

    Disclosed 2026-04-16: the MCP STDIO transport executed attacker-supplied
    argv before the handshake, giving pre-auth RCE across Claude Code,
    Cursor, Windsurf, Gemini-CLI, and GitHub Copilot. Anthropic declined a
    protocol-level fix; ``validate_stdio_command()`` + this preset is the
    client-side answer.

    Policy:

    - Binary allowlist: the common MCP launchers (``uvx``, ``npx``,
      ``pipx``, ``node``, ``python``, ``python3``, ``deno``, ``bunx``)
      plus the Python launcher ``uv``.
    - Absolute-path prefix allowlist: the system + user package dirs
      that Homebrew, apt, and pipx use. Anything outside these prefixes
      is rejected even if the basename would have matched — this is the
      ``/tmp/evil.sh`` defence.
    - Deny patterns: common remote-code patterns ``curl|wget piped into
      a shell``, ``base64 -d | sh``, python ``-c`` inline, and the
      literal ``IFS=`` tricks.
    - Shell metacharacters: always rejected (``;``, ``&&``, ``||``,
      ``|``, backtick, ``$(``, ``$``, newline, carriage return).

    Primary source:
      https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem
    """
    return StdioGuardConfig(
        allowed_binaries=frozenset(
            {
                "uvx",
                "uv",
                "npx",
                "pipx",
                "node",
                "python",
                "python3",
                "deno",
                "bunx",
            }
        ),
        allowed_binary_prefixes=(
            "/usr/bin/",
            "/usr/local/bin/",
            "/opt/homebrew/bin/",
            "/home/",  # pipx user installs: /home/$user/.local/bin/...
            "/Users/",  # macOS user installs
        ),
        deny_patterns=(
            re.compile(r"curl[^\n]*\bsh\b", re.IGNORECASE),
            re.compile(r"wget[^\n]*\bsh\b", re.IGNORECASE),
            re.compile(r"base64\s+-d", re.IGNORECASE),
            # Inline-code flags across interpreters we otherwise allow:
            # - python/bash:  -c
            # - node/deno:    -e / --eval
            # - perl:         -e
            re.compile(r"^-c$"),
            re.compile(r"^-e$"),
            re.compile(r"^--eval$"),
            re.compile(r"IFS\s*=", re.IGNORECASE),
        ),
        allow_shell_metachars=False,
    )


STDIO_GUARD_OX_DEFAULTS = stdio_guard_ox_defaults()
"""Eagerly-constructed default for the Ox STDIO sanitizer. Import this
constant unless you need dynamic overrides (then call the factory)."""


def oauth_audit_vercel_2026_defaults() -> OAuthAppAuditConfig:
    """OAuth app audit defaults driven by the 2026-04-19 Vercel breach.

    Vercel confirmed a compromise that started with a third-party
    Google Workspace OAuth app (Context.ai). The attacker used the
    app's legitimate consent flow to exfiltrate an employee's tokens
    and, from there, 580 employee records + API keys + source code.
    This preset seeds the deny-list with the Context.ai client_id
    disclosed in the Vercel bulletin and enforces PKCE + refresh-
    rotation + a 1-hour token-lifetime cap.

    Pair with ``MCPProxyGuard`` so any OAuth exchange run through
    ``agent_airlock.mcp_spec.oauth`` is audited before the token is
    cached.

    Primary source:
      https://vercel.com/kb/bulletin/vercel-april-2026-security-incident
    """
    from .mcp_spec.oauth_audit import KNOWN_COMPROMISED_CLIENT_IDS, OAuthAppAuditConfig

    return OAuthAppAuditConfig(
        blocked_client_ids=KNOWN_COMPROMISED_CLIENT_IDS,
        max_token_age_seconds=3600,
        require_pkce=True,
        require_refresh_rotation=True,
    )


OAUTH_AUDIT_VERCEL_2026_DEFAULTS = oauth_audit_vercel_2026_defaults()
"""Eagerly-constructed OAuth-audit defaults (post Vercel 2026-04-19)."""


def azure_mcp_cve_2026_32211_defaults() -> ResponseHeaderAuditConfig:
    """Response-header audit defaults for CVE-2026-32211.

    MSRC disclosed 2026-04-20: the reference Azure MCP server echoed
    the caller's ``Authorization`` header back in a ``WWW-Authenticate``
    field on 401 responses, leaking short-lived AAD tokens. CVSS 8.6,
    fixed in Azure MCP Server 1.4.2. This preset is the runtime
    defence — a proxy fronting an unpatched server will refuse to
    forward the leaked value.

    Primary sources:
      https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32211
      https://nvd.nist.gov/vuln/detail/CVE-2026-32211
    """
    from .mcp_spec.header_audit import (
        DEFAULT_FORBIDDEN_HEADER_NAMES_BY_STATUS,
        DEFAULT_FORBIDDEN_PATTERNS,
        ResponseHeaderAuditConfig,
    )

    return ResponseHeaderAuditConfig(
        forbidden_patterns=DEFAULT_FORBIDDEN_PATTERNS,
        forbidden_header_names_by_status=dict(DEFAULT_FORBIDDEN_HEADER_NAMES_BY_STATUS),
        max_header_value_bytes=8192,
    )


AZURE_MCP_CVE_2026_32211_DEFAULTS = azure_mcp_cve_2026_32211_defaults()
"""Eagerly-constructed response-header-audit defaults (CVE-2026-32211)."""


def ox_mcp_supply_chain_2026_04_defaults() -> dict[str, Any]:
    """Umbrella preset for the OX Security 2026-04-20 MCP dossier.

    Composes existing primitives (MCPwn / Flowise / Azure header
    audit) and adds three new micro-checks (tool-manifest tamper,
    MCP bridge SSRF, unsafe deserialization) into a single bundle
    covering the 10 CVEs disclosed in the "Mother of All AI Supply
    Chains" report.

    The returned mapping lets callers cherry-pick::

        cfg = ox_mcp_supply_chain_2026_04_defaults()
        cfg["destructive_tool_check"](my_tools)
        cfg["eval_token_check"](my_tools)
        cfg["header_audit"]                 # ResponseHeaderAuditConfig
        cfg["tool_registry"]                # ToolDefinitionRegistry
        cfg["bridge_ssrf_check"](target)    # callable
        cfg["content_type_check"](ct, name) # callable

    Primary source:
      https://www.ox.security/blog/mother-of-all-ai-supply-chains-2026-04-20
    """
    from .mcp_spec.supply_chain import (
        ToolDefinitionRegistry,
        check_mcp_bridge_target,
        check_tool_response_content_type,
    )

    return {
        "destructive_tool_check": mcpwn_cve_2026_33032_check,
        "eval_token_check": flowise_cve_2025_59528_check,
        "header_audit": azure_mcp_cve_2026_32211_defaults(),
        "tool_registry": ToolDefinitionRegistry(),
        "bridge_ssrf_check": check_mcp_bridge_target,
        "content_type_check": check_tool_response_content_type,
        "source": ("https://www.ox.security/blog/mother-of-all-ai-supply-chains-2026-04-20"),
        "cves": (
            "CVE-2025-65720",
            "CVE-2026-30615",
            "CVE-2026-30617",
            "CVE-2026-30618",
            "CVE-2026-30623",
            "CVE-2026-30624",
            "CVE-2026-30625",
            "CVE-2026-26015",
            "CVE-2026-33224",
            "CVE-2026-40933",
        ),
    }


# -----------------------------------------------------------------------------
# Unit 42 MCP sampling attack-vector preset (2026-04-24)
# -----------------------------------------------------------------------------


def unit42_mcp_sampling_defaults() -> SamplingGuardConfig:
    """Sampling-guard defaults for the Unit 42 MCP attack-vector catalog.

    Palo Alto Networks Unit 42 published a catalog of MCP sampling-layer
    abuses on 2026-04-24. Three patterns are in scope here: quota
    exhaustion, persistent system-role injection, and session-sticky
    consent bypass. This preset turns on the opt-in defenses the
    catalog recommends.

    Defaults:

    - ``max_sampling_requests_per_session`` = 50 (hard cap)
    - ``max_tokens_per_sampling_request`` = 4096
    - ``forbid_persistent_instructions`` = True (refuse system role)
    - ``require_user_consent_per_request`` = True (no session-sticky OK)

    Usage::

        from agent_airlock.policy_presets import unit42_mcp_sampling_defaults
        from agent_airlock.mcp_spec.sampling_guard import (
            SamplingSessionState,
            audit_sampling_request,
        )

        cfg = unit42_mcp_sampling_defaults()
        state = SamplingSessionState(session_id=req.session_id)
        audit_sampling_request(req.body, state, cfg, user_consented=ok)

    Primary source:
      https://unit42.paloaltonetworks.com/model-context-protocol-attack-vectors/
    """
    from .mcp_spec.sampling_guard import SamplingGuardConfig

    return SamplingGuardConfig(
        max_sampling_requests_per_session=50,
        max_tokens_per_sampling_request=4096,
        forbid_persistent_instructions=True,
        require_user_consent_per_request=True,
    )


UNIT42_MCP_SAMPLING_DEFAULTS = unit42_mcp_sampling_defaults()
"""Eagerly-constructed sampling-guard defaults (Unit 42 2026-04-24)."""


# -----------------------------------------------------------------------------
# OpenClaw CVE-2026-41349 — agentic consent-bypass (frozen-policy preset)
# -----------------------------------------------------------------------------


def openclaw_cve_2026_41349_defaults(
    base_policy: SecurityPolicy | None = None,
) -> SecurityPolicy:
    """Return a frozen ``SecurityPolicy`` guarding against CVE-2026-41349.

    OpenClaw agentic consent-bypass disclosed 2026-04-23 (CVSS 8.8).
    Exploit pattern: a prompt-injected agent rewrote its own
    ``allowed_tools`` / ``denied_tools`` mid-session, then invoked a
    tool the human operator had never approved. The ``config.patch``
    family of tool names was the visible tell in the advisory.

    This preset:

    1. Accepts an optional base policy (or defaults to a conservative
       template that forbids ``*config_patch*`` / ``*update_policy*``
       / ``*mutate_policy*`` tool name patterns, which are the
       advisory's named attack surface).
    2. Returns a :meth:`~SecurityPolicy.freeze`-d deep copy.
    3. The hosting ``Airlock`` dispatch re-verifies the digest before
       every tool call (see ``core.py``). Any mutation of the policy
       after this factory returns will raise
       :class:`PolicyMutationError`.

    Usage::

        from agent_airlock import Airlock
        from agent_airlock.policy_presets import openclaw_cve_2026_41349_defaults

        @Airlock(policy=openclaw_cve_2026_41349_defaults())
        def do_work(...): ...

    Primary source:
      https://www.thehackerwire.com/vulnerability/CVE-2026-41349/
    """
    policy = base_policy if base_policy is not None else SecurityPolicy()
    # Refuse the three known attack-surface name classes unless the
    # base policy already denied them (idempotent union).
    canary_denies = {"*config_patch*", "*update_policy*", "*mutate_policy*"}
    existing_denies = set(policy.denied_tools)
    merged = SecurityPolicy(
        allowed_tools=list(policy.allowed_tools),
        denied_tools=sorted(existing_denies | canary_denies),
        time_restrictions=dict(policy.time_restrictions),
        rate_limits=dict(policy.rate_limits),
        require_agent_id=policy.require_agent_id,
        allowed_roles=list(policy.allowed_roles),
        capability_policy=policy.capability_policy,
    )
    return merged.freeze()


# -----------------------------------------------------------------------------
# OpenClaw CVE-2026-41361 — IPv6 SSRF guard bypass (EndpointPolicy preset)
# -----------------------------------------------------------------------------


def openclaw_cve_2026_41361_ipv6_ssrf_defaults() -> dict[str, Any]:
    """Return the IPv6-range guard and a callable check for CVE-2026-41361.

    OpenClaw's IPv6 allow-list covered only ``::/128``, ``::1/128``,
    ``fe80::/10``, and ``fc00::/7``, leaving IPv4-mapped, NAT64, 6to4,
    and documentation ranges routable. Attackers used
    ``::ffff:169.254.169.254`` (IPv4-mapped) to reach AWS IMDS
    through a server that believed its IPv6 policy was complete.
    CVSS 7.1, disclosed 2026-04-23.

    Returned mapping::

        cfg = openclaw_cve_2026_41361_ipv6_ssrf_defaults()
        cfg["is_blocked"](addr)     # callable -> bool
        cfg["networks"]             # tuple[(cidr, reason), ...]
        cfg["source"]               # primary-source URL

    Primary source:
      https://www.redpacketsecurity.com/cve-alert-cve-2026-41361-openclaw-openclaw/
    """
    from .network import _BLOCKED_IPV6_NETWORKS, is_blocked_ipv6_range

    return {
        "is_blocked": is_blocked_ipv6_range,
        "networks": _BLOCKED_IPV6_NETWORKS,
        "source": ("https://www.redpacketsecurity.com/cve-alert-cve-2026-41361-openclaw-openclaw/"),
    }


# -----------------------------------------------------------------------------
# ModelCapabilityTier — offensive-cyber-capable model restrictions (v0.5.5+)
# -----------------------------------------------------------------------------


def offensive_cyber_model_defaults(model_id: str) -> CapabilityPolicy:
    """Return a ``CapabilityPolicy`` sized to the given model's tier.

    Introduced in response to the Anthropic Claude Mythos Preview
    disclosure (2026-04-23 InfoQ): frontier models can now chain
    reconnaissance + exploit synthesis autonomously. For such models,
    shell + network + unbounded filesystem writes should be denied
    unless the caller explicitly opts in by layering their own
    permissive policy on top.

    Behavior by tier:

    - ``STANDARD`` → empty restrictions (caller owns policy entirely).
    - ``OFFENSIVE_CYBER_CAPABLE`` → deny ``PROCESS_SHELL``,
      ``FILESYSTEM_WRITE``, ``FILESYSTEM_DELETE``, ``NETWORK_ARBITRARY``.
    - ``ZERO_DAY_CAPABLE`` → same as above plus ``PROCESS_EXEC``,
      ``NETWORK_HTTP`` / ``NETWORK_HTTPS`` denied — the model must
      run inside a sandbox with no network at all.

    Args:
        model_id: The driving LLM's model identifier.

    Returns:
        A :class:`CapabilityPolicy` with ``model_tier`` stamped and
        ``denied`` populated per the tier table.

    Primary source:
      https://www.infoq.com/news/2026/04/anthropic-claude-mythos/
    """
    from .capabilities import Capability, CapabilityPolicy, ModelCapabilityTier
    from .integrations.model_tier import classify_model

    tier = classify_model(model_id)

    if tier is ModelCapabilityTier.STANDARD:
        denied = Capability.NONE
    elif tier is ModelCapabilityTier.OFFENSIVE_CYBER_CAPABLE:
        denied = (
            Capability.PROCESS_SHELL
            | Capability.FILESYSTEM_WRITE
            | Capability.FILESYSTEM_DELETE
            | Capability.NETWORK_ARBITRARY
        )
    else:  # ZERO_DAY_CAPABLE
        denied = (
            Capability.PROCESS_SHELL
            | Capability.PROCESS_EXEC
            | Capability.FILESYSTEM_WRITE
            | Capability.FILESYSTEM_DELETE
            | Capability.NETWORK_ALL
        )

    return CapabilityPolicy(
        granted=Capability.NONE,
        denied=denied,
        require_sandbox_for=Capability.DANGEROUS,
        model_tier=tier,
    )


# -----------------------------------------------------------------------------
# CVE-2026-5023 — codebase-mcp RepoMix OS command injection (v0.5.5+)
# -----------------------------------------------------------------------------

_CODEBASE_MCP_TOOL_NAMES = re.compile(r"^(?:get|save)(?:Remote)?Codebase$")

# Shell metacharacters whose mere presence in an argument is a reject.
# A subset of the StdioGuard metachars with ``&`` added because the
# ShellJS/RepoMix call path flagged in the SentinelOne entry treated
# ampersand as a shell separator.
_CODEBASE_MCP_SHELL_METACHARS: tuple[str, ...] = (
    ";",
    "&&",
    "||",
    "&",
    "|",
    "`",
    "$(",
    "$",
    "\n",
    "\r",
    ">",
    "<",
)


class CodebaseMcpInjectionBlocked(AirlockError):
    """Raised when a codebase-mcp-style tool carries shell-inject input."""


def codebase_mcp_cve_2026_5023_defaults() -> dict[str, Any]:
    """Return the codebase-mcp regression check for CVE-2026-5023.

    The codebase-mcp package (npm ``codebase-mcp``) wraps the RepoMix
    CLI. ``getCodebase`` / ``getRemoteCodebase`` / ``saveCodebase``
    / ``saveRemoteCodebase`` shelled out with user-controlled paths,
    yielding trivial OS command injection. SentinelOne catalogued
    2026-04 (unpatched upstream as of 2026-04-24).

    Contract::

        cfg = codebase_mcp_cve_2026_5023_defaults()
        cfg["check"](tool_name, arguments, allow_subprocess=False)
        # Raises CodebaseMcpInjectionBlocked on shell metachars or
        # names matching the four-name allowlist unless
        # allow_subprocess=True is passed.

    Primary source:
      https://www.sentinelone.com/vulnerability-database/cve-2026-5023/
    """

    def check(
        tool_name: str,
        arguments: list[str] | tuple[str, ...],
        *,
        allow_subprocess: bool = False,
    ) -> None:
        if _CODEBASE_MCP_TOOL_NAMES.match(tool_name):
            if not allow_subprocess:
                raise CodebaseMcpInjectionBlocked(
                    f"tool {tool_name!r} is in the CVE-2026-5023 "
                    "codebase-mcp name allowlist and must be opted "
                    "into via allow_subprocess=True"
                )
            for idx, arg in enumerate(arguments):
                if not isinstance(arg, str):
                    continue
                for metachar in _CODEBASE_MCP_SHELL_METACHARS:
                    if metachar in arg:
                        raise CodebaseMcpInjectionBlocked(
                            f"tool {tool_name!r} argv[{idx}]={arg!r} "
                            f"contains shell metacharacter {metachar!r} "
                            "— refusing to spawn subprocess "
                            "(CVE-2026-5023 regression class)"
                        )

    return {
        "check": check,
        "tool_name_pattern": _CODEBASE_MCP_TOOL_NAMES.pattern,
        "metachars": _CODEBASE_MCP_SHELL_METACHARS,
        "source": ("https://www.sentinelone.com/vulnerability-database/cve-2026-5023/"),
    }


# -----------------------------------------------------------------------------
# CVE-2026-30615 — Windsurf zero-click MCP-config auto-load (v0.5.7+)
# -----------------------------------------------------------------------------


# -----------------------------------------------------------------------------
# Agent-commerce caps default preset (v0.5.8+, Anthropic Project Deal class)
# -----------------------------------------------------------------------------


def agent_commerce_default_caps(
    *,
    db_path: str = ":memory:",
) -> dict[str, Any]:
    """Default agent-commerce caps for Project Deal / Stripe Agentic flows.

    Sane caps: $10/counterparty/day + hard-stop $200/agent/week. Tighten
    or relax via the ``CapsConfig`` interface.

    Primary source:
      https://www.anthropic.com/features/project-deal
    """
    from .integrations.agent_commerce_caps import (
        AgentCommerceCaps,
        Cap,
        CapsConfig,
        SQLiteLedgerStore,
    )

    config = CapsConfig(
        caps=(
            Cap(amount_cents=1_000, window="day", scope="counterparty"),
            Cap(amount_cents=20_000, window="week", scope="agent"),
        )
    )
    caps = AgentCommerceCaps(config=config, store=SQLiteLedgerStore(db_path))
    return {
        "caps": caps,
        "config": config,
        "source": "https://www.anthropic.com/features/project-deal",
    }


# -----------------------------------------------------------------------------
# CVE-2026-27825 / -27826 mcp-atlassian LAN-unauth-RCE preset (v0.5.8+)
# -----------------------------------------------------------------------------


def mcp_atlassian_cve_2026_27825(*, profile: str = "prod") -> dict[str, Any]:
    """LAN-unauth-RCE guard preset for CVE-2026-27825 / -27826.

    Disclosed [2026-04-24 by The Hacker News](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html);
    NVD entries CVE-2026-27825 (CVSS 9.1) and CVE-2026-27826 (CVSS 8.2).
    ``mcp-atlassian`` bound to ``0.0.0.0`` and ``[::]`` with no auth
    headers, exposing the control surface to any device on the same
    network. Trivial in any office network.

    The class generalises — see also
    :func:`lan_unauth_mcp_guard` for the generic check.

    Args:
        profile: ``"prod"`` (default), ``"dev"``, or ``"strict"``
            per :class:`LANUnauthRCEPolicy`.

    Primary source:
      https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html
    """
    from .mcp_spec.lan_unauth_rce_guard import (
        LANUnauthRCEGuard,
        LANUnauthRCEPolicy,
    )

    guard = LANUnauthRCEGuard(LANUnauthRCEPolicy(profile=profile))  # type: ignore[arg-type]
    return {
        "guard": guard,
        "profile": profile,
        "source": ("https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html"),
        "covers": ("CVE-2026-27825", "CVE-2026-27826"),
    }


def lan_unauth_mcp_guard(*, profile: str = "prod") -> dict[str, Any]:
    """Generic LAN-unauth-RCE guard preset (the class, not the named CVE).

    Same machinery as :func:`mcp_atlassian_cve_2026_27825` but
    intended as a default catch for any MCP server registration —
    not scoped to atlassian-style names.
    """
    cfg = mcp_atlassian_cve_2026_27825(profile=profile)
    cfg["covers"] = ("class:lan-unauth-rce",)
    return cfg


# -----------------------------------------------------------------------------
# Comment-and-Control PR-metadata presets (v0.5.8+, Aonan Guan 2026-04-25)
# -----------------------------------------------------------------------------


def _build_pr_metadata_guard(*, dry_run: bool = False) -> Any:
    from .mcp_spec.pr_metadata_guard import PRMetadataGuard

    return PRMetadataGuard(
        rewrite_threshold=0.0,
        reject_threshold=0.9,
        dry_run=dry_run,
    )


def claude_code_security_review_cnc_2026_04(*, dry_run: bool = False) -> dict[str, Any]:
    """Comment-and-Control preset for Claude Code Security Review.

    Wires :class:`PRMetadataGuard` with conservative thresholds — every
    PR-metadata field gets sentinel-wrapped before reaching the model
    context, and any field with risk ≥ 0.9 raises
    :class:`PRMetadataInjectionRejected`.

    Set ``dry_run=True`` for the first deployment week to log without
    rewriting; flip to ``False`` once your own audit logs show no
    legitimate-PR false positives.

    Primary source:
      https://oddguan.com/blog/comment-and-control-prompt-injection-credential-theft-claude-code-gemini-cli-github-copilot/
    """
    return {
        "guard": _build_pr_metadata_guard(dry_run=dry_run),
        "ci_runner": "claude-code-security-review",
        "fields_in_scope": (
            "pr_title",
            "pr_body",
            "commit_message",
            "issue_title",
            "issue_body",
            "review_comment",
        ),
        "source": (
            "https://oddguan.com/blog/comment-and-control-prompt-injection-credential-theft-claude-code-gemini-cli-github-copilot/"
        ),
    }


def gemini_cli_action_cnc_2026_04(*, dry_run: bool = False) -> dict[str, Any]:
    """Comment-and-Control preset for the Gemini CLI Action.

    Same threat model as the Claude Code preset but tagged for the
    Gemini CLI runner so audit logs distinguish them.

    Primary source:
      https://oddguan.com/blog/comment-and-control-prompt-injection-credential-theft-claude-code-gemini-cli-github-copilot/
    """
    cfg = claude_code_security_review_cnc_2026_04(dry_run=dry_run)
    cfg["ci_runner"] = "gemini-cli-action"
    return cfg


@dataclass(frozen=True)
class PresetMeta:
    """Metadata about a registered preset, returned by ``list_active``."""

    preset_id: str
    factory_name: str
    """Top-level callable in :mod:`agent_airlock.policy_presets`."""
    docstring_summary: str = ""


def list_active() -> list[PresetMeta]:
    """Return metadata for every preset factory in this module.

    Single source of truth consumed by ``airlock graph``, the OWASP
    coverage matrix, and any future tool that needs to enumerate
    presets without re-walking the package.
    """
    import inspect
    import sys

    module = sys.modules[__name__]
    out: list[PresetMeta] = []
    for name, obj in inspect.getmembers(module, inspect.isfunction):
        # Heuristics to filter out helpers + check predicates:
        # only top-level zero-arg-or-kwargs-only callables that return
        # dicts / SecurityPolicy / CapabilityPolicy / dataclasses.
        if name.startswith("_"):
            continue
        if name in {"is_destructive_tool", "list_active", "list_presets"}:
            continue
        if not name.endswith(("_policy", "_defaults", "_caps", "_2026_04")):
            continue
        try:
            sig = inspect.signature(obj)
        except (TypeError, ValueError):
            continue
        if any(
            p.kind == inspect.Parameter.POSITIONAL_OR_KEYWORD
            and p.default is inspect.Parameter.empty
            for p in sig.parameters.values()
        ):
            # Skip predicates that demand mandatory positional args
            # (e.g. ``mcpwn_cve_2026_33032_check``).
            continue
        doc = (inspect.getdoc(obj) or "").splitlines()[0] if inspect.getdoc(obj) else ""
        out.append(
            PresetMeta(
                preset_id=name,
                factory_name=name,
                docstring_summary=doc,
            )
        )
    out.sort(key=lambda m: m.preset_id)
    return out


def copilot_agent_cnc_2026_04(*, dry_run: bool = False) -> dict[str, Any]:
    """Comment-and-Control preset for GitHub Copilot Agent.

    Same threat model as the Claude Code preset but tagged for the
    Copilot Agent runner so audit logs distinguish them.

    Primary source:
      https://oddguan.com/blog/comment-and-control-prompt-injection-credential-theft-claude-code-gemini-cli-github-copilot/
    """
    cfg = claude_code_security_review_cnc_2026_04(dry_run=dry_run)
    cfg["ci_runner"] = "copilot-agent"
    return cfg


def agent_capability_default_caps() -> dict[str, Any]:
    """Conservative capability caps for agent-on-agent surfaces.

    Mirrors the ``agent_commerce_default_caps`` preset shipped 2026-04-27
    (dollar caps) for the capability layer added 2026-04-28. Defaults:

    * ``SIGN_CONTRACT``: 0/agent without explicit grant (deny-by-default).
    * ``DELEGATE_TO_AGENT``: 3/agent/hour.
    * ``INVOKE_TOOL``: 100/agent/minute.
    * ``WRITE_FILE``: 50/agent/hour.
    * ``NETWORK_EGRESS``: 10_000_000 (10 MB) /agent/minute (counted in bytes).

    Primary source:
      https://www.anthropic.com/features/project-deal
    """
    from .capability_caps import Capability, CapabilityRule, CapabilityRulesConfig

    return {
        "preset_id": "agent_capability_default_caps",
        "advisory_url": "https://www.anthropic.com/features/project-deal",
        "rules_config": CapabilityRulesConfig(
            rules=(
                # SIGN_CONTRACT is deny-by-default; no rule = no grants.
                CapabilityRule(
                    capability=Capability.DELEGATE_TO_AGENT,
                    amount=3,
                    window="hour",
                ),
                CapabilityRule(
                    capability=Capability.INVOKE_TOOL,
                    amount=100,
                    window="minute",
                ),
                CapabilityRule(
                    capability=Capability.WRITE_FILE,
                    amount=50,
                    window="hour",
                ),
                CapabilityRule(
                    capability=Capability.NETWORK_EGRESS,
                    amount=10_000_000,
                    window="minute",
                ),
            )
        ),
    }


def gpt_5_5_spud_agent_defaults(
    *,
    max_parallel_tool_calls: int = 8,
    per_call_egress_cap_kb: int = 512,
    context_window_budget_tokens: int = 900_000,
    requires_baseline: bool = True,
) -> dict[str, Any]:
    """Conservative defaults for the OpenAI GPT-5.5 ("Spud") agent surface.

    GPT-5.5 GA'd 2026-04-23 with a 1M-token default context window and a
    homogenised tool-call shape. Without a preset, airlock-protected
    agents fall back to the model's own (zero) policy. These defaults
    bind:

    * ``max_parallel_tool_calls=8`` — refuse fan-out beyond 8 parallel
      calls in a single turn.
    * ``per_call_egress_cap_kb=512`` — cap per-tool-call outbound
      payload size; trips the existing egress budget.
    * ``context_window_budget_tokens=900_000`` — 10% headroom under the
      published 1M context window so a runaway agent cannot
      consume the entire window.
    * ``requires_baseline=True`` — every protected agent must produce a
      behavioural baseline (see ``airlock baseline init``) before
      being granted production capability grants.

    Primary source:
      https://openai.com/index/gpt-5-5/
    """
    return {
        "preset_id": "gpt_5_5_spud_agent_defaults",
        "model_id": "openai.gpt-5.5-spud",
        "schema_pinned_at": "2026-04-23",
        "max_parallel_tool_calls": max_parallel_tool_calls,
        "per_call_egress_cap_kb": per_call_egress_cap_kb,
        "context_window_budget_tokens": context_window_budget_tokens,
        "requires_baseline": requires_baseline,
        "advisory_url": "https://openai.com/index/gpt-5-5/",
    }


def oauth_state_injection_guard(
    *,
    max_state_bytes: int = 2048,
    entropy_skip_threshold: float = 3.0,
) -> dict[str, Any]:
    """Defence against OAuth ``state`` prompt-injection (BlackHat Asia 2026).

    Injects prompt strings into the OAuth ``state`` parameter and the
    callback handler decodes + relays them into a system message. This
    preset wires :class:`OAuthStateEntropyGuard` with the recommended
    defaults; high-entropy nonces and JWT tri-segments are ignored.

    Primary source:
      https://www.blackhat.com/asia-26/briefings/schedule/#oauth-state-injection
    """
    return {
        "preset_id": "oauth_state_injection_guard",
        "severity": "high",
        "default_action": "block",
        "advisory_url": (
            "https://www.blackhat.com/asia-26/briefings/schedule/#oauth-state-injection"
        ),
        "max_state_bytes": max_state_bytes,
        "entropy_skip_threshold": entropy_skip_threshold,
    }


def gemini_3_agent_defaults(
    *,
    redact_thought_signature: bool = True,
    fan_out_cap: int = 8,
    per_call_egress_cap_kb: int = 64,
) -> dict[str, Any]:
    """Conservative defaults for Google Gemini 3 Agent Mode.

    Gemini 3 GA'd 2026-04-25 with a ``function_response`` carrier and
    chain-of-thought ``thought_signature`` metadata. This preset wires
    ``redact_thought_signature=True`` (the audit-log default), a
    fan-out cap of 8 parallel calls, and a 64 KB per-call egress cap.

    Primary source:
      https://blog.google/technology/google-deepmind/gemini-3-agent-mode-ga/
    """
    return {
        "preset_id": "gemini_3_agent_defaults",
        "model_id": "gemini-3-agent",
        "schema_pinned_at": "2026-04-25",
        "redact_thought_signature": redact_thought_signature,
        "fan_out_cap": fan_out_cap,
        "per_call_egress_cap_kb": per_call_egress_cap_kb,
        "advisory_url": ("https://blog.google/technology/google-deepmind/gemini-3-agent-mode-ga/"),
    }


def mcp_config_path_traversal_cve_2026_31402(
    *,
    platform: str = "auto",
    allow_symlinks: bool = False,
) -> dict[str, Any]:
    """Path-traversal guard for MCP server-registration configs.

    CVE-2026-31402 (CVSS 8.8, NVD 2026-04-27) is a path-traversal in
    Claude Desktop's config loader that lets a hostile config write
    outside the sandboxed MCP install dir on first launch. This preset
    wires :class:`ConfigPathGuard` with the recommended defaults.

    Primary source:
      https://nvd.nist.gov/vuln/detail/CVE-2026-31402
    """
    return {
        "preset_id": "mcp_config_path_traversal_cve_2026_31402",
        "severity": "critical",
        "default_action": "block",
        "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-31402",
        "platform": platform,
        "allow_symlinks": allow_symlinks,
    }


def mcp_elicitation_guard_2026_04(
    *,
    allowlist_origins: frozenset[str] = frozenset(),
    strict: bool = False,
) -> dict[str, Any]:
    """Defence for MCP ``tool/elicitation`` (spec PR #1487, 2026-04-28).

    Server-initiated elicitation round-trips can render hostile prompts
    that look authoritative to the user. This preset wires the
    ``ElicitationGuard`` with the recommended per-class actions and an
    optional ``strict`` mode that downgrades the default
    ``relay_with_warning`` for destructive confirmations to ``block``.

    Primary source:
      https://github.com/modelcontextprotocol/specification/pull/1487
    """
    from .mcp_spec.elicitation_guard import ElicitationClass

    actions: dict[ElicitationClass, str] = {
        ElicitationClass.BENIGN: "relay_with_origin_badge",
        ElicitationClass.CREDENTIAL_REQUEST: "block",
        ElicitationClass.POLICY_OVERRIDE: "block",
        ElicitationClass.DESTRUCTIVE_CONFIRMATION: ("block" if strict else "relay_with_warning"),
    }
    return {
        "preset_id": "mcp_elicitation_guard_2026_04",
        "severity": "high",
        "default_action": "block",
        "advisory_url": "https://github.com/modelcontextprotocol/specification/pull/1487",
        "actions": actions,
        "allowlist_origins": allowlist_origins,
        "strict": strict,
    }


def mcp_stdio_meta_cve_2026_04(
    *,
    enable_manifest_drift_check: bool = True,
    enable_taint_check: bool = False,
) -> dict[str, Any]:
    """Bundled defense for the OX-disclosed STDIO RCE class (v0.5.9+).

    OX Security 2026-04-26 disclosed that the Anthropic MCP STDIO
    transport class is exploitable across 200K+ servers and Anthropic
    has declined to patch ("expected behavior"). This preset wires
    every airlock STDIO-defence into a single chain:

    * argv shape enforcement (no shell-form smuggle)
    * stdio_guard (per-arg metachar / unicode / allowlist)
    * manifest drift check (signed manifest vs runtime argv) — opt-out
    * AST taint scan for remote-input → stdin sinks — opt-in (filesystem)

    The preset is the recommended default for any MCP server registered
    after 2026-04-26.

    Primary sources:
      https://www.ox.security/blog/mother-of-all-ai-supply-chains-anthropic-mcp-stdio
      https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem
      https://www.theregister.com/2026/04/16/anthropic_mcp_design_flaw/
    """
    return {
        "preset_id": "mcp_stdio_meta_cve_2026_04",
        "severity": "critical",
        "default_action": "block",
        "advisory_url": (
            "https://www.ox.security/blog/mother-of-all-ai-supply-chains-anthropic-mcp-stdio"
        ),
        "stdio_config": stdio_guard_ox_defaults(),
        "enable_manifest_drift_check": enable_manifest_drift_check,
        "enable_taint_check": enable_taint_check,
        "covered_variants": (
            "argv_string_concat",
            "argv_shell_metachar",
            "argv_unicode_bidi",
            "argv_absolute_path_smuggle",
            "argv_basename_not_allowlisted",
            "argv_env_path_traversal",
            "manifest_runtime_drift",
            "stdin_remote_input_taint",
        ),
        "recommended_for": "any MCP server registered after 2026-04-26",
    }


def windsurf_cve_2026_30615_defaults(
    signer_allowlist: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """CVE-2026-30615 zero-click mcp.json auto-load preset.

    Composes :class:`ConfigFileWatchPolicy` with the Windsurf-specific
    config path and the signer-required default. The class
    generalises beyond Windsurf — VS Code, Cursor, Claude Code,
    JetBrains all auto-read project-local MCP config — but the named
    advisory triggered when ``.windsurf/mcp.json`` was rewritten by
    a prompt-injected HTML page.

    Args:
        signer_allowlist: Trusted signer identifiers. Empty means
            "any non-empty signer is acceptable" — adopt in stages.

    Contract::

        cfg = windsurf_cve_2026_30615_defaults(signer_allowlist=frozenset({"sre"}))
        cfg["audit"](path, old_sha256, new_content, old_content=...)

    Primary source:
      https://nvd.nist.gov/vuln/detail/CVE-2026-30615
    """
    from .mcp_spec.zero_click_config_guard import (
        DEFAULT_WATCHED_PATHS,
        ConfigFileWatchPolicy,
        audit_config_diff,
    )

    policy = ConfigFileWatchPolicy(
        watched_paths=DEFAULT_WATCHED_PATHS,
        require_signer_for_new_servers=True,
        quarantine_on_diff=True,
        signer_allowlist=signer_allowlist,
    )

    def audit(
        path: Any,  # pathlib.Path; kept loose to avoid an extra top-level import
        old_sha256: str | None,
        new_content: bytes,
        *,
        old_content: bytes | None = None,
    ) -> Any:
        return audit_config_diff(path, old_sha256, new_content, policy, old_content=old_content)

    return {
        "audit": audit,
        "policy": policy,
        "watched_paths": tuple(str(p) for p in policy.watched_paths),
        "source": "https://nvd.nist.gov/vuln/detail/CVE-2026-30615",
    }


# -----------------------------------------------------------------------------
# CVE-2026-6980 — Divyanshu-hash/GitPilot-MCP repo_path injection (v0.5.7+)
# -----------------------------------------------------------------------------

_GITPILOT_HANDLER_NAMES = re.compile(r"^(repo_path|run_git_command|exec_in_repo)$")


class GitPilotRepoPathInjection(AirlockError):
    """Raised when a GitPilot-MCP-style handler receives an unsafe repo_path."""

    def __init__(self, *, handler_name: str, repo_path: str, reason: str) -> None:
        self.handler_name = handler_name
        self.repo_path = repo_path
        self.reason = reason
        super().__init__(
            f"GitPilot-MCP handler {handler_name!r} refused repo_path "
            f"{repo_path!r}: {reason} (CVE-2026-6980)"
        )


def gitpilot_mcp_cve_2026_6980_defaults(
    safe_repo_roots: tuple[_Path_for_gitpilot, ...] = (),
) -> dict[str, Any]:
    """CVE-2026-6980 GitPilot-MCP repo_path regression preset.

    Disclosed 2026-04-25 by RedPacket Security (CVSS 7.3). The
    ``repo_path`` argument of ``Divyanshu-hash/GitPilot-MCP``'s
    ``main.py`` flowed into OS command execution. Public PoC; vendor
    unresponsive; project does not version — so the preset matches
    purely on **tool name**, not upstream package pin.

    Three handler names are caught: ``repo_path``, ``run_git_command``,
    ``exec_in_repo``. For each, the value supplied as ``repo_path``
    must:

    1. Resolve to an absolute path under one of ``safe_repo_roots``.
    2. Pass the ``shlex.quote(arg) == arg`` round-trip — i.e. contain
       no shell metacharacters.

    Args:
        safe_repo_roots: Allowed prefixes for ``repo_path``. Empty
            tuple means "any absolute path is acceptable" — but the
            shell-safe-token check still applies.

    Contract::

        cfg = gitpilot_mcp_cve_2026_6980_defaults(safe_repo_roots=(Path("/var/repos"),))
        cfg["check"]("repo_path", {"repo_path": "/var/repos/clean"})  # OK
        cfg["check"]("repo_path", {"repo_path": "/var/repos/foo`id`"})  # raises

    Primary source:
      https://www.redpacketsecurity.com/cve-alert-cve-2026-6980-divyanshu-hash-gitpilot-mcp/
    """
    roots = tuple(_Path_for_gitpilot(r).resolve() for r in safe_repo_roots)

    def check(handler_name: str, fields: dict[str, Any]) -> None:
        if not _GITPILOT_HANDLER_NAMES.match(handler_name or ""):
            return
        repo_path = fields.get("repo_path")
        if repo_path is None:
            return
        repo_path_str = str(repo_path)

        # Shell-metachar check — same shlex round-trip the
        # codebase-mcp preset uses, but applied to a single field.
        if _shlex_for_gitpilot.quote(repo_path_str) != repo_path_str:
            raise GitPilotRepoPathInjection(
                handler_name=handler_name,
                repo_path=repo_path_str,
                reason="shell-metacharacter present (shlex round-trip failed)",
            )

        path = _Path_for_gitpilot(repo_path_str)
        if not path.is_absolute():
            raise GitPilotRepoPathInjection(
                handler_name=handler_name,
                repo_path=repo_path_str,
                reason="repo_path must be absolute",
            )

        # Reject path traversal: resolved path must remain under a
        # safe root if any are configured.
        if roots:
            try:
                resolved = path.resolve()
            except (OSError, RuntimeError):
                raise GitPilotRepoPathInjection(
                    handler_name=handler_name,
                    repo_path=repo_path_str,
                    reason="resolve() failed — path is unreachable",
                ) from None
            if not any(str(resolved).startswith(str(r) + "/") or resolved == r for r in roots):
                raise GitPilotRepoPathInjection(
                    handler_name=handler_name,
                    repo_path=repo_path_str,
                    reason=f"resolved path not under {roots}",
                )

    return {
        "check": check,
        "tool_name_pattern": _GITPILOT_HANDLER_NAMES.pattern,
        "safe_repo_roots": roots,
        "source": (
            "https://www.redpacketsecurity.com/cve-alert-cve-2026-6980-divyanshu-hash-gitpilot-mcp/"
        ),
    }


# -----------------------------------------------------------------------------
# Archived MCP server advisory gate (v0.5.6+, GitHub issue #3662 class)
# -----------------------------------------------------------------------------

# Default block-list — inline so it survives wheel packaging.
#
# v0.5.6 shipped this list via a JSON file under ``tests/cves/fixtures/``,
# but ``tests/`` is not packaged in the wheel, so ``pip install``
# users got an empty block-list and the preset silently failed open.
# Fix landed in v0.5.6.1: list is hard-coded here; the JSON fixture
# stays in ``tests/`` for parser / schema tests only.
#
# Source per row: GitHub modelcontextprotocol/servers issue #3662 +
# the per-package archive notice. Kept short — three packages — to
# keep the wheel small. Callers wanting a larger block-list pass it
# via the ``block_list`` argument.
_ARCHIVED_MCP_DEFAULT_BLOCKLIST: tuple[dict[str, Any], ...] = (
    {
        "package": "@modelcontextprotocol/server-puppeteer",
        "registry": "npm",
        "archived_at": "2026-04",
        "monthly_downloads": 91000,
        "disclosed_classes": (
            "ssrf",
            "indirect_prompt_injection",
            "chromium_sandbox_bypass",
        ),
        "advisory_url": "https://github.com/modelcontextprotocol/servers/issues/3662",
    },
    {
        "package": "@modelcontextprotocol/server-brave-search",
        "registry": "npm",
        "archived_at": "2026-03",
        "monthly_downloads": 38000,
        "disclosed_classes": (
            "credential_passthrough",
            "indirect_prompt_injection",
        ),
        "advisory_url": "https://github.com/modelcontextprotocol/servers/issues/3201",
    },
    {
        "package": "@modelcontextprotocol/server-everart",
        "registry": "npm",
        "archived_at": "2026-02",
        "monthly_downloads": 12000,
        "disclosed_classes": ("ssrf",),
        "advisory_url": "https://github.com/modelcontextprotocol/servers/issues/2812",
    },
)


class ArchivedMcpServerBlocked(AirlockError):
    """Raised when a tool's package_origin is on the archived block-list."""


def archived_mcp_server_advisory_defaults(
    block_list: Iterable[dict[str, Any]] | None = None,
    allow_list: Iterable[str] = (),
) -> dict[str, Any]:
    """Fail-closed gate for tool manifests pointing at archived MCP packages.

    Motivation: GitHub issue #3662 (2026-04) documented that the
    archived ``@modelcontextprotocol/server-puppeteer`` package was
    still being installed ~91k times/month, with advisory text
    covering SSRF, indirect prompt injection, and Chromium sandbox
    bypass — none of which would ever be patched (repo archived).

    Args:
        block_list: Iterable of package metadata dicts, each at minimum
            with a ``"package"`` key. If ``None``, the default
            shipped fixture is loaded.
        allow_list: Package names that bypass the block check. Use
            sparingly; intended for in-house forks of an archived
            package where the archive text doesn't apply.

    Returns:
        A mapping with ``check(tool_manifest_dict)`` callable, the
        compiled block-set, and the primary advisory URL.

    Usage::

        cfg = archived_mcp_server_advisory_defaults()
        cfg["check"]({"package_origin": "@modelcontextprotocol/server-puppeteer"})
        # Raises ArchivedMcpServerBlocked.

    Primary source:
      https://github.com/modelcontextprotocol/servers/issues/3662
    """
    if block_list is None:
        block_list = _ARCHIVED_MCP_DEFAULT_BLOCKLIST

    block_map: dict[str, dict[str, Any]] = {}
    for entry in block_list or []:
        if isinstance(entry, dict) and "package" in entry:
            block_map[str(entry["package"])] = entry

    allow_set = frozenset(allow_list)

    def check(tool_manifest: dict[str, Any]) -> None:
        origin = tool_manifest.get("package_origin")
        if not origin:
            return
        if origin in allow_set:
            return
        if origin in block_map:
            details = block_map[origin]
            raise ArchivedMcpServerBlocked(
                f"tool manifest references archived MCP package "
                f"{origin!r} (archived {details.get('archived_at', '?')}, "
                f"~{details.get('monthly_downloads', '?')} downloads/month, "
                f"advisory: {details.get('advisory_url', '?')})"
            )

    return {
        "check": check,
        "block_list": tuple(block_map.keys()),
        "allow_list": allow_set,
        "source": "https://github.com/modelcontextprotocol/servers/issues/3662",
    }


# -----------------------------------------------------------------------------
# Claude Managed Agents safe defaults (v0.5.6+, 2026-04-08 launch)
# -----------------------------------------------------------------------------


def claude_managed_agents_safe_defaults() -> dict[str, Any]:
    """Conservative defaults for the Claude Managed Agents harness.

    Anthropic launched Managed Agents to public beta on 2026-04-08
    (used by Notion, Rakuten, Asana, Vibecode, Sentry; $0.08/runtime-
    hour). The runtime ships a curated tool surface — ``read_file``,
    ``bash``, ``web_browse``, ``code_execute`` — and streams raw tool
    inputs/outputs over Server-Sent Events.

    This preset returns a :class:`ManagedAgentsAuditConfig` with:

    - ``allowed_tools`` = empty (no managed-agent tool calls until
      caller explicitly opts in by listing tools).
    - ``require_beta_header`` = True
    - ``toolset_version`` = pinned at :data:`AGENT_TOOLSET_VERSION`
    - ``redact_sse_payloads`` = True

    The mapping returned also includes the harness tool list so
    callers can build their own intersection::

        cfg = claude_managed_agents_safe_defaults()
        audit = cfg["audit_config"]
        # Opt in to read-only operations
        audit.allowed_tools = ("read_file", "web_browse")

    Primary sources:
      https://claude.com/blog/claude-managed-agents
      https://platform.claude.com/docs/en/managed-agents/overview
    """
    from .integrations.claude_managed_agents import (
        AGENT_TOOLSET_VERSION,
        DEFAULT_HARNESS_TOOLS,
        MANAGED_AGENTS_BETA_HEADER,
        ManagedAgentsAuditConfig,
    )

    return {
        "audit_config": ManagedAgentsAuditConfig(
            allowed_tools=(),
            require_beta_header=True,
            toolset_version=AGENT_TOOLSET_VERSION,
            redact_sse_payloads=True,
        ),
        "harness_tools": DEFAULT_HARNESS_TOOLS,
        "beta_header": MANAGED_AGENTS_BETA_HEADER,
        "toolset_version": AGENT_TOOLSET_VERSION,
        "source": "https://claude.com/blog/claude-managed-agents",
    }


# -----------------------------------------------------------------------------
# CVE-2026-23744 — MCPJam Inspector bind-address regression (v0.5.6+)
# -----------------------------------------------------------------------------

_DEV_SERVER_TOOL_NAME_PATTERN = re.compile(r"(?i)^(?:mcpjam|inspector|dev[-_ ]?server|studio)\b")


def mcpjam_cve_2026_23744_defaults() -> dict[str, Any]:
    """Return the bind-address guard for CVE-2026-23744 (MCPJam ≤ 1.4.2).

    GHSA-232v-j27c-5pp6 (CVSS 9.8) — MCPJam Inspector ≤ 1.4.2 bound
    to ``0.0.0.0`` by default with no auth. Patched in 1.4.3. The
    bug class generalises to any local MCP dev server: bind to a
    public address without auth = LAN-reachable RCE.

    Contract::

        cfg = mcpjam_cve_2026_23744_defaults()
        cfg["check"](tool_name, addr, auth_required=True)

    The ``check`` callable matches ``tool_name`` against the dev-server
    name pattern (``mcpjam`` / ``inspector`` / ``dev-server`` /
    ``studio``) and validates ``addr`` against the bind-address guard.
    Tools outside the pattern are unaffected — this preset is
    deliberately scoped to known-dev-server tool name shapes.

    Primary source:
      https://github.com/advisories/GHSA-232v-j27c-5pp6
    """
    from .mcp_spec.bind_address_guard import (
        BindAddressGuardConfig,
        validate_bind_address,
    )

    def check(
        tool_name: str,
        addr: str,
        *,
        auth_required: bool = False,
        allow_public_bind: bool = False,
    ) -> None:
        if not _DEV_SERVER_TOOL_NAME_PATTERN.match(tool_name or ""):
            return
        cfg = BindAddressGuardConfig(
            allow_public_bind=allow_public_bind,
            auth_required=auth_required,
        )
        validate_bind_address(addr, cfg)

    return {
        "check": check,
        "tool_name_pattern": _DEV_SERVER_TOOL_NAME_PATTERN.pattern,
        "source": ("https://github.com/advisories/GHSA-232v-j27c-5pp6"),
    }


# -----------------------------------------------------------------------------
# CVE-2026-39884 — flux159/mcp-server-kubernetes argv flag-injection (v0.5.6+)
# -----------------------------------------------------------------------------

_KUBECTL_PORT_FORWARD_PATTERN = re.compile(r"(?i)port_?forward")

# Field names the SentinelOne advisory called out as injection-prone
# in ``port_forward``/kubectl handlers. The CVE-2026-39884 fix in
# ``mcp-server-kubernetes`` 3.5.0 added per-field validation for
# exactly these.
_KUBECTL_INJECTION_PRONE_FIELDS: tuple[str, ...] = (
    "namespace",
    "resourceType",
    "resourceName",
    "localPort",
    "targetPort",
)


def flux159_mcp_kubernetes_cve_2026_39884_defaults() -> dict[str, Any]:
    """Return the kubectl argv-injection check for CVE-2026-39884.

    The MCP server ``flux159/mcp-server-kubernetes`` (≤ 3.4.x) built
    kubectl invocations by string-concatenating user-controlled fields
    like ``localPort`` into a single argv element. A value such as
    ``"8080 --kubeconfig=/etc/shadow"`` thereby became extra flags
    rather than data. SentinelOne disclosed 2026-04-14; fixed in 3.5.0.

    Different injection class than v0.5.5's CVE-2026-5023 codebase-mcp
    preset: that one rejects shell metacharacters; this one rejects
    space-injected flag concatenation with no metacharacter present.

    Contract::

        cfg = flux159_mcp_kubernetes_cve_2026_39884_defaults()
        cfg["check"](tool_name, fields_dict)
        # Raises ArgvStringConcatenationError if any injection-prone
        # field carries a value that would survive shlex.quote unwrapped.

    Primary source:
      https://www.sentinelone.com/vulnerability-database/cve-2026-39884/
    """
    from .mcp_spec.argv_guard import (
        ArgvStringConcatenationError,
        enforce_argv_array,
    )

    def check(tool_name: str, fields: dict[str, Any]) -> None:
        if not _KUBECTL_PORT_FORWARD_PATTERN.search(tool_name or ""):
            return
        ordered_fields = [f for f in _KUBECTL_INJECTION_PRONE_FIELDS if f in fields]
        argv = [str(fields[f]) for f in ordered_fields]
        try:
            enforce_argv_array(argv, field_names=ordered_fields)
        except ArgvStringConcatenationError:
            raise

    return {
        "check": check,
        "tool_name_pattern": _KUBECTL_PORT_FORWARD_PATTERN.pattern,
        "injection_prone_fields": _KUBECTL_INJECTION_PRONE_FIELDS,
        "source": ("https://www.sentinelone.com/vulnerability-database/cve-2026-39884/"),
    }


# -----------------------------------------------------------------------------
# CVE-2026-33032 "MCPwn" — destructive-tool auth-middleware regression preset
# -----------------------------------------------------------------------------

# Matches write / exec / kill / destructive verbs. Expanded from the
# 12 nginx-ui tool names cataloged in the Rapid7 write-up.
_DESTRUCTIVE_TOOL_PATTERN = re.compile(
    r"(?i)^(?:"
    r"delete|destroy|drop|erase|purge|"
    r"install|uninstall|upload|overwrite|"
    r"reload|restart|stop|start|kill|"
    r"configure|enable|disable|patch|"
    r"run_shell|exec|execute|shell|"
    r"backup_restore|rollback|factory_reset"
    r").*$"
)

# Middleware identifiers we DO accept as enforcing real authentication.
# "ip_allowlist" alone is NOT accepted — nginx-ui's default was 0.0.0.0/0.
_TRUSTED_AUTH_MIDDLEWARES: frozenset[str] = frozenset(
    {
        "AuthRequired",
        "SessionRequired",
        "BearerRequired",
        "OIDCRequired",
        "OAuthRequired",
    }
)


class UnauthenticatedDestructiveToolError(AirlockError):
    """Raised when a destructive MCP tool lacks authenticating middleware."""


def is_destructive_tool(tool_name: str) -> bool:
    """Return True iff ``tool_name`` matches the destructive-verb pattern.

    Public so users can pre-classify their own tool catalogs before
    handing them to :func:`mcpwn_cve_2026_33032_check`.
    """
    return bool(_DESTRUCTIVE_TOOL_PATTERN.match(tool_name or ""))


def mcpwn_cve_2026_33032_check(
    tools: list[dict[str, Any]],
) -> None:
    """Assert every destructive tool is wrapped in real auth middleware.

    Args:
        tools: A list of tool manifests. Each entry must carry:
            - ``name`` (str): the MCP tool name.
            - ``middlewares`` (list[str]): the middleware names applied
              to the tool's HTTP endpoint, in order.

    Raises:
        UnauthenticatedDestructiveToolError: When a destructive tool
            name (see :func:`is_destructive_tool`) is present but no
            middleware in :data:`_TRUSTED_AUTH_MIDDLEWARES` is applied
            to it. Raised as soon as the first offender is found — the
            error details identify it.
    """
    for tool in tools:
        name = tool.get("name", "")
        if not is_destructive_tool(name):
            continue
        middlewares = tool.get("middlewares") or []
        has_auth = any(m in _TRUSTED_AUTH_MIDDLEWARES for m in middlewares)
        if not has_auth:
            raise UnauthenticatedDestructiveToolError(
                f"destructive MCP tool {name!r} exposes no "
                f"authenticating middleware (saw {middlewares!r}). "
                "Regression class: CVE-2026-33032 (nginx-ui MCPwn). "
                "See https://nvd.nist.gov/vuln/detail/CVE-2026-33032"
            )


def mcpwn_cve_2026_33032_defaults() -> dict[str, Any]:
    """Preset-style factory returning the MCPwn audit config.

    Because this preset's output is the checker function itself rather
    than a ``SecurityPolicy``, the return value is a small mapping that
    a caller uses like::

        from agent_airlock.policy_presets import mcpwn_cve_2026_33032_defaults

        cfg = mcpwn_cve_2026_33032_defaults()
        cfg["check"](my_tool_manifests)

    Primary source: https://nvd.nist.gov/vuln/detail/CVE-2026-33032
    """
    return {
        "check": mcpwn_cve_2026_33032_check,
        "is_destructive": is_destructive_tool,
        "trusted_middlewares": _TRUSTED_AUTH_MIDDLEWARES,
        "source": (
            "https://nvd.nist.gov/vuln/detail/CVE-2026-33032, "
            "https://www.rapid7.com/blog/post/etr-cve-2026-33032-nginx-ui-missing-mcp-authentication/"
        ),
    }


# -----------------------------------------------------------------------------
# CVE-2025-59528 Flowise CustomMCP RCE — eval/Function() tool-manifest ban
# -----------------------------------------------------------------------------

# Tokens whose presence inside a tool manifest's ``handler`` or
# ``config`` string means user input reaches JS dynamic-evaluation.
# Primary sources:
#   https://labs.cloudsecurityalliance.org/research/csa-research-note-flowise-mcp-rce-exploitation-20260409-csa/
#   https://advisories.gitlab.com/npm/flowise/CVE-2025-59528/
_EVAL_TOKENS: tuple[str, ...] = (
    "Function(",
    "new Function",
    "eval(",
    "Deno.eval",
    "vm.runInNewContext",
)


class FlowiseEvalTokenError(AirlockError):
    """Raised when a tool manifest embeds a JS dynamic-eval token."""


def flowise_cve_2025_59528_check(tools: list[dict[str, Any]]) -> None:
    """Reject any tool whose handler or config embeds a JS eval token.

    The Flowise CustomMCP RCE (CVE-2025-59528, CVSS 10.0) passed user-
    supplied strings from ``/api/v1/node-load-method/customMCP`` into
    the JavaScript ``Function()`` constructor. CSA documented active
    exploitation in April 2026 despite a September 2025 patch. This
    check makes the class non-transportable: if a manifest carries
    any of the banned tokens, refuse to register the tool.

    Args:
        tools: Tool manifests. Each entry may carry ``handler`` and/or
            ``config`` string fields.

    Raises:
        FlowiseEvalTokenError: First offender wins; error message names
            the tool and the banned token.
    """
    for tool in tools:
        for field_name in ("handler", "config"):
            value = tool.get(field_name)
            if not isinstance(value, str):
                continue
            for token in _EVAL_TOKENS:
                if token in value:
                    raise FlowiseEvalTokenError(
                        f"tool {tool.get('name', '<unnamed>')!r} "
                        f"field {field_name!r} contains banned JS "
                        f"eval token {token!r}. Regression class: "
                        "CVE-2025-59528 (Flowise CustomMCP RCE). "
                        "See https://labs.cloudsecurityalliance.org/research/csa-research-note-flowise-mcp-rce-exploitation-20260409-csa/"
                    )


def high_value_action_deny_by_default() -> dict[str, Any]:
    """Deny-by-default preset for financial / on-chain / high-value tools.

    Motivation: the 2026-04-19 Kelp DAO LayerZero bridge exploit ($292M
    stolen, ~$200M Aave bad debt) started with a cross-chain message
    forgery that reached an agent authorizing a collateral move. Any
    tool whose name implies money movement should require explicit
    opt-in.

    This preset tags a tool as "high-value" when its name matches
    ``(?i)(transfer|bridge|approve|withdraw|borrow|liquidate|swap|mint|burn)``
    and refuses to run it unless the ``@airlock`` caller passes
    ``allow_high_value=True``.

    Usage::

        from agent_airlock.policy_presets import (
            high_value_action_deny_by_default,
            HighValueActionBlocked,
        )

        cfg = high_value_action_deny_by_default()
        cfg["check"]("transfer", allow_high_value=False)   # raises
        cfg["check"]("transfer", allow_high_value=True)    # passes
        cfg["check"]("read_balance", allow_high_value=False)  # passes

    Primary sources:
      - https://www.bloomberg.com/news/articles/2026-04-19/crypto-hack-worth-290-million-triggers-defi-contagion-shock
      - https://thedefiant.io/news/defi/aave-price-crash-kelpdao-exploit-whale-dump-rxi8o9
    """
    pattern = re.compile(r"(?i)(transfer|bridge|approve|withdraw|borrow|liquidate|swap|mint|burn)")

    def is_high_value(tool_name: str) -> bool:
        return bool(pattern.search(tool_name or ""))

    def check(tool_name: str, allow_high_value: bool = False) -> None:
        if is_high_value(tool_name) and not allow_high_value:
            raise HighValueActionBlocked(
                f"tool {tool_name!r} matches the high-value pattern "
                f"({pattern.pattern!r}) and requires allow_high_value=True. "
                "Motivating incident: Kelp DAO LayerZero exploit 2026-04-19."
            )

    return {
        "check": check,
        "is_high_value": is_high_value,
        "pattern": pattern.pattern,
        "source": (
            "https://www.bloomberg.com/news/articles/2026-04-19/crypto-hack-worth-290-million-triggers-defi-contagion-shock"
        ),
    }


class HighValueActionBlocked(AirlockError):
    """Raised when a high-value action runs without explicit opt-in."""


def flowise_cve_2025_59528_defaults() -> dict[str, Any]:
    """Preset-style factory returning the Flowise-eval checker.

    Usage::

        from agent_airlock.policy_presets import flowise_cve_2025_59528_defaults

        cfg = flowise_cve_2025_59528_defaults()
        cfg["check"](my_tool_manifests)

    Primary source:
      https://labs.cloudsecurityalliance.org/research/csa-research-note-flowise-mcp-rce-exploitation-20260409-csa/
    """
    return {
        "check": flowise_cve_2025_59528_check,
        "banned_tokens": _EVAL_TOKENS,
        "source": (
            "https://labs.cloudsecurityalliance.org/research/csa-research-note-flowise-mcp-rce-exploitation-20260409-csa/"
        ),
    }


def mcp_inspector_exposure_guard_defaults(
    *,
    inspector_ports: frozenset[int] | None = None,
) -> dict[str, Any]:
    """Recommended config for the MCP Inspector exposure guard (v0.8.0+).

    CVE-2026-23744: MCPJam Inspector ≤ 1.4.2 binds to 0.0.0.0 by
    default with no auth, enabling remote install + execution of
    malicious MCP servers. This preset wires
    :class:`agent_airlock.mcp_spec.inspector_exposure_guard.InspectorExposureGuard`
    with the curated inspector port range (6274-6277). Complementary
    to v0.5.x ``bind_address_guard.py`` — that guard fires at config
    time, this one runs a runtime listener-scan on ``/proc/net/tcp``.

    Primary source:
      https://github.com/boroeurnprach/CVE-2026-23744-PoC
    """
    from .mcp_spec.inspector_exposure_guard import DEFAULT_INSPECTOR_PORTS

    return {
        "preset_id": "mcp_inspector_exposure_guard_2026_23744",
        "severity": "high",
        "default_action": "deny",
        "advisory_url": "https://github.com/boroeurnprach/CVE-2026-23744-PoC",
        "cves": ("CVE-2026-23744",),
        "inspector_ports": (
            inspector_ports if inspector_ports is not None else DEFAULT_INSPECTOR_PORTS
        ),
    }


def stdio_guard_eval_defaults_2026_05_15(
    *,
    extra_sinks: frozenset[str] = frozenset(),
    extra_vulnerable_packages: tuple[tuple[str, str], ...] = (),
) -> dict[str, Any]:
    """Recommended config for the bare-eval RCE guard (CVE-2026-44717 anchor, v0.8.0+).

    NVD 2026-05-15: MCP Calculate Server < 0.1.1 uses ``eval()`` to
    evaluate mathematical expressions without input sanitization,
    leading to RCE. Patched in 0.1.1 by pinning ``local_dict``.

    Complementary to v0.7.5 ``semantic_kernel_filter_eval_rce_2026_25592_26030_defaults``:
    that preset targets ``lambda`` / ``Expression.Lambda<>`` syntax;
    this one targets bare ``eval(`` / ``parse_expr(`` calls.

    Primary source:
      https://nvd.nist.gov/vuln/detail/CVE-2026-44717
    """
    from .mcp_spec.eval_rce_guard import DEFAULT_EVAL_SINKS, DEFAULT_VULNERABLE_PACKAGES

    return {
        "preset_id": "stdio_guard_eval_defaults_2026_05_15",
        "severity": "critical",
        "default_action": "deny",
        "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-44717",
        "cves": ("CVE-2026-44717",),
        "sinks": DEFAULT_EVAL_SINKS | extra_sinks,
        "extra_sinks": extra_sinks,
        "vulnerable_packages": DEFAULT_VULNERABLE_PACKAGES + extra_vulnerable_packages,
    }


# Default tool-name patterns for the MCP Calculate-Server class. Operators
# extend via ``extra_tool_name_patterns`` on the factory below.
_CALC_SERVER_TOOL_NAME_PATTERNS: tuple[str, ...] = (
    "calc",
    "calculate",
    "evaluate",
    "math_eval",
    "sympy_eval",
)


def mcp_calc_server_bundle_defaults_2026_05_15(
    *,
    extra_sinks: frozenset[str] = frozenset(),
    extra_metachars: frozenset[str] = frozenset(),
    extra_tool_name_patterns: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Composition preset for the MCP Calculate-Server class (CVE-2026-44717 anchor, v0.8.1+).

    Honest framing: this preset does **not** introduce a new runtime
    detector. It composes two existing guards under a single
    ``preset_id`` namespace so security teams cataloguing
    CVE-2026-44717 coverage have one row to point to:

    - v0.8.0 :class:`agent_airlock.mcp_spec.eval_rce_guard.EvalRCEGuard`
      via :func:`stdio_guard_eval_defaults_2026_05_15` — catches the
      bare-eval / parse_expr sinks.
    - v0.7.6 :class:`agent_airlock.mcp_spec.stdio_command_injection_guard.StdioCommandInjectionGuard`
      via :func:`mcp_stdio_command_injection_preset_defaults` —
      catches shell metachars in argv vectors that often arrive at
      ``calculate``-shaped tools that shell out for ``bc`` /
      ``python -c``.

    The bundle is scoped to a curated tool-name pattern set
    (``calc``, ``calculate``, ``evaluate``, ``sympy_eval``,
    ``math_eval``) — at the policy layer this scoping is how the
    two underlying guards are applied selectively to calc-server
    class tools.

    Operators wanting bare-eval detection on every tool regardless
    of name should keep using :func:`stdio_guard_eval_defaults_2026_05_15`
    directly. This preset is the per-tool-class projection of that
    surface.

    Args:
        extra_sinks: Additional eval-sink labels on top of
            :data:`agent_airlock.mcp_spec.eval_rce_guard.DEFAULT_EVAL_SINKS`.
        extra_metachars: Additional shell metachars on top of the
            v0.7.6 default block-list.
        extra_tool_name_patterns: Additional tool-name patterns on
            top of the curated calc-server class set.

    Raises:
        TypeError: if any of the override args is not the documented
            collection type.

    Primary source:
      https://nvd.nist.gov/vuln/detail/CVE-2026-44717
    """
    from .mcp_spec.eval_rce_guard import DEFAULT_EVAL_SINKS, DEFAULT_VULNERABLE_PACKAGES

    if not isinstance(extra_sinks, frozenset):
        raise TypeError(f"extra_sinks must be a frozenset[str]; got {type(extra_sinks).__name__}")
    if not isinstance(extra_metachars, frozenset):
        raise TypeError(
            f"extra_metachars must be a frozenset[str]; got {type(extra_metachars).__name__}"
        )
    if not isinstance(extra_tool_name_patterns, tuple):
        raise TypeError(
            "extra_tool_name_patterns must be a tuple of str; got "
            f"{type(extra_tool_name_patterns).__name__}"
        )

    return {
        "preset_id": "mcp_calc_server_bundle_2026_05_15",
        "severity": "critical",
        "default_action": "deny",
        "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-44717",
        "cves": ("CVE-2026-44717",),
        "tool_name_patterns": _CALC_SERVER_TOOL_NAME_PATTERNS + extra_tool_name_patterns,
        "eval_sinks": DEFAULT_EVAL_SINKS | extra_sinks,
        "vulnerable_packages": DEFAULT_VULNERABLE_PACKAGES,
        "extra_metachars": extra_metachars,
        "composes": (
            "stdio_guard_eval_defaults_2026_05_15",
            "mcp_stdio_command_injection_preset_defaults",
        ),
    }


def openapi_doc_drift_guard_defaults(
    *,
    spec: Mapping[str, Any],
    drift_mode: str = "strict",
) -> dict[str, Any]:
    """Recommended config for the v0.8.1 OpenAPI Drift Guard.

    Wires :class:`agent_airlock.mcp_spec.openapi_drift_guard.OpenAPIDriftGuard`
    to the operator-supplied OpenAPI 3.x spec at the configured
    drift mode. The Hermes paper (arXiv:2605.14312) finding maps to
    a runtime body-shape gate one layer above the v0.7.x / v0.8.0
    exploit-shape guards.

    Args:
        spec: Parsed OpenAPI document as a dict. The caller is
            responsible for loading and parsing — agent-airlock does
            not import PyYAML or any spec-loader.
        drift_mode: ``"strict"`` (default) / ``"warn"`` / ``"shadow"``.

    Raises:
        TypeError: ``spec`` is not a mapping.
        ValueError: ``drift_mode`` is unknown.

    Primary source:
      https://arxiv.org/abs/2605.14312
    """
    if not isinstance(spec, Mapping):
        raise TypeError(f"spec must be a dict-like mapping; got {type(spec).__name__}")
    if drift_mode not in ("strict", "warn", "shadow"):
        raise ValueError(f"drift_mode must be 'strict'|'warn'|'shadow'; got {drift_mode!r}")
    return {
        "preset_id": "openapi_doc_drift_guard_2026_05_17",
        "severity": "medium",
        "default_action": "deny" if drift_mode == "strict" else "allow",
        "advisory_url": "https://arxiv.org/abs/2605.14312",
        "drift_mode": drift_mode,
        "spec": dict(spec),
    }


def npm_oidc_publish_window_guard_defaults(
    *,
    blast_list: frozenset[tuple[str, str, str]] | None = None,
) -> dict[str, Any]:
    """Recommended config for the TanStack 2026-05-11 OIDC publish-window guard.

    The TanStack 2026-05-11 postmortem disclosed that an attacker
    extracted the runner's OIDC token directly from ``/proc/<pid>/maps``
    and ``/proc/<pid>/mem`` of the Runner.Worker process and used it
    to republish 42 packages × 84 versions outside the workflow's own
    publish step. Airlock's runtime surface for this class is "agent
    that fetches / runs just-mutated package versions should reject
    blast-list pairs". This preset wires
    :class:`agent_airlock.mcp_spec.oidc_publish_window_guard.OIDCPublishWindowGuard`
    with the curated 2026-05-11 blast list (TanStack postmortem + Aikido
    cross-ecosystem advisory).

    The list is a frozenset of ``(ecosystem, name, version)`` tuples.
    Operators on a non-default vocabulary can pass their own list.

    Primary sources:
      https://tanstack.com/blog/npm-supply-chain-compromise-postmortem
      https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised
    """
    from .mcp_spec.oidc_publish_window_guard import load_blast_list_from_2026_05_11

    return {
        "preset_id": "npm_oidc_publish_window_guard_2026_05_11",
        "severity": "critical",
        "default_action": "deny",
        "advisory_url": ("https://tanstack.com/blog/npm-supply-chain-compromise-postmortem"),
        "cross_ecosystem_url": (
            "https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised"
        ),
        "incident_id": "tanstack-oidc-blast-2026-05-11",
        "blast_list": (blast_list if blast_list is not None else load_blast_list_from_2026_05_11()),
    }


def mcp_stdio_command_injection_preset_defaults(
    *,
    cwd_allowlist: tuple[str, ...] = (),
    extra_metachars: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    """Recommended config for the MCP STDIO command-injection guard.

    Snyk ToxicSkills disclosed via Help Net Security 2026-05-05 that
    "1 in 4 MCP servers opens AI agent security to code execution
    risk". MCP STDIO transport accepts an argv vector that often
    arrives via the model's tool-call payload — a shell metachar in
    any element opens an injection path.

    This preset wires
    :class:`agent_airlock.mcp_spec.stdio_command_injection_guard.StdioCommandInjectionGuard`
    with a default block-list of shell metachars (``;``, ``&&``,
    ``||``, ``|``, newline, backtick, ``$(``) plus a path-traversal
    detector (``../`` outside an operator-supplied cwd allowlist).

    Primary source:
      https://www.helpnetsecurity.com/2026/05/05/ai-agent-security-skills-blind-spots/
    """
    return {
        "preset_id": "mcp_stdio_command_injection_2026_05_05",
        "severity": "critical",
        "default_action": "deny",
        "advisory_url": (
            "https://www.helpnetsecurity.com/2026/05/05/ai-agent-security-skills-blind-spots/"
        ),
        "cwd_allowlist": cwd_allowlist,
        "extra_metachars": extra_metachars,
    }


def semantic_kernel_filter_eval_rce_2026_25592_26030_defaults(
    *,
    suspect_fields: frozenset[str] | None = None,
    scan_all_fields: bool = False,
) -> dict[str, Any]:
    """Recommended config for the Semantic-Kernel-class filter-eval RCE guard (v0.7.5+).

    Microsoft's 2026-05-07 MSRC blog disclosed two CVEs in the
    Semantic Kernel filter-evaluation pipeline:

    - **CVE-2026-25592** — lambda-filter eval RCE (Python lambda
      reaches a runtime ``compile()`` / ``eval()`` sink).
    - **CVE-2026-26030** — template-expression eval RCE (C#
      ``Expression.Lambda<>`` reaches a runtime expression
      evaluator).

    The exploit class is **not Semantic-Kernel-specific** — any
    framework that compiles user-controlled filter expressions is
    vulnerable. This preset wires
    :class:`agent_airlock.mcp_spec.filter_eval_rce_guard.FilterEvalRCEGuard`
    with a default vocabulary of suspect fields. ``scan_all_fields=True``
    is the operator-defensive mode that inspects every value on the
    payload regardless of field name.

    Primary source:
      https://www.microsoft.com/en-us/security/blog/2026/05/07/prompts-become-shells-rce-vulnerabilities-ai-agent-frameworks/
    """
    from .mcp_spec.filter_eval_rce_guard import DEFAULT_SUSPECT_FIELDS

    return {
        "preset_id": "semantic_kernel_filter_eval_rce_2026_25592_26030",
        "severity": "critical",
        "default_action": "deny",
        "advisory_url": (
            "https://www.microsoft.com/en-us/security/blog/2026/05/07/"
            "prompts-become-shells-rce-vulnerabilities-ai-agent-frameworks/"
        ),
        "cves": ("CVE-2026-25592", "CVE-2026-26030"),
        "suspect_fields": (
            suspect_fields if suspect_fields is not None else DEFAULT_SUSPECT_FIELDS
        ),
        "scan_all_fields": scan_all_fields,
    }


def managed_agents_outcomes_2026_05_06_defaults(
    *,
    allowlist: frozenset[str] = frozenset(),
    provenance_field: str | None = None,
) -> dict[str, Any]:
    """Recommended config for the Managed Agents Outcomes-rubric guard (v0.7.4+).

    Anthropic's 2026-05-06 SF Code event shipped Managed Agents with
    a structured **Outcomes** rubric (beta). The rubric produces a
    verdict identifier that downstream tool calls should carry as a
    provenance anchor. This preset wires the operator-supplied
    rubric-ID allowlist into a fail-closed gate via
    :class:`agent_airlock.integrations.managed_agents_outcomes_guard.ManagedAgentsOutcomesGuard`.

    Default ``allowlist=frozenset()`` denies all calls — operators
    must explicitly enrol the rubric IDs they trust.

    Honest scope: Managed Agents and Outcomes are beta. The rubric
    ID format and the field name carrying the anchor in tool-call
    payloads may shift between today (2026-05-06 anchor) and Q3 2026
    GA. The allowlist is a frozenset of strings (no regex), and the
    field name is operator-overridable.

    Primary sources:
      https://platform.claude.com/docs/en/managed-agents/dreams
      https://code.claude.com/docs/en/routines
    """
    from .integrations.managed_agents_outcomes_guard import (
        MANAGED_AGENTS_OUTCOMES_2026_05_06_DEFAULT_FIELD,
    )

    return {
        "preset_id": "managed_agents_outcomes_2026_05_06",
        "severity": "high",
        "default_action": "deny",
        "advisory_url": "https://platform.claude.com/docs/en/managed-agents/dreams",
        "allowlist": allowlist,
        "provenance_field": (
            provenance_field
            if provenance_field is not None
            else MANAGED_AGENTS_OUTCOMES_2026_05_06_DEFAULT_FIELD
        ),
    }


GTG_1002_DEFENSE = gtg_1002_defense_policy()
MEX_GOV_2026 = mex_gov_2026_policy()
OWASP_MCP_TOP_10_2026 = owasp_mcp_top_10_2026_policy()
EU_AI_ACT_ARTICLE_15 = eu_ai_act_article_15_policy()
INDIA_DPDP_2023 = india_dpdp_2023_policy()


__all__ = [
    # Factory functions (stateless; use these for dynamic overrides)
    "gtg_1002_defense_policy",
    "mex_gov_2026_policy",
    "owasp_mcp_top_10_2026_policy",
    "eu_ai_act_article_15_policy",
    "india_dpdp_2023_policy",
    "stdio_guard_ox_defaults",
    "oauth_audit_vercel_2026_defaults",
    "azure_mcp_cve_2026_32211_defaults",
    "AZURE_MCP_CVE_2026_32211_DEFAULTS",
    "ox_mcp_supply_chain_2026_04_defaults",
    "unit42_mcp_sampling_defaults",
    "UNIT42_MCP_SAMPLING_DEFAULTS",
    "openclaw_cve_2026_41349_defaults",
    "openclaw_cve_2026_41361_ipv6_ssrf_defaults",
    "codebase_mcp_cve_2026_5023_defaults",
    "CodebaseMcpInjectionBlocked",
    "flux159_mcp_kubernetes_cve_2026_39884_defaults",
    "mcpjam_cve_2026_23744_defaults",
    "claude_managed_agents_safe_defaults",
    "archived_mcp_server_advisory_defaults",
    "ArchivedMcpServerBlocked",
    "gitpilot_mcp_cve_2026_6980_defaults",
    "GitPilotRepoPathInjection",
    "windsurf_cve_2026_30615_defaults",
    "claude_code_security_review_cnc_2026_04",
    "gemini_cli_action_cnc_2026_04",
    "copilot_agent_cnc_2026_04",
    "mcp_atlassian_cve_2026_27825",
    "lan_unauth_mcp_guard",
    "agent_commerce_default_caps",
    "offensive_cyber_model_defaults",
    "mcpwn_cve_2026_33032_defaults",
    "mcpwn_cve_2026_33032_check",
    "is_destructive_tool",
    "UnauthenticatedDestructiveToolError",
    "flowise_cve_2025_59528_defaults",
    "flowise_cve_2025_59528_check",
    "FlowiseEvalTokenError",
    "high_value_action_deny_by_default",
    "HighValueActionBlocked",
    "mcp_stdio_meta_cve_2026_04",
    "mcp_elicitation_guard_2026_04",
    "mcp_config_path_traversal_cve_2026_31402",
    "managed_agents_outcomes_2026_05_06_defaults",
    "semantic_kernel_filter_eval_rce_2026_25592_26030_defaults",
    "npm_oidc_publish_window_guard_defaults",
    "mcp_stdio_command_injection_preset_defaults",
    "stdio_guard_eval_defaults_2026_05_15",
    "mcp_inspector_exposure_guard_defaults",
    "mcp_calc_server_bundle_defaults_2026_05_15",
    "openapi_doc_drift_guard_defaults",
    "gemini_3_agent_defaults",
    "oauth_state_injection_guard",
    "gpt_5_5_spud_agent_defaults",
    "agent_capability_default_caps",
    "PresetMeta",
    "list_active",
    # Eagerly constructed defaults
    "GTG_1002_DEFENSE",
    "MEX_GOV_2026",
    "OWASP_MCP_TOP_10_2026",
    "EU_AI_ACT_ARTICLE_15",
    "INDIA_DPDP_2023",
    "STDIO_GUARD_OX_DEFAULTS",
    "OAUTH_AUDIT_VERCEL_2026_DEFAULTS",
]
