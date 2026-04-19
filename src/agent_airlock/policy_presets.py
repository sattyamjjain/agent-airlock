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
from typing import TYPE_CHECKING

from .policy import SecurityPolicy, StdioGuardConfig

if TYPE_CHECKING:
    from .capabilities import CapabilityPolicy


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
    # Eagerly constructed defaults
    "GTG_1002_DEFENSE",
    "MEX_GOV_2026",
    "OWASP_MCP_TOP_10_2026",
    "EU_AI_ACT_ARTICLE_15",
    "INDIA_DPDP_2023",
    "STDIO_GUARD_OX_DEFAULTS",
]
