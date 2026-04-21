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
from typing import TYPE_CHECKING, Any

from .exceptions import AirlockError
from .policy import SecurityPolicy, StdioGuardConfig

if TYPE_CHECKING:
    from .capabilities import CapabilityPolicy
    from .mcp_spec.header_audit import ResponseHeaderAuditConfig
    from .mcp_spec.oauth_audit import OAuthAppAuditConfig


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
    "mcpwn_cve_2026_33032_defaults",
    "mcpwn_cve_2026_33032_check",
    "is_destructive_tool",
    "UnauthenticatedDestructiveToolError",
    "flowise_cve_2025_59528_defaults",
    "flowise_cve_2025_59528_check",
    "FlowiseEvalTokenError",
    "high_value_action_deny_by_default",
    "HighValueActionBlocked",
    # Eagerly constructed defaults
    "GTG_1002_DEFENSE",
    "MEX_GOV_2026",
    "OWASP_MCP_TOP_10_2026",
    "EU_AI_ACT_ARTICLE_15",
    "INDIA_DPDP_2023",
    "STDIO_GUARD_OX_DEFAULTS",
    "OAUTH_AUDIT_VERCEL_2026_DEFAULTS",
]
