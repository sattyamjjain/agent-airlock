"""MCP response-header audit guard (v0.5.3+).

Motivation
----------
On 2026-04-20 Microsoft disclosed **CVE-2026-32211** (CVSS 8.6) in the
reference Azure MCP server: 401 responses echoed the caller's
``Authorization`` header back in a ``WWW-Authenticate`` field, leaking
short-lived AAD tokens to any prompt-injected agent that could read
response headers. Fixed upstream in Azure MCP Server 1.4.2.

agent-airlock's ``MCPProxyGuard`` proxies responses; without this
check, a proxy sitting in front of an unpatched server would forward
the leaked token downstream — extending the blast radius, not
containing it. This module adds a response-header audit hook that
runs symmetrically with the existing request-side checks.

Usage::

    from agent_airlock.mcp_spec.header_audit import audit_response_headers
    from agent_airlock.policy_presets import azure_mcp_cve_2026_32211_defaults

    cfg = azure_mcp_cve_2026_32211_defaults()
    audit_response_headers(status=401, headers=resp.headers, cfg=cfg)
    # Raises ResponseHeaderLeakError if a bearer token shape is echoed.

References
----------
- MSRC CVE-2026-32211:
  https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32211
- NVD:
  https://nvd.nist.gov/vuln/detail/CVE-2026-32211
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import structlog

from ..exceptions import AirlockError

logger = structlog.get_logger("agent-airlock.mcp_spec.header_audit")

# Default forbidden-pattern set — bearer-token-shaped and JWT-shaped
# values that should never appear in any outbound response header.
# Seed values come verbatim from MSRC CVE-2026-32211 guidance.
DEFAULT_FORBIDDEN_PATTERNS: tuple[str, ...] = (
    r"(?i)bearer\s+[A-Za-z0-9._~+/-]{16,}=*",  # Bearer <token>
    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",  # JWT
)

# Default forbidden header NAMES per status code. 401 responses must
# not carry a WWW-Authenticate value that leaks the original bearer
# (MSRC guidance: ``Basic realm="x"`` and unadorned ``Bearer`` stanzas
# are fine — the leak is when the token itself is echoed back).
DEFAULT_FORBIDDEN_HEADER_NAMES_BY_STATUS: dict[int, frozenset[str]] = {
    401: frozenset({"www-authenticate"}),
}


@dataclass
class ResponseHeaderAuditConfig:
    """Policy applied by :func:`audit_response_headers`.

    Attributes:
        forbidden_patterns: Regex strings that MUST NOT match any
            header value. Defaults include bearer and JWT shapes.
        forbidden_header_names_by_status: Map from HTTP status to
            a set of lowercase header names that require extra
            scrutiny at that status. See MSRC CVE-2026-32211 for why
            401 responses are singled out.
        max_header_value_bytes: DoS guard. A response-header value
            larger than this is rejected regardless of content.
    """

    forbidden_patterns: tuple[str, ...] = DEFAULT_FORBIDDEN_PATTERNS
    forbidden_header_names_by_status: dict[int, frozenset[str]] = field(
        default_factory=lambda: dict(DEFAULT_FORBIDDEN_HEADER_NAMES_BY_STATUS)
    )
    max_header_value_bytes: int = 8192


class ResponseHeaderLeakError(AirlockError):
    """Raised when a response header contains a forbidden pattern or name."""

    def __init__(
        self,
        *,
        header_name: str,
        status: int,
        reason: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.header_name = header_name
        self.status = status
        self.reason = reason
        self.details = details or {}
        super().__init__(
            f"response header leak detected on status={status} header={header_name!r}: {reason}"
        )


def _compiled_patterns(cfg: ResponseHeaderAuditConfig) -> list[re.Pattern[str]]:
    """Compile the regex set on every call. Cheap; keeps the config
    dataclass trivially shareable across threads."""
    return [re.compile(p) for p in cfg.forbidden_patterns]


def audit_response_headers(
    status: int,
    headers: dict[str, str],
    cfg: ResponseHeaderAuditConfig,
) -> None:
    """Audit an MCP response header bag before it reaches the caller.

    Args:
        status: HTTP status code of the response.
        headers: Header name → value mapping. Case-insensitive lookup
            is performed internally.
        cfg: ``ResponseHeaderAuditConfig`` — typically from
            ``azure_mcp_cve_2026_32211_defaults()``.

    Raises:
        ResponseHeaderLeakError: Any rule failure. The ``header_name``
            and ``reason`` attributes identify the check that fired.
    """
    lower_headers: dict[str, str] = {k.lower(): v for k, v in headers.items()}

    # 1. Size cap (DoS guard).
    for name, value in lower_headers.items():
        if len(value.encode("utf-8", errors="replace")) > cfg.max_header_value_bytes:
            raise ResponseHeaderLeakError(
                header_name=name,
                status=status,
                reason=(f"value is {len(value)} bytes, exceeds cap {cfg.max_header_value_bytes}"),
            )

    # 2. Per-status forbidden-header-name check.
    sensitive_names = cfg.forbidden_header_names_by_status.get(status, frozenset())
    patterns = _compiled_patterns(cfg)
    for name in sensitive_names:
        found = lower_headers.get(name)
        if found is None:
            continue
        value = found
        # The header name is on the "watch list" at this status; any
        # forbidden-pattern match here is a leak.
        for pat in patterns:
            if pat.search(value):
                raise ResponseHeaderLeakError(
                    header_name=name,
                    status=status,
                    reason=(
                        f"value matched forbidden pattern "
                        f"{pat.pattern!r} at sensitive status {status}"
                    ),
                    details={"pattern": pat.pattern},
                )

    # 3. Full-sweep forbidden-pattern check on every header.
    # Catches token echoes in e.g. Set-Cookie, X-Trace-Id, or a
    # debug header added by a misconfigured proxy.
    for name, value in lower_headers.items():
        for pat in patterns:
            if pat.search(value):
                raise ResponseHeaderLeakError(
                    header_name=name,
                    status=status,
                    reason=(f"value matched forbidden pattern {pat.pattern!r}"),
                    details={"pattern": pat.pattern},
                )

    logger.debug(
        "response_headers_audited",
        status=status,
        header_count=len(headers),
    )


__all__ = [
    "DEFAULT_FORBIDDEN_HEADER_NAMES_BY_STATUS",
    "DEFAULT_FORBIDDEN_PATTERNS",
    "ResponseHeaderAuditConfig",
    "ResponseHeaderLeakError",
    "audit_response_headers",
]
