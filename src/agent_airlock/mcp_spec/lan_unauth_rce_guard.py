"""LAN-bound unauthenticated MCP-server guard (v0.5.8+).

Motivation
----------
[The Hacker News (2026-04-24)](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html)
documented [CVE-2026-27825 / -27826](https://nvd.nist.gov/vuln/detail/CVE-2026-27825)
in ``mcp-atlassian`` — a flagship MCP server that bound to RFC1918
interfaces with no authentication, granting same-LAN unauth RCE.
CVSS 9.1 / 8.2.

The class generalises: any MCP server that registers without an
auth header and binds to anything other than strict loopback is a
trust-boundary failure waiting to happen on a normal office network.

This guard reads an MCP server registration spec, checks both the
bind address (via the existing v0.5.6 ``bind_address_guard``) AND
the presence of an auth header, and refuses to register the server
if both fail.

Three modes via :attr:`LANUnauthRCEPolicy.profile`:

- ``"prod"`` (default) — refuse any LAN-bound server without auth
- ``"dev"`` — log a warning instead of rejecting
- ``"strict"`` — refuse loopback-bound too unless auth is present

Primary sources
---------------
- The Hacker News (2026-04-24): https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html
- NVD CVE-2026-27825: https://nvd.nist.gov/vuln/detail/CVE-2026-27825
- NVD CVE-2026-27826: https://nvd.nist.gov/vuln/detail/CVE-2026-27826
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any, Literal

import structlog

from ..exceptions import AirlockError

logger = structlog.get_logger("agent-airlock.mcp_spec.lan_unauth_rce_guard")


Profile = Literal["prod", "dev", "strict"]


# Headers the guard will accept as evidence of authentication. An
# empty / missing value still counts as "no auth" — only a non-empty
# string passes.
_AUTH_HEADER_NAMES: frozenset[str] = frozenset(
    {
        "authorization",
        "x-api-key",
        "x-mcp-token",
        "x-auth-token",
        "x-airlock-key",
    }
)


# -----------------------------------------------------------------------------
# Errors
# -----------------------------------------------------------------------------


class LANUnauthMCPServerBlocked(AirlockError):
    """Raised when a LAN-bound MCP server registers without auth."""

    def __init__(
        self,
        *,
        server_name: str,
        bind_address: str,
        reason: str,
    ) -> None:
        self.server_name = server_name
        self.bind_address = bind_address
        self.reason = reason
        super().__init__(
            f"MCP server {server_name!r} bound to {bind_address!r} refused: "
            f"{reason} (CVE-2026-27825 class)"
        )


# -----------------------------------------------------------------------------
# Policy + verdict
# -----------------------------------------------------------------------------


@dataclass
class LANUnauthRCEPolicy:
    """Policy applied by :class:`LANUnauthRCEGuard`.

    Attributes:
        profile: ``"prod"`` (refuse LAN+no-auth), ``"dev"`` (warn
            only), or ``"strict"`` (refuse anything without auth).
        accepted_auth_headers: Header names the guard accepts as
            authentication evidence. Default covers the five
            canonical names; extend for custom auth schemes.
    """

    profile: Profile = "prod"
    accepted_auth_headers: frozenset[str] = field(default_factory=lambda: _AUTH_HEADER_NAMES)


@dataclass(frozen=True)
class Verdict:
    """The guard's decision on one server registration."""

    action: Literal["allow", "warn", "block"]
    reason: str
    bind_address: str
    has_auth: bool


# -----------------------------------------------------------------------------
# The guard
# -----------------------------------------------------------------------------


def _is_lan_bound(addr: str) -> bool:
    """Whether the address is a LAN / link-local / loopback / public-bind."""
    if not addr:
        return False
    addr_clean = addr.strip("[]")
    # Public-bind shapes from v0.5.6 bind_address_guard
    if addr_clean in {"0.0.0.0", "::", "0:0:0:0:0:0:0:0"}:
        return True
    try:
        ip = ipaddress.ip_address(addr_clean)
    except ValueError:
        # Non-loopback hostnames are treated as LAN-bound for this
        # guard's purposes — same threat model.
        return addr.lower() not in {"localhost"}
    if ip.is_unspecified:
        return True
    if ip.is_loopback:
        return False  # loopback is OK in default profile
    # Private (RFC1918), link-local, ULA — all LAN.
    return ip.is_private or ip.is_link_local


def _has_auth_header(
    headers: dict[str, str] | None,
    accepted: frozenset[str],
) -> bool:
    if not headers:
        return False
    for name, value in headers.items():
        if not isinstance(value, str) or not value.strip():
            continue
        if name.lower() in accepted:
            return True
    return False


@dataclass
class LANUnauthRCEGuard:
    """Inspect MCP server registration specs.

    Usage::

        guard = LANUnauthRCEGuard(LANUnauthRCEPolicy(profile="prod"))
        verdict = guard.inspect_server({
            "name": "my-mcp",
            "bind_address": "0.0.0.0",
            "auth_headers": {},
        })
        if verdict.action == "block":
            raise SystemExit(verdict.reason)
    """

    policy: LANUnauthRCEPolicy = field(default_factory=LANUnauthRCEPolicy)

    def inspect_server(self, spec: dict[str, Any]) -> Verdict:
        """Apply the policy to a single server registration."""
        name = str(spec.get("name", "<unnamed>"))
        bind = str(spec.get("bind_address", ""))
        headers = spec.get("auth_headers") or {}
        if not isinstance(headers, dict):
            headers = {}

        is_lan = _is_lan_bound(bind)
        has_auth = _has_auth_header(headers, self.policy.accepted_auth_headers)

        # strict: every server must carry auth, period.
        if self.policy.profile == "strict" and not has_auth:
            return Verdict(
                action="block",
                reason=(
                    "strict profile: every server must carry an auth "
                    "header, including loopback binds"
                ),
                bind_address=bind,
                has_auth=False,
            )

        if is_lan and not has_auth:
            if self.policy.profile == "dev":
                logger.warning(
                    "lan_unauth_mcp_server_warn",
                    name=name,
                    bind_address=bind,
                )
                return Verdict(
                    action="warn",
                    reason=(
                        "dev profile: LAN-bound server with no auth header (would block in prod)"
                    ),
                    bind_address=bind,
                    has_auth=False,
                )
            return Verdict(
                action="block",
                reason=(
                    f"LAN-bound {bind!r} with no auth header — refusing (same-LAN unauth RCE class)"
                ),
                bind_address=bind,
                has_auth=False,
            )

        return Verdict(
            action="allow",
            reason="loopback-bound or auth-protected — passes the guard",
            bind_address=bind,
            has_auth=has_auth,
        )

    def inspect_or_raise(self, spec: dict[str, Any]) -> Verdict:
        """Like :meth:`inspect_server` but raise on ``block``."""
        verdict = self.inspect_server(spec)
        if verdict.action == "block":
            raise LANUnauthMCPServerBlocked(
                server_name=str(spec.get("name", "<unnamed>")),
                bind_address=verdict.bind_address,
                reason=verdict.reason,
            )
        return verdict


__all__ = [
    "LANUnauthMCPServerBlocked",
    "LANUnauthRCEGuard",
    "LANUnauthRCEPolicy",
    "Profile",
    "Verdict",
]
