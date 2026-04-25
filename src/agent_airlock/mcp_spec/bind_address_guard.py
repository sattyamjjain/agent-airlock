"""MCP server bind-address guard — CVE-2026-23744 MCPJam (v0.5.6+).

Motivation
----------
GHSA-232v-j27c-5pp6 / CVE-2026-23744 (CVSS 9.8) disclosed that
``MCPJam Inspector`` ≤ 1.4.2 bound to ``0.0.0.0`` by default with no
authentication, exposing an authenticated-by-the-network-only RCE
surface to anyone on the same LAN. Patched in 1.4.3.

The exploit pattern generalises beyond MCPJam: any local MCP dev
server that binds to a public address without requiring auth becomes
the same surface. This module is the runtime guard.

Two surfaces:

1. :func:`validate_bind_address` — generic guard. Refuse public binds
   (``0.0.0.0``, ``::``, ``[::]``, ``0:0:0:0:0:0:0:0``) unless the
   caller explicitly opts into ``allow_public_bind=True``. When a
   public bind IS allowed, ``auth_required=True`` must also be set.
2. :class:`BindAddressPublicError` /
   :class:`UnauthenticatedPublicBindError` — raised on policy fail.

Companion preset
``policy_presets.mcpjam_cve_2026_23744_defaults()`` composes the
guard with a deny-list of dev-mode MCP server tool names
(``mcpjam``, ``inspector``, ``dev-server``, ``studio``).

Primary source
--------------
- GHSA-232v-j27c-5pp6 / CVE-2026-23744:
  <https://github.com/advisories/GHSA-232v-j27c-5pp6>
- SentinelOne: <https://www.sentinelone.com/vulnerability-database/cve-2026-23744/>
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

import structlog

from ..exceptions import AirlockError

logger = structlog.get_logger("agent-airlock.mcp_spec.bind_address_guard")


# Public-bind aliases. ``0.0.0.0`` is "any IPv4"; ``::`` and its
# bracketed / expanded forms are "any IPv6". A handler binding to
# any of these accepts connections on every NIC the host has.
_PUBLIC_BIND_LITERALS: frozenset[str] = frozenset(
    {
        "0.0.0.0",
        "::",
        "[::]",
        "0:0:0:0:0:0:0:0",
    }
)


@dataclass
class BindAddressGuardConfig:
    """Policy applied by :func:`validate_bind_address`.

    Attributes:
        allow_public_bind: If False (default), any address that
            resolves to "all interfaces" is rejected outright.
        auth_required: When ``allow_public_bind=True``, callers must
            also assert auth is in place by passing this True. Setting
            ``allow_public_bind=True`` with ``auth_required=False``
            never validates — that combination is the CVE-2026-23744
            shape itself.
    """

    allow_public_bind: bool = False
    auth_required: bool = True


class BindAddressPublicError(AirlockError):
    """Raised when an MCP server tries to bind to ``0.0.0.0`` / ``::`` etc.

    The ``allow_public_bind`` flag must be opted into explicitly.
    """

    def __init__(self, *, addr: str) -> None:
        self.addr = addr
        super().__init__(
            f"MCP server attempted to bind to public address {addr!r} — "
            "refusing without explicit allow_public_bind=True "
            "(CVE-2026-23744 regression class)"
        )


class UnauthenticatedPublicBindError(AirlockError):
    """Raised when a public bind is allowed but auth_required=False.

    The exact CVE-2026-23744 shape — MCPJam ≤ 1.4.2 bound to
    ``0.0.0.0`` with no authentication.
    """

    def __init__(self, *, addr: str) -> None:
        self.addr = addr
        super().__init__(
            f"MCP server bound to public address {addr!r} without "
            "auth_required=True — refusing (CVE-2026-23744 exact shape)"
        )


def _is_public_bind(addr: str) -> bool:
    """Whether ``addr`` resolves to "all interfaces" on this host."""
    if not addr:
        return False
    if addr in _PUBLIC_BIND_LITERALS:
        return True
    try:
        ip = ipaddress.ip_address(addr.strip("[]"))
    except ValueError:
        return False
    return ip.is_unspecified


def validate_bind_address(addr: str, cfg: BindAddressGuardConfig) -> None:
    """Validate an MCP server bind address against the guard policy.

    Args:
        addr: The address the server is about to bind to (e.g.
            ``"127.0.0.1"``, ``"0.0.0.0"``, ``"[::]"``).
        cfg: The :class:`BindAddressGuardConfig` to enforce.

    Raises:
        BindAddressPublicError: If ``addr`` is "all interfaces" and
            ``cfg.allow_public_bind`` is False.
        UnauthenticatedPublicBindError: If ``addr`` is "all
            interfaces", ``cfg.allow_public_bind`` is True, but
            ``cfg.auth_required`` is False — the exact CVE-2026-23744
            shape.
    """
    if not _is_public_bind(addr):
        return  # loopback or specific NIC — fine
    if not cfg.allow_public_bind:
        raise BindAddressPublicError(addr=addr)
    if not cfg.auth_required:
        raise UnauthenticatedPublicBindError(addr=addr)
    logger.debug(
        "public_bind_allowed_with_auth",
        addr=addr,
    )


__all__ = [
    "BindAddressGuardConfig",
    "BindAddressPublicError",
    "UnauthenticatedPublicBindError",
    "validate_bind_address",
]
