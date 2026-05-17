"""MCP Inspector exposure guard (v0.8.0+, CVE-2026-23744 runtime extension).

CVE-2026-23744 (MCPJam Inspector ≤ 1.4.2): the inspector binds to
``0.0.0.0`` by default with no auth, letting a crafted HTTP request
trigger remote install + execution of a malicious MCP server.

agent-airlock already ships ``bind_address_guard.py`` for the
**config-time** check — that fires when the operator-supplied
bind-address string is ``0.0.0.0`` / ``::``. This module adds the
complementary **runtime listener-scan**: it inspects the process's
actual LISTEN sockets via the stdlib (``/proc/net/tcp``) and fires
when the inspector port range is bound to ``0.0.0.0`` regardless of
how that bind arrived (binary path, dynamic argv, lib config).

Why stdlib-only (no psutil dep)
-------------------------------
The exposure class is a Linux-specific runtime concern (the
attacker tooling targets Docker / dev containers). Reading
``/proc/net/tcp`` is a 30-line stdlib operation; pulling in psutil
to get the same data would add a megabyte of transitive deps for
a hot-path guard.

On non-Linux platforms (macOS / Windows / BSD) the guard returns
:attr:`InspectorExposureVerdict.UNKNOWN_PLATFORM_UNSUPPORTED` and
**fails-open**. This is intentional: a CI matrix run on macOS
should not red-flag a Linux-only path. Operators on those platforms
who want a runtime check should use psutil-based scanners
explicitly.

Honest scope
------------
- Detects LISTEN sockets bound to ``0.0.0.0`` (and ``::``) on the
  inspector port range. Does NOT detect a server bound to a
  non-loopback IPv4 (e.g. ``192.168.0.5``) — the v0.5.x
  ``bind_address_guard.py`` covers that at config time.
- The auth-required bypass is keyed on
  ``MCP_INSPECTOR_REQUIRE_AUTH=1``. Other bypass shapes (e.g. an
  in-process auth-header check) are NOT introspected.

Primary source
--------------
https://github.com/boroeurnprach/CVE-2026-23744-PoC
"""

from __future__ import annotations

import enum
import os
import sys
from dataclasses import dataclass
from pathlib import Path

import structlog

logger = structlog.get_logger("agent-airlock.mcp_spec.inspector_exposure_guard")


# MCPJam inspector default port range. Operators can extend via
# ``inspector_ports``.
DEFAULT_INSPECTOR_PORTS: frozenset[int] = frozenset({6274, 6275, 6276, 6277})


_DEFAULT_PROC_NET_TCP = Path("/proc/net/tcp")
_AUTH_ENV_VAR = "MCP_INSPECTOR_REQUIRE_AUTH"
# /proc/net/tcp socket state hex: 0A = TCP_LISTEN.
_LISTEN_STATE = "0A"
_ZERO_IPV4 = "00000000"


class InspectorExposureVerdict(str, enum.Enum):
    """Stable reason codes for :class:`InspectorExposureDecision`."""

    ALLOW = "allow"
    ALLOW_AUTH_REQUIRED_DECLARED = "allow_auth_required_declared"
    DENY_UNAUTH_PUBLIC_BIND = "deny_unauth_public_bind"
    UNKNOWN_PLATFORM_UNSUPPORTED = "unknown_platform_unsupported"


@dataclass(frozen=True)
class InspectorExposureDecision:
    """Outcome of a single :meth:`InspectorExposureGuard.scan_listeners` call.

    Mirrors the v0.7.x decision family — both expose ``allowed: bool``
    for chain-friendly composition.

    Attributes:
        allowed: True iff no public-bind on an inspector port (or the
            operator declared auth required).
        verdict: Stable :class:`InspectorExposureVerdict` value.
        detail: Free-form explanation.
        matched_port: Inspector port that was found bound publicly, or
            ``None`` if no match.
        matched_address: Dotted-IPv4 representation of the matched
            bind address (typically ``0.0.0.0``), or ``None``.
    """

    allowed: bool
    verdict: InspectorExposureVerdict
    detail: str
    matched_port: int | None
    matched_address: str | None


class InspectorExposureGuard:
    """Runtime listener-scan for MCP Inspector exposure (CVE-2026-23744 class).

    Args:
        inspector_ports: Frozenset of integer port numbers to inspect.
            Defaults to :data:`DEFAULT_INSPECTOR_PORTS` (6274-6277).
            Each member must be an ``int``.

    Raises:
        TypeError: ``inspector_ports`` is not a frozenset, or any
            entry is not an int.
    """

    def __init__(
        self,
        *,
        inspector_ports: frozenset[int] = DEFAULT_INSPECTOR_PORTS,
    ) -> None:
        if not isinstance(inspector_ports, frozenset):
            raise TypeError(
                f"inspector_ports must be a frozenset[int]; got {type(inspector_ports).__name__}"
            )
        for port in inspector_ports:
            if not isinstance(port, int):
                raise TypeError(f"inspector_ports entries must be int; got {type(port).__name__}")
        self._inspector_ports = inspector_ports

    def scan_listeners(
        self,
        *,
        proc_net_tcp_path: Path | None = None,
    ) -> InspectorExposureDecision:
        """Scan the process's TCP LISTEN sockets and decide.

        Args:
            proc_net_tcp_path: Path to ``/proc/net/tcp`` (test seam).
                Defaults to ``/proc/net/tcp`` when ``None``.

        Returns:
            :class:`InspectorExposureDecision`. ``allowed=False`` maps
            to a refusal at the Airlock decorator boundary.
        """
        path = proc_net_tcp_path if proc_net_tcp_path is not None else _DEFAULT_PROC_NET_TCP

        # Non-Linux short-circuit: fail-open with a dedicated verdict.
        if not sys.platform.startswith("linux") and proc_net_tcp_path is None:
            return InspectorExposureDecision(
                allowed=True,
                verdict=InspectorExposureVerdict.UNKNOWN_PLATFORM_UNSUPPORTED,
                detail=(
                    f"runtime listener-scan needs /proc/net/tcp; "
                    f"platform {sys.platform!r} not supported"
                ),
                matched_port=None,
                matched_address=None,
            )

        if not path.exists():
            return InspectorExposureDecision(
                allowed=True,
                verdict=InspectorExposureVerdict.UNKNOWN_PLATFORM_UNSUPPORTED,
                detail=f"/proc/net/tcp not readable at {path!s}",
                matched_port=None,
                matched_address=None,
            )

        # Operator opt-out: auth-required env var declared.
        auth_declared = os.environ.get(_AUTH_ENV_VAR, "") == "1"

        try:
            content = path.read_text(encoding="utf-8")
        except OSError as exc:
            return InspectorExposureDecision(
                allowed=True,
                verdict=InspectorExposureVerdict.UNKNOWN_PLATFORM_UNSUPPORTED,
                detail=f"could not read {path!s}: {exc}",
                matched_port=None,
                matched_address=None,
            )

        match = self._find_public_inspector_bind(content)
        if match is None:
            return InspectorExposureDecision(
                allowed=True,
                verdict=InspectorExposureVerdict.ALLOW,
                detail="no inspector port bound publicly",
                matched_port=None,
                matched_address=None,
            )

        port, addr = match
        if auth_declared:
            logger.info(
                "inspector_exposure_auth_declared_bypass",
                port=port,
                address=addr,
            )
            return InspectorExposureDecision(
                allowed=True,
                verdict=InspectorExposureVerdict.ALLOW_AUTH_REQUIRED_DECLARED,
                detail=(
                    f"public bind on inspector port {port} detected, but {_AUTH_ENV_VAR}=1 declared"
                ),
                matched_port=port,
                matched_address=addr,
            )

        logger.warning(
            "inspector_exposure_unauth_public_bind",
            port=port,
            address=addr,
            cve="CVE-2026-23744",
        )
        return InspectorExposureDecision(
            allowed=False,
            verdict=InspectorExposureVerdict.DENY_UNAUTH_PUBLIC_BIND,
            detail=(
                f"MCP inspector port {port} bound on {addr} with no auth "
                f"declared (set {_AUTH_ENV_VAR}=1 to override, or bind to "
                "127.0.0.1)"
            ),
            matched_port=port,
            matched_address=addr,
        )

    def _find_public_inspector_bind(self, content: str) -> tuple[int, str] | None:
        """Parse ``/proc/net/tcp``; return ``(port, addr)`` of first match."""
        for line in content.splitlines()[1:]:  # skip header row
            parts = line.split()
            if len(parts) < 4:
                continue
            local = parts[1]
            state = parts[3]
            if state != _LISTEN_STATE:
                continue
            if ":" not in local:
                continue
            ip_hex, port_hex = local.split(":", 1)
            try:
                port = int(port_hex, 16)
            except ValueError:
                continue
            if port not in self._inspector_ports:
                continue
            # Public bind: IPv4 0.0.0.0 (hex "00000000") in /proc/net/tcp
            # column-major byte order — the all-zeros pattern is the same.
            if ip_hex == _ZERO_IPV4:
                # We return the literal address that the LISTEN socket
                # is bound to — this is a detection report, not a bind
                # call. The guard NEVER binds; B104 is a false positive
                # for a passive scanner.
                return port, "0.0.0.0"  # nosec B104 — report only, no bind
        return None


__all__ = [
    "DEFAULT_INSPECTOR_PORTS",
    "InspectorExposureDecision",
    "InspectorExposureGuard",
    "InspectorExposureVerdict",
]
