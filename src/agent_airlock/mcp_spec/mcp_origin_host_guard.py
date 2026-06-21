"""MCP Origin/Host DNS-rebinding guard (v0.8.30+, CVE-2026-11624 anchor).

CVE-2026-11624 (Google MCP Toolbox for Databases < 0.25.0, CWE-346 Origin
Validation Error, CVSS 9.4): the MCP server exposed an HTTP/SSE transport that
**did not validate the ``Origin`` (or ``Host``) header** of incoming requests.
A browser the developer visits can therefore script MCP tool calls at the
local server (DNS-rebinding: the attacker page's name resolves to
``127.0.0.1``), reaching file reads, command execution, and database access
through whatever tools the server exposes. Fixed in 0.25.0 by introducing an
``--allowed-hosts`` flag alongside the existing ``--allowed-origins`` — and by
**warning when either is left at the ``*`` wildcard**, which disables the
protection. The MCP specification likewise directs servers to "validate the
``Origin`` header on all incoming connections to prevent DNS rebinding
attacks."

This guard is the reusable primitive for any MCP server on an HTTP / SSE /
streamable-HTTP transport (it does not apply to stdio, which has no Origin).
It validates the inbound ``Origin`` **and** ``Host`` headers against explicit
allow-lists, deny-by-default:

- ``Host`` is always present on HTTP/1.1 and always checked. With an explicit
  ``allowed_hosts`` it must match; with none configured it must be a loopback
  host (``localhost`` / ``127.0.0.0/8`` / ``::1``) — anything else is a
  rebinding target and is refused.
- ``Origin`` is checked when present (a browser always sends it; the rebinding
  request therefore carries one). With an explicit ``allowed_origins`` it must
  match; with none configured it must be a loopback origin. A request with no
  ``Origin`` (a non-browser MCP client) is judged on ``Host`` alone.

Wildcard / unset = warn (mirrors the upstream fix)
--------------------------------------------------
Setting ``allowed_origins`` or ``allowed_hosts`` to ``["*"]`` allows everything
and **disables** DNS-rebinding protection; leaving it unset falls back to
loopback-only. Either way the guard records a startup warning (on
``startup_warnings`` and via the logger) so the weakened posture is visible at
boot, exactly as Toolbox 0.25.0 warns on ``*``.

Why structural (no server)
--------------------------
The guard never opens a socket — it inspects a header mapping and returns a
decision. It carries no listening surface of its own.

Primary sources (retrieved 2026-06-21):
  https://nvd.nist.gov/vuln/detail/CVE-2026-11624
  https://github.com/googleapis/mcp-toolbox/issues/3113
  https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
"""

from __future__ import annotations

import enum
import ipaddress
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import structlog

from ..exceptions import AirlockError

logger = structlog.get_logger("agent-airlock.mcp_spec.mcp_origin_host_guard")

_WILDCARD = "*"


class McpOriginHostVerdict(str, enum.Enum):
    """Stable reason codes for :class:`McpOriginHostDecision`."""

    ALLOW = "allow"
    ALLOW_LOOPBACK = "allow_loopback"
    ALLOW_ALLOWLISTED = "allow_allowlisted"
    ALLOW_WILDCARD = "allow_wildcard"
    DENY_FORBIDDEN_ORIGIN = "deny_forbidden_origin"
    DENY_FORBIDDEN_HOST = "deny_forbidden_host"


@dataclass(frozen=True)
class McpOriginHostDecision:
    """Outcome of a single :meth:`McpOriginHostGuard.check_headers` call.

    Mirrors the v0.7.x / v0.8.x guard decision family — exposes
    ``allowed: bool`` so integrators can chain on one short-circuit predicate.

    Attributes:
        allowed: True iff the request's Origin/Host are trusted. False =
            fail-closed (a likely DNS-rebinding request).
        verdict: A stable :class:`McpOriginHostVerdict` value.
        detail: Free-form human-readable explanation.
        matched_origin: The inbound ``Origin`` evaluated, or ``None``.
        matched_host: The inbound ``Host`` evaluated, or ``None``.
        fix_hints: Operator-actionable remediation hints.
    """

    allowed: bool
    verdict: McpOriginHostVerdict
    detail: str
    matched_origin: str | None = None
    matched_host: str | None = None
    fix_hints: list[str] = field(default_factory=list)


class McpOriginHostRebindingError(AirlockError):
    """Raised on a refused MCP request (likely DNS rebinding; fail-closed).

    Carries the :class:`McpOriginHostDecision` and exposes ``fix_hints`` so an
    upstream airlock layer can surface the refusal.

    Attributes:
        decision: The decision that triggered the refusal.
        fix_hints: Operator-actionable remediation hints.
    """

    def __init__(self, decision: McpOriginHostDecision) -> None:
        self.decision = decision
        self.fix_hints = decision.fix_hints
        super().__init__(decision.detail)


def _strip_port(host: str) -> str:
    """Return the bare host from a ``host[:port]`` / ``[ipv6]:port`` value."""
    h = host.strip()
    if h.startswith("["):  # bracketed IPv6, optionally with :port
        end = h.find("]")
        return h[1:end] if end != -1 else h.strip("[]")
    # IPv4 / name with optional :port (a bare IPv6 has multiple ':' and no port)
    if h.count(":") == 1:
        return h.rsplit(":", 1)[0]
    return h


def _is_loopback_host(host: str) -> bool:
    """Whether ``host`` (a Host-header value, port allowed) is loopback."""
    bare = _strip_port(host).lower()
    if bare in {"localhost", "ip6-localhost"}:
        return True
    try:
        return ipaddress.ip_address(bare).is_loopback
    except ValueError:
        return False


def _origin_host(origin: str) -> str | None:
    """Extract the host of an ``Origin`` (``scheme://host[:port]``)."""
    parts = urlsplit(origin.strip())
    return parts.hostname


def _normalize(value: str) -> str:
    """Case-insensitive, trailing-slash-insensitive normalization."""
    return value.strip().rstrip("/").lower()


class McpOriginHostGuard:
    """Deny-by-default Origin/Host gate for MCP HTTP/SSE transports (CVE-2026-11624).

    Args:
        allowed_origins: Trusted request ``Origin`` values
            (``scheme://host[:port]``). ``["*"]`` allows all (with a startup
            warning); empty / None falls back to loopback-only.
        allowed_hosts: Trusted request ``Host`` values (``host`` or
            ``host:port``). ``["*"]`` allows all (with a startup warning);
            empty / None falls back to loopback-only.
        advisory: Advisory / CVE id surfaced in deny ``fix_hints``.
        advisory_url: Optional primary-source URL surfaced alongside.

    Raises:
        TypeError: ``allowed_origins`` / ``allowed_hosts`` is a bare ``str``.
    """

    def __init__(
        self,
        *,
        allowed_origins: Iterable[str] | None = None,
        allowed_hosts: Iterable[str] | None = None,
        advisory: str | None = "CVE-2026-11624",
        advisory_url: str | None = None,
    ) -> None:
        if isinstance(allowed_origins, str):
            raise TypeError(
                f"allowed_origins must be an iterable of str, not a bare str: {allowed_origins!r}"
            )
        if isinstance(allowed_hosts, str):
            raise TypeError(
                f"allowed_hosts must be an iterable of str, not a bare str: {allowed_hosts!r}"
            )
        origins = list(allowed_origins or ())
        hosts = list(allowed_hosts or ())
        self._origin_wildcard = _WILDCARD in origins
        self._host_wildcard = _WILDCARD in hosts
        self._allowed_origins: frozenset[str] = frozenset(
            _normalize(o) for o in origins if o != _WILDCARD
        )
        self._allowed_hosts: frozenset[str] = frozenset(
            _normalize(h) for h in hosts if h != _WILDCARD
        )
        self._advisory = advisory
        self._advisory_url = advisory_url

        # Mirror the upstream fix: warn at startup when the protection is
        # disabled (``*``) or left unset (loopback-only fallback).
        self.startup_warnings: list[str] = []
        self._warn_posture("origins", origins, self._origin_wildcard)
        self._warn_posture("hosts", hosts, self._host_wildcard)

    def _warn_posture(self, which: str, configured: list[str], wildcard: bool) -> None:
        explicit = [c for c in configured if c != _WILDCARD]
        if wildcard:
            msg = (
                f"allowed_{which} contains '*': DNS-rebinding protection is "
                f"DISABLED for MCP {which} — any browser origin can reach this "
                "server (CVE-2026-11624)"
            )
        elif not explicit:
            msg = (
                f"no allowed_{which} configured: denying non-loopback {which} "
                f"by default; set allowed_{which} for a remote MCP transport "
                "(CVE-2026-11624)"
            )
        else:
            return
        self.startup_warnings.append(msg)
        logger.warning("mcp_origin_host_startup_posture", which=which, advisory=self._advisory)

    @property
    def origin_wildcard(self) -> bool:
        """Whether ``allowed_origins`` was set to ``*`` (protection disabled)."""
        return self._origin_wildcard

    @property
    def host_wildcard(self) -> bool:
        """Whether ``allowed_hosts`` was set to ``*`` (protection disabled)."""
        return self._host_wildcard

    def check_headers(self, headers: Mapping[str, str]) -> McpOriginHostDecision:
        """Validate an inbound request's ``Origin`` and ``Host`` headers.

        Args:
            headers: The request headers (case-insensitive lookup).

        Returns:
            :class:`McpOriginHostDecision`. ``allowed=False`` maps to a refusal
            of the request at the transport boundary.
        """
        origin = _header(headers, "origin")
        host = _header(headers, "host")

        # Host is always present on HTTP/1.1; validate it first.
        host_decision = self._check_host(host, origin)
        if not host_decision.allowed:
            return host_decision

        # Origin is validated only when the client sent one (browsers always
        # do; the rebinding request therefore carries one).
        if origin is not None and origin.strip():
            return self._check_origin(origin, host)

        return McpOriginHostDecision(
            allowed=True,
            verdict=host_decision.verdict,
            detail=host_decision.detail,
            matched_origin=None,
            matched_host=host,
        )

    def validate(self, headers: Mapping[str, str]) -> None:
        """Raise :class:`McpOriginHostRebindingError` on a refused request."""
        decision = self.check_headers(headers)
        if not decision.allowed:
            raise McpOriginHostRebindingError(decision)

    # -- internals --------------------------------------------------------

    def _check_host(self, host: str | None, origin: str | None) -> McpOriginHostDecision:
        if self._host_wildcard:
            return self._allow(
                McpOriginHostVerdict.ALLOW_WILDCARD, "allowed_hosts='*'", origin, host
            )
        if host is None or not host.strip():
            # No Host header at all — only legitimate for non-HTTP transports;
            # on an HTTP transport this is anomalous. Fail closed.
            return self._deny_host("<missing>", origin)
        if self._allowed_hosts:
            if _normalize(host) in self._allowed_hosts or _strip_port(host).lower() in (
                self._allowed_hosts
            ):
                return self._allow(
                    McpOriginHostVerdict.ALLOW_ALLOWLISTED, "host allow-listed", origin, host
                )
            return self._deny_host(host, origin)
        # No allow-list: loopback-only.
        if _is_loopback_host(host):
            return self._allow(McpOriginHostVerdict.ALLOW_LOOPBACK, "loopback host", origin, host)
        return self._deny_host(host, origin)

    def _check_origin(self, origin: str, host: str | None) -> McpOriginHostDecision:
        if self._origin_wildcard:
            return self._allow(
                McpOriginHostVerdict.ALLOW_WILDCARD, "allowed_origins='*'", origin, host
            )
        norm = _normalize(origin)
        if self._allowed_origins:
            if norm in self._allowed_origins:
                return self._allow(
                    McpOriginHostVerdict.ALLOW_ALLOWLISTED, "origin allow-listed", origin, host
                )
            return self._deny_origin(origin, host)
        # No allow-list: loopback-only.
        oh = _origin_host(origin)
        if oh is not None and _is_loopback_host(oh):
            return self._allow(McpOriginHostVerdict.ALLOW_LOOPBACK, "loopback origin", origin, host)
        return self._deny_origin(origin, host)

    def _allow(
        self,
        verdict: McpOriginHostVerdict,
        why: str,
        origin: str | None,
        host: str | None,
    ) -> McpOriginHostDecision:
        return McpOriginHostDecision(
            allowed=True,
            verdict=verdict,
            detail=f"MCP request accepted ({why})",
            matched_origin=origin,
            matched_host=host,
        )

    def _deny_host(self, host: str, origin: str | None) -> McpOriginHostDecision:
        logger.warning("mcp_host_rebinding_blocked", host=host, advisory=self._advisory)
        return McpOriginHostDecision(
            allowed=False,
            verdict=McpOriginHostVerdict.DENY_FORBIDDEN_HOST,
            detail=(
                f"inbound Host {host!r} is not allow-listed and is not loopback "
                "— refusing as a likely DNS-rebinding request"
            ),
            matched_origin=origin,
            matched_host=host,
            fix_hints=self._hints(
                f"Host {host!r} is not trusted. Add it to allowed_hosts if this "
                "is a legitimate MCP endpoint; otherwise this is a rebinding "
                "attempt and the refusal is correct.",
            ),
        )

    def _deny_origin(self, origin: str, host: str | None) -> McpOriginHostDecision:
        logger.warning("mcp_origin_rebinding_blocked", origin=origin, advisory=self._advisory)
        return McpOriginHostDecision(
            allowed=False,
            verdict=McpOriginHostVerdict.DENY_FORBIDDEN_ORIGIN,
            detail=(
                f"inbound Origin {origin!r} is not allow-listed and is not "
                "loopback — refusing as a likely DNS-rebinding request"
            ),
            matched_origin=origin,
            matched_host=host,
            fix_hints=self._hints(
                f"Origin {origin!r} is not trusted. Add it to allowed_origins "
                "only if it is a known MCP client UI; otherwise this is a "
                "cross-origin rebinding attempt and the refusal is correct.",
            ),
        )

    def _hints(self, *extra: str) -> list[str]:
        prefix = f"({self._advisory}) " if self._advisory else ""
        hints = [f"{prefix}{extra[0]}", *extra[1:]] if extra else []
        if self._advisory_url:
            hints.append(f"See: {self._advisory_url}")
        return hints


def _header(headers: Mapping[str, str], name: str) -> str | None:
    """Case-insensitive header lookup."""
    for key, value in headers.items():
        if isinstance(key, str) and key.lower() == name:
            return value
    return None


__all__ = [
    "McpOriginHostDecision",
    "McpOriginHostGuard",
    "McpOriginHostRebindingError",
    "McpOriginHostVerdict",
]
