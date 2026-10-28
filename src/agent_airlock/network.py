"""Network egress control module for Agent-Airlock.

Provides runtime network blocking to prevent data exfiltration during tool execution.
Uses socket monkeypatching, with the active policies held in a ContextVar so each call
is checked against its own.

SECURITY: This module is critical for preventing Moltbook-style attacks where
malicious tool calls attempt to exfiltrate data to external servers.

WHAT IS CHECKED:
    While an airgap is open, ``socket.socket.connect`` / ``connect_ex`` / ``sendto`` /
    ``sendmsg`` (the address), ``socket.getaddrinfo`` / ``gethostbyname`` /
    ``gethostbyname_ex`` / ``gethostbyaddr`` / ``getnameinfo`` (the name looked up), and
    asyncio's ``loop.getaddrinfo`` / ``loop.getnameinfo`` are checked against it. Until
    0.10.28 only ``connect``, ``connect_ex`` and ``getaddrinfo`` were: a UDP datagram, or
    a lookup through ``gethostbyname`` and the like, went out under ``NO_NETWORK_POLICY``.

CONTEXT SAFETY:
    1. Policy storage: the open airgaps live in a ContextVar (``_active_airgaps``), so
       each thread and each asyncio task sees only the airgaps entered in its own
       context. Until 0.10.28 they lived in a ``threading.local``: two airgapped tools
       interleaved on one event loop thread could leave each other without the airgap
       (egress allowed), and while one awaited inside its airgap, the host's own
       coroutines were refused.

    2. Nested airgaps intersect: a call is admitted only when every open airgap admits
       it, so an inner policy can never widen an outer one.

    3. Socket patching: ``_patch_lock`` protects the global monkeypatch; reference
       counting uninstalls it only when the last airgap in the process closes. The
       patched functions themselves run without the lock.

LIMITS:
    The airgap follows the call's context. Code the tool runs itself, asyncio tasks it
    creates and ``asyncio.to_thread`` (which copies the context) are airgapped. A thread
    it starts with ``threading.Thread``, a ``ThreadPoolExecutor`` or
    ``loop.run_in_executor`` starts without the call's context, so its socket calls are
    not airgapped (unless the interpreter copies the context into new threads,
    ``sys.flags.thread_inherit_context``). A subprocess the tool starts, a socket made
    from the ``_socket`` module directly, and an event loop that does its own socket I/O
    (uvloop, which connects and resolves through libuv) are not covered either. A task
    or thread the tool leaves running keeps the call's policy in its context, but it is
    enforced only while some airgap is open in the process: the patch is removed when the
    last one closes.
"""

from __future__ import annotations

import asyncio.base_events
import contextlib
import ipaddress
import re
import socket
import threading
from collections.abc import Generator, Iterable
from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from typing import Any, NoReturn

from ._log import structlog

logger = structlog.get_logger("agent-airlock.network")


class NetworkBlockedError(Exception):
    """Raised when a network operation is blocked by policy."""

    def __init__(
        self,
        message: str,
        operation: str,
        target: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.message = message
        self.operation = operation
        self.target = target
        self.details = details or {}
        super().__init__(message)


@dataclass
class NetworkPolicy:
    """Security policy for network egress control.

    Example:
        # Block all egress
        policy = NetworkPolicy(allow_egress=False)

        # Allow specific hosts only
        policy = NetworkPolicy(
            allow_egress=True,
            allowed_hosts=["api.company.com", "internal.service"],
            allowed_ports=[443, 8080],
        )

    Attributes:
        allow_egress: If False, block all outbound network connections.
                     SECURITY: Set False to completely airgap tool execution.
        allowed_hosts: List of allowed hostnames/IPs. Only applies if allow_egress=True.
                      Empty list means all hosts allowed.
        allowed_ports: List of allowed ports. Only applies if allow_egress=True.
                      Empty list means all ports allowed.
        block_dns: If True, also block DNS lookups. Prevents DNS-based exfiltration.
    """

    allow_egress: bool = True
    allowed_hosts: list[str] = field(default_factory=list)
    allowed_ports: list[int] = field(default_factory=list)
    block_dns: bool = False


@dataclass
class EndpointPolicy:
    """Per-tool URL endpoint allowlist.

    Prevents SSRF attacks like CVE-2026-26118 by restricting which
    URLs a tool can access based on hostname and pattern matching.

    Example:
        policy = EndpointPolicy(
            allowed_endpoints=["management.azure.com", "*.blob.core.windows.net"],
            blocked_patterns=["169.254.169.254", "localhost"],
        )
        validate_endpoint("https://management.azure.com/resource", policy)  # OK
        validate_endpoint("http://169.254.169.254/meta", policy)  # Raises

    Attributes:
        allowed_endpoints: Hostnames/patterns allowed. Supports wildcards (*.example.com).
            Empty list means no endpoint restriction (only blocked_patterns apply).
        blocked_patterns: Hostname patterns to always block. Checked before allowed_endpoints.
        allow_private_ips: If False (default), block private/loopback/link-local IPs.
        allow_metadata_urls: If False (default), block cloud metadata endpoints.
    """

    allowed_endpoints: list[str] = field(default_factory=list)
    blocked_patterns: list[str] = field(default_factory=list)
    allow_private_ips: bool = False
    allow_metadata_urls: bool = False


# Cloud metadata IPs/hosts to block
_METADATA_HOSTS = frozenset(
    {
        "169.254.169.254",
        "fd00:ec2::254",
        "metadata.google.internal",
        "169.254.169.253",
    }
)


def _matches_endpoint_pattern(hostname: str, pattern: str) -> bool:
    """Check if a hostname matches an endpoint pattern.

    Supports exact match and wildcard subdomains (*.example.com).
    """
    if pattern == hostname:
        return True
    if pattern.startswith("*.") and hostname.endswith(pattern[1:]):
        return True
    return False


def _is_private_ip(hostname: str) -> bool:
    """Check if a hostname is a private/loopback/link-local IP.

    v0.5.5: Also flags the comprehensive IPv6 range set from
    :func:`is_blocked_ipv6_range` (CVE-2026-41361), so callers that
    route through ``_is_private_ip`` automatically pick up IPv4-mapped,
    NAT64, 6to4, and documentation ranges that ``ipaddress.is_private``
    does not flag.
    """
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        return False
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return True
    if isinstance(ip, ipaddress.IPv6Address) and is_blocked_ipv6_range(hostname):
        return True
    return False


# -----------------------------------------------------------------------------
# CVE-2026-41361 — OpenClaw IPv6 SSRF guard bypass (v0.5.5+)
# -----------------------------------------------------------------------------
#
# Palo Alto / redpacketsecurity disclosed 2026-04-23: OpenClaw's IPv6
# allow-list only covered ``::/128``, ``::1/128``, ``fe80::/10``, and
# ``fc00::/7``, leaving IPv4-mapped (``::ffff:0:0/96``), NAT64
# (``64:ff9b::/96``), 6to4 (``2002::/16``), and the documentation-only
# range (``2001:db8::/32``) routable. Attackers abused
# ``::ffff:169.254.169.254`` to hit AWS IMDS through a server that
# thought its IPv6 allow-list was exhaustive. CVSS 7.1.
#
# Primary source:
#   https://www.redpacketsecurity.com/cve-alert-cve-2026-41361-openclaw-openclaw/

_BLOCKED_IPV6_NETWORKS: tuple[tuple[str, str], ...] = (
    ("::/128", "unspecified / all-zeros"),
    ("::1/128", "IPv6 loopback"),
    ("fe80::/10", "IPv6 link-local"),
    ("fc00::/7", "IPv6 unique-local (ULA)"),
    ("2001:db8::/32", "IPv6 documentation range (must not be routable)"),
    ("::ffff:0:0/96", "IPv4-mapped IPv6 (hides an IPv4 address)"),
    ("64:ff9b::/96", "IPv6 NAT64 (wraps arbitrary IPv4)"),
    ("2002::/16", "IPv6 6to4 (wraps arbitrary IPv4)"),
)

_BLOCKED_IPV6_NETS: list[tuple[ipaddress.IPv6Network, str]] = [
    (ipaddress.IPv6Network(net, strict=False), reason) for net, reason in _BLOCKED_IPV6_NETWORKS
]


def is_blocked_ipv6_range(addr: str) -> bool:
    """Whether ``addr`` falls inside one of the eight blocked IPv6 ranges.

    Covers CVE-2026-41361 (OpenClaw IPv6 SSRF guard bypass, CVSS 7.1,
    disclosed 2026-04-23). Returns ``False`` for:
      - IPv4 addresses (use :func:`_is_private_ip` for those)
      - unparseable strings
      - public-routable IPv6 addresses

    Args:
        addr: IPv6 address in string form.

    Returns:
        True if ``addr`` is inside any of the eight blocked ranges,
        otherwise False.
    """
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    if not isinstance(ip, ipaddress.IPv6Address):
        return False
    return any(ip in net for net, _reason in _BLOCKED_IPV6_NETS)


_AUTHORITY_DIFFERENTIAL = re.compile(r"[\\\t\n\r]")


def authority_has_differential(url: str) -> bool:
    """Whether the URL's authority holds a character that WHATWG URL parsers and
    ``urllib.parse`` read differently, so the host resolves one way here and another in
    a browser / HTTP client — a parser-differential SSRF.

    A backslash (WHATWG treats ``\\`` as ``/``, ending the authority early, so
    ``http://127.0.0.1\\@allowed/`` is host ``allowed`` to ``urlparse`` but ``127.0.0.1``
    to a browser) or a raw tab / newline / carriage return (WHATWG strips them from the
    authority) is refused. A well-formed authority contains none of these, so this never
    rejects a legitimate target. Adaptive red-team wave 1 (v0.10.25).
    """
    if "://" in url:
        after = url.split("://", 1)[1]
    elif url.startswith("//"):
        after = url[2:]
    else:
        after = url
    authority = re.split(r"[/?#]", after, maxsplit=1)[0]
    return _AUTHORITY_DIFFERENTIAL.search(authority) is not None


def validate_endpoint(url: str, policy: EndpointPolicy) -> None:
    """Validate a URL against an endpoint policy.

    Checks in order:
    1. Parse URL and extract hostname
    2. Check blocked patterns
    3. Check metadata URL blocking
    4. Check private IP blocking
    5. Check allowed endpoints (if specified)

    Args:
        url: The URL to validate.
        policy: The endpoint policy to enforce.

    Raises:
        NetworkBlockedError: If the URL is blocked by the policy.

    Example:
        policy = EndpointPolicy(
            allowed_endpoints=["api.example.com"],
            blocked_patterns=["evil.com"],
        )
        validate_endpoint("https://api.example.com/data", policy)  # OK
        validate_endpoint("https://evil.com/steal", policy)  # Raises
    """
    from urllib.parse import urlparse

    try:
        parsed = urlparse(url)
    except Exception as e:
        raise NetworkBlockedError(
            f"Invalid URL: {e}",
            operation="endpoint_validation",
            target=url,
            details={"reason": "parse_error"},
        ) from e

    hostname = parsed.hostname
    if not hostname:
        raise NetworkBlockedError(
            "URL must have a hostname",
            operation="endpoint_validation",
            target=url,
            details={"reason": "missing_hostname"},
        )

    # A backslash or control character in the authority means urlparse and a WHATWG
    # client disagree on the host (e.g. ``http://127.0.0.1\@allowed/`` is ``allowed``
    # here, ``127.0.0.1`` in a browser). Refuse before the allowlist, so the differential
    # cannot smuggle an allowlisted host past a loopback/metadata target.
    if authority_has_differential(url):
        logger.warning(
            "endpoint_blocked",
            url=url,
            hostname=hostname,
            reason="malformed_authority",
        )
        raise NetworkBlockedError(
            "URL authority contains a backslash or control character; use a well-formed URL",
            operation="endpoint_validation",
            target=url,
            details={"reason": "malformed_authority", "hostname": hostname},
        )

    # Check blocked patterns first
    for pattern in policy.blocked_patterns:
        if _matches_endpoint_pattern(hostname, pattern):
            logger.warning(
                "endpoint_blocked",
                url=url,
                hostname=hostname,
                pattern=pattern,
                reason="blocked_pattern",
            )
            raise NetworkBlockedError(
                f"URL blocked by pattern '{pattern}': {hostname}",
                operation="endpoint_validation",
                target=url,
                details={
                    "reason": "blocked_pattern",
                    "hostname": hostname,
                    "pattern": pattern,
                },
            )

    # Check metadata URLs
    if not policy.allow_metadata_urls and hostname in _METADATA_HOSTS:
        logger.warning(
            "endpoint_blocked",
            url=url,
            hostname=hostname,
            reason="metadata_url",
        )
        raise NetworkBlockedError(
            f"Cloud metadata endpoint blocked: {hostname}",
            operation="endpoint_validation",
            target=url,
            details={"reason": "metadata_url", "hostname": hostname},
        )

    # Check private IPs
    if not policy.allow_private_ips and _is_private_ip(hostname):
        logger.warning(
            "endpoint_blocked",
            url=url,
            hostname=hostname,
            reason="private_ip",
        )
        raise NetworkBlockedError(
            f"Private IP blocked: {hostname}",
            operation="endpoint_validation",
            target=url,
            details={"reason": "private_ip", "hostname": hostname},
        )

    # Check localhost aliases
    # nosec B104 - "0.0.0.0" is being blocklisted here, not used as a bind address
    if not policy.allow_private_ips and hostname in ("localhost", "0.0.0.0"):  # nosec B104
        raise NetworkBlockedError(
            f"Localhost blocked: {hostname}",
            operation="endpoint_validation",
            target=url,
            details={"reason": "localhost", "hostname": hostname},
        )

    # Check allowed endpoints (if specified)
    if policy.allowed_endpoints:
        for allowed in policy.allowed_endpoints:
            if _matches_endpoint_pattern(hostname, allowed):
                return  # Allowed
        logger.warning(
            "endpoint_blocked",
            url=url,
            hostname=hostname,
            reason="not_in_allowlist",
            allowed_endpoints=policy.allowed_endpoints,
        )
        raise NetworkBlockedError(
            f"Host '{hostname}' not in allowed endpoints",
            operation="endpoint_validation",
            target=url,
            details={
                "reason": "not_in_allowlist",
                "hostname": hostname,
                "allowed_endpoints": policy.allowed_endpoints,
            },
        )


@dataclass
class _AirgapFrame:
    """One open airgap: its policy, and the addresses the lookups it allowed returned.

    ``resolved`` is what a hostname allowlist admits at connect: the check there sees the
    address a name resolved to, not the name, so without it a listed name would be
    refused its own address. An airgap is opened once per guarded call (once per step of
    a generator tool), so an admission never outlives the call or reaches another one.
    """

    policy: NetworkPolicy
    resolved: set[str] = field(default_factory=set)


# The airgaps open in the current context, outermost first. A ContextVar, so each thread
# and each asyncio task has its own: until 0.10.28 this was a threading.local, which every
# task on a thread shared.
_active_airgaps: ContextVar[tuple[_AirgapFrame, ...]] = ContextVar(
    "agent_airlock_network_airgaps", default=()
)

# The functions the interceptors replaced, by interceptor name, saved for restoration.
# Kept after an uninstall, so a call already inside an interceptor still completes.
_originals: dict[str, Any] = {}
_socket_patched = False
_patch_lock = threading.Lock()

# Reference counting for socket interceptors
# Allows proper cleanup when last context manager exits
_interceptor_ref_count = 0


def _get_current_policy() -> NetworkPolicy | None:
    """The policy of the innermost airgap open in the current context, or None."""
    frames = _active_airgaps.get()
    return frames[-1].policy if frames else None


def _set_current_policy(policy: NetworkPolicy | None) -> None:
    """Make ``policy`` the only airgap open in the current context (None: no airgap)."""
    _active_airgaps.set((_AirgapFrame(policy),) if policy is not None else ())


def _original(name: str) -> Any:
    """The function the interceptor called ``name`` replaced.

    Raises:
        RuntimeError: If the interceptors were never installed.
    """
    original = _originals.get(name)
    if original is None:
        raise RuntimeError(f"Socket interceptors not properly installed: no original {name}")
    return original


def _ensure_original_socket_methods() -> None:
    """Ensure original socket methods are available.

    Raises:
        RuntimeError: If socket interceptors are not properly installed.

    Note:
        This replaces assert statements to ensure checks work even when
        Python is run with -O (optimize) flag which removes asserts.
    """
    for name in ("socket.connect", "socket.connect_ex", "getaddrinfo"):
        _original(name)


def _is_host_allowed(host: str, policy: NetworkPolicy) -> bool:
    """Check if a host is allowed by the policy."""
    if not policy.allowed_hosts:
        return True  # No restriction

    # Check exact match and wildcard patterns
    for allowed in policy.allowed_hosts:
        if allowed == host:
            return True
        # Support wildcard subdomains (*.example.com)
        if allowed.startswith("*.") and host.endswith(allowed[1:]):
            return True

    return False


def _is_port_allowed(port: int, policy: NetworkPolicy) -> bool:
    """Check if a port is allowed by the policy."""
    if not policy.allowed_ports:
        return True  # No restriction
    return port in policy.allowed_ports


def _extract_host_port(address: Any) -> tuple[str | None, int | None]:
    """Extract host and port from a socket address."""
    if isinstance(address, tuple) and len(address) >= 2:
        return str(address[0]), int(address[1])
    return None, None


def _host_text(host: Any) -> str | None:
    """A looked-up or resolved host as the text the allowlist is compared with."""
    if host is None:
        return None
    if isinstance(host, bytes | bytearray):
        return bytes(host).decode("ascii", "replace")
    return str(host)


def _blocked(
    operation: str,
    message: str,
    *,
    target: str,
    details: dict[str, Any],
    host: Any = None,
    port: int | None = None,
) -> NoReturn:
    """Log a refused network operation and raise its ``NetworkBlockedError``."""
    logger.warning(
        "network_blocked",
        operation=operation,
        host=host,
        port=port,
        reason=details["reason"],
    )
    raise NetworkBlockedError(message, operation=operation, target=target, details=details)


def _check_address(
    frames: tuple[_AirgapFrame, ...], address: Any, operation: str, noun: str
) -> None:
    """Refuse opening ``address`` unless every open airgap admits it.

    Nested airgaps intersect: an inner policy can only refuse more than an outer one.
    ``noun`` names what is being opened ("connection", "datagram") in the message.
    """
    host, port = _extract_host_port(address)
    for frame in frames:
        policy = frame.policy
        if not policy.allow_egress:
            _blocked(
                operation,
                f"Network egress blocked: {noun} to {address} denied",
                target=str(address),
                details={"reason": "egress_disabled"},
                host=host,
                port=port,
            )
        if host and not (_is_host_allowed(host, policy) or host in frame.resolved):
            _blocked(
                operation,
                f"Network egress blocked: host '{host}' not in allowed list",
                target=str(address),
                details={
                    "reason": "host_not_allowed",
                    "host": host,
                    "allowed_hosts": policy.allowed_hosts,
                },
                host=host,
                port=port,
            )
        if port and not _is_port_allowed(port, policy):
            _blocked(
                operation,
                f"Network egress blocked: port {port} not in allowed list",
                target=str(address),
                details={
                    "reason": "port_not_allowed",
                    "port": port,
                    "allowed_ports": policy.allowed_ports,
                },
                host=host,
                port=port,
            )


def _check_lookup(frames: tuple[_AirgapFrame, ...], host: Any, operation: str) -> None:
    """Refuse a name lookup of ``host`` unless every open airgap admits it."""
    text = _host_text(host)
    for frame in frames:
        policy = frame.policy
        if policy.block_dns:
            _blocked(
                operation,
                f"DNS lookup blocked: resolution of '{host}' denied",
                target=str(host),
                details={"reason": "dns_blocked"},
                host=host,
            )
        if not policy.allow_egress:
            _blocked(
                operation,
                "DNS lookup blocked: egress disabled",
                target=str(host),
                details={"reason": "egress_disabled"},
                host=host,
            )
        if text and not (_is_host_allowed(text, policy) or text in frame.resolved):
            _blocked(
                operation,
                f"DNS lookup blocked: host '{host}' not in allowed list",
                target=str(host),
                details={"reason": "host_not_allowed", "host": text},
                host=host,
            )


def _admit(frames: tuple[_AirgapFrame, ...], addresses: Iterable[Any]) -> None:
    """Admit at connect the addresses returned by a lookup every open airgap allowed.

    Only the open airgaps of the current call record them. A listed name that resolves
    to an internal address (127.0.0.1, 169.254.169.254) gets that address admitted with
    it: keeping a tool off internal addresses is the job of ``EndpointPolicy`` and the
    SSRF egress guard (``ssrf_egress_guard``), not of this allowlist.
    """
    hosts = [text for address in addresses if (text := _host_text(address))]
    for frame in frames:
        if frame.policy.allowed_hosts:
            frame.resolved.update(hosts)


def _resolved_addresses(infos: Any) -> list[Any]:
    """The addresses in ``getaddrinfo`` results."""
    addresses: list[Any] = []
    for info in infos or ():
        with contextlib.suppress(IndexError, KeyError, TypeError):
            addresses.append(info[4][0])
    return addresses


def _sockaddr_host(sockaddr: Any) -> Any:
    """The host of a ``getnameinfo`` socket address, or None."""
    if isinstance(sockaddr, tuple) and sockaddr:
        return sockaddr[0]
    return None


def _numeric_host_only(flags: Any) -> bool:
    """Whether ``getnameinfo`` was asked only to format the address, which looks up nothing."""
    return isinstance(flags, int) and bool(flags & socket.NI_NUMERICHOST)


def _blocked_connect(self: socket.socket, address: Any) -> None:
    """Intercepted socket.connect that enforces network policy."""
    frames = _active_airgaps.get()
    if frames:
        _check_address(frames, address, "connect", "connection")
    _original("socket.connect")(self, address)


def _blocked_connect_ex(self: socket.socket, address: Any) -> int:
    """Intercepted socket.connect_ex that enforces network policy."""
    frames = _active_airgaps.get()
    if frames:
        _check_address(frames, address, "connect_ex", "connection")
    return int(_original("socket.connect_ex")(self, address))


def _blocked_sendto(self: socket.socket, data: Any, *args: Any) -> int:
    """Intercepted socket.sendto, ``sendto(data, address)`` or ``sendto(data, flags, address)``.

    A datagram needs no connect, so until 0.10.28 UDP went out under any airgap.
    """
    frames = _active_airgaps.get()
    if frames and args:
        _check_address(frames, args[-1], "sendto", "datagram")
    return int(_original("socket.sendto")(self, data, *args))


def _blocked_sendmsg(self: socket.socket, buffers: Any, *args: Any) -> int:
    """Intercepted socket.sendmsg, ``sendmsg(buffers[, ancdata[, flags[, address]]])``."""
    frames = _active_airgaps.get()
    if frames and len(args) >= 3 and args[2] is not None:
        _check_address(frames, args[2], "sendmsg", "datagram")
    return int(_original("socket.sendmsg")(self, buffers, *args))


def _is_own_host_name(host: Any) -> bool:
    """Whether ``host`` is this machine's own name, ``socket.gethostname()``.

    Looking it up carries nothing from the call, and ``socket.getfqdn()`` (so ``smtplib``
    and ``email.utils.make_msgid()``) and ``gethostbyname(gethostname())`` depend on it.
    """
    text = _host_text(host)
    if not text:
        return False
    try:
        own = socket.gethostname()
    except OSError:
        return False
    return text.lower() == own.lower()


def _checked_lookup(host: Any, operation: str) -> tuple[_AirgapFrame, ...]:
    """Check a lookup of ``host`` against the open airgaps, and return the ones checked.

    Raises ``NetworkBlockedError`` when one of them refuses it. Returns no airgaps when
    none is open, or when ``host`` is this machine's own name, which is looked up
    unchecked (``_is_own_host_name``) and admits nothing at connect.
    """
    frames = _active_airgaps.get()
    if not frames or _is_own_host_name(host):
        return ()
    _check_lookup(frames, host, operation)
    return frames


def _blocked_getaddrinfo(
    host: Any,
    port: Any,
    family: int = 0,
    type: int = 0,
    proto: int = 0,
    flags: int = 0,
) -> list[Any]:
    """Intercepted socket.getaddrinfo that enforces DNS blocking.

    The parameters keep the standard library's names, so ``type=`` passed by keyword
    works (until 0.10.28 it was ``type_`` here, and ``type=`` raised under an airgap).
    """
    frames = _checked_lookup(host, "dns_lookup")
    infos = _original("getaddrinfo")(host, port, family, type, proto, flags)
    _admit(frames, _resolved_addresses(infos))
    return infos  # type: ignore[no-any-return]


def _blocked_gethostbyname(hostname: Any) -> Any:
    """Intercepted socket.gethostbyname (a lookup the airgap did not see until 0.10.28)."""
    frames = _checked_lookup(hostname, "dns_lookup")
    address = _original("gethostbyname")(hostname)
    _admit(frames, [address])
    return address


def _blocked_gethostbyname_ex(hostname: Any) -> Any:
    """Intercepted socket.gethostbyname_ex."""
    frames = _checked_lookup(hostname, "dns_lookup")
    result = _original("gethostbyname_ex")(hostname)
    _admit(frames, result[2])
    return result


def _blocked_gethostbyaddr(ip_address: Any) -> Any:
    """Intercepted socket.gethostbyaddr, which also resolves a name it is given."""
    frames = _checked_lookup(ip_address, "reverse_dns_lookup")
    result = _original("gethostbyaddr")(ip_address)
    _admit(frames, result[2])
    return result


def _blocked_getnameinfo(sockaddr: Any, flags: Any) -> Any:
    """Intercepted socket.getnameinfo. With ``NI_NUMERICHOST`` it only formats the address."""
    if not _numeric_host_only(flags):
        _checked_lookup(_sockaddr_host(sockaddr), "reverse_dns_lookup")
    return _original("getnameinfo")(sockaddr, flags)


async def _airgapped_loop_getaddrinfo(
    self: Any,
    host: Any,
    port: Any,
    *,
    family: int = 0,
    type: int = 0,
    proto: int = 0,
    flags: int = 0,
) -> Any:
    """asyncio's ``loop.getaddrinfo``, checked in the calling task's context.

    The loop runs the lookup in its default executor, a thread the call's context does
    not reach, so ``socket.getaddrinfo`` there sees no airgap. Checking here, before the
    hand-off, refuses it in the task that asked (until 0.10.28 an async tool's lookup,
    and every async HTTP client's, went out under any airgap).
    """
    frames = _checked_lookup(host, "dns_lookup")
    infos = await _original("loop.getaddrinfo")(
        self, host, port, family=family, type=type, proto=proto, flags=flags
    )
    _admit(frames, _resolved_addresses(infos))
    return infos


async def _airgapped_loop_getnameinfo(self: Any, sockaddr: Any, flags: int = 0) -> Any:
    """asyncio's ``loop.getnameinfo``, checked in the calling task's context."""
    if not _numeric_host_only(flags):
        _checked_lookup(_sockaddr_host(sockaddr), "reverse_dns_lookup")
    return await _original("loop.getnameinfo")(self, sockaddr, flags)


def _patch_targets() -> list[tuple[str, Any, str, Any]]:
    """``(name, owner, attribute, interceptor)`` for every function the airgap replaces."""
    loop_class = asyncio.base_events.BaseEventLoop
    targets: list[tuple[str, Any, str, Any]] = [
        ("socket.connect", socket.socket, "connect", _blocked_connect),
        ("socket.connect_ex", socket.socket, "connect_ex", _blocked_connect_ex),
        ("socket.sendto", socket.socket, "sendto", _blocked_sendto),
        ("getaddrinfo", socket, "getaddrinfo", _blocked_getaddrinfo),
        ("gethostbyname", socket, "gethostbyname", _blocked_gethostbyname),
        ("gethostbyname_ex", socket, "gethostbyname_ex", _blocked_gethostbyname_ex),
        ("gethostbyaddr", socket, "gethostbyaddr", _blocked_gethostbyaddr),
        ("getnameinfo", socket, "getnameinfo", _blocked_getnameinfo),
        ("loop.getaddrinfo", loop_class, "getaddrinfo", _airgapped_loop_getaddrinfo),
        ("loop.getnameinfo", loop_class, "getnameinfo", _airgapped_loop_getnameinfo),
    ]
    if hasattr(socket.socket, "sendmsg"):  # not on Windows
        targets.append(("socket.sendmsg", socket.socket, "sendmsg", _blocked_sendmsg))
    return targets


def _restore_originals() -> None:
    """Put back every function the interceptors replaced. Call with ``_patch_lock`` held."""
    for name, owner, attribute, _interceptor in _patch_targets():
        original = _originals.get(name)
        if original is not None:
            setattr(owner, attribute, original)


def _install_socket_interceptors() -> None:
    """Install socket interceptors globally with reference counting (thread-safe).

    Uses reference counting to track how many contexts are using interceptors.
    Interceptors are only installed on first reference and uninstalled when
    the last reference is released.
    """
    global _socket_patched, _interceptor_ref_count

    with _patch_lock:
        _interceptor_ref_count += 1

        if _socket_patched:
            # Already installed, just increment ref count
            logger.debug(
                "socket_interceptors_ref_incremented",
                ref_count=_interceptor_ref_count,
            )
            return

        for name, owner, attribute, interceptor in _patch_targets():
            _originals[name] = getattr(owner, attribute)
            setattr(owner, attribute, interceptor)

        _socket_patched = True
        logger.debug(
            "socket_interceptors_installed",
            ref_count=_interceptor_ref_count,
        )


def _uninstall_socket_interceptors() -> None:
    """Uninstall socket interceptors when ref count reaches 0 (thread-safe).

    Uses reference counting to ensure interceptors are only uninstalled
    when no contexts are using them.
    """
    global _socket_patched, _interceptor_ref_count

    with _patch_lock:
        if _interceptor_ref_count > 0:
            _interceptor_ref_count -= 1

        if _interceptor_ref_count > 0:
            # Still in use by other contexts
            logger.debug(
                "socket_interceptors_ref_decremented",
                ref_count=_interceptor_ref_count,
            )
            return

        if not _socket_patched:
            return

        _restore_originals()
        _socket_patched = False
        logger.debug("socket_interceptors_uninstalled")


def _close_airgap(token: Token[tuple[_AirgapFrame, ...]]) -> None:
    """Close the airgap ``token`` opened, in the context it was opened in.

    An airgap held across a ``yield`` and closed from another context (a generator
    resumed by another task or thread) cannot be reset there. The context it was opened
    in keeps it, which can only refuse more; the current one is left as it is, since
    resetting a context this airgap was never opened in could drop that context's own.
    """
    try:
        _active_airgaps.reset(token)
    except (ValueError, RuntimeError) as e:
        logger.warning("network_airgap_closed_in_another_context", error=str(e))


@contextlib.contextmanager
def network_airgap(policy: NetworkPolicy | None = None) -> Generator[None, None, None]:
    """Context manager that enforces network policy during execution.

    The policy applies to the current context only: the thread or asyncio task that
    entered it, and the tasks it creates. Nested airgaps intersect, so an operation must
    be admitted by every open one. Uses reference counting to uninstall the socket
    interceptors when the last airgap in the process exits.

    Example:
        # Block all network access
        with network_airgap(NetworkPolicy(allow_egress=False)):
            result = dangerous_tool()  # Any network call raises NetworkBlockedError

        # Allow specific hosts only
        with network_airgap(NetworkPolicy(allowed_hosts=["api.internal"])):
            result = tool_that_calls_api()

    Args:
        policy: Network policy to enforce. Defaults to blocking all egress.

    Yields:
        None

    Raises:
        NetworkBlockedError: If code within the context attempts a blocked operation.
    """
    if policy is None:
        policy = NetworkPolicy(allow_egress=False)

    # Ensure interceptors are installed (increments ref count)
    _install_socket_interceptors()
    token = _active_airgaps.set((*_active_airgaps.get(), _AirgapFrame(policy)))

    try:
        yield
    finally:
        _close_airgap(token)
        # Decrement ref count, uninstall if last context
        _uninstall_socket_interceptors()


# Predefined policies for common use cases

NO_NETWORK_POLICY = NetworkPolicy(
    allow_egress=False,
    block_dns=True,
)
"""Complete network airgap - blocks all connections and DNS lookups."""


INTERNAL_ONLY_POLICY = NetworkPolicy(
    allow_egress=True,
    allowed_hosts=["localhost", "127.0.0.1", "::1", "*.internal", "*.local"],
    allowed_ports=[],  # All ports allowed for internal hosts
    block_dns=False,
)
"""Only allows connections to localhost and internal domains."""


HTTPS_ONLY_POLICY = NetworkPolicy(
    allow_egress=True,
    allowed_hosts=[],  # All hosts allowed
    allowed_ports=[443, 8443],  # HTTPS ports only
    block_dns=False,
)
"""Only allows HTTPS connections (ports 443, 8443)."""


def _reset_interceptors() -> None:
    """Reset all network interceptor state for testing.

    This function should only be used in tests to ensure isolation
    between test cases.
    """
    global _socket_patched, _interceptor_ref_count

    with _patch_lock:
        # Force uninstall if patched
        if _socket_patched:
            _restore_originals()
            _socket_patched = False

        _interceptor_ref_count = 0

    # Close every airgap open in the current context
    _set_current_policy(None)
