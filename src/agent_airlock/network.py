"""Network egress control module for Agent-Airlock.

Provides runtime network blocking to prevent data exfiltration during tool execution.
Uses socket monkeypatching with thread-local storage to ensure thread safety.

SECURITY: This module is critical for preventing Moltbook-style attacks where
malicious tool calls attempt to exfiltrate data to external servers.

THREAD SAFETY:
    This module is thread-safe through careful design:

    1. Policy Storage: Uses thread-local storage (_thread_local) so each thread
       has its own NetworkPolicy. This ensures policy enforcement doesn't leak
       across threads.

    2. Socket Patching: Uses _patch_lock (threading.Lock) to protect the global
       socket monkeypatch installation/uninstallation. Reference counting ensures
       interceptors are only uninstalled when no contexts are using them.

    3. Lock Acquisition Order: _patch_lock is a single lock with no dependencies.
       It should be acquired before any socket operations during install/uninstall.

    Note: The socket methods themselves are called without locks held to prevent
    deadlocks during actual network operations.
"""

from __future__ import annotations

import contextlib
import socket
import threading
from collections.abc import Generator
from dataclasses import dataclass, field
from typing import Any

import structlog

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


# Thread-local storage for policy enforcement
_thread_local = threading.local()

# Original socket methods (saved for restoration)
_original_socket_connect: Any = None
_original_socket_connect_ex: Any = None
_original_getaddrinfo: Any = None
_socket_patched = False
_patch_lock = threading.Lock()

# Reference counting for socket interceptors
# Allows proper cleanup when last context manager exits
_interceptor_ref_count = 0


def _get_current_policy() -> NetworkPolicy | None:
    """Get the current thread's network policy."""
    return getattr(_thread_local, "network_policy", None)


def _ensure_original_socket_methods() -> None:
    """Ensure original socket methods are available.

    Raises:
        RuntimeError: If socket interceptors are not properly installed.

    Note:
        This replaces assert statements to ensure checks work even when
        Python is run with -O (optimize) flag which removes asserts.
    """
    if _original_socket_connect is None:
        raise RuntimeError(
            "Socket interceptors not properly installed: _original_socket_connect is None"
        )
    if _original_socket_connect_ex is None:
        raise RuntimeError(
            "Socket interceptors not properly installed: _original_socket_connect_ex is None"
        )
    if _original_getaddrinfo is None:
        raise RuntimeError(
            "Socket interceptors not properly installed: _original_getaddrinfo is None"
        )


def _set_current_policy(policy: NetworkPolicy | None) -> None:
    """Set the current thread's network policy."""
    _thread_local.network_policy = policy


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


def _blocked_connect(self: socket.socket, address: Any) -> None:
    """Intercepted socket.connect that enforces network policy."""
    policy = _get_current_policy()

    if policy is None:
        # No policy active, use original
        if _original_socket_connect is None:
            raise RuntimeError("Socket interceptors not properly installed")
        return _original_socket_connect(self, address)

    if not policy.allow_egress:
        host, port = _extract_host_port(address)
        logger.warning(
            "network_blocked",
            operation="connect",
            host=host,
            port=port,
            reason="egress_disabled",
        )
        raise NetworkBlockedError(
            f"Network egress blocked: connection to {address} denied",
            operation="connect",
            target=str(address),
            details={"reason": "egress_disabled"},
        )

    host, port = _extract_host_port(address)

    if host and not _is_host_allowed(host, policy):
        logger.warning(
            "network_blocked",
            operation="connect",
            host=host,
            port=port,
            reason="host_not_allowed",
        )
        raise NetworkBlockedError(
            f"Network egress blocked: host '{host}' not in allowed list",
            operation="connect",
            target=str(address),
            details={
                "reason": "host_not_allowed",
                "host": host,
                "allowed_hosts": policy.allowed_hosts,
            },
        )

    if port and not _is_port_allowed(port, policy):
        logger.warning(
            "network_blocked",
            operation="connect",
            host=host,
            port=port,
            reason="port_not_allowed",
        )
        raise NetworkBlockedError(
            f"Network egress blocked: port {port} not in allowed list",
            operation="connect",
            target=str(address),
            details={
                "reason": "port_not_allowed",
                "port": port,
                "allowed_ports": policy.allowed_ports,
            },
        )

    # Connection allowed
    if _original_socket_connect is None:
        raise RuntimeError("Socket interceptors not properly installed")
    return _original_socket_connect(self, address)


def _blocked_connect_ex(self: socket.socket, address: Any) -> int:
    """Intercepted socket.connect_ex that enforces network policy."""
    policy = _get_current_policy()

    if policy is None:
        if _original_socket_connect_ex is None:
            raise RuntimeError("Socket interceptors not properly installed")
        return _original_socket_connect_ex(self, address)  # type: ignore[no-any-return]

    # Apply same checks as connect
    if not policy.allow_egress:
        host, port = _extract_host_port(address)
        logger.warning(
            "network_blocked",
            operation="connect_ex",
            host=host,
            port=port,
            reason="egress_disabled",
        )
        raise NetworkBlockedError(
            f"Network egress blocked: connection to {address} denied",
            operation="connect_ex",
            target=str(address),
            details={"reason": "egress_disabled"},
        )

    host, port = _extract_host_port(address)

    if host and not _is_host_allowed(host, policy):
        raise NetworkBlockedError(
            f"Network egress blocked: host '{host}' not in allowed list",
            operation="connect_ex",
            target=str(address),
            details={"reason": "host_not_allowed", "host": host},
        )

    if port and not _is_port_allowed(port, policy):
        raise NetworkBlockedError(
            f"Network egress blocked: port {port} not in allowed list",
            operation="connect_ex",
            target=str(address),
            details={"reason": "port_not_allowed", "port": port},
        )

    if _original_socket_connect_ex is None:
        raise RuntimeError("Socket interceptors not properly installed")
    return _original_socket_connect_ex(self, address)  # type: ignore[no-any-return]


def _blocked_getaddrinfo(
    host: str | None,
    port: int | str | None,
    family: int = 0,
    type_: int = 0,
    proto: int = 0,
    flags: int = 0,
) -> list[Any]:
    """Intercepted socket.getaddrinfo that enforces DNS blocking."""
    policy = _get_current_policy()

    if policy is None:
        if _original_getaddrinfo is None:
            raise RuntimeError("Socket interceptors not properly installed")
        return _original_getaddrinfo(host, port, family, type_, proto, flags)  # type: ignore[no-any-return]

    if policy.block_dns:
        logger.warning(
            "network_blocked",
            operation="dns_lookup",
            host=host,
            reason="dns_blocked",
        )
        raise NetworkBlockedError(
            f"DNS lookup blocked: resolution of '{host}' denied",
            operation="dns_lookup",
            target=str(host),
            details={"reason": "dns_blocked"},
        )

    if not policy.allow_egress:
        logger.warning(
            "network_blocked",
            operation="dns_lookup",
            host=host,
            reason="egress_disabled",
        )
        raise NetworkBlockedError(
            "DNS lookup blocked: egress disabled",
            operation="dns_lookup",
            target=str(host),
            details={"reason": "egress_disabled"},
        )

    # Check if the host is allowed
    if host and not _is_host_allowed(host, policy):
        logger.warning(
            "network_blocked",
            operation="dns_lookup",
            host=host,
            reason="host_not_allowed",
        )
        raise NetworkBlockedError(
            f"DNS lookup blocked: host '{host}' not in allowed list",
            operation="dns_lookup",
            target=host,
            details={"reason": "host_not_allowed", "host": host},
        )

    if _original_getaddrinfo is None:
        raise RuntimeError("Socket interceptors not properly installed")
    return _original_getaddrinfo(host, port, family, type_, proto, flags)  # type: ignore[no-any-return]


def _install_socket_interceptors() -> None:
    """Install socket interceptors globally with reference counting (thread-safe).

    Uses reference counting to track how many contexts are using interceptors.
    Interceptors are only installed on first reference and uninstalled when
    the last reference is released.
    """
    global _socket_patched, _original_socket_connect, _original_socket_connect_ex
    global _original_getaddrinfo, _interceptor_ref_count

    with _patch_lock:
        _interceptor_ref_count += 1

        if _socket_patched:
            # Already installed, just increment ref count
            logger.debug(
                "socket_interceptors_ref_incremented",
                ref_count=_interceptor_ref_count,
            )
            return

        # Save original methods
        _original_socket_connect = socket.socket.connect
        _original_socket_connect_ex = socket.socket.connect_ex
        _original_getaddrinfo = socket.getaddrinfo

        # Install interceptors
        socket.socket.connect = _blocked_connect  # type: ignore[method-assign]
        socket.socket.connect_ex = _blocked_connect_ex  # type: ignore[method-assign]
        socket.getaddrinfo = _blocked_getaddrinfo  # type: ignore[assignment]

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

        if _original_socket_connect is not None:
            socket.socket.connect = _original_socket_connect  # type: ignore[method-assign]
        if _original_socket_connect_ex is not None:
            socket.socket.connect_ex = _original_socket_connect_ex  # type: ignore[method-assign]
        if _original_getaddrinfo is not None:
            socket.getaddrinfo = _original_getaddrinfo  # type: ignore[assignment]

        _socket_patched = False
        logger.debug("socket_interceptors_uninstalled")


@contextlib.contextmanager
def network_airgap(policy: NetworkPolicy | None = None) -> Generator[None, None, None]:
    """Context manager that enforces network policy during execution.

    Thread-safe: Uses thread-local storage to ensure policy only applies
    to the current thread. Uses reference counting to properly uninstall
    socket interceptors when the last context exits.

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

    # Save any existing policy and set new one
    previous_policy = _get_current_policy()
    _set_current_policy(policy)

    try:
        yield
    finally:
        # Restore previous policy (or None)
        _set_current_policy(previous_policy)
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
            if _original_socket_connect is not None:
                socket.socket.connect = _original_socket_connect  # type: ignore[method-assign]
            if _original_socket_connect_ex is not None:
                socket.socket.connect_ex = _original_socket_connect_ex  # type: ignore[method-assign]
            if _original_getaddrinfo is not None:
                socket.getaddrinfo = _original_getaddrinfo  # type: ignore[assignment]
            _socket_patched = False

        _interceptor_ref_count = 0

    # Clear thread-local policy
    _set_current_policy(None)
