"""Capability gating for Agent-Airlock (V0.4.0).

Provides per-tool capability requirements that can be checked against policy.
This prevents tools from accessing resources they shouldn't have access to.

The capability model:
    Tools declare what capabilities they need (filesystem, network, etc.)
    Policies grant or deny capabilities to tools
    At runtime, Airlock checks if the tool's capabilities are allowed

Usage:
    from agent_airlock import Airlock, requires, Capability

    @Airlock()
    @requires(Capability.FILESYSTEM_READ)
    def read_config(path: str) -> str:
        return Path(path).read_text()

    @Airlock(sandbox=True)
    @requires(Capability.PROCESS_SHELL)
    def run_command(cmd: str) -> str:
        return subprocess.check_output(cmd, shell=True)
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Flag, auto
from typing import Any, TypeVar

import structlog

logger = structlog.get_logger("agent-airlock.capabilities")

F = TypeVar("F", bound=Callable[..., Any])


class Capability(Flag):
    """Capabilities that tools can require.

    Use the | operator to combine capabilities:
        Capability.FILESYSTEM_READ | Capability.NETWORK_HTTPS

    Examples:
        # Tool that reads files
        @requires(Capability.FILESYSTEM_READ)
        def read_file(path: str) -> str: ...

        # Tool that makes HTTPS requests
        @requires(Capability.NETWORK_HTTPS)
        def fetch_url(url: str) -> str: ...

        # Tool that needs multiple capabilities
        @requires(Capability.FILESYSTEM_READ | Capability.NETWORK_HTTPS)
        def upload_file(path: str, url: str) -> None: ...
    """

    NONE = 0

    # Filesystem capabilities
    FILESYSTEM_READ = auto()
    """Read files from the filesystem."""

    FILESYSTEM_WRITE = auto()
    """Write files to the filesystem."""

    FILESYSTEM_DELETE = auto()
    """Delete files from the filesystem."""

    # Network capabilities
    NETWORK_HTTP = auto()
    """Make HTTP (unencrypted) requests."""

    NETWORK_HTTPS = auto()
    """Make HTTPS (encrypted) requests."""

    NETWORK_ARBITRARY = auto()
    """Make arbitrary network connections (raw sockets)."""

    # Process capabilities
    PROCESS_EXEC = auto()
    """Execute external processes (no shell)."""

    PROCESS_SHELL = auto()
    """Execute shell commands (DANGEROUS)."""

    # Sensitive data capabilities
    DATA_PII = auto()
    """Access personally identifiable information."""

    DATA_SECRETS = auto()
    """Access secrets (API keys, passwords, etc.)."""

    # Database capabilities
    DATABASE_READ = auto()
    """Read from database."""

    DATABASE_WRITE = auto()
    """Write to database."""

    # Convenience combinations
    FILESYSTEM_ALL = FILESYSTEM_READ | FILESYSTEM_WRITE | FILESYSTEM_DELETE
    """All filesystem capabilities."""

    NETWORK_ALL = NETWORK_HTTP | NETWORK_HTTPS | NETWORK_ARBITRARY
    """All network capabilities."""

    DANGEROUS = PROCESS_SHELL | FILESYSTEM_DELETE | NETWORK_ARBITRARY
    """Capabilities that should require sandbox execution."""

    # Common safe combinations
    SAFE_READ = FILESYSTEM_READ | DATABASE_READ | NETWORK_HTTPS
    """Common safe read-only capabilities."""


class CapabilityDeniedError(Exception):
    """Raised when a tool requires capabilities that are not granted.

    Attributes:
        tool_name: Name of the tool that was denied.
        required: Capabilities that were required.
        missing: Capabilities that were missing.
        denied: Capabilities that were explicitly denied.
    """

    def __init__(
        self,
        message: str,
        tool_name: str = "",
        required: Capability = Capability.NONE,
        missing: Capability = Capability.NONE,
        denied: Capability = Capability.NONE,
    ) -> None:
        self.message = message
        self.tool_name = tool_name
        self.required = required
        self.missing = missing
        self.denied = denied
        super().__init__(message)


@dataclass
class CapabilityPolicy:
    """Policy for capability gating.

    Attributes:
        granted: Capabilities that are explicitly granted.
        denied: Capabilities that are explicitly denied (takes precedence over granted).
        require_sandbox_for: Capabilities that require sandbox execution.

    Examples:
        # Allow filesystem read and HTTPS, deny shell execution
        policy = CapabilityPolicy(
            granted=Capability.FILESYSTEM_READ | Capability.NETWORK_HTTPS,
            denied=Capability.PROCESS_SHELL,
        )

        # Grant everything but require sandbox for dangerous operations
        policy = CapabilityPolicy(
            granted=Capability.FILESYSTEM_ALL | Capability.NETWORK_ALL,
            require_sandbox_for=Capability.DANGEROUS,
        )
    """

    granted: Capability = Capability.NONE
    denied: Capability = Capability.NONE
    require_sandbox_for: Capability = field(default_factory=lambda: Capability.DANGEROUS)

    def check(self, required: Capability, tool_name: str) -> None:
        """Check if required capabilities are allowed.

        Args:
            required: Capabilities required by the tool.
            tool_name: Name of the tool (for error messages).

        Raises:
            CapabilityDeniedError: If capabilities are denied or not granted.
        """
        if required == Capability.NONE:
            return

        # Explicit deny takes precedence
        # Note: mypy has known issues with Flag enum bitwise ops, runtime works correctly
        denied_caps = required & self.denied  # type: ignore[operator]
        if denied_caps:
            denied_names = _capability_flag_names(denied_caps)
            raise CapabilityDeniedError(
                f"Tool '{tool_name}' requires denied capabilities: {denied_names}",
                tool_name=tool_name,
                required=required,
                denied=denied_caps,
            )

        # Check if granted (only if granted is not NONE)
        if self.granted != Capability.NONE:
            missing = required & ~self.granted  # type: ignore[operator]
            if missing:
                missing_names = _capability_flag_names(missing)
                raise CapabilityDeniedError(
                    f"Tool '{tool_name}' requires capabilities not granted: {missing_names}",
                    tool_name=tool_name,
                    required=required,
                    missing=missing,
                )

    def requires_sandbox(self, required: Capability) -> bool:
        """Check if capabilities require sandbox execution.

        Args:
            required: Capabilities to check.

        Returns:
            True if any of the capabilities require sandbox.
        """
        return bool(required & self.require_sandbox_for)

    def is_allowed(self, required: Capability) -> bool:
        """Check if capabilities are allowed without raising an exception.

        Args:
            required: Capabilities to check.

        Returns:
            True if capabilities are allowed.
        """
        try:
            self.check(required, "check")
            return True
        except CapabilityDeniedError:
            return False


def requires(*capabilities: Capability) -> Callable[[F], F]:
    """Decorator to declare capabilities required by a tool.

    This decorator marks a function with the capabilities it requires.
    Airlock will check these capabilities against the policy at runtime.

    Args:
        *capabilities: One or more Capability flags.

    Returns:
        Decorator that adds __airlock_capabilities__ attribute to the function.

    Examples:
        @requires(Capability.FILESYSTEM_READ)
        def read_file(path: str) -> str:
            return Path(path).read_text()

        @requires(Capability.FILESYSTEM_READ, Capability.NETWORK_HTTPS)
        def upload_file(path: str, url: str) -> None:
            ...
    """
    combined = Capability.NONE
    for cap in capabilities:
        combined |= cap

    def decorator(func: F) -> F:
        func.__airlock_capabilities__ = combined  # type: ignore[attr-defined]

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return func(*args, **kwargs)

        wrapper.__airlock_capabilities__ = combined  # type: ignore[attr-defined]
        return wrapper  # type: ignore[return-value]

    return decorator


def get_required_capabilities(func: Callable[..., Any]) -> Capability:
    """Get the capabilities required by a function.

    Args:
        func: Function to check.

    Returns:
        Capability flags required by the function, or NONE if not decorated.
    """
    return getattr(func, "__airlock_capabilities__", Capability.NONE)


def _capability_flag_names(caps: Capability) -> list[str]:
    """Extract individual flag names from a Capability value.

    This is a mypy-compatible way to iterate over Flag members.

    Args:
        caps: Capability flags to extract names from.

    Returns:
        List of individual capability names.
    """
    names: list[str] = []
    for member in Capability:
        # Skip NONE and composite flags
        if member == Capability.NONE:
            continue
        # Check if this individual flag is set (using bitwise AND)
        if member.value and (caps.value & member.value) == member.value:
            # Only include primitive flags (not composites)
            if member.name and member.value.bit_count() == 1:
                names.append(member.name)
    return names


def capabilities_to_list(caps: Capability) -> list[str]:
    """Convert Capability flags to a list of names.

    Useful for logging and audit records.

    Args:
        caps: Capability flags to convert.

    Returns:
        List of capability names.
    """
    return _capability_flag_names(caps)


# Predefined capability policies
PERMISSIVE_CAPABILITY_POLICY = CapabilityPolicy(
    granted=Capability.SAFE_READ,
    denied=Capability.NONE,
    require_sandbox_for=Capability.DANGEROUS,
)
"""Permissive policy: grants safe read capabilities, denies nothing."""

STRICT_CAPABILITY_POLICY = CapabilityPolicy(
    granted=Capability.FILESYSTEM_READ | Capability.NETWORK_HTTPS,
    denied=Capability.PROCESS_SHELL | Capability.FILESYSTEM_DELETE,
    require_sandbox_for=Capability.DANGEROUS,
)
"""Strict policy: grants limited read, denies shell and delete."""

READ_ONLY_CAPABILITY_POLICY = CapabilityPolicy(
    granted=Capability.FILESYSTEM_READ | Capability.DATABASE_READ | Capability.NETWORK_HTTPS,
    denied=Capability.FILESYSTEM_WRITE | Capability.FILESYSTEM_DELETE | Capability.DATABASE_WRITE,
    require_sandbox_for=Capability.PROCESS_EXEC | Capability.PROCESS_SHELL,
)
"""Read-only policy: grants read capabilities, denies all writes."""

NO_NETWORK_CAPABILITY_POLICY = CapabilityPolicy(
    granted=Capability.FILESYSTEM_READ | Capability.DATABASE_READ,
    denied=Capability.NETWORK_ALL,
    require_sandbox_for=Capability.DANGEROUS,
)
"""No network policy: grants local access, denies all network."""
