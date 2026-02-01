"""Policy engine for Agent-Airlock.

Provides RBAC (Role-Based Access Control) for AI agents with:
- Tool allow/deny lists
- Time-based restrictions
- Rate limiting
- Agent identity tracking
- Capability gating (V0.4.0)
"""

from __future__ import annotations

import fnmatch
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from .capabilities import CapabilityPolicy

logger = structlog.get_logger("agent-airlock.policy")


class PolicyViolation(Exception):
    """Raised when a policy check fails."""

    def __init__(
        self,
        message: str,
        violation_type: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.message = message
        self.violation_type = violation_type
        self.details = details or {}
        super().__init__(message)


class ViolationType(str, Enum):
    """Types of policy violations."""

    TOOL_DENIED = "tool_denied"
    TOOL_NOT_ALLOWED = "tool_not_allowed"
    TIME_RESTRICTED = "time_restricted"
    RATE_LIMITED = "rate_limited"


@dataclass
class TimeWindow:
    """Represents a time window for restrictions.

    Format: "HH:MM-HH:MM" (24-hour format)
    Example: "09:00-17:00" means allowed between 9 AM and 5 PM
    """

    start_hour: int
    start_minute: int
    end_hour: int
    end_minute: int

    @classmethod
    def parse(cls, window_str: str) -> TimeWindow:
        """Parse a time window string.

        Args:
            window_str: Time window in "HH:MM-HH:MM" format.

        Returns:
            TimeWindow instance.

        Raises:
            ValueError: If format is invalid.
        """
        pattern = r"^(\d{2}):(\d{2})-(\d{2}):(\d{2})$"
        match = re.match(pattern, window_str)

        if not match:
            raise ValueError(
                f"Invalid time window format: '{window_str}'. "
                "Expected 'HH:MM-HH:MM' (e.g., '09:00-17:00')"
            )

        start_hour, start_minute, end_hour, end_minute = map(int, match.groups())

        # Validate ranges
        if not (0 <= start_hour <= 23 and 0 <= end_hour <= 23):
            raise ValueError("Hour must be between 00 and 23")
        if not (0 <= start_minute <= 59 and 0 <= end_minute <= 59):
            raise ValueError("Minute must be between 00 and 59")

        return cls(start_hour, start_minute, end_hour, end_minute)

    def is_within(self, dt: datetime | None = None) -> bool:
        """Check if a datetime is within this time window.

        Args:
            dt: Datetime to check. Defaults to now.

        Returns:
            True if within window, False otherwise.
        """
        dt = dt or datetime.now()
        current_minutes = dt.hour * 60 + dt.minute
        start_minutes = self.start_hour * 60 + self.start_minute
        end_minutes = self.end_hour * 60 + self.end_minute

        # Handle overnight windows (e.g., "22:00-06:00")
        if end_minutes < start_minutes:
            return current_minutes >= start_minutes or current_minutes <= end_minutes

        return start_minutes <= current_minutes <= end_minutes


@dataclass
class RateLimit:
    """Rate limit configuration using token bucket algorithm.

    Format: "count/period" where period is hour, minute, or second
    Examples: "100/hour", "10/minute", "1/second"
    """

    max_tokens: int
    refill_period_seconds: float
    tokens: float = field(default=0.0, repr=False)
    last_refill: float = field(default_factory=time.time, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        """Initialize tokens to max."""
        self.tokens = float(self.max_tokens)

    @classmethod
    def parse(cls, limit_str: str) -> RateLimit:
        """Parse a rate limit string.

        Args:
            limit_str: Rate limit in "count/period" format.

        Returns:
            RateLimit instance.

        Raises:
            ValueError: If format is invalid.
        """
        pattern = r"^(\d+)/(second|minute|hour|day)$"
        match = re.match(pattern, limit_str.lower())

        if not match:
            raise ValueError(
                f"Invalid rate limit format: '{limit_str}'. "
                "Expected 'count/period' (e.g., '100/hour', '10/minute')"
            )

        count = int(match.group(1))
        period = match.group(2)

        period_seconds = {
            "second": 1.0,
            "minute": 60.0,
            "hour": 3600.0,
            "day": 86400.0,
        }

        return cls(max_tokens=count, refill_period_seconds=period_seconds[period])

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.time()
        elapsed = now - self.last_refill

        # Calculate tokens to add
        tokens_to_add = (elapsed / self.refill_period_seconds) * self.max_tokens
        self.tokens = min(self.max_tokens, self.tokens + tokens_to_add)
        self.last_refill = now

    def acquire(self, tokens: int = 1) -> bool:
        """Try to acquire tokens.

        Args:
            tokens: Number of tokens to acquire.

        Returns:
            True if tokens acquired, False if rate limited.
        """
        with self._lock:
            self._refill()

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True

            return False

    def remaining(self) -> int:
        """Get remaining tokens."""
        with self._lock:
            self._refill()
            return int(self.tokens)


@dataclass
class AgentIdentity:
    """Represents an AI agent's identity for policy enforcement.

    Attributes:
        agent_id: Unique identifier for the agent.
        session_id: Current session identifier.
        roles: List of roles assigned to this agent.
        metadata: Additional agent metadata.
    """

    agent_id: str
    session_id: str | None = None
    roles: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def has_role(self, role: str) -> bool:
        """Check if agent has a specific role."""
        return role in self.roles


@dataclass
class SecurityPolicy:
    """Security policy for tool access control.

    Example:
        policy = SecurityPolicy(
            allowed_tools=["read_file", "write_file"],
            denied_tools=["delete_database", "rm_*"],
            time_restrictions={"delete_*": "09:00-17:00"},
            rate_limits={"*": "100/hour", "expensive_*": "10/minute"},
        )

    Attributes:
        allowed_tools: List of allowed tool patterns. If empty, all tools allowed
                       (unless explicitly denied). Supports glob patterns.
        denied_tools: List of denied tool patterns. Takes precedence over allowed.
                      Supports glob patterns.
        time_restrictions: Dict mapping tool patterns to time windows.
                          Tools matching pattern only allowed during window.
        rate_limits: Dict mapping tool patterns to rate limit strings.
                     More specific patterns take precedence.
        require_agent_id: If True, reject calls without agent identity.
        allowed_roles: If set, agent must have at least one of these roles.
        capability_policy: V0.4.0 - Capability gating policy for per-tool permissions.
    """

    allowed_tools: list[str] = field(default_factory=list)
    denied_tools: list[str] = field(default_factory=list)
    time_restrictions: dict[str, str] = field(default_factory=dict)
    rate_limits: dict[str, str] = field(default_factory=dict)
    require_agent_id: bool = False
    allowed_roles: list[str] = field(default_factory=list)
    # V0.4.0 capability gating
    capability_policy: CapabilityPolicy | None = None

    # Parsed/cached values
    _time_windows: dict[str, TimeWindow] = field(default_factory=dict, repr=False)
    _rate_limiters: dict[str, RateLimit] = field(default_factory=dict, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        """Parse time restrictions and rate limits."""
        # Parse time windows
        for pattern, window_str in self.time_restrictions.items():
            self._time_windows[pattern] = TimeWindow.parse(window_str)

        # Parse rate limits
        for pattern, limit_str in self.rate_limits.items():
            self._rate_limiters[pattern] = RateLimit.parse(limit_str)

    def _matches_pattern(self, tool_name: str, pattern: str) -> bool:
        """Check if tool name matches a glob pattern."""
        return fnmatch.fnmatch(tool_name, pattern)

    def _find_matching_patterns(self, tool_name: str, patterns: dict[str, Any]) -> list[str]:
        """Find all patterns that match a tool name, sorted by specificity."""
        matches = [p for p in patterns if self._matches_pattern(tool_name, p)]
        # Sort by specificity (longer patterns are more specific)
        # Patterns without wildcards are most specific
        return sorted(
            matches,
            key=lambda p: (p.count("*") == 0, len(p.replace("*", ""))),
            reverse=True,
        )

    def check_tool_allowed(self, tool_name: str) -> None:
        """Check if a tool is allowed by allow/deny lists.

        Args:
            tool_name: Name of the tool to check.

        Raises:
            PolicyViolation: If tool is denied or not in allowed list.
        """
        # Check denied list first (takes precedence)
        for pattern in self.denied_tools:
            if self._matches_pattern(tool_name, pattern):
                raise PolicyViolation(
                    f"Tool '{tool_name}' is denied by policy (matches '{pattern}')",
                    violation_type=ViolationType.TOOL_DENIED.value,
                    details={"tool": tool_name, "pattern": pattern},
                )

        # Check allowed list (if specified)
        if self.allowed_tools:
            allowed = any(
                self._matches_pattern(tool_name, pattern) for pattern in self.allowed_tools
            )
            if not allowed:
                raise PolicyViolation(
                    f"Tool '{tool_name}' is not in allowed tools list",
                    violation_type=ViolationType.TOOL_NOT_ALLOWED.value,
                    details={"tool": tool_name, "allowed": self.allowed_tools},
                )

    def check_time_restriction(self, tool_name: str, dt: datetime | None = None) -> None:
        """Check if a tool call is within allowed time window.

        Args:
            tool_name: Name of the tool to check.
            dt: Datetime to check against. Defaults to now.

        Raises:
            PolicyViolation: If outside allowed time window.
        """
        matching_patterns = self._find_matching_patterns(tool_name, self._time_windows)

        if not matching_patterns:
            return  # No time restriction applies

        # Use most specific matching pattern
        pattern = matching_patterns[0]
        window = self._time_windows[pattern]

        if not window.is_within(dt):
            dt = dt or datetime.now()
            raise PolicyViolation(
                f"Tool '{tool_name}' is time-restricted. "
                f"Allowed: {self.time_restrictions[pattern]}, "
                f"Current: {dt.strftime('%H:%M')}",
                violation_type=ViolationType.TIME_RESTRICTED.value,
                details={
                    "tool": tool_name,
                    "pattern": pattern,
                    "allowed_window": self.time_restrictions[pattern],
                    "current_time": dt.strftime("%H:%M"),
                },
            )

    def check_rate_limit(self, tool_name: str) -> None:
        """Check if a tool call is within rate limits.

        Args:
            tool_name: Name of the tool to check.

        Raises:
            PolicyViolation: If rate limit exceeded.
        """
        matching_patterns = self._find_matching_patterns(tool_name, self._rate_limiters)

        if not matching_patterns:
            return  # No rate limit applies

        # Use most specific matching pattern
        pattern = matching_patterns[0]
        limiter = self._rate_limiters[pattern]

        if not limiter.acquire():
            raise PolicyViolation(
                f"Rate limit exceeded for tool '{tool_name}'. Limit: {self.rate_limits[pattern]}",
                violation_type=ViolationType.RATE_LIMITED.value,
                details={
                    "tool": tool_name,
                    "pattern": pattern,
                    "limit": self.rate_limits[pattern],
                    "remaining": limiter.remaining(),
                },
            )

    def check_agent_identity(self, agent: AgentIdentity | None) -> None:
        """Check if agent identity meets policy requirements.

        Args:
            agent: Agent identity to check.

        Raises:
            PolicyViolation: If agent identity requirements not met.
        """
        if self.require_agent_id and agent is None:
            raise PolicyViolation(
                "Agent identity required but not provided",
                violation_type="agent_required",
                details={},
            )

        if agent and self.allowed_roles:
            has_allowed_role = any(agent.has_role(role) for role in self.allowed_roles)
            if not has_allowed_role:
                raise PolicyViolation(
                    f"Agent does not have required role. "
                    f"Required: one of {self.allowed_roles}, "
                    f"Agent roles: {agent.roles}",
                    violation_type="role_required",
                    details={
                        "required_roles": self.allowed_roles,
                        "agent_roles": agent.roles,
                    },
                )

    def check(
        self,
        tool_name: str,
        agent: AgentIdentity | None = None,
        dt: datetime | None = None,
    ) -> None:
        """Run all policy checks for a tool call.

        Args:
            tool_name: Name of the tool to check.
            agent: Agent identity (optional).
            dt: Datetime for time checks (defaults to now).

        Raises:
            PolicyViolation: If any policy check fails.
        """
        logger.debug(
            "policy_check",
            tool=tool_name,
            agent_id=agent.agent_id if agent else None,
        )

        # Check agent identity
        self.check_agent_identity(agent)

        # Check allow/deny lists
        self.check_tool_allowed(tool_name)

        # Check time restrictions
        self.check_time_restriction(tool_name, dt)

        # Check rate limits
        self.check_rate_limit(tool_name)

        logger.debug("policy_check_passed", tool=tool_name)


# Predefined policies for common use cases


PERMISSIVE_POLICY = SecurityPolicy()
"""Allows all tools with no restrictions."""


def _get_strict_capability_policy() -> CapabilityPolicy | None:
    """Lazy import capability policy for STRICT_POLICY."""
    try:
        from .capabilities import Capability, CapabilityPolicy

        return CapabilityPolicy(
            granted=Capability.FILESYSTEM_READ
            | Capability.NETWORK_HTTPS
            | Capability.DATABASE_READ,
            denied=Capability.PROCESS_SHELL | Capability.FILESYSTEM_DELETE,
            require_sandbox_for=Capability.DANGEROUS,
        )
    except ImportError:
        return None


def _get_read_only_capability_policy() -> CapabilityPolicy | None:
    """Lazy import capability policy for READ_ONLY_POLICY."""
    try:
        from .capabilities import Capability, CapabilityPolicy

        return CapabilityPolicy(
            granted=Capability.FILESYSTEM_READ
            | Capability.DATABASE_READ
            | Capability.NETWORK_HTTPS,
            denied=Capability.FILESYSTEM_WRITE
            | Capability.FILESYSTEM_DELETE
            | Capability.DATABASE_WRITE,
            require_sandbox_for=Capability.PROCESS_EXEC | Capability.PROCESS_SHELL,
        )
    except ImportError:
        return None


STRICT_POLICY = SecurityPolicy(
    require_agent_id=True,
    rate_limits={"*": "100/hour"},
    capability_policy=_get_strict_capability_policy(),
)
"""Requires agent identity, applies global rate limit, and enforces strict capabilities.

V0.4.0: Adds capability policy that:
- Grants: FILESYSTEM_READ, NETWORK_HTTPS, DATABASE_READ
- Denies: PROCESS_SHELL, FILESYSTEM_DELETE
- Requires sandbox for: DANGEROUS operations
"""


READ_ONLY_POLICY = SecurityPolicy(
    allowed_tools=["read_*", "get_*", "list_*", "search_*"],
    denied_tools=["write_*", "delete_*", "update_*", "create_*"],
    capability_policy=_get_read_only_capability_policy(),
)
"""Only allows read operations with matching capability policy.

V0.4.0: Adds capability policy that denies write/delete capabilities.
"""


BUSINESS_HOURS_POLICY = SecurityPolicy(
    time_restrictions={
        "delete_*": "09:00-17:00",
        "drop_*": "09:00-17:00",
        "*_production": "09:00-17:00",
    },
)
"""Restricts dangerous operations to business hours."""
