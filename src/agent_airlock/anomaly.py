"""Anomaly detection for tool call patterns (V0.4.1).

Monitors tool call patterns per session and flags/blocks anomalous behavior.
Detects call rate spikes, endpoint diversity spikes, high error rates,
and sequential blocked calls that may indicate agent misbehavior or attacks.

THREAD SAFETY:
    This module is thread-safe. All mutable state is protected by
    threading.Lock. The sliding window uses collections.deque for
    efficient O(1) append/popleft operations.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger("agent-airlock.anomaly")


class AnomalyType(str, Enum):
    """Types of detected anomalies."""

    CALL_RATE_SPIKE = "call_rate_spike"
    ENDPOINT_DIVERSITY_SPIKE = "endpoint_diversity_spike"
    HIGH_ERROR_RATE = "high_error_rate"
    CONSECUTIVE_BLOCKED = "consecutive_blocked"


class AnomalySeverity(str, Enum):
    """Severity levels for anomaly events."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AnomalyDetectorConfig:
    """Configuration for tool call anomaly detection.

    Example:
        config = AnomalyDetectorConfig(
            window_seconds=60.0,
            max_calls_per_window=50,
            max_error_rate=0.5,
        )
        detector = AnomalyDetector(config)

    Attributes:
        window_seconds: Sliding window duration for rate analysis.
        max_calls_per_window: Maximum tool calls allowed per window.
        max_unique_endpoints_per_window: Maximum distinct URLs per window.
        max_error_rate: Block if error rate exceeds this threshold (0.0-1.0).
        max_consecutive_blocked: Block session after N consecutive blocks.
        auto_block_duration_seconds: Duration of automatic session block.
        enabled: If False, detector passes everything without checking.
    """

    window_seconds: float = 60.0
    max_calls_per_window: int = 50
    max_unique_endpoints_per_window: int = 10
    max_error_rate: float = 0.5
    max_consecutive_blocked: int = 5
    auto_block_duration_seconds: float = 300.0
    enabled: bool = True


@dataclass
class AnomalyEvent:
    """Represents a detected anomaly.

    Attributes:
        event_type: The type of anomaly detected.
        tool_name: The tool that triggered the anomaly.
        session_id: The session where the anomaly was detected.
        timestamp: When the anomaly was detected.
        details: Additional details about the anomaly.
        severity: Severity level of the anomaly.
    """

    event_type: AnomalyType
    tool_name: str
    session_id: str
    timestamp: float = field(default_factory=time.time)
    details: dict[str, Any] = field(default_factory=dict)
    severity: AnomalySeverity = AnomalySeverity.MEDIUM


@dataclass
class _CallRecord:
    """Internal record of a single tool call."""

    timestamp: float
    tool_name: str
    was_blocked: bool
    endpoint_url: str | None


@dataclass
class _SessionState:
    """Internal state for a session's anomaly tracking."""

    calls: deque[_CallRecord] = field(default_factory=deque)
    consecutive_blocked: int = 0
    blocked_until: float = 0.0


class AnomalyDetector:
    """Monitors tool call patterns and detects anomalous behavior.

    Detects:
    - Call rate spikes (too many calls in a time window)
    - Endpoint diversity spikes (tool suddenly hitting many different URLs)
    - High error rates (repeated failures suggest probing)
    - Sequential blocked calls (agent ignoring security boundaries)

    Example:
        detector = AnomalyDetector(AnomalyDetectorConfig(
            max_calls_per_window=50,
            max_error_rate=0.5,
        ))

        event = detector.record_call("my_tool", "session-1", {"url": "..."})
        if event and event.severity in (AnomalySeverity.HIGH, AnomalySeverity.CRITICAL):
            print(f"Anomaly: {event.event_type}")

    Thread Safety:
        All public methods are thread-safe via internal locking.
    """

    def __init__(self, config: AnomalyDetectorConfig | None = None) -> None:
        self._config = config or AnomalyDetectorConfig()
        self._sessions: dict[str, _SessionState] = {}
        self._lock = threading.Lock()

    @property
    def config(self) -> AnomalyDetectorConfig:
        """Get the detector configuration."""
        return self._config

    def record_call(
        self,
        tool_name: str,
        session_id: str,
        params: dict[str, Any] | None = None,
        was_blocked: bool = False,
        endpoint_url: str | None = None,
    ) -> AnomalyEvent | None:
        """Record a tool call and return an AnomalyEvent if anomalous.

        Args:
            tool_name: Name of the tool being called.
            session_id: Session identifier.
            params: Tool call parameters (unused currently, reserved for future).
            was_blocked: Whether this call was blocked by security policy.
            endpoint_url: URL accessed by this call, if any.

        Returns:
            AnomalyEvent if anomalous behavior detected, None otherwise.
        """
        if not self._config.enabled:
            return None

        with self._lock:
            state = self._sessions.setdefault(session_id, _SessionState())
            now = time.time()

            # Record the call
            record = _CallRecord(
                timestamp=now,
                tool_name=tool_name,
                was_blocked=was_blocked,
                endpoint_url=endpoint_url,
            )
            state.calls.append(record)

            # Track consecutive blocked
            if was_blocked:
                state.consecutive_blocked += 1
            else:
                state.consecutive_blocked = 0

            # Prune old entries outside window
            cutoff = now - self._config.window_seconds
            while state.calls and state.calls[0].timestamp < cutoff:
                state.calls.popleft()

            # Check anomalies in priority order
            event = self._check_consecutive_blocked(state, tool_name, session_id, now)
            if event:
                return event

            event = self._check_call_rate(state, tool_name, session_id, now)
            if event:
                return event

            event = self._check_error_rate(state, tool_name, session_id, now)
            if event:
                return event

            event = self._check_endpoint_diversity(state, tool_name, session_id, now)
            if event:
                return event

            return None

    def is_session_blocked(self, session_id: str) -> bool:
        """Check if a session is currently auto-blocked.

        Args:
            session_id: Session identifier.

        Returns:
            True if session is blocked, False otherwise.
        """
        if not self._config.enabled:
            return False

        with self._lock:
            state = self._sessions.get(session_id)
            if state is None:
                return False
            return state.blocked_until > time.time()

    def get_session_stats(self, session_id: str) -> dict[str, Any]:
        """Get current anomaly stats for a session.

        Args:
            session_id: Session identifier.

        Returns:
            Dictionary with session statistics.
        """
        with self._lock:
            state = self._sessions.get(session_id)
            if state is None:
                return {
                    "calls_in_window": 0,
                    "blocked_calls": 0,
                    "unique_endpoints": 0,
                    "consecutive_blocked": 0,
                    "is_blocked": False,
                }

            now = time.time()
            calls_in_window = list(state.calls)
            blocked_calls = sum(1 for c in calls_in_window if c.was_blocked)
            unique_endpoints = len({c.endpoint_url for c in calls_in_window if c.endpoint_url})

            return {
                "calls_in_window": len(calls_in_window),
                "blocked_calls": blocked_calls,
                "unique_endpoints": unique_endpoints,
                "consecutive_blocked": state.consecutive_blocked,
                "is_blocked": state.blocked_until > now,
            }

    def reset_session(self, session_id: str) -> None:
        """Reset anomaly tracking for a session.

        Args:
            session_id: Session identifier.
        """
        with self._lock:
            self._sessions.pop(session_id, None)
            logger.info("session_anomaly_reset", session_id=session_id)

    def _check_call_rate(
        self,
        state: _SessionState,
        tool_name: str,
        session_id: str,
        now: float,
    ) -> AnomalyEvent | None:
        """Check for call rate spike."""
        if len(state.calls) > self._config.max_calls_per_window:
            self._auto_block(state, now)
            logger.warning(
                "anomaly_detected",
                event_type=AnomalyType.CALL_RATE_SPIKE.value,
                session_id=session_id,
                calls_in_window=len(state.calls),
                max_allowed=self._config.max_calls_per_window,
            )
            return AnomalyEvent(
                event_type=AnomalyType.CALL_RATE_SPIKE,
                tool_name=tool_name,
                session_id=session_id,
                timestamp=now,
                severity=AnomalySeverity.HIGH,
                details={
                    "calls_in_window": len(state.calls),
                    "max_allowed": self._config.max_calls_per_window,
                    "window_seconds": self._config.window_seconds,
                },
            )
        return None

    def _check_endpoint_diversity(
        self,
        state: _SessionState,
        tool_name: str,
        session_id: str,
        now: float,
    ) -> AnomalyEvent | None:
        """Check for endpoint diversity spike."""
        unique_endpoints = {c.endpoint_url for c in state.calls if c.endpoint_url}
        if len(unique_endpoints) > self._config.max_unique_endpoints_per_window:
            logger.warning(
                "anomaly_detected",
                event_type=AnomalyType.ENDPOINT_DIVERSITY_SPIKE.value,
                session_id=session_id,
                unique_endpoints=len(unique_endpoints),
                max_allowed=self._config.max_unique_endpoints_per_window,
            )
            return AnomalyEvent(
                event_type=AnomalyType.ENDPOINT_DIVERSITY_SPIKE,
                tool_name=tool_name,
                session_id=session_id,
                timestamp=now,
                severity=AnomalySeverity.MEDIUM,
                details={
                    "unique_endpoints": len(unique_endpoints),
                    "max_allowed": self._config.max_unique_endpoints_per_window,
                },
            )
        return None

    def _check_error_rate(
        self,
        state: _SessionState,
        tool_name: str,
        session_id: str,
        now: float,
    ) -> AnomalyEvent | None:
        """Check for high error rate."""
        total = len(state.calls)
        if total < 5:  # Need minimum sample size
            return None

        blocked = sum(1 for c in state.calls if c.was_blocked)
        error_rate = blocked / total

        if error_rate > self._config.max_error_rate:
            self._auto_block(state, now)
            logger.warning(
                "anomaly_detected",
                event_type=AnomalyType.HIGH_ERROR_RATE.value,
                session_id=session_id,
                error_rate=round(error_rate, 2),
                max_allowed=self._config.max_error_rate,
            )
            return AnomalyEvent(
                event_type=AnomalyType.HIGH_ERROR_RATE,
                tool_name=tool_name,
                session_id=session_id,
                timestamp=now,
                severity=AnomalySeverity.HIGH,
                details={
                    "error_rate": round(error_rate, 2),
                    "blocked_calls": blocked,
                    "total_calls": total,
                    "max_error_rate": self._config.max_error_rate,
                },
            )
        return None

    def _check_consecutive_blocked(
        self,
        state: _SessionState,
        tool_name: str,
        session_id: str,
        now: float,
    ) -> AnomalyEvent | None:
        """Check for consecutive blocked calls."""
        if state.consecutive_blocked >= self._config.max_consecutive_blocked:
            self._auto_block(state, now)
            logger.warning(
                "anomaly_detected",
                event_type=AnomalyType.CONSECUTIVE_BLOCKED.value,
                session_id=session_id,
                consecutive=state.consecutive_blocked,
                max_allowed=self._config.max_consecutive_blocked,
            )
            return AnomalyEvent(
                event_type=AnomalyType.CONSECUTIVE_BLOCKED,
                tool_name=tool_name,
                session_id=session_id,
                timestamp=now,
                severity=AnomalySeverity.CRITICAL,
                details={
                    "consecutive_blocked": state.consecutive_blocked,
                    "max_allowed": self._config.max_consecutive_blocked,
                },
            )
        return None

    def _auto_block(self, state: _SessionState, now: float) -> None:
        """Auto-block a session."""
        state.blocked_until = now + self._config.auto_block_duration_seconds
        logger.warning(
            "session_auto_blocked",
            duration_seconds=self._config.auto_block_duration_seconds,
        )
