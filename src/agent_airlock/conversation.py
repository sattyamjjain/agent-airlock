"""Multi-agent conversation validation and state tracking.

This module provides conversation-level state tracking for AI agent tool calls,
enabling cross-turn validation rules like:
- Cooldowns after sensitive operations (e.g., block calls after delete)
- Rate limiting across conversation turns
- Sequential operation requirements
- Conversation-level quotas
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import structlog

logger = structlog.get_logger("agent-airlock.conversation")


@dataclass
class ToolCall:
    """Record of a single tool call within a conversation."""

    tool_name: str
    timestamp: datetime
    blocked: bool
    block_reason: str | None = None
    args_hash: str | None = None
    result_type: str | None = None
    duration_ms: float | None = None


@dataclass
class ConversationState:
    """State for a single conversation/session."""

    session_id: str
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    tool_calls: list[ToolCall] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    blocked_until: datetime | None = None
    block_reason: str | None = None

    @property
    def call_count(self) -> int:
        """Total number of tool calls in this conversation."""
        return len(self.tool_calls)

    @property
    def blocked_count(self) -> int:
        """Number of blocked tool calls in this conversation."""
        return sum(1 for call in self.tool_calls if call.blocked)

    @property
    def success_count(self) -> int:
        """Number of successful tool calls in this conversation."""
        return sum(1 for call in self.tool_calls if not call.blocked)

    @property
    def last_call(self) -> ToolCall | None:
        """Most recent tool call, if any."""
        return self.tool_calls[-1] if self.tool_calls else None

    @property
    def is_blocked(self) -> bool:
        """Check if the conversation is currently blocked."""
        if self.blocked_until is None:
            return False
        return datetime.now(timezone.utc) < self.blocked_until

    def get_calls_for_tool(self, tool_name: str) -> list[ToolCall]:
        """Get all calls for a specific tool."""
        return [call for call in self.tool_calls if call.tool_name == tool_name]

    def get_successful_calls_for_tool(self, tool_name: str) -> list[ToolCall]:
        """Get all successful calls for a specific tool."""
        return [
            call for call in self.tool_calls if call.tool_name == tool_name and not call.blocked
        ]


@dataclass
class ConversationConstraints:
    """Constraints that can be applied at the conversation level.

    Attributes:
        cooldown_after: Dict mapping tool names to cooldown seconds.
            After a tool executes successfully, all tools are blocked for that duration.
            Example: {"delete_user": 300} blocks everything for 5 minutes after delete_user.
        tool_cooldowns: Dict mapping tool names to per-tool cooldown seconds.
            A specific tool can't be called again within this duration.
            Example: {"send_email": 60} prevents send_email more than once per minute.
        max_calls_per_tool: Dict mapping tool names to maximum call counts per conversation.
            Example: {"delete_database": 1} allows only one delete_database per conversation.
        required_before: Dict mapping tool names to lists of required prior tools.
            Example: {"delete_user": ["get_user"]} requires get_user before delete_user.
        max_total_calls: Maximum total tool calls allowed per conversation.
        max_blocked_ratio: Maximum ratio of blocked calls before blocking conversation.
            Example: 0.5 means if 50%+ calls are blocked, block the conversation.
    """

    cooldown_after: dict[str, int] = field(default_factory=dict)
    tool_cooldowns: dict[str, int] = field(default_factory=dict)
    max_calls_per_tool: dict[str, int] = field(default_factory=dict)
    required_before: dict[str, list[str]] = field(default_factory=dict)
    max_total_calls: int | None = None
    max_blocked_ratio: float | None = None


class ConversationTracker:
    """Thread-safe conversation state tracker.

    Tracks tool calls across multiple conversations/sessions and enforces
    conversation-level constraints.

    Example:
        tracker = ConversationTracker()
        constraints = ConversationConstraints(
            cooldown_after={"delete_user": 300},  # 5 min cooldown after delete
            max_calls_per_tool={"drop_table": 1},  # Only one drop per conversation
        )

        # Check before allowing a tool call
        should_block, reason = tracker.should_block(
            session_id="session-123",
            tool_name="delete_user",
            constraints=constraints,
        )

        # Record the call after execution
        tracker.record_call(
            session_id="session-123",
            tool_name="delete_user",
            blocked=False,
        )
    """

    def __init__(self, ttl_seconds: int = 3600) -> None:
        """Initialize the tracker.

        Args:
            ttl_seconds: Time-to-live for conversation state in seconds.
                         Conversations older than this are cleaned up.
        """
        self._sessions: dict[str, ConversationState] = {}
        self._lock = threading.RLock()
        self._ttl_seconds = ttl_seconds
        self._last_cleanup = time.time()
        self._cleanup_interval = 300  # Cleanup every 5 minutes

    def _maybe_cleanup(self) -> None:
        """Clean up expired sessions if cleanup interval has passed."""
        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return

        self._last_cleanup = now
        cutoff = datetime.now(timezone.utc).timestamp() - self._ttl_seconds
        expired = [
            sid for sid, state in self._sessions.items() if state.created_at.timestamp() < cutoff
        ]

        for sid in expired:
            del self._sessions[sid]

        if expired:
            logger.debug("conversation_cleanup", expired_count=len(expired))

    def get_or_create_state(self, session_id: str) -> ConversationState:
        """Get or create conversation state for a session.

        Args:
            session_id: The session identifier.

        Returns:
            The conversation state for this session.
        """
        with self._lock:
            self._maybe_cleanup()

            if session_id not in self._sessions:
                self._sessions[session_id] = ConversationState(session_id=session_id)
                logger.debug("conversation_created", session_id=session_id)

            return self._sessions[session_id]

    def get_state(self, session_id: str) -> ConversationState | None:
        """Get conversation state if it exists.

        Args:
            session_id: The session identifier.

        Returns:
            The conversation state or None if not found.
        """
        with self._lock:
            return self._sessions.get(session_id)

    def record_call(
        self,
        session_id: str,
        tool_name: str,
        blocked: bool,
        block_reason: str | None = None,
        duration_ms: float | None = None,
        result_type: str | None = None,
    ) -> None:
        """Record a tool call in the conversation state.

        Args:
            session_id: The session identifier.
            tool_name: Name of the tool that was called.
            blocked: Whether the call was blocked.
            block_reason: Reason for blocking, if blocked.
            duration_ms: Execution duration in milliseconds.
            result_type: Type name of the result.
        """
        with self._lock:
            state = self.get_or_create_state(session_id)
            call = ToolCall(
                tool_name=tool_name,
                timestamp=datetime.now(timezone.utc),
                blocked=blocked,
                block_reason=block_reason,
                duration_ms=duration_ms,
                result_type=result_type,
            )
            state.tool_calls.append(call)

            logger.debug(
                "conversation_call_recorded",
                session_id=session_id,
                tool_name=tool_name,
                blocked=blocked,
                call_count=state.call_count,
            )

    def should_block(
        self,
        session_id: str,
        tool_name: str,
        constraints: ConversationConstraints,
    ) -> tuple[bool, str | None]:
        """Check if a tool call should be blocked based on conversation state.

        Args:
            session_id: The session identifier.
            tool_name: Name of the tool being called.
            constraints: Constraints to apply.

        Returns:
            Tuple of (should_block, reason). If should_block is True,
            reason contains the explanation.
        """
        with self._lock:
            state = self.get_or_create_state(session_id)
            now = datetime.now(timezone.utc)

            # Check if conversation is blocked
            if state.is_blocked:
                return (
                    True,
                    f"Conversation blocked until {state.blocked_until}: {state.block_reason}",
                )

            # Check cooldown_after constraints
            for trigger_tool, cooldown_seconds in constraints.cooldown_after.items():
                for call in state.get_successful_calls_for_tool(trigger_tool):
                    elapsed = (now - call.timestamp).total_seconds()
                    if elapsed < cooldown_seconds:
                        remaining = int(cooldown_seconds - elapsed)
                        return True, (
                            f"Cooldown active after '{trigger_tool}': "
                            f"{remaining}s remaining of {cooldown_seconds}s"
                        )

            # Check per-tool cooldowns
            if tool_name in constraints.tool_cooldowns:
                cooldown = constraints.tool_cooldowns[tool_name]
                recent_calls = state.get_successful_calls_for_tool(tool_name)
                if recent_calls:
                    last_call = recent_calls[-1]
                    elapsed = (now - last_call.timestamp).total_seconds()
                    if elapsed < cooldown:
                        remaining = int(cooldown - elapsed)
                        return True, (
                            f"Tool '{tool_name}' cooldown: {remaining}s remaining of {cooldown}s"
                        )

            # Check max calls per tool
            if tool_name in constraints.max_calls_per_tool:
                max_calls = constraints.max_calls_per_tool[tool_name]
                current_calls = len(state.get_successful_calls_for_tool(tool_name))
                if current_calls >= max_calls:
                    return True, (
                        f"Tool '{tool_name}' limit reached: {current_calls}/{max_calls} calls used"
                    )

            # Check required_before constraints
            if tool_name in constraints.required_before:
                required_tools = constraints.required_before[tool_name]
                called_tools = {call.tool_name for call in state.tool_calls if not call.blocked}
                missing = set(required_tools) - called_tools
                if missing:
                    return True, (
                        f"Tool '{tool_name}' requires prior calls to: {', '.join(sorted(missing))}"
                    )

            # Check max total calls
            if (
                constraints.max_total_calls is not None
                and state.success_count >= constraints.max_total_calls
            ):
                return True, (
                    f"Conversation call limit reached: "
                    f"{state.success_count}/{constraints.max_total_calls}"
                )

            # Check blocked ratio
            if constraints.max_blocked_ratio is not None and state.call_count > 0:
                blocked_ratio = state.blocked_count / state.call_count
                if blocked_ratio >= constraints.max_blocked_ratio:
                    return True, (
                        f"Too many blocked calls: "
                        f"{blocked_ratio:.1%} >= {constraints.max_blocked_ratio:.1%} threshold"
                    )

            return False, None

    def block_conversation(
        self,
        session_id: str,
        duration_seconds: int,
        reason: str,
    ) -> None:
        """Manually block a conversation for a duration.

        Args:
            session_id: The session identifier.
            duration_seconds: How long to block the conversation.
            reason: Reason for the block.
        """
        with self._lock:
            state = self.get_or_create_state(session_id)
            from datetime import timedelta

            state.blocked_until = datetime.now(timezone.utc) + timedelta(seconds=duration_seconds)
            state.block_reason = reason

            logger.warning(
                "conversation_blocked",
                session_id=session_id,
                duration_seconds=duration_seconds,
                reason=reason,
            )

    def unblock_conversation(self, session_id: str) -> None:
        """Remove a block from a conversation.

        Args:
            session_id: The session identifier.
        """
        with self._lock:
            state = self.get_state(session_id)
            if state:
                state.blocked_until = None
                state.block_reason = None
                logger.info("conversation_unblocked", session_id=session_id)

    def clear_session(self, session_id: str) -> None:
        """Remove all state for a session.

        Args:
            session_id: The session identifier.
        """
        with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                logger.debug("conversation_cleared", session_id=session_id)

    def get_stats(self) -> dict[str, Any]:
        """Get tracker statistics.

        Returns:
            Dict with tracker statistics.
        """
        with self._lock:
            total_calls = sum(s.call_count for s in self._sessions.values())
            total_blocked = sum(s.blocked_count for s in self._sessions.values())

            return {
                "active_sessions": len(self._sessions),
                "total_calls": total_calls,
                "total_blocked": total_blocked,
                "blocked_ratio": total_blocked / total_calls if total_calls > 0 else 0,
            }


# Global tracker instance
_global_tracker: ConversationTracker | None = None
_tracker_lock = threading.Lock()


def get_conversation_tracker() -> ConversationTracker:
    """Get the global conversation tracker instance.

    Returns:
        The global ConversationTracker.
    """
    global _global_tracker
    with _tracker_lock:
        if _global_tracker is None:
            _global_tracker = ConversationTracker()
        return _global_tracker


def reset_conversation_tracker() -> None:
    """Reset the global conversation tracker (mainly for testing)."""
    global _global_tracker
    with _tracker_lock:
        _global_tracker = None
