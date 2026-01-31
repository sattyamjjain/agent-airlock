"""Tests for multi-agent conversation validation and tracking."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from agent_airlock.conversation import (
    ConversationConstraints,
    ConversationState,
    ConversationTracker,
    ToolCall,
    get_conversation_tracker,
    reset_conversation_tracker,
)


class TestToolCall:
    """Tests for ToolCall dataclass."""

    def test_tool_call_creation(self) -> None:
        """ToolCall can be created with required fields."""
        call = ToolCall(
            tool_name="test_tool",
            timestamp=datetime.now(timezone.utc),
            blocked=False,
        )
        assert call.tool_name == "test_tool"
        assert not call.blocked
        assert call.block_reason is None

    def test_tool_call_with_block_reason(self) -> None:
        """ToolCall can store block reason."""
        call = ToolCall(
            tool_name="blocked_tool",
            timestamp=datetime.now(timezone.utc),
            blocked=True,
            block_reason="Rate limit exceeded",
        )
        assert call.blocked
        assert call.block_reason == "Rate limit exceeded"


class TestConversationState:
    """Tests for ConversationState dataclass."""

    def test_empty_state(self) -> None:
        """Empty state has correct initial values."""
        state = ConversationState(session_id="test-session")
        assert state.call_count == 0
        assert state.blocked_count == 0
        assert state.success_count == 0
        assert state.last_call is None
        assert not state.is_blocked

    def test_call_counts(self) -> None:
        """Call counts are calculated correctly."""
        state = ConversationState(session_id="test-session")
        now = datetime.now(timezone.utc)

        state.tool_calls = [
            ToolCall(tool_name="tool1", timestamp=now, blocked=False),
            ToolCall(tool_name="tool2", timestamp=now, blocked=True),
            ToolCall(tool_name="tool3", timestamp=now, blocked=False),
        ]

        assert state.call_count == 3
        assert state.blocked_count == 1
        assert state.success_count == 2

    def test_last_call(self) -> None:
        """last_call returns the most recent call."""
        state = ConversationState(session_id="test-session")
        now = datetime.now(timezone.utc)

        state.tool_calls = [
            ToolCall(tool_name="first", timestamp=now, blocked=False),
            ToolCall(tool_name="last", timestamp=now, blocked=False),
        ]

        assert state.last_call is not None
        assert state.last_call.tool_name == "last"

    def test_is_blocked(self) -> None:
        """is_blocked returns True when blocked_until is in the future."""
        state = ConversationState(session_id="test-session")

        # Not blocked by default
        assert not state.is_blocked

        # Blocked until future
        state.blocked_until = datetime.now(timezone.utc) + timedelta(seconds=60)
        assert state.is_blocked

        # Not blocked if blocked_until is in the past
        state.blocked_until = datetime.now(timezone.utc) - timedelta(seconds=1)
        assert not state.is_blocked

    def test_get_calls_for_tool(self) -> None:
        """get_calls_for_tool filters by tool name."""
        state = ConversationState(session_id="test-session")
        now = datetime.now(timezone.utc)

        state.tool_calls = [
            ToolCall(tool_name="tool_a", timestamp=now, blocked=False),
            ToolCall(tool_name="tool_b", timestamp=now, blocked=False),
            ToolCall(tool_name="tool_a", timestamp=now, blocked=True),
        ]

        tool_a_calls = state.get_calls_for_tool("tool_a")
        assert len(tool_a_calls) == 2

        tool_b_calls = state.get_calls_for_tool("tool_b")
        assert len(tool_b_calls) == 1

    def test_get_successful_calls_for_tool(self) -> None:
        """get_successful_calls_for_tool filters by tool name and success."""
        state = ConversationState(session_id="test-session")
        now = datetime.now(timezone.utc)

        state.tool_calls = [
            ToolCall(tool_name="tool_a", timestamp=now, blocked=False),
            ToolCall(tool_name="tool_a", timestamp=now, blocked=True),
            ToolCall(tool_name="tool_a", timestamp=now, blocked=False),
        ]

        successful = state.get_successful_calls_for_tool("tool_a")
        assert len(successful) == 2


class TestConversationTracker:
    """Tests for ConversationTracker."""

    def setup_method(self) -> None:
        """Reset global tracker before each test."""
        reset_conversation_tracker()

    def test_get_or_create_state(self) -> None:
        """get_or_create_state creates new state if not exists."""
        tracker = ConversationTracker()

        state1 = tracker.get_or_create_state("session-1")
        assert state1.session_id == "session-1"

        state2 = tracker.get_or_create_state("session-1")
        assert state1 is state2  # Same instance

    def test_record_call(self) -> None:
        """record_call adds call to conversation state."""
        tracker = ConversationTracker()

        tracker.record_call(
            session_id="session-1",
            tool_name="test_tool",
            blocked=False,
            duration_ms=100.5,
        )

        state = tracker.get_state("session-1")
        assert state is not None
        assert state.call_count == 1
        assert state.tool_calls[0].tool_name == "test_tool"
        assert state.tool_calls[0].duration_ms == 100.5

    def test_clear_session(self) -> None:
        """clear_session removes session state."""
        tracker = ConversationTracker()

        tracker.record_call("session-1", "tool", False)
        assert tracker.get_state("session-1") is not None

        tracker.clear_session("session-1")
        assert tracker.get_state("session-1") is None

    def test_block_conversation(self) -> None:
        """block_conversation blocks the session."""
        tracker = ConversationTracker()

        tracker.block_conversation(
            session_id="session-1",
            duration_seconds=60,
            reason="Too many errors",
        )

        state = tracker.get_state("session-1")
        assert state is not None
        assert state.is_blocked
        assert state.block_reason == "Too many errors"

    def test_unblock_conversation(self) -> None:
        """unblock_conversation removes the block."""
        tracker = ConversationTracker()

        tracker.block_conversation("session-1", 60, "Testing")
        tracker.unblock_conversation("session-1")

        state = tracker.get_state("session-1")
        assert state is not None
        assert not state.is_blocked

    def test_get_stats(self) -> None:
        """get_stats returns correct statistics."""
        tracker = ConversationTracker()

        tracker.record_call("session-1", "tool1", blocked=False)
        tracker.record_call("session-1", "tool2", blocked=True)
        tracker.record_call("session-2", "tool3", blocked=False)

        stats = tracker.get_stats()
        assert stats["active_sessions"] == 2
        assert stats["total_calls"] == 3
        assert stats["total_blocked"] == 1


class TestConversationConstraints:
    """Tests for constraint checking."""

    def setup_method(self) -> None:
        """Reset global tracker before each test."""
        reset_conversation_tracker()

    def test_cooldown_after_blocks_all_tools(self) -> None:
        """cooldown_after blocks all tools after trigger."""
        tracker = ConversationTracker()
        constraints = ConversationConstraints(
            cooldown_after={"delete_user": 60},  # 60 second cooldown after delete
        )

        # Record a successful delete_user call
        tracker.record_call("session-1", "delete_user", blocked=False)

        # Any tool should now be blocked
        should_block, reason = tracker.should_block("session-1", "any_tool", constraints)
        assert should_block
        assert "delete_user" in reason
        assert "Cooldown" in reason

    def test_cooldown_after_only_triggers_on_success(self) -> None:
        """cooldown_after only triggers on successful calls."""
        tracker = ConversationTracker()
        constraints = ConversationConstraints(
            cooldown_after={"delete_user": 60},
        )

        # Record a BLOCKED delete_user call
        tracker.record_call("session-1", "delete_user", blocked=True)

        # Should not trigger cooldown
        should_block, _ = tracker.should_block("session-1", "any_tool", constraints)
        assert not should_block

    def test_tool_cooldowns(self) -> None:
        """tool_cooldowns prevents rapid repeated calls."""
        tracker = ConversationTracker()
        constraints = ConversationConstraints(
            tool_cooldowns={"send_email": 10},  # 10 second cooldown per tool
        )

        # First call should work
        should_block, _ = tracker.should_block("session-1", "send_email", constraints)
        assert not should_block

        tracker.record_call("session-1", "send_email", blocked=False)

        # Second call should be blocked
        should_block, reason = tracker.should_block("session-1", "send_email", constraints)
        assert should_block
        assert "cooldown" in reason.lower()

    def test_max_calls_per_tool(self) -> None:
        """max_calls_per_tool limits tool usage."""
        tracker = ConversationTracker()
        constraints = ConversationConstraints(
            max_calls_per_tool={"delete_database": 1},
        )

        # First call should work
        should_block, _ = tracker.should_block("session-1", "delete_database", constraints)
        assert not should_block

        tracker.record_call("session-1", "delete_database", blocked=False)

        # Second call should be blocked
        should_block, reason = tracker.should_block("session-1", "delete_database", constraints)
        assert should_block
        assert "limit reached" in reason.lower()

    def test_required_before(self) -> None:
        """required_before enforces tool ordering."""
        tracker = ConversationTracker()
        constraints = ConversationConstraints(
            required_before={"delete_user": ["get_user", "confirm_delete"]},
        )

        # Can't delete without prerequisites
        should_block, reason = tracker.should_block("session-1", "delete_user", constraints)
        assert should_block
        assert "requires prior calls" in reason.lower()

        # Call get_user
        tracker.record_call("session-1", "get_user", blocked=False)

        # Still blocked - need confirm_delete
        should_block, reason = tracker.should_block("session-1", "delete_user", constraints)
        assert should_block
        assert "confirm_delete" in reason

        # Call confirm_delete
        tracker.record_call("session-1", "confirm_delete", blocked=False)

        # Now delete_user should be allowed
        should_block, _ = tracker.should_block("session-1", "delete_user", constraints)
        assert not should_block

    def test_max_total_calls(self) -> None:
        """max_total_calls limits total conversation calls."""
        tracker = ConversationTracker()
        constraints = ConversationConstraints(max_total_calls=3)

        for i in range(3):
            should_block, _ = tracker.should_block("session-1", f"tool_{i}", constraints)
            assert not should_block
            tracker.record_call("session-1", f"tool_{i}", blocked=False)

        # 4th call should be blocked
        should_block, reason = tracker.should_block("session-1", "tool_4", constraints)
        assert should_block
        assert "limit reached" in reason.lower()

    def test_max_blocked_ratio(self) -> None:
        """max_blocked_ratio blocks when too many calls fail."""
        tracker = ConversationTracker()
        constraints = ConversationConstraints(max_blocked_ratio=0.5)

        # 1 success, 1 blocked = 50% blocked
        tracker.record_call("session-1", "tool1", blocked=False)
        tracker.record_call("session-1", "tool2", blocked=True)

        # At exactly 50%, should be blocked
        should_block, reason = tracker.should_block("session-1", "tool3", constraints)
        assert should_block
        assert "blocked calls" in reason.lower()

    def test_conversation_blocked_state(self) -> None:
        """Manually blocked conversations reject all calls."""
        tracker = ConversationTracker()
        constraints = ConversationConstraints()

        tracker.block_conversation("session-1", 60, "Manual block")

        should_block, reason = tracker.should_block("session-1", "any_tool", constraints)
        assert should_block
        assert "blocked until" in reason.lower()


class TestGlobalTracker:
    """Tests for global tracker functions."""

    def setup_method(self) -> None:
        """Reset global tracker before each test."""
        reset_conversation_tracker()

    def test_get_conversation_tracker_singleton(self) -> None:
        """get_conversation_tracker returns same instance."""
        tracker1 = get_conversation_tracker()
        tracker2 = get_conversation_tracker()
        assert tracker1 is tracker2

    def test_reset_conversation_tracker(self) -> None:
        """reset_conversation_tracker creates new instance."""
        tracker1 = get_conversation_tracker()
        tracker1.record_call("session-1", "tool", False)

        reset_conversation_tracker()
        tracker2 = get_conversation_tracker()

        assert tracker1 is not tracker2
        assert tracker2.get_state("session-1") is None


class TestThreadSafety:
    """Tests for thread safety."""

    def test_concurrent_record_calls(self) -> None:
        """Multiple threads can record calls safely."""
        import threading

        tracker = ConversationTracker()
        errors: list[Exception] = []

        def record_calls(session_id: str) -> None:
            try:
                for i in range(100):
                    tracker.record_call(session_id, f"tool_{i}", blocked=False)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=record_calls, args=(f"session-{i}",)) for i in range(10)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        stats = tracker.get_stats()
        assert stats["active_sessions"] == 10
        assert stats["total_calls"] == 1000


class TestCleanup:
    """Tests for automatic cleanup."""

    def test_expired_sessions_cleanup(self) -> None:
        """Expired sessions are cleaned up."""
        # Use very short TTL for testing
        tracker = ConversationTracker(ttl_seconds=0)
        tracker._cleanup_interval = 0  # Force cleanup on every operation

        tracker.record_call("session-1", "tool", False)

        # Force a small delay to ensure TTL expires
        time.sleep(0.01)

        # Next operation should trigger cleanup
        tracker.get_or_create_state("session-2")

        # session-1 should be gone
        assert tracker.get_state("session-1") is None
        assert tracker.get_state("session-2") is not None
