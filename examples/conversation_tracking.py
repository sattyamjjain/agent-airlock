"""Conversation Tracking Example - Multi-agent conversation validation.

This example demonstrates how to track tool calls across conversation turns,
implementing cooldowns, quotas, and sequential requirements.

Run with: python examples/conversation_tracking.py
"""

from __future__ import annotations

from agent_airlock import (
    ConversationConstraints,
    ConversationTracker,
    get_conversation_tracker,
    reset_conversation_tracker,
)


def demonstrate_cooldown_after() -> None:
    """Demonstrate cooldown after sensitive operations."""
    print("\n1. Cooldown After Sensitive Operations:")
    print("-" * 40)

    tracker = ConversationTracker()

    # Constraint: 60-second cooldown after delete_user
    constraints = ConversationConstraints(
        cooldown_after={"delete_user": 60},  # Block all tools for 60s after delete
    )

    session_id = "session-001"

    # First, check if we can call delete_user
    can_delete, reason = tracker.should_block(session_id, "delete_user", constraints)
    print(f"Can call delete_user: {not can_delete}")

    # Simulate calling delete_user
    tracker.record_call(session_id, "delete_user", blocked=False)
    print("Called delete_user successfully")

    # Now try to call another tool
    can_call, reason = tracker.should_block(session_id, "list_users", constraints)
    print(f"Can call list_users after delete: {not can_call}")
    if reason:
        print(f"Reason: {reason}")


def demonstrate_tool_quotas() -> None:
    """Demonstrate per-tool call quotas."""
    print("\n2. Per-Tool Call Quotas:")
    print("-" * 40)

    tracker = ConversationTracker()

    # Constraint: Can only call drop_table once per conversation
    constraints = ConversationConstraints(
        max_calls_per_tool={"drop_table": 1},
    )

    session_id = "session-002"

    # First call should work
    can_call, _ = tracker.should_block(session_id, "drop_table", constraints)
    print(f"First drop_table allowed: {not can_call}")
    tracker.record_call(session_id, "drop_table", blocked=False)

    # Second call should be blocked
    can_call, reason = tracker.should_block(session_id, "drop_table", constraints)
    print(f"Second drop_table allowed: {not can_call}")
    if reason:
        print(f"Reason: {reason}")


def demonstrate_required_sequence() -> None:
    """Demonstrate required tool sequence."""
    print("\n3. Required Tool Sequence:")
    print("-" * 40)

    tracker = ConversationTracker()

    # Constraint: Must call get_user and confirm before delete_user
    constraints = ConversationConstraints(
        required_before={
            "delete_user": ["get_user", "confirm_delete"],
        },
    )

    session_id = "session-003"

    # Try to delete without prerequisites
    can_delete, reason = tracker.should_block(session_id, "delete_user", constraints)
    print(f"Can delete without prerequisites: {not can_delete}")
    print(f"Missing: {reason}")

    # Call get_user
    tracker.record_call(session_id, "get_user", blocked=False)
    print("\nCalled get_user...")

    can_delete, reason = tracker.should_block(session_id, "delete_user", constraints)
    print(f"Can delete after get_user: {not can_delete}")

    # Call confirm_delete
    tracker.record_call(session_id, "confirm_delete", blocked=False)
    print("Called confirm_delete...")

    can_delete, _ = tracker.should_block(session_id, "delete_user", constraints)
    print(f"Can delete after both: {not can_delete}")


def demonstrate_blocked_ratio() -> None:
    """Demonstrate blocking based on error ratio."""
    print("\n4. Blocked Call Ratio Detection:")
    print("-" * 40)

    tracker = ConversationTracker()

    # Constraint: Block if more than 50% of calls are blocked
    constraints = ConversationConstraints(
        max_blocked_ratio=0.5,
    )

    session_id = "session-004"

    # Record some calls
    tracker.record_call(session_id, "tool_1", blocked=False)
    print("Call 1: Success")

    tracker.record_call(session_id, "tool_2", blocked=True)
    print("Call 2: Blocked (validation error)")

    # Check if we can continue
    state = tracker.get_state(session_id)
    print(f"Current ratio: {state.blocked_count}/{state.call_count} = "
          f"{state.blocked_count/state.call_count:.0%}")

    can_continue, reason = tracker.should_block(session_id, "tool_3", constraints)
    print(f"Can continue: {not can_continue}")
    if reason:
        print(f"Reason: {reason}")


def demonstrate_conversation_stats() -> None:
    """Demonstrate conversation statistics."""
    print("\n5. Conversation Statistics:")
    print("-" * 40)

    tracker = ConversationTracker()
    constraints = ConversationConstraints()

    # Simulate multiple sessions
    for session_num in range(3):
        session_id = f"session-{session_num:03d}"
        for call_num in range(5):
            tracker.record_call(
                session_id,
                f"tool_{call_num}",
                blocked=(call_num % 3 == 0),  # Every 3rd call blocked
            )

    stats = tracker.get_stats()
    print(f"Active sessions: {stats['active_sessions']}")
    print(f"Total calls: {stats['total_calls']}")
    print(f"Total blocked: {stats['total_blocked']}")
    print(f"Block ratio: {stats['blocked_ratio']:.1%}")


def demonstrate_manual_blocking() -> None:
    """Demonstrate manual conversation blocking."""
    print("\n6. Manual Conversation Blocking:")
    print("-" * 40)

    tracker = ConversationTracker()
    constraints = ConversationConstraints()

    session_id = "session-bad-actor"

    # Manually block a suspicious session
    tracker.block_conversation(
        session_id,
        duration_seconds=300,  # 5 minutes
        reason="Suspicious activity detected",
    )

    can_call, reason = tracker.should_block(session_id, "any_tool", constraints)
    print(f"Session blocked: {can_call}")
    print(f"Reason: {reason}")

    # Unblock
    tracker.unblock_conversation(session_id)
    can_call, _ = tracker.should_block(session_id, "any_tool", constraints)
    print(f"After unblock, can call: {not can_call}")


def demonstrate_global_tracker() -> None:
    """Demonstrate the global tracker singleton."""
    print("\n7. Global Tracker (Singleton):")
    print("-" * 40)

    # Reset for clean state
    reset_conversation_tracker()

    # Get global tracker
    tracker1 = get_conversation_tracker()
    tracker2 = get_conversation_tracker()

    print(f"Same instance: {tracker1 is tracker2}")

    # Use it
    tracker1.record_call("global-session", "test_tool", blocked=False)
    state = tracker2.get_state("global-session")
    print(f"Calls in session: {state.call_count if state else 0}")


def main() -> None:
    """Run conversation tracking examples."""
    print("=" * 60)
    print("Conversation Tracking Example")
    print("=" * 60)

    demonstrate_cooldown_after()
    demonstrate_tool_quotas()
    demonstrate_required_sequence()
    demonstrate_blocked_ratio()
    demonstrate_conversation_stats()
    demonstrate_manual_blocking()
    demonstrate_global_tracker()

    print("\n" + "=" * 60)
    print("Conversation tracking examples completed!")
    print("\nKey features demonstrated:")
    print("- Cooldown after sensitive operations")
    print("- Per-tool call quotas")
    print("- Required tool sequences")
    print("- Error ratio detection")
    print("- Manual session blocking")
    print("- Global tracker singleton")


if __name__ == "__main__":
    main()
