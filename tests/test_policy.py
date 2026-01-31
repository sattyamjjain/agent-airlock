"""Tests for the policy module."""

import time
from datetime import datetime

import pytest

from agent_airlock import (
    BUSINESS_HOURS_POLICY,
    PERMISSIVE_POLICY,
    READ_ONLY_POLICY,
    STRICT_POLICY,
    AgentIdentity,
    Airlock,
    PolicyViolation,
    RateLimit,
    SecurityPolicy,
    TimeWindow,
    ViolationType,
)


class TestTimeWindow:
    """Tests for TimeWindow parsing and checking."""

    def test_parse_valid_window(self) -> None:
        window = TimeWindow.parse("09:00-17:00")
        assert window.start_hour == 9
        assert window.start_minute == 0
        assert window.end_hour == 17
        assert window.end_minute == 0

    def test_parse_with_minutes(self) -> None:
        window = TimeWindow.parse("08:30-18:45")
        assert window.start_hour == 8
        assert window.start_minute == 30
        assert window.end_hour == 18
        assert window.end_minute == 45

    def test_parse_overnight_window(self) -> None:
        window = TimeWindow.parse("22:00-06:00")
        assert window.start_hour == 22
        assert window.end_hour == 6

    def test_parse_invalid_format(self) -> None:
        with pytest.raises(ValueError, match="Invalid time window format"):
            TimeWindow.parse("9:00-17:00")  # Missing leading zero

    def test_parse_invalid_hour(self) -> None:
        with pytest.raises(ValueError, match="Hour must be between"):
            TimeWindow.parse("25:00-17:00")

    def test_parse_invalid_minute(self) -> None:
        with pytest.raises(ValueError, match="Minute must be between"):
            TimeWindow.parse("09:60-17:00")

    def test_is_within_normal_window(self) -> None:
        window = TimeWindow.parse("09:00-17:00")

        # Within window
        dt_noon = datetime(2026, 1, 31, 12, 0)
        assert window.is_within(dt_noon) is True

        # Before window
        dt_early = datetime(2026, 1, 31, 8, 0)
        assert window.is_within(dt_early) is False

        # After window
        dt_late = datetime(2026, 1, 31, 18, 0)
        assert window.is_within(dt_late) is False

        # At start
        dt_start = datetime(2026, 1, 31, 9, 0)
        assert window.is_within(dt_start) is True

        # At end
        dt_end = datetime(2026, 1, 31, 17, 0)
        assert window.is_within(dt_end) is True

    def test_is_within_overnight_window(self) -> None:
        window = TimeWindow.parse("22:00-06:00")

        # Late night
        dt_midnight = datetime(2026, 1, 31, 0, 0)
        assert window.is_within(dt_midnight) is True

        # Early morning
        dt_early = datetime(2026, 1, 31, 4, 0)
        assert window.is_within(dt_early) is True

        # Late evening
        dt_evening = datetime(2026, 1, 31, 23, 0)
        assert window.is_within(dt_evening) is True

        # Daytime (outside window)
        dt_noon = datetime(2026, 1, 31, 12, 0)
        assert window.is_within(dt_noon) is False

    # === Edge Case Tests ===

    def test_parse_edge_boundary_full_day(self) -> None:
        """Test full day window from midnight to 23:59."""
        window = TimeWindow.parse("00:00-23:59")
        assert window.start_hour == 0
        assert window.start_minute == 0
        assert window.end_hour == 23
        assert window.end_minute == 59

        # Should allow any time
        assert window.is_within(datetime(2026, 1, 31, 0, 0)) is True
        assert window.is_within(datetime(2026, 1, 31, 12, 0)) is True
        assert window.is_within(datetime(2026, 1, 31, 23, 59)) is True

    def test_parse_edge_boundary_midnight_start(self) -> None:
        """Test window starting at midnight."""
        window = TimeWindow.parse("00:00-06:00")
        assert window.start_hour == 0
        assert window.start_minute == 0

        assert window.is_within(datetime(2026, 1, 31, 0, 0)) is True
        assert window.is_within(datetime(2026, 1, 31, 3, 0)) is True
        assert window.is_within(datetime(2026, 1, 31, 6, 0)) is True
        assert window.is_within(datetime(2026, 1, 31, 7, 0)) is False

    def test_parse_edge_boundary_end_at_2359(self) -> None:
        """Test window ending at 23:59."""
        window = TimeWindow.parse("18:00-23:59")
        assert window.end_hour == 23
        assert window.end_minute == 59

        assert window.is_within(datetime(2026, 1, 31, 18, 0)) is True
        assert window.is_within(datetime(2026, 1, 31, 23, 59)) is True
        assert window.is_within(datetime(2026, 1, 31, 17, 59)) is False

    def test_parse_same_start_end_time(self) -> None:
        """Test zero-width window (same start and end time)."""
        window = TimeWindow.parse("12:00-12:00")
        assert window.start_hour == 12
        assert window.end_hour == 12

        # Only exact time should match
        assert window.is_within(datetime(2026, 1, 31, 12, 0)) is True
        assert window.is_within(datetime(2026, 1, 31, 12, 1)) is False
        assert window.is_within(datetime(2026, 1, 31, 11, 59)) is False

    def test_parse_invalid_format_empty_string(self) -> None:
        """Test empty string format."""
        with pytest.raises(ValueError, match="Invalid time window format"):
            TimeWindow.parse("")

    def test_parse_invalid_format_single_time(self) -> None:
        """Test single time without range."""
        with pytest.raises(ValueError, match="Invalid time window format"):
            TimeWindow.parse("09:00")

    def test_parse_invalid_format_wrong_separator(self) -> None:
        """Test wrong separator."""
        with pytest.raises(ValueError, match="Invalid time window format"):
            TimeWindow.parse("09:00_17:00")

    def test_parse_invalid_format_reversed(self) -> None:
        """Test time format with colons reversed."""
        with pytest.raises(ValueError, match="Invalid time window format"):
            TimeWindow.parse("09-00:17-00")

    def test_parse_invalid_hour_24(self) -> None:
        """Test hour = 24 (should fail, max is 23)."""
        with pytest.raises(ValueError, match="Hour must be between"):
            TimeWindow.parse("24:00-17:00")

    def test_parse_invalid_hour_end(self) -> None:
        """Test invalid hour in end time."""
        with pytest.raises(ValueError, match="Hour must be between"):
            TimeWindow.parse("09:00-25:00")

    def test_parse_invalid_minute_end(self) -> None:
        """Test invalid minute in end time."""
        with pytest.raises(ValueError, match="Minute must be between"):
            TimeWindow.parse("09:00-17:61")

    def test_parse_invalid_format_letters(self) -> None:
        """Test format with letters."""
        with pytest.raises(ValueError, match="Invalid time window format"):
            TimeWindow.parse("09:00-5pm")

    def test_parse_invalid_format_spaces(self) -> None:
        """Test format with spaces."""
        with pytest.raises(ValueError, match="Invalid time window format"):
            TimeWindow.parse("09:00 - 17:00")

    def test_is_within_one_minute_window(self) -> None:
        """Test very small window (1 minute)."""
        window = TimeWindow.parse("12:30-12:31")

        assert window.is_within(datetime(2026, 1, 31, 12, 30)) is True
        assert window.is_within(datetime(2026, 1, 31, 12, 31)) is True
        assert window.is_within(datetime(2026, 1, 31, 12, 29)) is False
        assert window.is_within(datetime(2026, 1, 31, 12, 32)) is False

    def test_is_within_overnight_at_boundaries(self) -> None:
        """Test overnight window at exact boundaries."""
        window = TimeWindow.parse("23:00-01:00")

        # At start boundary
        assert window.is_within(datetime(2026, 1, 31, 23, 0)) is True
        # At end boundary
        assert window.is_within(datetime(2026, 1, 31, 1, 0)) is True
        # Just before start
        assert window.is_within(datetime(2026, 1, 31, 22, 59)) is False
        # Just after end
        assert window.is_within(datetime(2026, 1, 31, 1, 1)) is False


class TestRateLimit:
    """Tests for RateLimit parsing and token bucket algorithm."""

    def test_parse_per_hour(self) -> None:
        limit = RateLimit.parse("100/hour")
        assert limit.max_tokens == 100
        assert limit.refill_period_seconds == 3600.0

    def test_parse_per_minute(self) -> None:
        limit = RateLimit.parse("10/minute")
        assert limit.max_tokens == 10
        assert limit.refill_period_seconds == 60.0

    def test_parse_per_second(self) -> None:
        limit = RateLimit.parse("5/second")
        assert limit.max_tokens == 5
        assert limit.refill_period_seconds == 1.0

    def test_parse_per_day(self) -> None:
        limit = RateLimit.parse("1000/day")
        assert limit.max_tokens == 1000
        assert limit.refill_period_seconds == 86400.0

    def test_parse_invalid_format(self) -> None:
        with pytest.raises(ValueError, match="Invalid rate limit format"):
            RateLimit.parse("100/week")

    def test_acquire_success(self) -> None:
        limit = RateLimit.parse("10/second")
        assert limit.acquire() is True
        assert limit.remaining() == 9

    def test_acquire_exhausted(self) -> None:
        limit = RateLimit.parse("2/second")
        assert limit.acquire() is True
        assert limit.acquire() is True
        assert limit.acquire() is False  # Exhausted

    def test_acquire_multiple_tokens(self) -> None:
        limit = RateLimit.parse("10/second")
        assert limit.acquire(tokens=5) is True
        assert limit.remaining() == 5
        assert limit.acquire(tokens=6) is False  # Not enough tokens

    def test_token_refill(self) -> None:
        limit = RateLimit.parse("10/second")
        limit.acquire(tokens=10)  # Exhaust all tokens
        assert limit.remaining() == 0

        # Wait for refill
        time.sleep(0.15)  # Wait 150ms

        # Should have some tokens back
        assert limit.remaining() > 0

    # === Edge Case Tests ===

    def test_parse_zero_count(self) -> None:
        """Test rate limit with zero count (edge case)."""
        limit = RateLimit.parse("0/hour")
        assert limit.max_tokens == 0
        assert limit.refill_period_seconds == 3600.0
        # Should immediately fail to acquire
        assert limit.acquire() is False
        assert limit.remaining() == 0

    def test_parse_large_count(self) -> None:
        """Test rate limit with very large count."""
        limit = RateLimit.parse("1000000/day")
        assert limit.max_tokens == 1000000
        assert limit.refill_period_seconds == 86400.0
        assert limit.remaining() == 1000000

    def test_parse_case_insensitive(self) -> None:
        """Test case insensitivity of period."""
        limit1 = RateLimit.parse("10/HOUR")
        limit2 = RateLimit.parse("10/Hour")
        limit3 = RateLimit.parse("10/hOuR")

        assert limit1.refill_period_seconds == 3600.0
        assert limit2.refill_period_seconds == 3600.0
        assert limit3.refill_period_seconds == 3600.0

    def test_parse_invalid_format_empty_string(self) -> None:
        """Test empty string format."""
        with pytest.raises(ValueError, match="Invalid rate limit format"):
            RateLimit.parse("")

    def test_parse_invalid_format_no_period(self) -> None:
        """Test format without period."""
        with pytest.raises(ValueError, match="Invalid rate limit format"):
            RateLimit.parse("100")

    def test_parse_invalid_format_no_count(self) -> None:
        """Test format without count."""
        with pytest.raises(ValueError, match="Invalid rate limit format"):
            RateLimit.parse("/hour")

    def test_parse_invalid_format_negative(self) -> None:
        """Test negative count (regex won't match)."""
        with pytest.raises(ValueError, match="Invalid rate limit format"):
            RateLimit.parse("-10/hour")

    def test_parse_invalid_format_decimal(self) -> None:
        """Test decimal count (regex won't match)."""
        with pytest.raises(ValueError, match="Invalid rate limit format"):
            RateLimit.parse("10.5/hour")

    def test_parse_invalid_period(self) -> None:
        """Test invalid period names."""
        with pytest.raises(ValueError, match="Invalid rate limit format"):
            RateLimit.parse("100/week")

        with pytest.raises(ValueError, match="Invalid rate limit format"):
            RateLimit.parse("100/month")

        with pytest.raises(ValueError, match="Invalid rate limit format"):
            RateLimit.parse("100/year")

    def test_parse_invalid_format_spaces(self) -> None:
        """Test format with spaces."""
        with pytest.raises(ValueError, match="Invalid rate limit format"):
            RateLimit.parse("100 / hour")

    def test_acquire_zero_tokens(self) -> None:
        """Test acquiring zero tokens."""
        limit = RateLimit.parse("10/second")
        # Acquiring 0 tokens should always succeed
        assert limit.acquire(tokens=0) is True
        assert limit.remaining() == 10  # No tokens consumed

    def test_acquire_exact_remaining(self) -> None:
        """Test acquiring exactly the remaining tokens."""
        limit = RateLimit.parse("5/second")
        assert limit.acquire(tokens=5) is True
        assert limit.remaining() == 0
        assert limit.acquire(tokens=1) is False

    def test_acquire_more_than_max(self) -> None:
        """Test acquiring more than max tokens."""
        limit = RateLimit.parse("5/second")
        assert limit.acquire(tokens=6) is False
        # Tokens should not be consumed on failed acquire
        assert limit.remaining() == 5

    def test_remaining_after_partial_refill(self) -> None:
        """Test remaining tokens after partial refill."""
        limit = RateLimit.parse("10/second")
        limit.acquire(tokens=10)  # Exhaust all
        assert limit.remaining() == 0

        # Wait for partial refill (50%)
        time.sleep(0.5)
        remaining = limit.remaining()
        # Should have approximately 5 tokens (allow some variance)
        assert 4 <= remaining <= 6

    def test_token_bucket_does_not_exceed_max(self) -> None:
        """Test that tokens never exceed max after refill."""
        limit = RateLimit.parse("5/second")
        assert limit.remaining() == 5

        # Wait longer than refill period
        time.sleep(0.2)

        # Should still be capped at max
        assert limit.remaining() == 5

    def test_acquire_single_token_repeatedly(self) -> None:
        """Test acquiring single tokens until exhaustion."""
        limit = RateLimit.parse("3/second")

        assert limit.acquire() is True
        assert limit.remaining() == 2
        assert limit.acquire() is True
        assert limit.remaining() == 1
        assert limit.acquire() is True
        assert limit.remaining() == 0
        assert limit.acquire() is False


class TestAgentIdentity:
    """Tests for AgentIdentity."""

    def test_basic_identity(self) -> None:
        agent = AgentIdentity(agent_id="agent-123")
        assert agent.agent_id == "agent-123"
        assert agent.session_id is None
        assert agent.roles == []

    def test_identity_with_roles(self) -> None:
        agent = AgentIdentity(
            agent_id="agent-123",
            session_id="session-456",
            roles=["admin", "analyst"],
        )
        assert agent.has_role("admin") is True
        assert agent.has_role("analyst") is True
        assert agent.has_role("guest") is False

    def test_identity_with_metadata(self) -> None:
        agent = AgentIdentity(
            agent_id="agent-123",
            metadata={"model": "claude-3", "version": "2.0"},
        )
        assert agent.metadata["model"] == "claude-3"


class TestSecurityPolicy:
    """Tests for SecurityPolicy."""

    def test_empty_policy_allows_all(self) -> None:
        policy = SecurityPolicy()
        policy.check("any_tool")  # Should not raise

    def test_allowed_tools(self) -> None:
        policy = SecurityPolicy(allowed_tools=["read_file", "write_file"])
        policy.check("read_file")  # Should not raise
        policy.check("write_file")  # Should not raise

        with pytest.raises(PolicyViolation) as exc_info:
            policy.check("delete_file")
        assert exc_info.value.violation_type == ViolationType.TOOL_NOT_ALLOWED.value

    def test_denied_tools(self) -> None:
        policy = SecurityPolicy(denied_tools=["delete_*", "drop_database"])

        with pytest.raises(PolicyViolation) as exc_info:
            policy.check("delete_file")
        assert exc_info.value.violation_type == ViolationType.TOOL_DENIED.value

        with pytest.raises(PolicyViolation) as exc_info:
            policy.check("drop_database")
        assert exc_info.value.violation_type == ViolationType.TOOL_DENIED.value

    def test_denied_takes_precedence_over_allowed(self) -> None:
        policy = SecurityPolicy(
            allowed_tools=["*"],  # Allow all
            denied_tools=["delete_*"],  # But deny delete
        )

        policy.check("read_file")  # Allowed

        with pytest.raises(PolicyViolation):
            policy.check("delete_file")  # Denied

    def test_glob_patterns(self) -> None:
        policy = SecurityPolicy(allowed_tools=["read_*", "list_*"])

        policy.check("read_file")
        policy.check("read_database")
        policy.check("list_users")

        with pytest.raises(PolicyViolation):
            policy.check("write_file")

    def test_time_restriction(self) -> None:
        policy = SecurityPolicy(
            time_restrictions={"delete_*": "09:00-17:00"},
        )

        # Within business hours
        dt_noon = datetime(2026, 1, 31, 12, 0)
        policy.check("delete_file", dt=dt_noon)  # Should not raise

        # Outside business hours
        dt_night = datetime(2026, 1, 31, 20, 0)
        with pytest.raises(PolicyViolation) as exc_info:
            policy.check("delete_file", dt=dt_night)
        assert exc_info.value.violation_type == ViolationType.TIME_RESTRICTED.value

    def test_rate_limit(self) -> None:
        policy = SecurityPolicy(rate_limits={"*": "2/second"})

        policy.check("any_tool")
        policy.check("any_tool")

        with pytest.raises(PolicyViolation) as exc_info:
            policy.check("any_tool")
        assert exc_info.value.violation_type == ViolationType.RATE_LIMITED.value

    def test_specific_rate_limit_pattern(self) -> None:
        policy = SecurityPolicy(
            rate_limits={
                "*": "100/hour",
                "expensive_*": "2/minute",
            }
        )

        # Expensive tool has stricter limit
        policy.check("expensive_operation")
        policy.check("expensive_operation")

        with pytest.raises(PolicyViolation):
            policy.check("expensive_operation")

        # Regular tools still work
        policy.check("read_file")

    def test_require_agent_id(self) -> None:
        policy = SecurityPolicy(require_agent_id=True)

        with pytest.raises(PolicyViolation) as exc_info:
            policy.check("any_tool", agent=None)
        assert exc_info.value.violation_type == "agent_required"

        # With agent identity
        agent = AgentIdentity(agent_id="agent-123")
        policy.check("any_tool", agent=agent)  # Should not raise

    def test_allowed_roles(self) -> None:
        policy = SecurityPolicy(allowed_roles=["admin", "operator"])

        admin_agent = AgentIdentity(agent_id="agent-1", roles=["admin"])
        operator_agent = AgentIdentity(agent_id="agent-2", roles=["operator"])
        guest_agent = AgentIdentity(agent_id="agent-3", roles=["guest"])

        policy.check("any_tool", agent=admin_agent)  # Should not raise
        policy.check("any_tool", agent=operator_agent)  # Should not raise

        with pytest.raises(PolicyViolation) as exc_info:
            policy.check("any_tool", agent=guest_agent)
        assert exc_info.value.violation_type == "role_required"


class TestPredefinedPolicies:
    """Tests for predefined policy constants."""

    def test_permissive_policy(self) -> None:
        PERMISSIVE_POLICY.check("any_tool")
        PERMISSIVE_POLICY.check("delete_everything")

    def test_read_only_policy(self) -> None:
        READ_ONLY_POLICY.check("read_file")
        READ_ONLY_POLICY.check("get_user")
        READ_ONLY_POLICY.check("list_items")
        READ_ONLY_POLICY.check("search_database")

        with pytest.raises(PolicyViolation):
            READ_ONLY_POLICY.check("write_file")

        with pytest.raises(PolicyViolation):
            READ_ONLY_POLICY.check("delete_user")

    def test_strict_policy_requires_agent(self) -> None:
        with pytest.raises(PolicyViolation):
            STRICT_POLICY.check("any_tool", agent=None)

        agent = AgentIdentity(agent_id="agent-123")
        STRICT_POLICY.check("any_tool", agent=agent)

    def test_business_hours_policy(self) -> None:
        dt_business = datetime(2026, 1, 31, 14, 0)
        dt_night = datetime(2026, 1, 31, 22, 0)

        BUSINESS_HOURS_POLICY.check("delete_file", dt=dt_business)

        with pytest.raises(PolicyViolation):
            BUSINESS_HOURS_POLICY.check("delete_file", dt=dt_night)


class TestAirlockPolicyIntegration:
    """Tests for Airlock decorator with policy enforcement."""

    def test_policy_allows_call(self) -> None:
        policy = SecurityPolicy(allowed_tools=["add"])

        @Airlock(policy=policy)
        def add(x: int, y: int) -> int:
            return x + y

        result = add(x=2, y=3)
        assert result == 5

    def test_policy_denies_call(self) -> None:
        policy = SecurityPolicy(denied_tools=["add"])

        @Airlock(policy=policy)
        def add(x: int, y: int) -> int:
            return x + y

        result = add(x=2, y=3)

        assert isinstance(result, dict)
        assert result["success"] is False
        assert result["block_reason"] == "policy_violation"

    def test_rate_limit_blocks_excessive_calls(self) -> None:
        policy = SecurityPolicy(rate_limits={"multiply": "2/second"})

        @Airlock(policy=policy)
        def multiply(x: int, y: int) -> int:
            return x * y

        # First two calls succeed
        assert multiply(x=2, y=3) == 6
        assert multiply(x=3, y=4) == 12

        # Third call is rate limited
        result = multiply(x=4, y=5)
        assert isinstance(result, dict)
        assert result["success"] is False
        assert result["block_reason"] == "rate_limit"

    def test_policy_with_glob_pattern(self) -> None:
        policy = SecurityPolicy(allowed_tools=["read_*"])

        @Airlock(policy=policy)
        def read_file(path: str) -> str:
            return f"Contents of {path}"

        @Airlock(policy=policy)
        def write_file(path: str, _content: str) -> str:
            return f"Wrote to {path}"

        # read_file matches pattern
        result1 = read_file(path="/tmp/test.txt")
        assert result1 == "Contents of /tmp/test.txt"

        # write_file does not match pattern
        result2 = write_file(path="/tmp/test.txt", content="hello")
        assert isinstance(result2, dict)
        assert result2["success"] is False


class TestPolicyViolationException:
    """Tests for PolicyViolation exception."""

    def test_exception_attributes(self) -> None:
        exc = PolicyViolation(
            message="Tool denied",
            violation_type=ViolationType.TOOL_DENIED.value,
            details={"tool": "delete_all", "pattern": "delete_*"},
        )

        assert exc.message == "Tool denied"
        assert exc.violation_type == "tool_denied"
        assert exc.details["tool"] == "delete_all"
        assert str(exc) == "Tool denied"

    def test_violation_types(self) -> None:
        assert ViolationType.TOOL_DENIED.value == "tool_denied"
        assert ViolationType.TOOL_NOT_ALLOWED.value == "tool_not_allowed"
        assert ViolationType.TIME_RESTRICTED.value == "time_restricted"
        assert ViolationType.RATE_LIMITED.value == "rate_limited"
