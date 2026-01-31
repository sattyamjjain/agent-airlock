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
