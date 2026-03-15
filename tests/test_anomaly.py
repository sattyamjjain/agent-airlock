"""Tests for anomaly detection (V0.4.1).

Tests AnomalyDetector, AnomalyDetectorConfig, AnomalyEvent,
and integration with TOML config parsing.
"""

from __future__ import annotations

import threading
import time

from agent_airlock.anomaly import (
    AnomalyDetector,
    AnomalyDetectorConfig,
    AnomalyEvent,
    AnomalySeverity,
    AnomalyType,
)


class TestAnomalyDetectorConfig:
    """Tests for AnomalyDetectorConfig defaults."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = AnomalyDetectorConfig()
        assert config.window_seconds == 60.0
        assert config.max_calls_per_window == 50
        assert config.max_unique_endpoints_per_window == 10
        assert config.max_error_rate == 0.5
        assert config.max_consecutive_blocked == 5
        assert config.auto_block_duration_seconds == 300.0
        assert config.enabled is True


class TestCallRateSpike:
    """Tests for call rate spike detection."""

    def test_call_rate_spike_detection(self) -> None:
        """Test detection when call count exceeds max_calls_per_window."""
        config = AnomalyDetectorConfig(max_calls_per_window=5, window_seconds=60.0)
        detector = AnomalyDetector(config)

        # Record 5 calls (at limit, no anomaly yet)
        for _i in range(5):
            event = detector.record_call("tool", "session-1", {})
            assert event is None

        # 6th call triggers anomaly
        event = detector.record_call("tool", "session-1", {})
        assert event is not None
        assert event.event_type == AnomalyType.CALL_RATE_SPIKE
        assert event.severity == AnomalySeverity.HIGH


class TestEndpointDiversitySpike:
    """Tests for endpoint diversity spike detection."""

    def test_endpoint_diversity_spike(self) -> None:
        """Test detection when unique endpoints exceed threshold."""
        config = AnomalyDetectorConfig(
            max_unique_endpoints_per_window=3,
            max_calls_per_window=100,
        )
        detector = AnomalyDetector(config)

        for i in range(3):
            event = detector.record_call(
                "tool", "session-1", {}, endpoint_url=f"https://host{i}.com/api"
            )
            assert event is None

        # 4th unique endpoint triggers anomaly
        event = detector.record_call("tool", "session-1", {}, endpoint_url="https://host3.com/api")
        assert event is not None
        assert event.event_type == AnomalyType.ENDPOINT_DIVERSITY_SPIKE


class TestHighErrorRate:
    """Tests for high error rate detection."""

    def test_high_error_rate_detection(self) -> None:
        """Test detection when error rate exceeds threshold."""
        config = AnomalyDetectorConfig(
            max_error_rate=0.5,
            max_calls_per_window=100,
            max_consecutive_blocked=100,  # Disable consecutive check
        )
        detector = AnomalyDetector(config)

        # Record 3 blocked + 2 success = 60% error rate
        for _ in range(3):
            detector.record_call("tool", "session-1", {}, was_blocked=True)
        for _ in range(2):
            detector.record_call("tool", "session-1", {})

        # Next blocked call should trigger (4/6 = 67% > 50%)
        event = detector.record_call("tool", "session-1", {}, was_blocked=True)
        assert event is not None
        assert event.event_type == AnomalyType.HIGH_ERROR_RATE

    def test_low_sample_size_no_trigger(self) -> None:
        """Test that error rate check needs minimum sample size."""
        config = AnomalyDetectorConfig(
            max_error_rate=0.5,
            max_calls_per_window=100,
            max_consecutive_blocked=100,
        )
        detector = AnomalyDetector(config)

        # 3 blocked calls = 100% error rate but only 3 samples
        event = None
        for _ in range(3):
            event = detector.record_call("tool", "session-1", {}, was_blocked=True)

        # Should not trigger (< 5 samples)
        assert event is None


class TestConsecutiveBlocked:
    """Tests for consecutive blocked call detection."""

    def test_consecutive_blocked_detection(self) -> None:
        """Test detection after N consecutive blocked calls."""
        config = AnomalyDetectorConfig(
            max_consecutive_blocked=3,
            max_calls_per_window=100,
        )
        detector = AnomalyDetector(config)

        for _ in range(2):
            event = detector.record_call("tool", "session-1", {}, was_blocked=True)
            assert event is None

        # 3rd consecutive blocked triggers
        event = detector.record_call("tool", "session-1", {}, was_blocked=True)
        assert event is not None
        assert event.event_type == AnomalyType.CONSECUTIVE_BLOCKED
        assert event.severity == AnomalySeverity.CRITICAL

    def test_consecutive_blocked_resets_on_success(self) -> None:
        """Test consecutive counter resets on successful call."""
        config = AnomalyDetectorConfig(
            max_consecutive_blocked=3,
            max_calls_per_window=100,
            max_error_rate=1.0,  # Disable error rate check for this test
        )
        detector = AnomalyDetector(config)

        detector.record_call("tool", "session-1", {}, was_blocked=True)
        detector.record_call("tool", "session-1", {}, was_blocked=True)
        # Success resets counter
        detector.record_call("tool", "session-1", {})
        detector.record_call("tool", "session-1", {}, was_blocked=True)
        event = detector.record_call("tool", "session-1", {}, was_blocked=True)
        assert event is None  # Only 2 consecutive, not 3


class TestAutoBlock:
    """Tests for automatic session blocking."""

    def test_auto_block_triggers_and_expires(self) -> None:
        """Test auto-block triggers and expires after duration."""
        config = AnomalyDetectorConfig(
            max_consecutive_blocked=2,
            auto_block_duration_seconds=0.1,  # 100ms for testing
            max_calls_per_window=100,
        )
        detector = AnomalyDetector(config)

        detector.record_call("tool", "session-1", {}, was_blocked=True)
        detector.record_call("tool", "session-1", {}, was_blocked=True)

        assert detector.is_session_blocked("session-1") is True

        # Wait for block to expire
        time.sleep(0.15)
        assert detector.is_session_blocked("session-1") is False

    def test_is_session_blocked_returns_true(self) -> None:
        """Test is_session_blocked returns True during block."""
        config = AnomalyDetectorConfig(
            max_consecutive_blocked=1,
            auto_block_duration_seconds=10.0,
            max_calls_per_window=100,
        )
        detector = AnomalyDetector(config)

        detector.record_call("tool", "session-1", {}, was_blocked=True)
        assert detector.is_session_blocked("session-1") is True
        assert detector.is_session_blocked("session-2") is False


class TestResetSession:
    """Tests for session reset."""

    def test_reset_session_clears_state(self) -> None:
        """Test reset_session clears all tracking state."""
        config = AnomalyDetectorConfig(max_calls_per_window=100)
        detector = AnomalyDetector(config)

        for _ in range(10):
            detector.record_call("tool", "session-1", {})

        stats = detector.get_session_stats("session-1")
        assert stats["calls_in_window"] == 10

        detector.reset_session("session-1")
        stats = detector.get_session_stats("session-1")
        assert stats["calls_in_window"] == 0


class TestDisabledDetector:
    """Tests for disabled detector."""

    def test_disabled_detector_passes_everything(self) -> None:
        """Test disabled detector never returns anomaly events."""
        config = AnomalyDetectorConfig(enabled=False, max_calls_per_window=1)
        detector = AnomalyDetector(config)

        for _ in range(100):
            event = detector.record_call("tool", "session-1", {}, was_blocked=True)
            assert event is None

    def test_disabled_detector_never_blocks(self) -> None:
        """Test disabled detector never blocks sessions."""
        config = AnomalyDetectorConfig(enabled=False)
        detector = AnomalyDetector(config)
        assert detector.is_session_blocked("any-session") is False


class TestThreadSafety:
    """Tests for thread safety."""

    def test_concurrent_calls_from_multiple_threads(self) -> None:
        """Test thread safety with concurrent calls."""
        config = AnomalyDetectorConfig(
            max_calls_per_window=1000,
            window_seconds=60.0,
        )
        detector = AnomalyDetector(config)
        errors: list[Exception] = []

        def worker(thread_id: int) -> None:
            try:
                for i in range(50):
                    detector.record_call(
                        f"tool_{i}",
                        f"session-{thread_id}",
                        {},
                        endpoint_url=f"https://host{i}.com",
                    )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        # Each thread recorded 50 calls
        for i in range(10):
            stats = detector.get_session_stats(f"session-{i}")
            assert stats["calls_in_window"] == 50


class TestSessionStats:
    """Tests for session statistics."""

    def test_get_session_stats(self) -> None:
        """Test session stats are accurate."""
        config = AnomalyDetectorConfig(max_calls_per_window=100)
        detector = AnomalyDetector(config)

        detector.record_call("tool", "s1", {}, was_blocked=True, endpoint_url="https://a.com")
        detector.record_call("tool", "s1", {}, endpoint_url="https://b.com")
        detector.record_call("tool", "s1", {})

        stats = detector.get_session_stats("s1")
        assert stats["calls_in_window"] == 3
        assert stats["blocked_calls"] == 1
        assert stats["unique_endpoints"] == 2

    def test_unknown_session_returns_zeros(self) -> None:
        """Test unknown session returns zero stats."""
        detector = AnomalyDetector()
        stats = detector.get_session_stats("nonexistent")
        assert stats["calls_in_window"] == 0
        assert stats["is_blocked"] is False


class TestConfigParsing:
    """Tests for TOML config parsing."""

    def test_parse_anomaly_config(self) -> None:
        """Test parsing anomaly config from dict."""
        from agent_airlock.config import _parse_anomaly_config

        data = {
            "enabled": True,
            "window_seconds": 30,
            "max_calls_per_window": 25,
            "max_error_rate": 0.3,
        }
        config = _parse_anomaly_config(data)
        assert config.enabled is True
        assert config.window_seconds == 30.0
        assert config.max_calls_per_window == 25
        assert config.max_error_rate == 0.3


class TestAnomalyEvent:
    """Tests for AnomalyEvent dataclass."""

    def test_anomaly_event_creation(self) -> None:
        """Test AnomalyEvent can be created with all fields."""
        event = AnomalyEvent(
            event_type=AnomalyType.CALL_RATE_SPIKE,
            tool_name="test_tool",
            session_id="session-1",
            severity=AnomalySeverity.HIGH,
            details={"calls_in_window": 100},
        )
        assert event.event_type == AnomalyType.CALL_RATE_SPIKE
        assert event.tool_name == "test_tool"
        assert event.session_id == "session-1"
        assert event.severity == AnomalySeverity.HIGH
        assert event.details["calls_in_window"] == 100
        assert event.timestamp > 0


class TestSelfHealIntegration:
    """Tests for self_heal.py anomaly block handler."""

    def test_handle_anomaly_block(self) -> None:
        """Test handle_anomaly_block creates proper response."""
        from agent_airlock.self_heal import (
            BlockReason,
            handle_anomaly_block,
        )

        response = handle_anomaly_block(
            func_name="dangerous_tool",
            session_id="session-42",
            anomaly_type="call_rate_spike",
            details={"calls_in_window": 100},
        )
        assert response.success is False
        assert response.block_reason == BlockReason.ANOMALY_DETECTED
        assert "dangerous_tool" in (response.error or "")
        assert response.metadata["session_id"] == "session-42"
        assert response.metadata["anomaly_type"] == "call_rate_spike"
        assert response.metadata["calls_in_window"] == 100

    def test_handle_anomaly_block_no_details(self) -> None:
        """Test handle_anomaly_block works without details."""
        from agent_airlock.self_heal import handle_anomaly_block

        response = handle_anomaly_block(
            func_name="tool",
            session_id="s1",
            anomaly_type="consecutive_blocked",
        )
        assert response.success is False
        assert len(response.fix_hints) == 3
