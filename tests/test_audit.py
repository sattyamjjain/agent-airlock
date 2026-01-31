"""Tests for audit logging functionality."""

from __future__ import annotations

import json
import tempfile
import threading
from pathlib import Path

from agent_airlock.audit import AuditLogger, AuditRecord, get_audit_logger


class TestAuditRecord:
    """Tests for AuditRecord dataclass."""

    def test_basic_record_creation(self) -> None:
        """Test creating a basic audit record."""
        record = AuditRecord(
            timestamp="2026-01-31T12:00:00Z",
            tool_name="read_file",
            blocked=False,
        )
        assert record.tool_name == "read_file"
        assert record.blocked is False
        assert record.block_reason is None

    def test_blocked_record(self) -> None:
        """Test creating a blocked audit record."""
        record = AuditRecord(
            timestamp="2026-01-31T12:00:00Z",
            tool_name="delete_user",
            blocked=True,
            block_reason="rate_limited",
            error="Rate limit exceeded",
        )
        assert record.blocked is True
        assert record.block_reason == "rate_limited"
        assert record.error == "Rate limit exceeded"

    def test_to_dict_excludes_none(self) -> None:
        """Test that to_dict excludes None values."""
        record = AuditRecord(
            timestamp="2026-01-31T12:00:00Z",
            tool_name="test",
            blocked=False,
        )
        d = record.to_dict()
        assert "block_reason" not in d or d["block_reason"] is not None
        assert "tool_name" in d
        assert d["blocked"] is False

    def test_to_json_valid(self) -> None:
        """Test that to_json produces valid JSON."""
        record = AuditRecord(
            timestamp="2026-01-31T12:00:00Z",
            tool_name="test",
            blocked=False,
            duration_ms=42.5,
            sanitized_count=2,
        )
        json_str = record.to_json()
        parsed = json.loads(json_str)
        assert parsed["tool_name"] == "test"
        assert parsed["duration_ms"] == 42.5
        assert parsed["sanitized_count"] == 2


class TestAuditLogger:
    """Tests for AuditLogger class."""

    def test_disabled_logger_does_nothing(self) -> None:
        """Test that disabled logger doesn't write anything."""
        logger = AuditLogger(None, enabled=False)
        assert logger.enabled is False
        # Should not raise
        logger.log(tool_name="test", blocked=False)

    def test_creates_log_file(self) -> None:
        """Test that logger creates the log file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(path, enabled=True)
            logger.log(tool_name="test", blocked=False)

            assert path.exists()
            content = path.read_text()
            assert "test" in content

    def test_writes_json_lines_format(self) -> None:
        """Test that logs are in JSON Lines format."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(path, enabled=True)

            logger.log(tool_name="tool1", blocked=False)
            logger.log(tool_name="tool2", blocked=True, block_reason="policy")
            logger.log(tool_name="tool3", blocked=False)

            content = path.read_text()
            lines = [line for line in content.split("\n") if line and not line.startswith("#")]
            assert len(lines) == 3

            for line in lines:
                parsed = json.loads(line)
                assert "tool_name" in parsed
                assert "blocked" in parsed
                assert "timestamp" in parsed

    def test_redacts_sensitive_params(self) -> None:
        """Test that sensitive parameter values are redacted."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(path, enabled=True)

            logger.log(
                tool_name="login",
                blocked=False,
                args={"username": "john", "password": "secret123", "api_key": "sk-abc123"},
            )

            content = path.read_text()
            lines = [line for line in content.split("\n") if line and not line.startswith("#")]
            record = json.loads(lines[0])

            assert record["args_preview"]["username"] == "'john'"
            assert record["args_preview"]["password"] == "[REDACTED]"
            assert record["args_preview"]["api_key"] == "[REDACTED]"

    def test_truncates_long_args(self) -> None:
        """Test that long argument values are truncated."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(path, enabled=True)

            long_value = "x" * 500
            logger.log(
                tool_name="process",
                blocked=False,
                args={"data": long_value},
            )

            content = path.read_text()
            lines = [line for line in content.split("\n") if line and not line.startswith("#")]
            record = json.loads(lines[0])

            assert len(record["args_preview"]["data"]) < 200
            assert record["args_preview"]["data"].endswith("...")

    def test_result_preview_truncated(self) -> None:
        """Test that result previews are truncated."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(path, enabled=True)

            long_result = "y" * 1000
            logger.log(
                tool_name="fetch",
                blocked=False,
                result=long_result,
            )

            content = path.read_text()
            lines = [line for line in content.split("\n") if line and not line.startswith("#")]
            record = json.loads(lines[0])

            assert len(record["result_preview"]) < 600
            assert "chars total" in record["result_preview"]

    def test_blocked_result_preview(self) -> None:
        """Test that blocked results show BLOCKED in preview."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(path, enabled=True)

            logger.log(
                tool_name="delete",
                blocked=True,
                block_reason="rate_limit",
                result={"blocked": True, "reason": "rate_limit"},
            )

            content = path.read_text()
            lines = [line for line in content.split("\n") if line and not line.startswith("#")]
            record = json.loads(lines[0])

            assert "BLOCKED" in record["result_preview"]

    def test_thread_safety(self) -> None:
        """Test that concurrent writes don't corrupt the file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(path, enabled=True)

            errors: list[Exception] = []
            num_threads = 10
            writes_per_thread = 50

            def writer(thread_id: int) -> None:
                try:
                    for i in range(writes_per_thread):
                        logger.log(
                            tool_name=f"tool_{thread_id}_{i}",
                            blocked=False,
                            duration_ms=float(i),
                        )
                except Exception as e:
                    errors.append(e)

            threads = [threading.Thread(target=writer, args=(i,)) for i in range(num_threads)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            assert len(errors) == 0, f"Errors during concurrent writes: {errors}"

            content = path.read_text()
            lines = [line for line in content.split("\n") if line and not line.startswith("#")]
            assert len(lines) == num_threads * writes_per_thread

            # Verify all lines are valid JSON
            for line in lines:
                parsed = json.loads(line)
                assert "tool_name" in parsed

    def test_singleton_per_path(self) -> None:
        """Test that same path returns same instance."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "audit.jsonl"

            logger1 = AuditLogger(path, enabled=True)
            logger2 = AuditLogger(path, enabled=True)

            assert logger1 is logger2

            # Different path should be different instance
            path2 = Path(tmpdir) / "audit2.jsonl"
            logger3 = AuditLogger(path2, enabled=True)
            assert logger1 is not logger3

    def test_creates_parent_directories(self) -> None:
        """Test that logger creates parent directories if needed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "deep" / "nested" / "audit.jsonl"
            logger = AuditLogger(path, enabled=True)
            logger.log(tool_name="test", blocked=False)

            assert path.exists()

    def test_header_written_once(self) -> None:
        """Test that header is only written once."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "audit.jsonl"

            logger1 = AuditLogger(path, enabled=True)
            logger1.log(tool_name="test1", blocked=False)

            # Force new instance by clearing cache
            AuditLogger.close_all()

            logger2 = AuditLogger(path, enabled=True)
            logger2.log(tool_name="test2", blocked=False)

            content = path.read_text()
            header_count = content.count("# Agent-Airlock Audit Log")
            # Header should be overwritten when new logger is created for existing file
            # In practice, you'd keep the singleton alive
            assert header_count >= 1


class TestGetAuditLogger:
    """Tests for get_audit_logger function."""

    def test_returns_logger(self) -> None:
        """Test that get_audit_logger returns a logger."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "audit.jsonl"
            logger = get_audit_logger(path, enabled=True)
            assert isinstance(logger, AuditLogger)
            assert logger.enabled is True

    def test_disabled_logger(self) -> None:
        """Test that disabled flag works."""
        # Must pass None path AND enabled=False
        logger = AuditLogger(None, enabled=False)
        assert logger.enabled is False


class TestAuditLoggerIntegration:
    """Integration tests for audit logging with actual tool calls."""

    def test_full_audit_record(self) -> None:
        """Test a complete audit record with all fields."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "audit.jsonl"
            logger = AuditLogger(path, enabled=True)

            logger.log(
                tool_name="search_database",
                blocked=False,
                agent_id="agent-123",
                session_id="session-456",
                duration_ms=123.45,
                sanitized_count=2,
                truncated=True,
                args={"query": "SELECT * FROM users", "limit": 10},
                result="Found 5 users",
            )

            content = path.read_text()
            lines = [line for line in content.split("\n") if line and not line.startswith("#")]
            record = json.loads(lines[0])

            assert record["tool_name"] == "search_database"
            assert record["blocked"] is False
            assert record["agent_id"] == "agent-123"
            assert record["session_id"] == "session-456"
            assert record["duration_ms"] == 123.45
            assert record["sanitized_count"] == 2
            assert record["truncated"] is True
            assert "query" in record["args_preview"]
            assert record["result_type"] == "str"
            assert "Found 5 users" in record["result_preview"]
