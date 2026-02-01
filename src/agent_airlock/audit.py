"""Audit logging for Agent-Airlock.

Provides thread-safe JSON Lines audit logging for all tool calls.
This was previously a config-only feature - now fully implemented.

THREAD SAFETY:
    This module is thread-safe. The AuditLogger uses:
    - Class-level _lock for managing the global instances dict
    - Instance-level _file_lock for protecting file writes

    Lock Acquisition Order (to prevent deadlocks):
    1. AuditLogger._lock (class lock) - acquired for close_all()
    2. self._file_lock (instance lock) - acquired for individual writes

    File writes are atomic within a single log() call. Multiple threads
    can safely write to the same audit logger concurrently.
"""

from __future__ import annotations

import json
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger("agent-airlock.audit")

# Parameter names to redact from audit logs
AUDIT_REDACT_PARAMS = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "key",
        "api_key",
        "apikey",
        "auth",
        "authorization",
        "credential",
        "credentials",
        "private_key",
        "privatekey",
        "access_token",
        "refresh_token",
        "session_token",
        "bearer",
        "ssn",
        "social_security",
        "credit_card",
        "card_number",
        "cvv",
        "pin",
    }
)


@dataclass
class AuditRecord:
    """A single audit log entry."""

    timestamp: str
    tool_name: str
    blocked: bool
    block_reason: str | None = None
    agent_id: str | None = None
    session_id: str | None = None
    duration_ms: float | None = None
    sanitized_count: int = 0
    truncated: bool = False
    args_preview: dict[str, str] = field(default_factory=dict)
    result_type: str = "unknown"
    result_preview: str = ""
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary, excluding None values."""
        result = asdict(self)
        return {k: v for k, v in result.items() if v is not None}

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), default=str, ensure_ascii=False)


class AuditLogger:
    """Thread-safe JSON Lines audit logger.

    Writes audit records to a file in JSON Lines format (one JSON object per line).
    This format is easy to parse, stream, and analyze with tools like jq.

    Example output:
        {"timestamp": "2026-01-31T12:00:00Z", "tool_name": "read_file", "blocked": false, ...}
        {"timestamp": "2026-01-31T12:00:01Z", "tool_name": "delete_user", "blocked": true, ...}
    """

    _lock = threading.Lock()
    _instances: dict[Path, AuditLogger] = {}

    def __new__(cls, path: Path | str | None, enabled: bool = True) -> AuditLogger:
        """Singleton per file path to ensure thread-safe writes."""
        if path is None or not enabled:
            # Return a no-op instance
            instance = super().__new__(cls)
            instance._init_noop()
            return instance

        path = Path(path).resolve()
        with cls._lock:
            if path not in cls._instances:
                instance = super().__new__(cls)
                instance._init_real(path)
                cls._instances[path] = instance
            return cls._instances[path]

    def _init_noop(self) -> None:
        """Initialize as a no-op logger."""
        self.path: Path | None = None
        self.enabled = False
        self._file_lock = threading.Lock()

    def _init_real(self, path: Path) -> None:
        """Initialize with actual file path."""
        self.path = path
        self.enabled = True
        self._file_lock = threading.Lock()

        # Ensure parent directory exists
        self.path.parent.mkdir(parents=True, exist_ok=True)

        # Write header comment on first creation
        if not self.path.exists():
            self._write_header()

    def _write_header(self) -> None:
        """Write a header comment to new audit files."""
        if self.path is None:
            return
        header = (
            f"# Agent-Airlock Audit Log\n"
            f"# Created: {datetime.now(timezone.utc).isoformat()}\n"
            f"# Format: JSON Lines (one record per line)\n"
            f"# \n"
        )
        with open(self.path, "w") as f:
            f.write(header)

    def log(
        self,
        tool_name: str,
        *,
        blocked: bool,
        block_reason: str | None = None,
        agent_id: str | None = None,
        session_id: str | None = None,
        duration_ms: float | None = None,
        sanitized_count: int = 0,
        truncated: bool = False,
        args: dict[str, Any] | None = None,
        result: Any = None,
        error: str | None = None,
    ) -> None:
        """Write an audit record to the log file.

        Args:
            tool_name: Name of the tool that was called.
            blocked: Whether the call was blocked by Airlock.
            block_reason: Reason for blocking (if blocked).
            agent_id: ID of the agent making the call.
            session_id: Session or conversation ID.
            duration_ms: Execution time in milliseconds.
            sanitized_count: Number of sensitive values masked.
            truncated: Whether output was truncated.
            args: Tool arguments (will be redacted).
            result: Tool result (will be previewed).
            error: Error message if call failed.
        """
        if not self.enabled or self.path is None:
            return

        record = AuditRecord(
            timestamp=datetime.now(timezone.utc).isoformat(),
            tool_name=tool_name,
            blocked=blocked,
            block_reason=block_reason,
            agent_id=agent_id,
            session_id=session_id,
            duration_ms=round(duration_ms, 2) if duration_ms else None,
            sanitized_count=sanitized_count,
            truncated=truncated,
            args_preview=self._redact_args(args or {}),
            result_type=type(result).__name__ if result is not None else "None",
            result_preview=self._preview_result(result, blocked),
            error=error,
        )

        self._write_record(record)

    def _write_record(self, record: AuditRecord) -> None:
        """Thread-safe write of a record to the log file."""
        if self.path is None:
            return
        try:
            with self._file_lock, open(self.path, "a", encoding="utf-8") as f:
                f.write(record.to_json() + "\n")
        except OSError as e:
            # Log failure but don't crash the tool call
            logger.error(
                "audit_log_write_failed",
                path=str(self.path),
                error=str(e),
            )

    @staticmethod
    def _redact_args(args: dict[str, Any]) -> dict[str, str]:
        """Redact sensitive argument values for audit.

        Returns a dict with string representations, sensitive values replaced.
        """
        result = {}
        for key, value in args.items():
            # Check if parameter name suggests sensitive data
            key_lower = key.lower()
            if any(sensitive in key_lower for sensitive in AUDIT_REDACT_PARAMS):
                result[key] = "[REDACTED]"
            elif isinstance(value, str) and len(value) > 100:
                # Truncate long string arguments
                result[key] = value[:100] + "..."
            else:
                # Convert to string representation
                result[key] = repr(value)[:200]

        return result

    @staticmethod
    def _preview_result(result: Any, blocked: bool) -> str:
        """Create a preview of the result for audit logging.

        Args:
            result: The function result.
            blocked: Whether the call was blocked.

        Returns:
            A truncated string preview of the result.
        """
        if blocked:
            if isinstance(result, dict) and "reason" in result:
                return f"BLOCKED: {result.get('reason', 'unknown')}"
            return "BLOCKED"

        if result is None:
            return "None"

        # For dict results (like AirlockResponse)
        if isinstance(result, dict):
            if result.get("blocked"):
                return f"BLOCKED: {result.get('reason', 'unknown')}"
            if "result" in result:
                result = result["result"]

        # Create string preview
        try:
            s = str(result)
            max_len = 500
            if len(s) > max_len:
                return s[:max_len] + f"... ({len(s):,} chars total)"
            return s
        except Exception as e:
            logger.debug(
                "preview_result_failed",
                result_type=type(result).__name__,
                error=str(e),
            )
            return f"<{type(result).__name__}>"

    def flush(self) -> None:
        """Ensure all pending writes are flushed to disk."""
        # Since we open/close on each write, this is a no-op
        # but kept for API consistency
        pass

    @classmethod
    def close_all(cls) -> None:
        """Close all audit logger instances (for testing/cleanup)."""
        with cls._lock:
            cls._instances.clear()


# Global audit logger instance (lazy initialization)
_global_audit_logger: AuditLogger | None = None


def get_audit_logger(path: Path | str | None = None, enabled: bool = True) -> AuditLogger:
    """Get or create the global audit logger.

    Args:
        path: Path to audit log file. If None, uses default from config.
        enabled: Whether audit logging is enabled.

    Returns:
        AuditLogger instance.
    """
    global _global_audit_logger

    if path is None and _global_audit_logger is not None:
        return _global_audit_logger

    logger_instance = AuditLogger(path, enabled)

    if path is not None:
        _global_audit_logger = logger_instance

    return logger_instance
