"""Benchmarks for sanitization operations.

Run with: pytest benchmarks/benchmark_sanitizer.py --benchmark-only
"""

from __future__ import annotations

import pytest

from agent_airlock.sanitizer import (
    SensitiveDataType,
    detect_sensitive_data,
    mask_sensitive_data,
    sanitize,
)


# Sample content with varying PII density
CONTENT_MINIMAL = "This is a simple message with no sensitive data."

CONTENT_SINGLE_PII = """
Hello John,

Your order has been shipped to john.doe@example.com.
Thank you for your purchase!
"""

CONTENT_MULTIPLE_PII = """
Customer Record:
Name: John Doe
Email: john.doe@example.com
Phone: +1 (555) 123-4567
SSN: 123-45-6789
Credit Card: 4532015112830366

Notes: Customer called about order #12345.
"""

CONTENT_INDIA_PII = """
Customer Record (India):
Name: Raj Kumar
Aadhaar: 2345 6789 0123
PAN: ABCDE1234F
UPI: rajkumar@okaxis
Bank IFSC: SBIN0001234
"""

CONTENT_SECRETS = """
Configuration:
API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz123456
AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE
password = "mysupersecretpassword123"
DATABASE_URL=postgres://user:pass@localhost:5432/db
JWT: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U
"""

CONTENT_LARGE = CONTENT_MULTIPLE_PII * 100  # ~50KB of content


class TestDetectionBenchmarks:
    """Benchmark PII/secret detection."""

    def test_detect_minimal_content(self, benchmark) -> None:  # type: ignore[no-untyped-def]
        """Detection on content with no PII."""
        result = benchmark(detect_sensitive_data, CONTENT_MINIMAL)
        assert len(result) == 0

    def test_detect_single_pii(self, benchmark) -> None:  # type: ignore[no-untyped-def]
        """Detection on content with single PII."""
        result = benchmark(detect_sensitive_data, CONTENT_SINGLE_PII)
        assert len(result) >= 1

    def test_detect_multiple_pii(self, benchmark) -> None:  # type: ignore[no-untyped-def]
        """Detection on content with multiple PII types."""
        result = benchmark(detect_sensitive_data, CONTENT_MULTIPLE_PII)
        assert len(result) >= 4

    def test_detect_india_pii(self, benchmark) -> None:  # type: ignore[no-untyped-def]
        """Detection of India-specific PII."""
        types = [
            SensitiveDataType.AADHAAR,
            SensitiveDataType.PAN,
            SensitiveDataType.UPI_ID,
            SensitiveDataType.IFSC,
        ]
        result = benchmark(detect_sensitive_data, CONTENT_INDIA_PII, types)
        assert len(result) >= 4

    def test_detect_secrets(self, benchmark) -> None:  # type: ignore[no-untyped-def]
        """Detection of secrets."""
        result = benchmark(detect_sensitive_data, CONTENT_SECRETS)
        assert len(result) >= 3

    def test_detect_large_content(self, benchmark) -> None:  # type: ignore[no-untyped-def]
        """Detection on large content (~50KB)."""
        result = benchmark(detect_sensitive_data, CONTENT_LARGE)
        assert len(result) >= 100


class TestMaskingBenchmarks:
    """Benchmark masking operations."""

    def test_mask_minimal(self, benchmark) -> None:  # type: ignore[no-untyped-def]
        """Masking on minimal content."""
        result, _ = benchmark(mask_sensitive_data, CONTENT_MINIMAL)
        assert result == CONTENT_MINIMAL

    def test_mask_multiple_pii(self, benchmark) -> None:  # type: ignore[no-untyped-def]
        """Masking multiple PII types."""
        result, detections = benchmark(mask_sensitive_data, CONTENT_MULTIPLE_PII)
        assert "123-45-6789" not in result
        assert len(detections) >= 4

    def test_mask_large_content(self, benchmark) -> None:  # type: ignore[no-untyped-def]
        """Masking on large content."""
        result, _ = benchmark(mask_sensitive_data, CONTENT_LARGE)
        assert "123-45-6789" not in result


class TestSanitizeBenchmarks:
    """Benchmark full sanitization pipeline."""

    def test_sanitize_minimal(self, benchmark) -> None:  # type: ignore[no-untyped-def]
        """Full sanitization on minimal content."""
        result = benchmark(sanitize, CONTENT_MINIMAL)
        assert result.content == CONTENT_MINIMAL

    def test_sanitize_with_pii(self, benchmark) -> None:  # type: ignore[no-untyped-def]
        """Full sanitization with PII."""
        result = benchmark(sanitize, CONTENT_MULTIPLE_PII)
        assert result.detection_count >= 4

    def test_sanitize_with_truncation(self, benchmark) -> None:  # type: ignore[no-untyped-def]
        """Full sanitization with truncation."""
        result = benchmark(sanitize, CONTENT_LARGE, max_chars=1000)
        assert result.was_truncated
        assert len(result.content) <= 1000
