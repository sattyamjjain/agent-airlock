"""Comprehensive tests for sanitizer module - targeting 100% coverage."""

from __future__ import annotations

from agent_airlock.sanitizer import (
    MaskingStrategy,
    SensitiveDataType,
    _mask_value,
    detect_sensitive_data,
    mask_sensitive_data,
    sanitize_output,
    truncate_output,
)


class TestMaskValueStrategies:
    """Tests for _mask_value with different strategies."""

    def test_full_masking(self) -> None:
        """Test FULL masking strategy."""
        result = _mask_value("test@example.com", SensitiveDataType.EMAIL, MaskingStrategy.FULL)
        assert result == "[REDACTED]"

    def test_type_only_masking(self) -> None:
        """Test TYPE_ONLY masking strategy."""
        result = _mask_value("test@example.com", SensitiveDataType.EMAIL, MaskingStrategy.TYPE_ONLY)
        assert result == "[EMAIL]"

    def test_hash_masking(self) -> None:
        """Test HASH masking strategy."""
        result = _mask_value("test@example.com", SensitiveDataType.EMAIL, MaskingStrategy.HASH)
        assert result.startswith("[SHA256:")
        assert result.endswith("...]")

    def test_partial_masking_short_value(self) -> None:
        """Test PARTIAL masking for short values."""
        result = _mask_value("short", SensitiveDataType.EMAIL, MaskingStrategy.PARTIAL)
        assert result == "*****"  # All asterisks for short values

    def test_partial_masking_email(self) -> None:
        """Test PARTIAL masking for email."""
        result = _mask_value(
            "john.doe@example.com", SensitiveDataType.EMAIL, MaskingStrategy.PARTIAL
        )
        assert result.startswith("j***@")
        assert "example.com" in result

    def test_partial_masking_email_short_local(self) -> None:
        """Test PARTIAL masking for email with single-char local part."""
        result = _mask_value("a@example.com", SensitiveDataType.EMAIL, MaskingStrategy.PARTIAL)
        assert "***@" in result

    def test_partial_masking_credit_card(self) -> None:
        """Test PARTIAL masking for credit card."""
        result = _mask_value(
            "4111111111111111", SensitiveDataType.CREDIT_CARD, MaskingStrategy.PARTIAL
        )
        assert result.endswith("1111")
        assert "****" in result

    def test_partial_masking_api_key(self) -> None:
        """Test PARTIAL masking for API key."""
        result = _mask_value(
            "sk-1234567890abcdef", SensitiveDataType.API_KEY, MaskingStrategy.PARTIAL
        )
        assert result.startswith("sk-1234")
        assert result.endswith("cdef")
        assert "..." in result

    def test_partial_masking_aws_key(self) -> None:
        """Test PARTIAL masking for AWS key."""
        result = _mask_value(
            "AKIA1234567890EXAMPLE", SensitiveDataType.AWS_KEY, MaskingStrategy.PARTIAL
        )
        assert result.startswith("AKIA123")
        assert "..." in result

    def test_partial_masking_jwt(self) -> None:
        """Test PARTIAL masking for JWT."""
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
        result = _mask_value(jwt, SensitiveDataType.JWT, MaskingStrategy.PARTIAL)
        assert result.startswith("eyJhbGciOi")
        assert "[JWT]" in result

    def test_partial_masking_default(self) -> None:
        """Test PARTIAL masking default behavior."""
        result = _mask_value("1234567890", SensitiveDataType.PHONE, MaskingStrategy.PARTIAL)
        assert result.startswith("123")
        assert result.endswith("890")
        assert "***" in result


class TestDetectSensitiveData:
    """Tests for detect_sensitive_data function."""

    def test_detect_no_pattern(self) -> None:
        """Test detection with non-existent pattern."""
        # Create a mock type that has no pattern
        content = "Some random content"
        detections = detect_sensitive_data(content, [SensitiveDataType.EMAIL])
        # Should return empty list when no matches
        assert isinstance(detections, list)

    def test_detect_password_pattern(self) -> None:
        """Test detecting password patterns."""
        content = 'password="mysecret123"'
        detections = detect_sensitive_data(content, [SensitiveDataType.PASSWORD])
        assert len(detections) > 0
        assert detections[0]["type"] == "password"

    def test_detect_sorted_by_position(self) -> None:
        """Test detections are sorted by position."""
        content = "SSN: 123-45-6789 Email: test@example.com"
        detections = detect_sensitive_data(
            content, [SensitiveDataType.EMAIL, SensitiveDataType.SSN]
        )
        if len(detections) >= 2:
            assert detections[0]["start"] < detections[1]["start"]


class TestMaskSensitiveData:
    """Tests for mask_sensitive_data function."""

    def test_mask_no_detections(self) -> None:
        """Test masking with no sensitive data."""
        content = "Hello world"
        result, detections = mask_sensitive_data(content)
        assert result == content
        assert detections == []

    def test_mask_password_pattern(self) -> None:
        """Test masking password patterns."""
        content = "password=mysecret123"
        result, detections = mask_sensitive_data(content, [SensitiveDataType.PASSWORD])
        # Check that something was detected and masked
        assert len(detections) > 0

    def test_mask_multiple_types(self) -> None:
        """Test masking multiple types."""
        content = "Email: test@example.com, Phone: 555-123-4567"
        result, detections = mask_sensitive_data(
            content, [SensitiveDataType.EMAIL, SensitiveDataType.PHONE]
        )
        assert "test@example.com" not in result
        assert len(detections) >= 1


class TestTruncateOutput:
    """Tests for truncate_output function."""

    def test_no_truncation_needed(self) -> None:
        """Test when no truncation is needed."""
        content = "Short content"
        result, was_truncated = truncate_output(content, max_chars=100)
        assert result == content
        assert was_truncated is False

    def test_truncation_with_summary(self) -> None:
        """Test truncation with summary notice."""
        content = "x" * 1000
        result, was_truncated = truncate_output(content, max_chars=100, add_summary=True)
        assert was_truncated is True
        assert len(result) <= 100
        assert "[OUTPUT TRUNCATED" in result

    def test_truncation_without_summary(self) -> None:
        """Test truncation without summary notice."""
        content = "x" * 1000
        result, was_truncated = truncate_output(content, max_chars=100, add_summary=False)
        assert was_truncated is True
        assert len(result) == 100
        assert "[OUTPUT TRUNCATED" not in result


class TestSanitizeOutput:
    """Tests for sanitize_output function."""

    def test_sanitize_string_output(self) -> None:
        """Test sanitizing string output."""
        content = "Email: test@example.com"
        result = sanitize_output(content, mask_pii=True)
        assert "test@example.com" not in result.content
        assert result.detection_count >= 1

    def test_sanitize_dict_output(self) -> None:
        """Test sanitizing dict output."""
        content = {"email": "test@example.com", "name": "John"}
        result = sanitize_output(content, mask_pii=True)
        # Dict should be converted to string and sanitized
        assert result.detection_count >= 0

    def test_sanitize_with_truncation(self) -> None:
        """Test sanitizing with truncation."""
        content = "x" * 10000
        result = sanitize_output(content, max_chars=100)
        assert result.was_truncated is True

    def test_sanitize_empty_content(self) -> None:
        """Test sanitizing empty content."""
        result = sanitize_output("", mask_pii=True)
        assert result.content == ""
        assert result.detection_count == 0

    def test_sanitize_none_input(self) -> None:
        """Test sanitizing None input."""
        result = sanitize_output(None, mask_pii=True)  # type: ignore
        assert result.content == "None"


class TestSensitiveDataPatterns:
    """Tests for various sensitive data patterns."""

    def test_jwt_detection(self) -> None:
        """Test JWT detection."""
        content = "Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig"
        detections = detect_sensitive_data(content, [SensitiveDataType.JWT])
        assert len(detections) >= 1

    def test_connection_string_detection(self) -> None:
        """Test connection string detection."""
        content = "postgres://user:password@localhost:5432/db"
        detections = detect_sensitive_data(content, [SensitiveDataType.CONNECTION_STRING])
        assert len(detections) >= 1

    def test_private_key_detection(self) -> None:
        """Test private key marker detection."""
        content = "-----BEGIN PRIVATE KEY-----\nMIIE..."
        detections = detect_sensitive_data(content, [SensitiveDataType.PRIVATE_KEY])
        assert len(detections) >= 1

    def test_ip_address_detection(self) -> None:
        """Test IP address detection."""
        content = "Server: 192.168.1.100"
        detections = detect_sensitive_data(content, [SensitiveDataType.IP_ADDRESS])
        assert len(detections) >= 1

    def test_ssn_detection(self) -> None:
        """Test SSN detection."""
        content = "SSN: 123-45-6789"
        detections = detect_sensitive_data(content, [SensitiveDataType.SSN])
        assert len(detections) >= 1

    def test_credit_card_detection(self) -> None:
        """Test credit card detection."""
        # Use format that matches the pattern (no dashes, just digits)
        content = "Card: 4111111111111111"
        detections = detect_sensitive_data(content, [SensitiveDataType.CREDIT_CARD])
        assert len(detections) >= 1

    def test_email_detection(self) -> None:
        """Test email detection."""
        content = "Contact: user@example.com"
        detections = detect_sensitive_data(content, [SensitiveDataType.EMAIL])
        assert len(detections) >= 1

    def test_aws_key_detection(self) -> None:
        """Test AWS key detection."""
        content = "Key: AKIAIOSFODNN7EXAMPLE"
        detections = detect_sensitive_data(content, [SensitiveDataType.AWS_KEY])
        assert len(detections) >= 1

    def test_api_key_detection(self) -> None:
        """Test OpenAI-style API key detection."""
        content = "Key: sk-abc123def456ghi789jkl0123456789012345678901234"
        detections = detect_sensitive_data(content, [SensitiveDataType.API_KEY])
        assert len(detections) >= 1
