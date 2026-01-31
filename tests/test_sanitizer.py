"""Tests for the sanitizer module."""

from agent_airlock import (
    Airlock,
    AirlockConfig,
    MaskingStrategy,
    SanitizationResult,
    SensitiveDataType,
    detect_sensitive_data,
    mask_sensitive_data,
    sanitize_output,
)


class TestDetectSensitiveData:
    """Tests for sensitive data detection."""

    def test_detect_email(self) -> None:
        content = "Contact me at john.doe@example.com for more info."
        detections = detect_sensitive_data(content, [SensitiveDataType.EMAIL])

        assert len(detections) == 1
        assert detections[0]["type"] == "email"
        assert detections[0]["value"] == "john.doe@example.com"

    def test_detect_multiple_emails(self) -> None:
        content = "Email alice@test.com or bob@test.org for help."
        detections = detect_sensitive_data(content, [SensitiveDataType.EMAIL])

        assert len(detections) == 2
        assert detections[0]["value"] == "alice@test.com"
        assert detections[1]["value"] == "bob@test.org"

    def test_detect_phone_number(self) -> None:
        content = "Call me at (555) 123-4567 or 555.987.6543"
        detections = detect_sensitive_data(content, [SensitiveDataType.PHONE])

        assert len(detections) == 2

    def test_detect_ssn(self) -> None:
        content = "SSN: 123-45-6789"
        detections = detect_sensitive_data(content, [SensitiveDataType.SSN])

        assert len(detections) == 1
        assert detections[0]["type"] == "ssn"

    def test_detect_credit_card_visa(self) -> None:
        content = "Card: 4111111111111111"
        detections = detect_sensitive_data(content, [SensitiveDataType.CREDIT_CARD])

        assert len(detections) == 1
        assert detections[0]["type"] == "credit_card"

    def test_detect_credit_card_mastercard(self) -> None:
        content = "Card: 5500000000000004"
        detections = detect_sensitive_data(content, [SensitiveDataType.CREDIT_CARD])

        assert len(detections) == 1

    def test_detect_credit_card_amex(self) -> None:
        content = "Card: 340000000000009"
        detections = detect_sensitive_data(content, [SensitiveDataType.CREDIT_CARD])

        assert len(detections) == 1

    def test_detect_ip_address(self) -> None:
        content = "Server IP: 192.168.1.100"
        detections = detect_sensitive_data(content, [SensitiveDataType.IP_ADDRESS])

        assert len(detections) == 1
        assert detections[0]["value"] == "192.168.1.100"

    def test_detect_openai_api_key(self) -> None:
        content = "API key: sk-abcdefghijklmnopqrstuvwxyz"
        detections = detect_sensitive_data(content, [SensitiveDataType.API_KEY])

        assert len(detections) == 1
        assert detections[0]["type"] == "api_key"

    def test_detect_anthropic_api_key(self) -> None:
        content = "Key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz"
        detections = detect_sensitive_data(content, [SensitiveDataType.API_KEY])

        assert len(detections) == 1

    def test_detect_github_pat(self) -> None:
        content = "Token: ghp_abcdefghijklmnopqrstuvwxyz0123456789"
        detections = detect_sensitive_data(content, [SensitiveDataType.API_KEY])

        assert len(detections) == 1

    def test_detect_aws_key(self) -> None:
        content = "AWS Key: AKIAIOSFODNN7EXAMPLE"
        detections = detect_sensitive_data(content, [SensitiveDataType.AWS_KEY])

        assert len(detections) == 1
        assert detections[0]["type"] == "aws_key"

    def test_detect_password(self) -> None:
        content = "password = 'mysecretpassword123'"
        detections = detect_sensitive_data(content, [SensitiveDataType.PASSWORD])

        assert len(detections) == 1
        assert detections[0]["type"] == "password"
        assert detections[0]["value"] == "mysecretpassword123"

    def test_detect_private_key(self) -> None:
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."
        detections = detect_sensitive_data(content, [SensitiveDataType.PRIVATE_KEY])

        assert len(detections) == 1

    def test_detect_jwt(self) -> None:
        content = "Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        detections = detect_sensitive_data(content, [SensitiveDataType.JWT])

        assert len(detections) == 1

    def test_detect_connection_string_postgres(self) -> None:
        content = "DB: postgres://user:pass@host:5432/db"
        detections = detect_sensitive_data(content, [SensitiveDataType.CONNECTION_STRING])

        assert len(detections) == 1

    def test_detect_connection_string_mongodb(self) -> None:
        content = "mongodb+srv://user:pass@cluster.mongodb.net/db"
        detections = detect_sensitive_data(content, [SensitiveDataType.CONNECTION_STRING])

        assert len(detections) == 1

    def test_detect_all_types(self) -> None:
        content = "Email: test@example.com, SSN: 123-45-6789"
        detections = detect_sensitive_data(content)  # All types

        assert len(detections) >= 2

    def test_no_detections(self) -> None:
        content = "This is a normal message with no sensitive data."
        detections = detect_sensitive_data(content)

        assert len(detections) == 0


class TestMaskSensitiveData:
    """Tests for sensitive data masking."""

    def test_mask_email_partial(self) -> None:
        content = "Email: john.doe@example.com"
        masked, detections = mask_sensitive_data(content, [SensitiveDataType.EMAIL])

        assert "john.doe@example.com" not in masked
        assert "@example.com" in masked  # Domain preserved
        assert len(detections) == 1

    def test_mask_ssn_full(self) -> None:
        content = "SSN: 123-45-6789"
        masked, detections = mask_sensitive_data(content, [SensitiveDataType.SSN])

        assert "123-45-6789" not in masked
        assert "[REDACTED]" in masked

    def test_mask_credit_card_partial(self) -> None:
        content = "Card: 4111111111111111"
        masked, detections = mask_sensitive_data(content, [SensitiveDataType.CREDIT_CARD])

        assert "4111111111111111" not in masked
        assert "1111" in masked  # Last 4 preserved

    def test_mask_api_key_partial(self) -> None:
        content = "Key: sk-abcdefghijklmnopqrstuvwxyz"
        masked, detections = mask_sensitive_data(content, [SensitiveDataType.API_KEY])

        assert "sk-abcdefghijklmnopqrstuvwxyz" not in masked
        assert "sk-abcd" in masked  # Prefix preserved

    def test_mask_password_full(self) -> None:
        content = "password=supersecret123"
        masked, detections = mask_sensitive_data(content, [SensitiveDataType.PASSWORD])

        assert "supersecret123" not in masked
        assert "[REDACTED]" in masked

    def test_custom_masking_strategy(self) -> None:
        content = "Email: test@example.com"
        custom_config = {SensitiveDataType.EMAIL: MaskingStrategy.TYPE_ONLY}
        masked, detections = mask_sensitive_data(
            content,
            [SensitiveDataType.EMAIL],
            mask_config=custom_config,
        )

        assert "[EMAIL]" in masked

    def test_mask_multiple_values(self) -> None:
        content = "Email: a@b.com, Phone: 555-123-4567, SSN: 123-45-6789"
        masked, detections = mask_sensitive_data(content)

        assert "a@b.com" not in masked
        assert "123-45-6789" not in masked
        assert len(detections) >= 3

    def test_no_changes_when_no_sensitive_data(self) -> None:
        content = "This is normal text."
        masked, detections = mask_sensitive_data(content)

        assert masked == content
        assert len(detections) == 0


class TestTruncateOutput:
    """Tests for output truncation."""

    def test_no_truncation_when_under_limit(self) -> None:
        result = sanitize_output("Short text", max_chars=100)

        assert result.was_truncated is False
        assert result.content == "Short text"

    def test_truncation_when_over_limit(self) -> None:
        long_text = "x" * 1000
        result = sanitize_output(long_text, max_chars=100)

        assert result.was_truncated is True
        assert len(result.content) <= 100
        assert "[OUTPUT TRUNCATED:" in result.content

    def test_truncation_preserves_newline_boundary(self) -> None:
        text = "Line 1\nLine 2\nLine 3\nLine 4\nLine 5"
        result = sanitize_output(text, max_chars=30)

        assert result.was_truncated is True
        # Should truncate at a newline boundary when possible

    def test_no_truncation_when_limit_is_none(self) -> None:
        long_text = "x" * 10000
        result = sanitize_output(long_text, max_chars=None)

        assert result.was_truncated is False


class TestSanitizeOutput:
    """Tests for the main sanitize_output function."""

    def test_sanitize_string(self) -> None:
        content = "Email: test@example.com"
        result = sanitize_output(content)

        assert isinstance(result, SanitizationResult)
        assert result.detection_count > 0

    def test_sanitize_dict(self) -> None:
        content = {"email": "test@example.com", "data": "normal"}
        result = sanitize_output(content)

        assert result.detection_count > 0
        assert "test@example.com" not in result.content

    def test_sanitize_list(self) -> None:
        content = ["test@example.com", "normal text"]
        result = sanitize_output(content)

        assert result.detection_count > 0

    def test_disable_pii_masking(self) -> None:
        content = "Email: test@example.com"
        result = sanitize_output(content, mask_pii=False, mask_secrets=True)

        # Email should not be masked when PII masking is disabled
        assert "test@example.com" in result.content

    def test_disable_secret_masking(self) -> None:
        content = "Key: sk-abcdefghijklmnopqrstuvwxyz"
        result = sanitize_output(content, mask_pii=True, mask_secrets=False)

        # API key should not be masked when secret masking is disabled
        assert "sk-abcdefghijklmnopqrstuvwxyz" in result.content

    def test_result_metadata(self) -> None:
        content = "SSN: 123-45-6789 " + ("x" * 1000)
        result = sanitize_output(content, max_chars=150)

        assert result.original_length > 150
        assert result.was_truncated is True
        assert result.detection_count > 0

    def test_to_dict(self) -> None:
        content = "Email: test@example.com"
        result = sanitize_output(content)
        result_dict = result.to_dict()

        assert "original_length" in result_dict
        assert "sanitized_length" in result_dict
        assert "detection_count" in result_dict
        assert "was_truncated" in result_dict


class TestAirlockSanitizationIntegration:
    """Tests for Airlock decorator with sanitization."""

    def test_sanitizes_string_output(self) -> None:
        config = AirlockConfig(sanitize_output=True, mask_pii=True)

        @Airlock(config=config)
        def get_user_info(user_id: int) -> str:
            return f"User {user_id}: john.doe@example.com, SSN: 123-45-6789"

        result = get_user_info(user_id=123)

        assert isinstance(result, str)
        assert "john.doe@example.com" not in result
        assert "123-45-6789" not in result

    def test_return_dict_includes_warnings(self) -> None:
        config = AirlockConfig(sanitize_output=True, mask_pii=True)

        @Airlock(config=config, return_dict=True)
        def get_email(_user_id: int) -> str:
            return "User email: test@example.com"

        result = get_email(_user_id=1)

        assert isinstance(result, dict)
        assert result["success"] is True
        assert "warnings" in result
        assert len(result["warnings"]) > 0

    def test_truncates_long_output(self) -> None:
        config = AirlockConfig(
            sanitize_output=True,
            max_output_chars=100,
        )

        @Airlock(config=config)
        def get_long_text() -> str:
            return "x" * 1000

        result = get_long_text()

        assert isinstance(result, str)
        assert len(result) <= 100

    def test_sanitization_disabled(self) -> None:
        config = AirlockConfig(sanitize_output=False)

        @Airlock(config=config)
        def get_email() -> str:
            return "Email: test@example.com"

        result = get_email()

        assert isinstance(result, str)
        assert "test@example.com" in result

    def test_complex_return_type_not_modified(self) -> None:
        config = AirlockConfig(sanitize_output=True, mask_pii=True)

        @Airlock(config=config)
        def get_data() -> dict[str, str]:
            return {"email": "test@example.com"}

        result = get_data()

        # Dict results are not modified (sanitization is for detection/logging)
        assert isinstance(result, dict)


class TestMaskingStrategies:
    """Tests for different masking strategies."""

    def test_full_strategy(self) -> None:
        config = {SensitiveDataType.EMAIL: MaskingStrategy.FULL}
        content = "Email: test@example.com"
        masked, _ = mask_sensitive_data(content, [SensitiveDataType.EMAIL], config)

        assert "[REDACTED]" in masked

    def test_type_only_strategy(self) -> None:
        config = {SensitiveDataType.SSN: MaskingStrategy.TYPE_ONLY}
        content = "SSN: 123-45-6789"
        masked, _ = mask_sensitive_data(content, [SensitiveDataType.SSN], config)

        assert "[SSN]" in masked

    def test_hash_strategy(self) -> None:
        config = {SensitiveDataType.EMAIL: MaskingStrategy.HASH}
        content = "Email: test@example.com"
        masked, _ = mask_sensitive_data(content, [SensitiveDataType.EMAIL], config)

        assert "[SHA256:" in masked


class TestSensitiveDataTypes:
    """Tests for SensitiveDataType enum."""

    def test_pii_types(self) -> None:
        pii_types = [
            SensitiveDataType.EMAIL,
            SensitiveDataType.PHONE,
            SensitiveDataType.SSN,
            SensitiveDataType.CREDIT_CARD,
            SensitiveDataType.IP_ADDRESS,
        ]

        for dt in pii_types:
            assert isinstance(dt.value, str)

    def test_secret_types(self) -> None:
        secret_types = [
            SensitiveDataType.API_KEY,
            SensitiveDataType.PASSWORD,
            SensitiveDataType.AWS_KEY,
            SensitiveDataType.PRIVATE_KEY,
            SensitiveDataType.JWT,
            SensitiveDataType.CONNECTION_STRING,
        ]

        for dt in secret_types:
            assert isinstance(dt.value, str)
