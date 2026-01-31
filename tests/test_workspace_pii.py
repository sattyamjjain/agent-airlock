"""Tests for workspace-specific PII handling."""

from __future__ import annotations

import pytest

from agent_airlock.sanitizer import (
    MaskingStrategy,
    SensitiveDataType,
    WorkspacePIIConfig,
    sanitize_with_workspace_config,
)


class TestWorkspacePIIConfig:
    """Tests for WorkspacePIIConfig."""

    def test_default_masks_all_emails(self) -> None:
        """By default, all emails are masked."""
        config = WorkspacePIIConfig(workspace_id="test")

        assert config.should_mask_email("user@example.com")
        assert config.should_mask_email("admin@company.com")
        assert config.should_mask_email("test@internal.org")

    def test_allow_email_domains(self) -> None:
        """Emails from allowed domains are not masked."""
        config = WorkspacePIIConfig(
            workspace_id="test",
            allow_email_domains=["company.com", "internal.org"],
        )

        assert not config.should_mask_email("user@company.com")
        assert not config.should_mask_email("admin@internal.org")
        assert config.should_mask_email("user@external.com")

    def test_mask_email_domains_only(self) -> None:
        """When mask_email_domains is set, only those domains are masked."""
        config = WorkspacePIIConfig(
            workspace_id="test",
            mask_email_domains=["competitor.com"],
        )

        assert config.should_mask_email("spy@competitor.com")
        assert not config.should_mask_email("user@company.com")
        assert not config.should_mask_email("friend@example.com")

    def test_allow_overrides_mask(self) -> None:
        """Allow domains take precedence over mask domains."""
        config = WorkspacePIIConfig(
            workspace_id="test",
            mask_email_domains=["example.com"],
            allow_email_domains=["safe.example.com"],
        )

        # Subdomains of allowed should not be masked
        assert not config.should_mask_email("user@safe.example.com")
        # But parent domain should be masked
        assert config.should_mask_email("user@example.com")

    def test_default_masks_all_phones(self) -> None:
        """By default, all phone numbers are masked."""
        config = WorkspacePIIConfig(workspace_id="test")

        assert config.should_mask_phone("+1-555-123-4567")
        assert config.should_mask_phone("555-123-4567")
        assert config.should_mask_phone("+44 20 7946 0958")

    def test_allow_phone_prefixes(self) -> None:
        """Phones with allowed prefixes are not masked."""
        config = WorkspacePIIConfig(
            workspace_id="test",
            allow_phone_prefixes=["+1800", "1800"],  # Toll-free
        )

        assert not config.should_mask_phone("+1800-555-1234")
        assert not config.should_mask_phone("1800-555-1234")
        assert config.should_mask_phone("+1-555-123-4567")

    def test_mask_phone_prefixes_only(self) -> None:
        """When mask_phone_prefixes is set, only those prefixes are masked."""
        config = WorkspacePIIConfig(
            workspace_id="test",
            mask_phone_prefixes=["+44"],  # Only mask UK numbers
        )

        assert config.should_mask_phone("+44 20 7946 0958")
        assert not config.should_mask_phone("+1-555-123-4567")

    def test_disabled_types(self) -> None:
        """Disabled types are excluded from active types."""
        config = WorkspacePIIConfig(
            workspace_id="test",
            disabled_types=[SensitiveDataType.EMAIL, SensitiveDataType.PHONE],
        )

        active = config.get_active_types()
        assert SensitiveDataType.EMAIL not in active
        assert SensitiveDataType.PHONE not in active
        assert SensitiveDataType.SSN in active
        assert SensitiveDataType.API_KEY in active

    def test_enabled_types_overrides_disabled(self) -> None:
        """enabled_types takes precedence over disabled_types."""
        config = WorkspacePIIConfig(
            workspace_id="test",
            disabled_types=[SensitiveDataType.SSN],  # This is ignored
            enabled_types=[SensitiveDataType.EMAIL, SensitiveDataType.SSN],
        )

        active = config.get_active_types()
        assert active == [SensitiveDataType.EMAIL, SensitiveDataType.SSN]

    def test_custom_patterns(self) -> None:
        """Custom patterns can be compiled."""
        config = WorkspacePIIConfig(
            workspace_id="test",
            custom_patterns={
                "employee_id": r"EMP-\d{6}",
                "ticket_id": r"TICKET-[A-Z]{3}-\d{4}",
            },
        )

        patterns = config.get_custom_compiled_patterns()
        assert len(patterns) == 2
        assert patterns["employee_id"].match("EMP-123456")
        assert patterns["ticket_id"].match("TICKET-ABC-1234")

    def test_invalid_custom_pattern_logged(self) -> None:
        """Invalid regex patterns are logged but don't crash."""
        config = WorkspacePIIConfig(
            workspace_id="test",
            custom_patterns={
                "valid": r"\d+",
                "invalid": r"[invalid(",  # Bad regex
            },
        )

        patterns = config.get_custom_compiled_patterns()
        assert "valid" in patterns
        assert "invalid" not in patterns  # Skipped due to error


class TestSanitizeWithWorkspaceConfig:
    """Tests for sanitize_with_workspace_config."""

    def test_basic_sanitization(self) -> None:
        """Basic sanitization works with workspace config."""
        config = WorkspacePIIConfig(workspace_id="test")
        content = "Contact user@example.com for help"

        result = sanitize_with_workspace_config(content, config)

        assert "user@example.com" not in result.content
        assert result.detection_count == 1

    def test_allow_domains_not_masked(self) -> None:
        """Allowed email domains are not masked."""
        config = WorkspacePIIConfig(
            workspace_id="enterprise",
            allow_email_domains=["company.com"],
        )
        content = "Contact internal@company.com or external@other.com"

        result = sanitize_with_workspace_config(content, config)

        assert "internal@company.com" in result.content  # Not masked
        assert "external@other.com" not in result.content  # Masked
        assert result.detection_count == 1

    def test_mask_specific_domains_only(self) -> None:
        """Only specified domains are masked when mask_email_domains is set."""
        config = WorkspacePIIConfig(
            workspace_id="test",
            mask_email_domains=["competitor.com"],
        )
        content = "Friend: friend@example.com, Competitor: spy@competitor.com"

        result = sanitize_with_workspace_config(content, config)

        assert "friend@example.com" in result.content  # Not masked
        assert "spy@competitor.com" not in result.content  # Masked
        assert result.detection_count == 1

    def test_disabled_types_not_detected(self) -> None:
        """Disabled sensitive data types are not detected."""
        config = WorkspacePIIConfig(
            workspace_id="test",
            disabled_types=[SensitiveDataType.EMAIL],
        )
        content = "Email: user@example.com, SSN: 123-45-6789"

        result = sanitize_with_workspace_config(content, config)

        assert "user@example.com" in result.content  # Not masked (disabled)
        assert "123-45-6789" not in result.content  # Masked (SSN still active)
        assert result.detection_count == 1

    def test_custom_patterns_masked(self) -> None:
        """Custom patterns are detected and masked."""
        config = WorkspacePIIConfig(
            workspace_id="test",
            custom_patterns={
                "employee_id": r"EMP-\d{6}",
            },
        )
        content = "Employee EMP-123456 submitted the request"

        result = sanitize_with_workspace_config(content, config)

        assert "EMP-123456" not in result.content
        assert "[REDACTED]" in result.content
        assert result.detection_count == 1

    def test_custom_pattern_with_type_only_strategy(self) -> None:
        """Custom patterns can use TYPE_ONLY strategy."""
        config = WorkspacePIIConfig(
            workspace_id="test",
            custom_patterns={
                "order_id": r"ORD-\d{8}",
            },
            custom_strategies={
                "order_id": MaskingStrategy.TYPE_ONLY,
            },
        )
        content = "Order ORD-12345678 confirmed"

        result = sanitize_with_workspace_config(content, config)

        assert "ORD-12345678" not in result.content
        assert "[ORDER_ID]" in result.content

    def test_truncation_with_workspace_config(self) -> None:
        """Output truncation works with workspace config."""
        config = WorkspacePIIConfig(workspace_id="test")
        content = "x" * 1000

        result = sanitize_with_workspace_config(content, config, max_chars=500)

        assert result.was_truncated
        assert len(result.content) <= 600  # Some buffer for notice

    def test_secrets_with_workspace_config(self) -> None:
        """Secrets are masked with workspace config."""
        config = WorkspacePIIConfig(workspace_id="test")
        content = "API key: sk-1234567890abcdefghijklmnop"

        result = sanitize_with_workspace_config(content, config)

        assert "sk-1234567890abcdefghijklmnop" not in result.content
        assert result.detection_count == 1

    def test_mask_pii_false_skips_pii(self) -> None:
        """mask_pii=False skips PII masking."""
        config = WorkspacePIIConfig(workspace_id="test")
        content = "Email: user@example.com, API: sk-1234567890abcdefghijklmnop"

        result = sanitize_with_workspace_config(
            content, config, mask_pii=False, mask_secrets=True
        )

        assert "user@example.com" in result.content  # PII not masked
        assert "sk-1234567890abcdefghijklmnop" not in result.content  # Secret masked

    def test_mask_secrets_false_skips_secrets(self) -> None:
        """mask_secrets=False skips secret masking."""
        config = WorkspacePIIConfig(workspace_id="test")
        content = "Email: user@example.com, API: sk-1234567890abcdefghijklmnop"

        result = sanitize_with_workspace_config(
            content, config, mask_pii=True, mask_secrets=False
        )

        assert "user@example.com" not in result.content  # PII masked
        assert "sk-1234567890abcdefghijklmnop" in result.content  # Secret not masked


class TestMultipleWorkspaces:
    """Tests for multiple workspace configurations."""

    def test_different_workspaces_different_rules(self) -> None:
        """Different workspaces can have different rules."""
        content = "Contact partner@partner.com or support@company.com"

        # Workspace A: Only mask partner emails
        config_a = WorkspacePIIConfig(
            workspace_id="workspace-a",
            mask_email_domains=["partner.com"],
        )
        result_a = sanitize_with_workspace_config(content, config_a)
        assert "support@company.com" in result_a.content
        assert "partner@partner.com" not in result_a.content

        # Workspace B: Allow internal emails
        config_b = WorkspacePIIConfig(
            workspace_id="workspace-b",
            allow_email_domains=["company.com"],
        )
        result_b = sanitize_with_workspace_config(content, config_b)
        assert "support@company.com" in result_b.content
        assert "partner@partner.com" not in result_b.content

    def test_enterprise_vs_startup_config(self) -> None:
        """Enterprise vs startup configurations differ."""
        content = "SSN: 123-45-6789, Email: test@example.com"

        # Enterprise: Strict - mask everything
        enterprise = WorkspacePIIConfig(workspace_id="enterprise")
        result_enterprise = sanitize_with_workspace_config(content, enterprise)
        assert result_enterprise.detection_count == 2

        # Startup: Relaxed - only mask SSN
        startup = WorkspacePIIConfig(
            workspace_id="startup",
            enabled_types=[SensitiveDataType.SSN],  # Only SSN
        )
        result_startup = sanitize_with_workspace_config(content, startup)
        assert "123-45-6789" not in result_startup.content
        assert "test@example.com" in result_startup.content
        assert result_startup.detection_count == 1
