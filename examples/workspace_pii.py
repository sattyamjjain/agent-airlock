"""Workspace-Specific PII Example - Multi-tenant PII handling.

This example demonstrates how to configure different PII masking rules
for different workspaces/tenants, enabling customized data protection.

Run with: python examples/workspace_pii.py
"""

from __future__ import annotations

from agent_airlock import (
    MaskingStrategy,
    SensitiveDataType,
    WorkspacePIIConfig,
    sanitize_with_workspace_config,
)


def demonstrate_allow_internal_emails() -> None:
    """Demonstrate allowing internal company emails."""
    print("\n1. Allow Internal Emails:")
    print("-" * 40)

    # Enterprise workspace: Don't mask internal emails
    config = WorkspacePIIConfig(
        workspace_id="enterprise-acme",
        allow_email_domains=["acme.com", "acme.internal"],
    )

    content = """
    Contact information:
    - Internal: alice@acme.com
    - Partner: bob@partner.com
    - Customer: customer@gmail.com
    """

    result = sanitize_with_workspace_config(content, config)
    print("Original:")
    print(content)
    print("\nSanitized (internal emails preserved):")
    print(result.content)
    print(f"\nMasked {result.detection_count} items")


def demonstrate_mask_competitor_only() -> None:
    """Demonstrate masking only specific domains."""
    print("\n2. Mask Competitor Emails Only:")
    print("-" * 40)

    # Only mask emails from competitor domains
    config = WorkspacePIIConfig(
        workspace_id="sales-team",
        mask_email_domains=["competitor1.com", "competitor2.com"],
    )

    content = """
    Leads:
    - Prospect: lead@prospect.com (keep visible)
    - Competitor spy: mole@competitor1.com (mask this!)
    - Friend: friend@example.com (keep visible)
    """

    result = sanitize_with_workspace_config(content, config)
    print("Sanitized (only competitor emails masked):")
    print(result.content)


def demonstrate_phone_filtering() -> None:
    """Demonstrate phone number filtering by prefix."""
    print("\n3. Phone Number Filtering:")
    print("-" * 40)

    # Allow toll-free numbers, mask personal numbers
    config = WorkspacePIIConfig(
        workspace_id="support-team",
        allow_phone_prefixes=["+1800", "1800", "+1888", "1888"],
    )

    content = """
    Contact numbers:
    - Toll-free: 1-800-555-1234 (public, keep visible)
    - Personal: 555-123-4567 (mask this)
    - Support: +1888-555-9999 (public, keep visible)
    """

    result = sanitize_with_workspace_config(content, config)
    print("Sanitized (toll-free numbers preserved):")
    print(result.content)


def demonstrate_custom_patterns() -> None:
    """Demonstrate custom regex patterns."""
    print("\n4. Custom Patterns:")
    print("-" * 40)

    # Define custom patterns for workspace-specific data
    config = WorkspacePIIConfig(
        workspace_id="hr-department",
        custom_patterns={
            "employee_id": r"EMP-\d{6}",
            "badge_number": r"BADGE-[A-Z]{2}\d{4}",
            "salary": r"\$\d{1,3}(?:,\d{3})*(?:\.\d{2})?",
        },
        custom_strategies={
            "employee_id": MaskingStrategy.TYPE_ONLY,
            "salary": MaskingStrategy.FULL,
        },
    )

    content = """
    Employee Record:
    - ID: EMP-123456
    - Badge: BADGE-AB1234
    - Email: employee@company.com
    - Salary: $85,000.00
    """

    result = sanitize_with_workspace_config(content, config)
    print("Sanitized (custom patterns masked):")
    print(result.content)


def demonstrate_disabled_types() -> None:
    """Demonstrate disabling specific sensitive data types."""
    print("\n5. Disabled Data Types:")
    print("-" * 40)

    # Startup workspace: More relaxed, only mask critical data
    config = WorkspacePIIConfig(
        workspace_id="startup-dev",
        disabled_types=[
            SensitiveDataType.EMAIL,
            SensitiveDataType.PHONE,
            SensitiveDataType.IP_ADDRESS,
        ],
    )

    content = """
    Debug info:
    - User: dev@startup.com
    - Phone: 555-123-4567
    - Server: 192.168.1.100
    - SSN: 123-45-6789 (still masked!)
    - API Key: sk-1234567890abcdef (still masked!)
    """

    result = sanitize_with_workspace_config(content, config)
    print("Sanitized (only SSN and secrets masked):")
    print(result.content)


def demonstrate_enabled_types_only() -> None:
    """Demonstrate enabling only specific types."""
    print("\n6. Enabled Types Only:")
    print("-" * 40)

    # HIPAA-focused: Only mask medical-related identifiers
    config = WorkspacePIIConfig(
        workspace_id="healthcare-app",
        enabled_types=[SensitiveDataType.SSN],  # Only SSN for HIPAA
    )

    content = """
    Patient record:
    - Name: John Doe
    - SSN: 123-45-6789 (mask this - PHI)
    - Email: patient@gmail.com (not masked in this config)
    - Phone: 555-123-4567 (not masked in this config)
    """

    result = sanitize_with_workspace_config(content, config)
    print("Sanitized (only SSN masked for HIPAA focus):")
    print(result.content)


def demonstrate_multiple_workspaces() -> None:
    """Demonstrate different configs for different workspaces."""
    print("\n7. Multiple Workspace Comparison:")
    print("-" * 40)

    content = """
    Report:
    - Contact: user@example.com
    - Phone: 555-123-4567
    - SSN: 123-45-6789
    """

    # Enterprise: Strict - mask everything
    enterprise = WorkspacePIIConfig(workspace_id="enterprise")

    # Startup: Relaxed - only mask SSN
    startup = WorkspacePIIConfig(
        workspace_id="startup",
        enabled_types=[SensitiveDataType.SSN],
    )

    # Development: Very relaxed - mask nothing
    development = WorkspacePIIConfig(
        workspace_id="development",
        disabled_types=list(SensitiveDataType),
    )

    print("Same content, different workspace configs:\n")

    for name, config in [
        ("Enterprise (strict)", enterprise),
        ("Startup (SSN only)", startup),
        ("Development (none)", development),
    ]:
        result = sanitize_with_workspace_config(content, config)
        print(f"{name}:")
        print(f"  Masked items: {result.detection_count}")
        # Show first line of result
        first_line = result.content.strip().split("\n")[1]
        print(f"  Email line: {first_line}")


def main() -> None:
    """Run workspace PII examples."""
    print("=" * 60)
    print("Workspace-Specific PII Example")
    print("=" * 60)

    demonstrate_allow_internal_emails()
    demonstrate_mask_competitor_only()
    demonstrate_phone_filtering()
    demonstrate_custom_patterns()
    demonstrate_disabled_types()
    demonstrate_enabled_types_only()
    demonstrate_multiple_workspaces()

    print("\n" + "=" * 60)
    print("Workspace PII examples completed!")
    print("\nKey features demonstrated:")
    print("- Allow/mask specific email domains")
    print("- Phone number prefix filtering")
    print("- Custom regex patterns")
    print("- Disable/enable specific data types")
    print("- Multi-tenant configuration")


if __name__ == "__main__":
    main()
