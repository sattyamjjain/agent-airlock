"""Output sanitization for Agent-Airlock.

Provides PII detection, secret masking, and token truncation to prevent
sensitive data leakage back to LLMs and control output costs.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import structlog

logger = structlog.get_logger("agent-airlock.sanitizer")


class SensitiveDataType(str, Enum):
    """Types of sensitive data that can be detected."""

    # PII
    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    IP_ADDRESS = "ip_address"

    # Secrets
    API_KEY = "api_key"
    PASSWORD = "password"  # nosec B105 - enum value name, not actual password
    AWS_KEY = "aws_key"
    PRIVATE_KEY = "private_key"
    JWT = "jwt"
    CONNECTION_STRING = "connection_string"


class MaskingStrategy(str, Enum):
    """Strategies for masking sensitive data."""

    FULL = "full"  # Replace entirely with [REDACTED]
    PARTIAL = "partial"  # Keep first/last few chars: sk-****-abcd
    TYPE_ONLY = "type_only"  # Replace with [EMAIL], [SSN], etc.
    HASH = "hash"  # Replace with hash prefix: [SHA256:a1b2c3...]


@dataclass
class SanitizationResult:
    """Result of sanitizing content."""

    original_length: int
    sanitized_length: int
    content: str
    was_truncated: bool = False
    detections: list[dict[str, Any]] = field(default_factory=list)
    detection_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "original_length": self.original_length,
            "sanitized_length": self.sanitized_length,
            "was_truncated": self.was_truncated,
            "detection_count": self.detection_count,
            "detections": self.detections,
        }


# Compiled regex patterns for sensitive data detection
PATTERNS: dict[SensitiveDataType, re.Pattern[str]] = {
    # PII Patterns
    SensitiveDataType.EMAIL: re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    SensitiveDataType.PHONE: re.compile(
        r"\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b"
    ),
    SensitiveDataType.SSN: re.compile(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b"),
    SensitiveDataType.CREDIT_CARD: re.compile(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|"  # Visa
        r"5[1-5][0-9]{14}|"  # Mastercard
        r"3[47][0-9]{13}|"  # Amex
        r"6(?:011|5[0-9]{2})[0-9]{12})\b"  # Discover
    ),
    SensitiveDataType.IP_ADDRESS: re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    ),
    # Secret Patterns
    SensitiveDataType.API_KEY: re.compile(
        r"\b(?:"
        r"sk-[a-zA-Z0-9]{20,}|"  # OpenAI
        r"sk-ant-[a-zA-Z0-9-]{20,}|"  # Anthropic
        r"AIza[0-9A-Za-z_-]{35}|"  # Google
        r"ghp_[a-zA-Z0-9]{36}|"  # GitHub PAT
        r"gho_[a-zA-Z0-9]{36}|"  # GitHub OAuth
        r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}|"  # GitHub fine-grained
        r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}"  # Slack
        r")\b"
    ),
    SensitiveDataType.AWS_KEY: re.compile(r"\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b"),
    SensitiveDataType.PASSWORD: re.compile(
        r"(?i)(?:password|passwd|pwd|secret|token)[\s]*[=:]\s*['\"]?([^\s'\"]{8,})['\"]?",
    ),
    SensitiveDataType.PRIVATE_KEY: re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    ),
    SensitiveDataType.JWT: re.compile(r"\beyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\b"),
    SensitiveDataType.CONNECTION_STRING: re.compile(
        r"(?i)(?:"
        r"mongodb(?:\+srv)?://[^\s]+|"
        r"postgres(?:ql)?://[^\s]+|"
        r"mysql://[^\s]+|"
        r"redis://[^\s]+|"
        r"amqp://[^\s]+|"
        r"Server=[^;]+;.*(?:Password|Pwd)=[^;]+"
        r")"
    ),
}

# Default masking configuration
DEFAULT_MASK_CONFIG: dict[SensitiveDataType, MaskingStrategy] = {
    SensitiveDataType.EMAIL: MaskingStrategy.PARTIAL,
    SensitiveDataType.PHONE: MaskingStrategy.PARTIAL,
    SensitiveDataType.SSN: MaskingStrategy.FULL,
    SensitiveDataType.CREDIT_CARD: MaskingStrategy.PARTIAL,
    SensitiveDataType.IP_ADDRESS: MaskingStrategy.PARTIAL,
    SensitiveDataType.API_KEY: MaskingStrategy.PARTIAL,
    SensitiveDataType.AWS_KEY: MaskingStrategy.PARTIAL,
    SensitiveDataType.PASSWORD: MaskingStrategy.FULL,
    SensitiveDataType.PRIVATE_KEY: MaskingStrategy.FULL,
    SensitiveDataType.JWT: MaskingStrategy.PARTIAL,
    SensitiveDataType.CONNECTION_STRING: MaskingStrategy.FULL,
}


def _mask_value(
    value: str,
    data_type: SensitiveDataType,
    strategy: MaskingStrategy,
) -> str:
    """Apply masking strategy to a sensitive value.

    Args:
        value: The sensitive value to mask.
        data_type: Type of sensitive data.
        strategy: Masking strategy to apply.

    Returns:
        Masked value string.
    """
    if strategy == MaskingStrategy.FULL:
        return "[REDACTED]"

    if strategy == MaskingStrategy.TYPE_ONLY:
        return f"[{data_type.value.upper()}]"

    if strategy == MaskingStrategy.HASH:
        import hashlib

        hash_prefix = hashlib.sha256(value.encode()).hexdigest()[:8]
        return f"[SHA256:{hash_prefix}...]"

    # PARTIAL masking - show first and last few characters
    if len(value) <= 8:
        return "*" * len(value)

    if data_type == SensitiveDataType.EMAIL:
        # Show first char of local part and domain
        parts = value.split("@")
        if len(parts) == 2:
            local, domain = parts
            masked_local = local[0] + "***" if len(local) > 1 else "***"
            return f"{masked_local}@{domain}"

    if data_type == SensitiveDataType.CREDIT_CARD:
        # Show last 4 digits only
        return "**** **** **** " + value[-4:]

    if data_type in (SensitiveDataType.API_KEY, SensitiveDataType.AWS_KEY):
        # Show prefix and last 4 chars
        return value[:7] + "..." + value[-4:]

    if data_type == SensitiveDataType.JWT:
        # Show just the header type
        return value[:10] + "...[JWT]"

    # Default partial: show first 3 and last 3
    return value[:3] + "***" + value[-3:]


def detect_sensitive_data(
    content: str,
    types: list[SensitiveDataType] | None = None,
) -> list[dict[str, Any]]:
    """Detect sensitive data in content.

    Args:
        content: Text content to scan.
        types: Types of sensitive data to detect. If None, detect all.

    Returns:
        List of detection dictionaries with type, value, and position.
    """
    types = types or list(SensitiveDataType)
    detections: list[dict[str, Any]] = []

    for data_type in types:
        pattern = PATTERNS.get(data_type)
        if not pattern:  # pragma: no cover - all types have patterns
            continue

        for match in pattern.finditer(content):
            # For password pattern, use the captured group
            if data_type == SensitiveDataType.PASSWORD:
                value = match.group(1) if match.lastindex else match.group(0)
            else:
                value = match.group(0)

            detections.append(
                {
                    "type": data_type.value,
                    "value": value,
                    "start": match.start(),
                    "end": match.end(),
                    "full_match": match.group(0),
                }
            )

    # Sort by position
    detections.sort(key=lambda d: d["start"])
    return detections


def mask_sensitive_data(
    content: str,
    types: list[SensitiveDataType] | None = None,
    mask_config: dict[SensitiveDataType, MaskingStrategy] | None = None,
) -> tuple[str, list[dict[str, Any]]]:
    """Mask sensitive data in content.

    Args:
        content: Text content to sanitize.
        types: Types of sensitive data to mask. If None, mask all.
        mask_config: Masking strategy per type. Uses defaults if not provided.

    Returns:
        Tuple of (masked_content, list of detections).
    """
    mask_config = mask_config or DEFAULT_MASK_CONFIG
    detections = detect_sensitive_data(content, types)

    if not detections:
        return content, []

    # Apply masks in reverse order to preserve positions
    result = content
    for detection in reversed(detections):
        data_type = SensitiveDataType(detection["type"])
        strategy = mask_config.get(data_type, MaskingStrategy.FULL)

        if data_type == SensitiveDataType.PASSWORD:
            # For passwords, we need to replace just the password value
            # but keep the "password=" prefix
            full_match = detection["full_match"]
            password_value = detection["value"]
            masked_value = _mask_value(password_value, data_type, strategy)
            masked_full = full_match.replace(password_value, masked_value)
            result = result[: detection["start"]] + masked_full + result[detection["end"] :]
        else:
            masked = _mask_value(detection["value"], data_type, strategy)
            result = result[: detection["start"]] + masked + result[detection["end"] :]

        detection["masked_as"] = masked if data_type != SensitiveDataType.PASSWORD else "[REDACTED]"

    return result, detections


def truncate_output(
    content: str,
    max_chars: int = 20000,
    add_summary: bool = True,
) -> tuple[str, bool]:
    """Truncate content if it exceeds maximum length.

    Args:
        content: Content to potentially truncate.
        max_chars: Maximum character length.
        add_summary: If True, add truncation notice.

    Returns:
        Tuple of (content, was_truncated).
    """
    if len(content) <= max_chars:
        return content, False

    # Reserve space for truncation notice
    notice = f"\n\n[OUTPUT TRUNCATED: Showing {max_chars:,} of {len(content):,} characters]"
    truncate_at = max_chars - len(notice) if add_summary else max_chars

    # Try to truncate at a natural boundary
    truncated = content[:truncate_at]

    # Find last newline for cleaner truncation
    last_newline = truncated.rfind("\n")
    if last_newline > truncate_at * 0.8:  # Only use if reasonably close
        truncated = truncated[:last_newline]

    if add_summary:
        truncated += notice

    logger.info(
        "output_truncated",
        original_length=len(content),
        truncated_length=len(truncated),
    )

    return truncated, True


def sanitize_output(
    content: Any,
    mask_pii: bool = True,
    mask_secrets: bool = True,
    max_chars: int | None = None,
    mask_config: dict[SensitiveDataType, MaskingStrategy] | None = None,
) -> SanitizationResult:
    """Sanitize output content.

    Converts content to string, masks sensitive data, and truncates if needed.

    Args:
        content: Content to sanitize (will be converted to string).
        mask_pii: If True, mask PII (email, phone, SSN, etc.).
        mask_secrets: If True, mask secrets (API keys, passwords, etc.).
        max_chars: Maximum output length. None for no limit.
        mask_config: Custom masking strategies per type.

    Returns:
        SanitizationResult with sanitized content and metadata.
    """
    # Convert to string
    if isinstance(content, str):
        text = content
    elif isinstance(content, dict | list):
        try:
            text = json.dumps(content, indent=2, default=str)
        except (TypeError, ValueError):
            text = str(content)
    else:
        text = str(content)

    original_length = len(text)
    detections: list[dict[str, Any]] = []

    # Determine which types to mask
    types_to_mask: list[SensitiveDataType] = []

    if mask_pii:
        types_to_mask.extend(
            [
                SensitiveDataType.EMAIL,
                SensitiveDataType.PHONE,
                SensitiveDataType.SSN,
                SensitiveDataType.CREDIT_CARD,
                SensitiveDataType.IP_ADDRESS,
            ]
        )

    if mask_secrets:
        types_to_mask.extend(
            [
                SensitiveDataType.API_KEY,
                SensitiveDataType.PASSWORD,
                SensitiveDataType.AWS_KEY,
                SensitiveDataType.PRIVATE_KEY,
                SensitiveDataType.JWT,
                SensitiveDataType.CONNECTION_STRING,
            ]
        )

    # Mask sensitive data
    if types_to_mask:
        text, detections = mask_sensitive_data(text, types_to_mask, mask_config)

        if detections:
            logger.info(
                "sensitive_data_masked",
                detection_count=len(detections),
                types=[d["type"] for d in detections],
            )

    # Truncate if needed
    was_truncated = False
    if max_chars is not None and len(text) > max_chars:
        text, was_truncated = truncate_output(text, max_chars)

    return SanitizationResult(
        original_length=original_length,
        sanitized_length=len(text),
        content=text,
        was_truncated=was_truncated,
        detections=detections,
        detection_count=len(detections),
    )


@dataclass
class SanitizationConfig:
    """Configuration for output sanitization.

    Attributes:
        enabled: If False, skip all sanitization.
        mask_pii: Mask personally identifiable information.
        mask_secrets: Mask API keys, passwords, etc.
        max_output_chars: Maximum output length in characters.
        mask_strategies: Custom masking strategies per data type.
        pii_types: Specific PII types to mask (None = all).
        secret_types: Specific secret types to mask (None = all).
    """

    enabled: bool = True
    mask_pii: bool = True
    mask_secrets: bool = True
    max_output_chars: int | None = 20000
    mask_strategies: dict[SensitiveDataType, MaskingStrategy] = field(
        default_factory=lambda: dict(DEFAULT_MASK_CONFIG)
    )
    pii_types: list[SensitiveDataType] | None = None
    secret_types: list[SensitiveDataType] | None = None


@dataclass
class WorkspacePIIConfig:
    """Workspace-specific PII handling configuration.

    Allows different workspaces/tenants to have customized PII masking rules.

    Attributes:
        workspace_id: Identifier for this workspace configuration.
        mask_email_domains: Only mask emails from these domains. Empty list = mask all.
        allow_email_domains: Never mask emails from these domains.
        mask_phone_prefixes: Only mask phones with these prefixes. Empty list = mask all.
        allow_phone_prefixes: Never mask phones with these prefixes.
        custom_patterns: Workspace-specific regex patterns to detect and mask.
            Keys are pattern names, values are regex patterns.
        custom_strategies: Masking strategies for custom patterns.
        disabled_types: Sensitive data types to NOT mask for this workspace.
        enabled_types: If set, ONLY mask these types (overrides disabled_types).

    Example:
        config = WorkspacePIIConfig(
            workspace_id="enterprise-123",
            mask_email_domains=["competitor.com"],  # Only mask competitor emails
            allow_email_domains=["company.com"],  # Never mask internal emails
            custom_patterns={
                "employee_id": r"EMP-\\d{6}",  # Custom employee ID format
            },
        )
    """

    workspace_id: str
    mask_email_domains: list[str] = field(default_factory=list)
    allow_email_domains: list[str] = field(default_factory=list)
    mask_phone_prefixes: list[str] = field(default_factory=list)
    allow_phone_prefixes: list[str] = field(default_factory=list)
    custom_patterns: dict[str, str] = field(default_factory=dict)
    custom_strategies: dict[str, MaskingStrategy] = field(default_factory=dict)
    disabled_types: list[SensitiveDataType] = field(default_factory=list)
    enabled_types: list[SensitiveDataType] | None = None

    def should_mask_email(self, email: str) -> bool:
        """Determine if an email should be masked based on workspace rules.

        Args:
            email: The email address to check.

        Returns:
            True if the email should be masked, False otherwise.
        """
        domain = email.split("@")[-1].lower() if "@" in email else ""

        # Never mask allowed domains
        if any(domain.endswith(allowed.lower()) for allowed in self.allow_email_domains):
            return False

        # If mask_email_domains is set, only mask those domains
        if self.mask_email_domains:
            return any(domain.endswith(masked.lower()) for masked in self.mask_email_domains)

        # Default: mask all emails
        return True

    def should_mask_phone(self, phone: str) -> bool:
        """Determine if a phone number should be masked based on workspace rules.

        Args:
            phone: The phone number to check.

        Returns:
            True if the phone should be masked, False otherwise.
        """
        # Normalize phone for prefix checking
        normalized = re.sub(r"[^\d+]", "", phone)

        # Never mask allowed prefixes
        if any(normalized.startswith(allowed) for allowed in self.allow_phone_prefixes):
            return False

        # If mask_phone_prefixes is set, only mask those prefixes
        if self.mask_phone_prefixes:
            return any(normalized.startswith(prefix) for prefix in self.mask_phone_prefixes)

        # Default: mask all phones
        return True

    def get_active_types(self) -> list[SensitiveDataType]:
        """Get the list of sensitive data types that should be checked.

        Returns:
            List of SensitiveDataType that should be active for this workspace.
        """
        if self.enabled_types is not None:
            return self.enabled_types

        return [t for t in SensitiveDataType if t not in self.disabled_types]

    def get_custom_compiled_patterns(self) -> dict[str, re.Pattern[str]]:
        """Get compiled regex patterns for custom patterns.

        Returns:
            Dict mapping pattern name to compiled regex.
        """
        compiled: dict[str, re.Pattern[str]] = {}
        for name, pattern in self.custom_patterns.items():
            try:
                compiled[name] = re.compile(pattern)
            except re.error as e:
                logger.warning(
                    "invalid_custom_pattern",
                    workspace_id=self.workspace_id,
                    pattern_name=name,
                    error=str(e),
                )
        return compiled


def sanitize_with_workspace_config(
    content: Any,
    workspace_config: WorkspacePIIConfig,
    mask_pii: bool = True,
    mask_secrets: bool = True,
    max_chars: int | None = None,
    mask_config: dict[SensitiveDataType, MaskingStrategy] | None = None,
) -> SanitizationResult:
    """Sanitize output with workspace-specific PII rules.

    Args:
        content: Content to sanitize.
        workspace_config: Workspace-specific configuration.
        mask_pii: If True, mask PII.
        mask_secrets: If True, mask secrets.
        max_chars: Maximum output length.
        mask_config: Custom masking strategies.

    Returns:
        SanitizationResult with sanitized content.
    """
    # Convert to string
    if isinstance(content, str):
        text = content
    elif isinstance(content, dict | list):
        try:
            text = json.dumps(content, indent=2, default=str)
        except (TypeError, ValueError):
            text = str(content)
    else:
        text = str(content)

    original_length = len(text)
    detections: list[dict[str, Any]] = []
    result_text = text

    # Get active types based on workspace config
    active_types = workspace_config.get_active_types()

    # Filter by PII/secrets flags
    types_to_check: list[SensitiveDataType] = []
    pii_types = {
        SensitiveDataType.EMAIL,
        SensitiveDataType.PHONE,
        SensitiveDataType.SSN,
        SensitiveDataType.CREDIT_CARD,
        SensitiveDataType.IP_ADDRESS,
    }
    secret_types = {
        SensitiveDataType.API_KEY,
        SensitiveDataType.PASSWORD,
        SensitiveDataType.AWS_KEY,
        SensitiveDataType.PRIVATE_KEY,
        SensitiveDataType.JWT,
        SensitiveDataType.CONNECTION_STRING,
    }

    if mask_pii:
        types_to_check.extend(t for t in active_types if t in pii_types)
    if mask_secrets:
        types_to_check.extend(t for t in active_types if t in secret_types)

    # Detect sensitive data
    mask_config = mask_config or DEFAULT_MASK_CONFIG
    all_detections = detect_sensitive_data(text, types_to_check)

    # Filter detections based on workspace rules
    filtered_detections: list[dict[str, Any]] = []
    for detection in all_detections:
        data_type = SensitiveDataType(detection["type"])

        # Apply workspace-specific filtering
        if data_type == SensitiveDataType.EMAIL and not workspace_config.should_mask_email(
            detection["value"]
        ):
            continue

        if data_type == SensitiveDataType.PHONE and not workspace_config.should_mask_phone(
            detection["value"]
        ):
            continue

        filtered_detections.append(detection)

    # Apply custom patterns
    custom_patterns = workspace_config.get_custom_compiled_patterns()
    for name, pattern in custom_patterns.items():
        for match in pattern.finditer(text):
            filtered_detections.append(
                {
                    "type": f"custom:{name}",
                    "value": match.group(0),
                    "start": match.start(),
                    "end": match.end(),
                    "full_match": match.group(0),
                }
            )

    # Sort by position for proper replacement
    filtered_detections.sort(key=lambda d: d["start"])

    # Apply masks in reverse order
    for detection in reversed(filtered_detections):
        type_str = detection["type"]

        # Handle custom patterns
        if type_str.startswith("custom:"):
            pattern_name = type_str[7:]
            strategy = workspace_config.custom_strategies.get(pattern_name, MaskingStrategy.FULL)
            masked = (
                f"[{pattern_name.upper()}]"
                if strategy == MaskingStrategy.TYPE_ONLY
                else "[REDACTED]"
            )
        else:
            data_type = SensitiveDataType(type_str)
            strategy = mask_config.get(data_type, MaskingStrategy.FULL)

            if data_type == SensitiveDataType.PASSWORD:
                full_match = detection["full_match"]
                password_value = detection["value"]
                masked_value = _mask_value(password_value, data_type, strategy)
                masked = full_match.replace(password_value, masked_value)
                result_text = (
                    result_text[: detection["start"]] + masked + result_text[detection["end"] :]
                )
                detection["masked_as"] = "[REDACTED]"
                detections.append(detection)
                continue
            else:
                masked = _mask_value(detection["value"], data_type, strategy)

        result_text = result_text[: detection["start"]] + masked + result_text[detection["end"] :]
        detection["masked_as"] = masked
        detections.append(detection)

    # Reverse detections list to maintain original order
    detections.reverse()

    # Truncate if needed
    was_truncated = False
    if max_chars is not None and len(result_text) > max_chars:
        result_text, was_truncated = truncate_output(result_text, max_chars)

    if detections:
        logger.info(
            "workspace_sensitive_data_masked",
            workspace_id=workspace_config.workspace_id,
            detection_count=len(detections),
        )

    return SanitizationResult(
        original_length=original_length,
        sanitized_length=len(result_text),
        content=result_text,
        was_truncated=was_truncated,
        detections=detections,
        detection_count=len(detections),
    )
