"""Unknown/hallucinated argument handling for Agent-Airlock (V0.4.0).

Provides explicit policy for handling arguments that don't exist in the
function signature - a critical security decision that was previously
just a boolean flag.

The "shadow-ban by default" problem:
    Silently stripping unknown args hides attack attempts. Attackers WANT
    you to strip + continue quietly because it masks their probing.

Recommendation:
    Use UnknownArgsMode.BLOCK in production. This is the default in STRICT_POLICY.
"""

from __future__ import annotations

import warnings
from enum import Enum
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from .audit import AuditLogger

logger = structlog.get_logger("agent-airlock.unknown_args")


class UnknownArgsMode(str, Enum):
    """How to handle unknown/hallucinated arguments.

    This replaces the boolean `strict_mode` with explicit, auditable policies.

    Examples:
        # Production (recommended)
        config = AirlockConfig(unknown_args=UnknownArgsMode.BLOCK)

        # Migration/staging
        config = AirlockConfig(unknown_args=UnknownArgsMode.STRIP_AND_LOG)

        # Development only (DANGEROUS)
        config = AirlockConfig(unknown_args=UnknownArgsMode.STRIP_SILENT)
    """

    BLOCK = "block"
    """Reject the call with a validation error.

    RECOMMENDED for production. This is the secure default.
    - Unknown args are treated as a security event
    - The call fails with a self-healing error response
    - Attackers cannot probe for behavior by injecting flags
    """

    STRIP_AND_LOG = "strip_and_log"
    """Strip unknown args but emit an audit event.

    Use for staged rollouts or migration from permissive mode.
    - Unknown args are removed before the call proceeds
    - An audit event is emitted with the stripped arg names
    - Security teams can monitor for suspicious patterns
    """

    STRIP_SILENT = "strip_silent"
    """Strip unknown args silently without logging.

    DANGEROUS - hides potential attack attempts. Development only.
    - Unknown args are silently discarded
    - No audit trail of what was stripped
    - Only use in isolated dev environments
    """


def mode_from_strict_bool(strict_mode: bool) -> UnknownArgsMode:
    """Convert legacy strict_mode boolean to UnknownArgsMode.

    This provides backward compatibility during migration.

    Args:
        strict_mode: Legacy boolean flag (True = reject, False = strip)

    Returns:
        Equivalent UnknownArgsMode value.

    Examples:
        >>> mode_from_strict_bool(True)
        <UnknownArgsMode.BLOCK: 'block'>
        >>> mode_from_strict_bool(False)
        <UnknownArgsMode.STRIP_AND_LOG: 'strip_and_log'>
    """
    if strict_mode:
        return UnknownArgsMode.BLOCK
    # Default to STRIP_AND_LOG for migration (not STRIP_SILENT)
    # This ensures existing users get audit trail even if they had strict_mode=False
    return UnknownArgsMode.STRIP_AND_LOG


def emit_deprecation_warning_for_strict_mode() -> None:
    """Emit deprecation warning when strict_mode is used."""
    warnings.warn(
        "strict_mode is deprecated. Use unknown_args=UnknownArgsMode.BLOCK instead. "
        "See migration guide: https://github.com/anthropics/agent-airlock/blob/main/MIGRATION.md",
        DeprecationWarning,
        stacklevel=4,  # Caller's caller's caller
    )


def handle_unknown_args(
    mode: UnknownArgsMode,
    func_name: str,
    stripped_args: set[str],
    audit_logger: AuditLogger | None = None,
) -> None:
    """Handle stripped unknown arguments based on mode.

    Called after ghost argument stripping to apply the configured policy.

    Args:
        mode: The UnknownArgsMode policy
        func_name: Name of the function being called
        stripped_args: Set of argument names that were stripped
        audit_logger: Optional audit logger for emitting events

    Raises:
        ValueError: If mode is BLOCK and args were stripped (should be caught upstream)
    """
    if not stripped_args:
        return

    if mode == UnknownArgsMode.BLOCK:
        # This should be handled upstream in core.py via GhostArgumentError
        # If we reach here, it's a programming error
        raise ValueError(
            f"BLOCK mode active but unknown args {stripped_args} were stripped instead of rejected"
        )

    elif mode == UnknownArgsMode.STRIP_AND_LOG:
        # Log the event for security monitoring
        logger.warning(
            "unknown_args_stripped",
            function=func_name,
            stripped_args=sorted(stripped_args),
            count=len(stripped_args),
            mode=mode.value,
            hint="Consider switching to BLOCK mode in production",
        )

        # Emit audit event if logger available
        if audit_logger is not None:
            from datetime import datetime, timezone

            from .audit import AuditRecord

            record = AuditRecord(
                timestamp=datetime.now(timezone.utc).isoformat(),
                tool_name=func_name,
                blocked=False,
                block_reason=None,
                args_preview={"_stripped": ", ".join(sorted(stripped_args))},
                result_type="unknown_args_event",
                result_preview=f"Stripped {len(stripped_args)} unknown args",
            )
            audit_logger.write(record)

    elif mode == UnknownArgsMode.STRIP_SILENT:
        # Silent strip - only debug log
        logger.debug(
            "unknown_args_stripped_silent",
            function=func_name,
            stripped_count=len(stripped_args),
        )


# Predefined mode configurations for convenience
PRODUCTION_MODE = UnknownArgsMode.BLOCK
STAGING_MODE = UnknownArgsMode.STRIP_AND_LOG
DEVELOPMENT_MODE = UnknownArgsMode.STRIP_SILENT


def get_recommended_mode(environment: str) -> UnknownArgsMode:
    """Get recommended mode for an environment.

    Args:
        environment: Environment name (production, staging, development)

    Returns:
        Recommended UnknownArgsMode for the environment.

    Examples:
        >>> get_recommended_mode("production")
        <UnknownArgsMode.BLOCK: 'block'>
        >>> get_recommended_mode("development")
        <UnknownArgsMode.STRIP_SILENT: 'strip_silent'>
    """
    env_lower = environment.lower()
    if env_lower in ("production", "prod", "live"):
        return UnknownArgsMode.BLOCK
    elif env_lower in ("staging", "stage", "test", "qa"):
        return UnknownArgsMode.STRIP_AND_LOG
    elif env_lower in ("development", "dev", "local"):
        return UnknownArgsMode.STRIP_AND_LOG  # Not STRIP_SILENT - always log
    else:
        # Unknown environment - be safe
        return UnknownArgsMode.BLOCK
