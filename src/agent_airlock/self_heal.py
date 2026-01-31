"""Self-healing error response system for Agent-Airlock.

Instead of crashing on validation errors, Airlock returns structured
error responses that help the LLM retry with corrected arguments.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from pydantic import ValidationError

from .validator import GhostArgumentError, format_validation_error


class BlockReason(str, Enum):
    """Reasons why a tool call was blocked."""

    VALIDATION_ERROR = "validation_error"
    GHOST_ARGUMENTS = "ghost_arguments"
    POLICY_VIOLATION = "policy_violation"
    RATE_LIMIT = "rate_limit"
    SANDBOX_ERROR = "sandbox_error"
    OUTPUT_SANITIZED = "output_sanitized"


@dataclass
class AirlockResponse:
    """Structured response from Airlock for blocked or modified calls.

    This response format is designed to be easily parsed by LLMs
    to understand what went wrong and how to fix it.
    """

    success: bool
    status: str
    result: Any = None
    error: str | None = None
    block_reason: BlockReason | None = None
    fix_hints: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        data: dict[str, Any] = {
            "success": self.success,
            "status": self.status,
        }

        if self.result is not None:
            data["result"] = self.result

        if self.error:
            data["error"] = self.error

        if self.block_reason:
            data["block_reason"] = self.block_reason.value

        if self.fix_hints:
            data["fix_hints"] = self.fix_hints

        if self.warnings:
            data["warnings"] = self.warnings

        if self.metadata:
            data["metadata"] = self.metadata

        return data

    @classmethod
    def success_response(
        cls,
        result: Any,
        warnings: list[str] | None = None,
    ) -> AirlockResponse:
        """Create a successful response."""
        return cls(
            success=True,
            status="completed",
            result=result,
            warnings=warnings or [],
        )

    @classmethod
    def blocked_response(
        cls,
        reason: BlockReason,
        error: str,
        fix_hints: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AirlockResponse:
        """Create a blocked response with fix hints."""
        return cls(
            success=False,
            status="blocked",
            error=error,
            block_reason=reason,
            fix_hints=fix_hints or [],
            metadata=metadata or {},
        )


def handle_validation_error(
    error: ValidationError,
    func_name: str,
) -> AirlockResponse:
    """Convert a Pydantic ValidationError into a self-healing response.

    Args:
        error: The Pydantic validation error.
        func_name: Name of the function that was being called.

    Returns:
        AirlockResponse with structured error info and fix hints.
    """
    formatted = format_validation_error(error)
    fix_hints = [err["fix_hint"] for err in formatted["errors"]]

    # Create LLM-friendly error message
    error_summary = "; ".join(f"{err['field']}: {err['message']}" for err in formatted["errors"])

    return AirlockResponse.blocked_response(
        reason=BlockReason.VALIDATION_ERROR,
        error=f"AIRLOCK_BLOCK: Tool '{func_name}' validation failed. {error_summary}",
        fix_hints=fix_hints,
        metadata={
            "function": func_name,
            "error_count": formatted["error_count"],
            "errors": formatted["errors"],
        },
    )


def handle_ghost_argument_error(
    error: GhostArgumentError,
) -> AirlockResponse:
    """Convert a GhostArgumentError into a self-healing response.

    Args:
        error: The ghost argument error.

    Returns:
        AirlockResponse with info about unknown arguments.
    """
    ghost_list = ", ".join(sorted(error.ghost_args))
    fix_hints = [
        f"Remove these unknown arguments: {ghost_list}",
        "Check the function signature for valid parameter names",
    ]

    return AirlockResponse.blocked_response(
        reason=BlockReason.GHOST_ARGUMENTS,
        error=f"AIRLOCK_BLOCK: Unknown arguments detected: {ghost_list}",
        fix_hints=fix_hints,
        metadata={
            "function": error.func_name,
            "ghost_arguments": sorted(error.ghost_args),
        },
    )


def handle_policy_violation(
    func_name: str,
    policy_name: str,
    reason: str,
) -> AirlockResponse:
    """Create a response for policy violations.

    Args:
        func_name: Name of the function that was blocked.
        policy_name: Name of the policy that was violated.
        reason: Human-readable reason for the violation.

    Returns:
        AirlockResponse explaining the policy violation.
    """
    return AirlockResponse.blocked_response(
        reason=BlockReason.POLICY_VIOLATION,
        error=f"AIRLOCK_BLOCK: Policy violation for '{func_name}'. {reason}",
        fix_hints=[
            "This operation is not permitted by the current security policy",
            "Contact the administrator if you believe this is an error",
        ],
        metadata={
            "function": func_name,
            "policy": policy_name,
            "violation_reason": reason,
        },
    )


def handle_rate_limit(
    func_name: str,
    limit: str,
    reset_seconds: int,
) -> AirlockResponse:
    """Create a response for rate limit violations.

    Args:
        func_name: Name of the function that was rate limited.
        limit: The rate limit that was exceeded (e.g., "100/hour").
        reset_seconds: Seconds until the rate limit resets.

    Returns:
        AirlockResponse with rate limit info.
    """
    return AirlockResponse.blocked_response(
        reason=BlockReason.RATE_LIMIT,
        error=f"AIRLOCK_BLOCK: Rate limit exceeded for '{func_name}'.",
        fix_hints=[
            f"Rate limit is {limit}",
            f"Wait {reset_seconds} seconds before retrying",
        ],
        metadata={
            "function": func_name,
            "limit": limit,
            "reset_seconds": reset_seconds,
        },
    )
