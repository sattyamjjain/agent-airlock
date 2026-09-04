"""Self-healing error response system for Agent-Airlock.

Instead of crashing on validation errors, Airlock returns structured
error responses that help the LLM retry with corrected arguments.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal

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
    # V0.3.0 security reasons
    PATH_VIOLATION = "path_violation"
    NETWORK_BLOCKED = "network_blocked"
    # V0.4.0 security reasons
    CAPABILITY_DENIED = "capability_denied"
    # V0.4.1 security reasons
    ENDPOINT_BLOCKED = "endpoint_blocked"
    ANOMALY_DETECTED = "anomaly_detected"
    # V0.8.7 cost-budget reasons
    BUDGET_EXCEEDED = "budget_exceeded"
    # V0.8.74 third-verdict reasons (issue #143). Distinct from POLICY_VIOLATION on
    # purpose: "blocked because nobody could approve it" and "blocked because it is
    # forbidden" are different operational situations, and collapsing them hides a
    # missing approver integration behind a working-looking denial.
    ESCALATION_REQUIRED = "escalation_required"
    ESCALATION_DENIED = "escalation_denied"
    ESCALATION_TIMEOUT = "escalation_timeout"
    # V0.8.86: an operator froze the fleet. Distinct from POLICY_VIOLATION for the same
    # reason the three above are: "an operator halted everything" and "this call is
    # forbidden" need different responses, and collapsing them hides an active incident
    # behind a routine denial.
    KILL_SWITCH = "kill_switch"
    # V0.8.74 resource-amplification reasons (issue #142).
    AMPLIFICATION_EXCEEDED = "amplification_exceeded"
    # V0.8.77 capability-handle reasons (MCP 2026-07-28 / SEP-2567). One per failure mode,
    # because "the integration was never wired up" (HANDLE_NOT_ISSUED on every call) and "an
    # agent is replaying a capability across scopes" (HANDLE_WRONG_SCOPE on some calls) need
    # different responses from whoever reads the log. These are *reasons*, not verdicts: a
    # handle rejection is an ordinary deny, so allow/deny/escalate stays the whole verdict set.
    HANDLE_NOT_ISSUED = "handle_not_issued"
    HANDLE_WRONG_ISSUER = "handle_wrong_issuer"
    HANDLE_WRONG_SCOPE = "handle_wrong_scope"
    HANDLE_EXPIRED = "handle_expired"


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
        AirlockResponse with structured error info and fix hints. A capability-handle
        rejection (V0.8.77) is recognised here and reported with its own
        :class:`BlockReason` instead of the generic ``VALIDATION_ERROR``, so the four
        handle failure modes stay distinguishable in the audit log.
    """
    handle_response = _handle_field_rejection(error, func_name)
    if handle_response is not None:
        return handle_response

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


#: ``HandleRejectionReason`` value -> ``BlockReason``. Written out rather than derived from
#: the string values so that renaming one enum without the other fails at import of the test
#: that walks this map, instead of silently falling back to a generic block reason.
_HANDLE_BLOCK_REASONS: dict[str, BlockReason] = {
    "handle_not_issued": BlockReason.HANDLE_NOT_ISSUED,
    "handle_wrong_issuer": BlockReason.HANDLE_WRONG_ISSUER,
    "handle_wrong_scope": BlockReason.HANDLE_WRONG_SCOPE,
    "handle_expired": BlockReason.HANDLE_EXPIRED,
}

#: What the model should do about each failure mode. A handle rejection is one of the few
#: blocks where retrying the *same* call is always wrong: the value is a capability, so the
#: fix is always to obtain a different one, never to reformat this one.
_HANDLE_FIX_HINTS: dict[str, str] = {
    "handle_not_issued": (
        "This handle was not issued in this run. Call the tool that mints it and pass the "
        "value that call returned — do not reuse a handle from an earlier run, a transcript, "
        "or another tool's output."
    ),
    "handle_wrong_issuer": (
        "This handle came from a different tool than this parameter accepts. Mint one from "
        "the issuer this parameter declares."
    ),
    "handle_wrong_scope": (
        "This handle was issued for a different scope. Mint a handle for the scope this tool "
        "operates on; a handle is not transferable between scopes."
    ),
    "handle_expired": (
        "This handle has expired. Mint a fresh one; an expired handle cannot be replayed."
    ),
}


def _handle_field_rejection(
    error: ValidationError,
    func_name: str,
) -> AirlockResponse | None:
    """Return a handle-specific response, or ``None`` if this is ordinary validation failure.

    A ``HandleField`` rejection arrives here wrapped in a Pydantic ``ValidationError``,
    because the check runs as an ``AfterValidator`` — which is the point: the capability
    check rides the validation path that already exists rather than adding a gate beside it.
    Unwrapping it back into a structured reason is what keeps the audit record specific.

    ``None`` is the common case and is not a degraded one; the caller falls through to the
    generic formatter.
    """
    from .handles import handle_rejection_from

    errors = error.errors()
    for err in errors:
        ctx = err.get("ctx") or {}
        rejection = handle_rejection_from(ctx.get("error"), err.get("msg", ""))
        if rejection is None:
            continue

        reason = rejection.reason.value
        field_path = ".".join(str(loc) for loc in err["loc"]) or (rejection.field_name or "handle")
        fix_hints = [_HANDLE_FIX_HINTS.get(reason, "Obtain a valid handle and retry.")]

        # `block_reason` can only hold one value, and a capability failure is the one worth
        # surfacing — mixing a type error into it would dilute a security signal. But the
        # other errors must not vanish silently, or the model fixes the handle, retries, and
        # discovers the rest one round trip at a time.
        others = len(errors) - 1
        if others:
            fix_hints.append(
                f"{others} other validation error(s) on this call are not shown while the "
                f"handle is invalid; they will be reported once a valid handle is supplied."
            )

        return AirlockResponse.blocked_response(
            reason=_HANDLE_BLOCK_REASONS.get(reason, BlockReason.VALIDATION_ERROR),
            error=(
                f"AIRLOCK_BLOCK: Tool '{func_name}' refused the capability handle in "
                f"'{field_path}'. {rejection}"
            ),
            fix_hints=fix_hints,
            metadata={
                "function": func_name,
                "field": field_path,
                "other_error_count": others,
                **rejection.audit_event,
            },
        )
    return None


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


def handle_amplification_exceeded(
    func_name: str,
    *,
    reason: str,
    run_call_count: int,
    baseline_calls: int | None,
    amplification_ratio: float | None,
    verdict: str,
) -> AirlockResponse:
    """Create a response for a run that exceeded its amplification budget.

    Args:
        func_name: Name of the function that tripped the budget.
        reason: Human-readable explanation from the guard.
        run_call_count: Calls recorded for the run, including this one.
        baseline_calls: The policy's declared baseline, when set.
        amplification_ratio: ``run_call_count / baseline_calls``, when computable.
        verdict: The :class:`~agent_airlock.amplification.AmplificationVerdict` value.

    Returns:
        AirlockResponse explaining the amplification block.
    """
    unconfigured = verdict == "unconfigured"
    fix_hints = (
        [
            "Amplification checking is enabled but no threshold is set",
            "Set AmplificationBudget(max_calls_per_run=N), or "
            "max_amplification_ratio=R with baseline_calls_per_run=B",
            "Blocked deny-by-default: a budget that cannot fire is not a budget",
        ]
        if unconfigured
        else [
            "This run made more tool calls than its declared budget allows",
            "If the extra calls are legitimate, raise the budget; if not, the run may "
            "have been recruited into a detour (arXiv:2608.12273)",
            "Use action='warn' to record the ratio without blocking while you establish a baseline",
        ]
    )

    return AirlockResponse.blocked_response(
        reason=BlockReason.AMPLIFICATION_EXCEEDED,
        error=f"AIRLOCK_BLOCK: '{func_name}' — {reason}",
        fix_hints=fix_hints,
        metadata={
            "function": func_name,
            "amplification_verdict": verdict,
            "run_call_count": run_call_count,
            "run_baseline_calls": baseline_calls,
            "run_amplification_ratio": amplification_ratio,
        },
    )


def handle_escalation(
    func_name: str,
    *,
    reason: str,
    rule: str,
    outcome: Literal["no_approver", "denied", "timeout"],
    detail: str = "",
    approver: str | None = None,
) -> AirlockResponse:
    """Create a response for a call that escalated and did not come back approved.

    Args:
        func_name: Name of the function that was held.
        reason: The operator-authored reason from the matching escalation rule.
        rule: The ``escalate_tools`` pattern that fired.
        outcome: Why the call is blocked. ``"no_approver"`` means the policy escalated
            with nothing registered to escalate to — a **configuration** failure, and the
            reason this helper exists as its own block reason rather than reusing
            ``POLICY_VIOLATION``.
        detail: Free-form detail from the approver, when there was one.
        approver: Identifier of the human/system that decided, when known.

    Returns:
        AirlockResponse explaining the escalation outcome.
    """
    block_reason = {
        "no_approver": BlockReason.ESCALATION_REQUIRED,
        "denied": BlockReason.ESCALATION_DENIED,
        "timeout": BlockReason.ESCALATION_TIMEOUT,
    }[outcome]

    if outcome == "no_approver":
        error = (
            f"AIRLOCK_BLOCK: '{func_name}' requires human approval (rule {rule!r}: {reason}) "
            f"but no approver is registered on the policy. Blocked deny-by-default."
        )
        fix_hints = [
            "This call needs human approval and the policy has no approver wired up",
            "Register one: SecurityPolicy(..., approver=my_approver) — see "
            "agent_airlock.oversight.Approver",
            "Do not retry; this is a configuration gap, not a transient failure",
        ]
    elif outcome == "denied":
        error = (
            f"AIRLOCK_BLOCK: '{func_name}' was denied by human approval "
            f"(rule {rule!r}: {reason}). {detail}"
        )
        fix_hints = [
            "A human reviewed this call and declined it",
            "Do not retry the same call; ask the operator why it was declined",
        ]
    else:
        error = (
            f"AIRLOCK_BLOCK: human approval for '{func_name}' timed out "
            f"(rule {rule!r}: {reason}). {detail}"
        )
        fix_hints = [
            "The approval request was not answered in time",
            "Blocked rather than allowed, because an unanswered gate is not consent",
        ]

    return AirlockResponse.blocked_response(
        reason=block_reason,
        error=error,
        fix_hints=fix_hints,
        metadata={
            "function": func_name,
            "escalation_rule": rule,
            "escalation_reason": reason,
            "escalation_outcome": outcome,
            "approver": approver,
            "detail": detail,
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


def handle_path_violation(
    func_name: str,
    path: str,
    violation_type: str,
    details: dict[str, Any] | None = None,
) -> AirlockResponse:
    """Create a response for filesystem path violations.

    Args:
        func_name: Name of the function that was blocked.
        path: The path that violated the policy.
        violation_type: Type of path violation (e.g., "outside_allowed_roots").
        details: Additional details about the violation.

    Returns:
        AirlockResponse explaining the path violation.
    """
    fix_hints = [
        "The specified path is not accessible due to security policy",
        "Use paths within the allowed directory roots",
    ]

    if violation_type == "symlink_detected":
        fix_hints.append("Symlinks are not allowed; use direct paths")
    elif violation_type == "denied_pattern":
        fix_hints.append("This file type or location is explicitly blocked")

    return AirlockResponse.blocked_response(
        reason=BlockReason.PATH_VIOLATION,
        error=f"AIRLOCK_BLOCK: Path '{path}' blocked for '{func_name}'",
        fix_hints=fix_hints,
        metadata={
            "function": func_name,
            "path": path,
            "violation_type": violation_type,
            **(details or {}),
        },
    )


def handle_network_blocked(
    func_name: str,
    operation: str,
    target: str | None,
    details: dict[str, Any] | None = None,
) -> AirlockResponse:
    """Create a response for blocked network operations.

    Args:
        func_name: Name of the function that was blocked.
        operation: Type of network operation (e.g., "connect", "dns_lookup").
        target: The target host/address that was blocked.
        details: Additional details about the blocked operation.

    Returns:
        AirlockResponse explaining the network block.
    """
    return AirlockResponse.blocked_response(
        reason=BlockReason.NETWORK_BLOCKED,
        error=f"AIRLOCK_BLOCK: Network {operation} blocked for '{func_name}'",
        fix_hints=[
            "Network access is restricted during tool execution",
            "This operation requires explicit network permission",
        ],
        metadata={
            "function": func_name,
            "operation": operation,
            "target": target,
            **(details or {}),
        },
    )


def handle_endpoint_violation(
    func_name: str,
    url: str,
    hostname: str,
    reason: str,
    allowed_endpoints: list[str] | None = None,
) -> AirlockResponse:
    """Create a response for endpoint policy violations.

    Args:
        func_name: Name of the function that was blocked.
        url: The URL that violated the policy.
        hostname: The hostname that was blocked.
        reason: The reason for blocking.
        allowed_endpoints: List of allowed endpoints (for fix hints).

    Returns:
        AirlockResponse explaining the endpoint violation with fix hints.
    """
    fix_hints = [
        f"The URL '{url}' is not permitted by the endpoint policy for this tool",
    ]
    if allowed_endpoints:
        fix_hints.append(f"Allowed endpoints for this tool: {', '.join(allowed_endpoints)}")
    fix_hints.append("Use only URLs that match the tool's configured endpoint allowlist")

    return AirlockResponse.blocked_response(
        reason=BlockReason.ENDPOINT_BLOCKED,
        error=f"AIRLOCK_BLOCK: Endpoint blocked for '{func_name}': {hostname}",
        fix_hints=fix_hints,
        metadata={
            "function": func_name,
            "url": url,
            "hostname": hostname,
            "block_reason": reason,
            "allowed_endpoints": allowed_endpoints or [],
        },
    )


def handle_budget_exceeded(
    func_name: str,
    *,
    tier: str,
    cap_cost_cents: int | None,
    cap_output_tokens: int | None,
    estimated_cost_cents: int,
    estimated_output_tokens: int,
    budget_type: str,
    model_id: str | None = None,
) -> AirlockResponse:
    """Create a response for per-model-tier budget violations (v0.8.7).

    Args:
        func_name: Name of the function that was blocked.
        tier: Resolved tier label (e.g. "frontier").
        cap_cost_cents: The tier's per-call cost cap in cents (if set).
        cap_output_tokens: The tier's per-call output-token cap (if set).
        estimated_cost_cents: Worst-case estimated cost that triggered the block.
        estimated_output_tokens: Worst-case output assumed by the estimate.
        budget_type: "cost" or "tokens" — which cap was breached.
        model_id: Optional model identifier for telemetry.

    Returns:
        AirlockResponse with ``block_reason=BUDGET_EXCEEDED`` and the tier,
        cap, and estimate in ``metadata``.
    """
    fix_hints: list[str] = []
    if cap_cost_cents is not None:
        fix_hints.append(
            f"Tier {tier!r} caps per-call cost at {cap_cost_cents}¢ "
            f"(this call estimated {estimated_cost_cents}¢)."
        )
    if cap_output_tokens is not None:
        fix_hints.append(f"Tier {tier!r} caps per-call output at {cap_output_tokens} tokens.")
    fix_hints.append("Reduce input_tokens, route to a cheaper tier, or raise the cap on this tier.")

    return AirlockResponse.blocked_response(
        reason=BlockReason.BUDGET_EXCEEDED,
        error=(
            f"AIRLOCK_BLOCK: Tier {tier!r} budget exceeded for '{func_name}' "
            f"(budget_type={budget_type})"
        ),
        fix_hints=fix_hints,
        metadata={
            "function": func_name,
            "tier": tier,
            "cap": {
                "max_cost_cents": cap_cost_cents,
                "max_output_tokens": cap_output_tokens,
            },
            "estimated_cost_cents": estimated_cost_cents,
            "estimated_output_tokens": estimated_output_tokens,
            "budget_type": budget_type,
            "model_id": model_id,
        },
    )


def handle_anomaly_block(
    func_name: str,
    session_id: str,
    anomaly_type: str,
    details: dict[str, Any] | None = None,
) -> AirlockResponse:
    """Create a response for anomaly-based session blocks.

    Args:
        func_name: Name of the function that was blocked.
        session_id: The blocked session ID.
        anomaly_type: Type of anomaly that triggered the block.
        details: Additional details about the anomaly.

    Returns:
        AirlockResponse explaining the anomaly block.
    """
    return AirlockResponse.blocked_response(
        reason=BlockReason.ANOMALY_DETECTED,
        error=(f"AIRLOCK_BLOCK: Session blocked due to anomalous behavior for '{func_name}'"),
        fix_hints=[
            "Your session has been temporarily blocked due to unusual activity",
            f"Anomaly type: {anomaly_type}",
            "Wait for the block to expire or contact the administrator",
        ],
        metadata={
            "function": func_name,
            "session_id": session_id,
            "anomaly_type": anomaly_type,
            **(details or {}),
        },
    )
