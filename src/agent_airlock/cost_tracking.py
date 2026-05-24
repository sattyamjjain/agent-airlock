"""Cost tracking for Agent-Airlock.

Provides hooks for tracking token usage and costs per tool call,
with callback interface for external systems.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Literal, Protocol

import structlog

from .exceptions import AirlockError

logger = structlog.get_logger("agent-airlock.cost_tracking")


@dataclass
class TokenUsage:
    """Token usage for a single call."""

    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0

    def __post_init__(self) -> None:
        if self.total_tokens == 0:
            self.total_tokens = self.input_tokens + self.output_tokens


@dataclass
class CostRecord:
    """Record of cost for a single tool call."""

    tool_name: str
    timestamp: float
    tokens: TokenUsage
    cost_usd: Decimal = Decimal("0")
    duration_ms: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "tool_name": self.tool_name,
            "timestamp": self.timestamp,
            "input_tokens": self.tokens.input_tokens,
            "output_tokens": self.tokens.output_tokens,
            "total_tokens": self.tokens.total_tokens,
            "cost_usd": str(self.cost_usd),
            "duration_ms": self.duration_ms,
            "metadata": self.metadata,
        }


@dataclass
class CostSummary:
    """Aggregated cost summary."""

    total_calls: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_tokens: int = 0
    total_cost_usd: Decimal = Decimal("0")
    total_duration_ms: float = 0.0
    by_tool: dict[str, dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_calls": self.total_calls,
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "total_tokens": self.total_tokens,
            "total_cost_usd": str(self.total_cost_usd),
            "total_duration_ms": self.total_duration_ms,
            "by_tool": self.by_tool,
        }


class CostCallback(Protocol):
    """Protocol for cost tracking callbacks."""

    def __call__(self, record: CostRecord) -> None:
        """Called when a cost record is created.

        Args:
            record: The cost record for the tool call.
        """
        ...


class BudgetExceededError(Exception):
    """Raised when a budget limit is exceeded."""

    def __init__(
        self,
        message: str,
        current_cost: Decimal,
        budget_limit: Decimal,
        budget_type: str,
    ) -> None:
        super().__init__(message)
        self.current_cost = current_cost
        self.budget_limit = budget_limit
        self.budget_type = budget_type


@dataclass
class BudgetConfig:
    """Budget configuration for cost limits."""

    max_cost_per_call: Decimal | None = None
    max_cost_per_session: Decimal | None = None
    max_tokens_per_call: int | None = None
    max_tokens_per_session: int | None = None
    warn_at_percentage: float = 80.0  # Warn when reaching this % of budget


# Default pricing per 1K tokens (as of 2026)
DEFAULT_PRICING: dict[str, dict[str, Decimal]] = {
    "gpt-4o": {
        "input": Decimal("0.0025"),
        "output": Decimal("0.01"),
    },
    "gpt-4o-mini": {
        "input": Decimal("0.00015"),
        "output": Decimal("0.0006"),
    },
    "claude-3-5-sonnet": {
        "input": Decimal("0.003"),
        "output": Decimal("0.015"),
    },
    "claude-3-5-haiku": {
        "input": Decimal("0.001"),
        "output": Decimal("0.005"),
    },
    "claude-3-opus": {
        "input": Decimal("0.015"),
        "output": Decimal("0.075"),
    },
    "default": {
        "input": Decimal("0.003"),
        "output": Decimal("0.015"),
    },
}


class CostTracker:
    """Tracks costs across tool calls.

    Usage:
        tracker = CostTracker()
        tracker.add_callback(my_callback)

        # Record a call
        with tracker.track("my_tool") as t:
            result = do_work()
            t.set_tokens(input=100, output=50)

        # Get summary
        print(tracker.get_summary())
    """

    def __init__(
        self,
        model: str = "default",
        budget: BudgetConfig | None = None,
        pricing: dict[str, dict[str, Decimal]] | None = None,
    ) -> None:
        """Initialize cost tracker.

        Args:
            model: Model name for pricing lookup.
            budget: Budget configuration.
            pricing: Custom pricing (per 1K tokens).
        """
        self.model = model
        self.budget = budget
        self.pricing = pricing or DEFAULT_PRICING
        self._records: list[CostRecord] = []
        self._callbacks: list[CostCallback] = []
        self._lock = threading.Lock()

    def get_price(self, token_type: str) -> Decimal:
        """Get price per 1K tokens for model.

        Args:
            token_type: "input" or "output".

        Returns:
            Price per 1K tokens.
        """
        model_pricing = self.pricing.get(self.model, self.pricing["default"])
        return model_pricing.get(token_type, Decimal("0"))

    def calculate_cost(self, tokens: TokenUsage) -> Decimal:
        """Calculate cost for token usage.

        Args:
            tokens: Token usage.

        Returns:
            Cost in USD.
        """
        input_cost = (Decimal(tokens.input_tokens) / 1000) * self.get_price("input")
        output_cost = (Decimal(tokens.output_tokens) / 1000) * self.get_price("output")
        return input_cost + output_cost

    def add_callback(self, callback: CostCallback) -> None:
        """Add callback for cost records.

        Args:
            callback: Function to call with each cost record.
        """
        self._callbacks.append(callback)

    def record(
        self,
        tool_name: str,
        tokens: TokenUsage,
        duration_ms: float = 0.0,
        metadata: dict[str, Any] | None = None,
    ) -> CostRecord:
        """Record a cost entry.

        Args:
            tool_name: Name of the tool.
            tokens: Token usage.
            duration_ms: Execution duration in milliseconds.
            metadata: Additional metadata.

        Returns:
            The created cost record.

        Raises:
            BudgetExceededError: If budget limit is exceeded.
        """
        cost = self.calculate_cost(tokens)

        record = CostRecord(
            tool_name=tool_name,
            timestamp=time.time(),
            tokens=tokens,
            cost_usd=cost,
            duration_ms=duration_ms,
            metadata=metadata or {},
        )

        with self._lock:
            # Check budget limits before recording
            self._check_budget(tokens, cost)

            self._records.append(record)

            logger.debug(
                "cost_recorded",
                tool=tool_name,
                tokens=tokens.total_tokens,
                cost=str(cost),
            )

        # Notify callbacks
        for callback in self._callbacks:
            try:
                callback(record)
            except Exception:
                logger.exception("cost_callback_error", tool=tool_name)

        return record

    def _check_budget(self, tokens: TokenUsage, cost: Decimal) -> None:
        """Check if operation would exceed budget."""
        if not self.budget:
            return

        # Check per-call limits
        if self.budget.max_cost_per_call and cost > self.budget.max_cost_per_call:
            raise BudgetExceededError(
                f"Call cost ${cost} exceeds limit ${self.budget.max_cost_per_call}",
                current_cost=cost,
                budget_limit=self.budget.max_cost_per_call,
                budget_type="per_call_cost",
            )

        if (
            self.budget.max_tokens_per_call
            and tokens.total_tokens > self.budget.max_tokens_per_call
        ):
            raise BudgetExceededError(
                f"Call tokens {tokens.total_tokens} exceeds limit "
                f"{self.budget.max_tokens_per_call}",
                current_cost=cost,
                budget_limit=Decimal(self.budget.max_tokens_per_call),
                budget_type="per_call_tokens",
            )

        # Check session limits
        summary = self._get_summary_unlocked()

        if self.budget.max_cost_per_session:
            new_total = summary.total_cost_usd + cost
            if new_total > self.budget.max_cost_per_session:
                raise BudgetExceededError(
                    f"Session cost ${new_total} exceeds limit ${self.budget.max_cost_per_session}",
                    current_cost=new_total,
                    budget_limit=self.budget.max_cost_per_session,
                    budget_type="session_cost",
                )

            # Warn if approaching limit
            percentage = float(new_total / self.budget.max_cost_per_session) * 100
            if percentage >= self.budget.warn_at_percentage:
                logger.warning(
                    "budget_warning",
                    current=str(new_total),
                    limit=str(self.budget.max_cost_per_session),
                    percentage=percentage,
                )

        if self.budget.max_tokens_per_session:
            new_total_tokens = summary.total_tokens + tokens.total_tokens
            if new_total_tokens > self.budget.max_tokens_per_session:
                raise BudgetExceededError(
                    f"Session tokens {new_total_tokens} exceeds limit "
                    f"{self.budget.max_tokens_per_session}",
                    current_cost=Decimal(new_total_tokens),
                    budget_limit=Decimal(self.budget.max_tokens_per_session),
                    budget_type="session_tokens",
                )

    def _get_summary_unlocked(self) -> CostSummary:
        """Get summary without lock (internal use)."""
        summary = CostSummary()
        by_tool: dict[str, dict[str, Any]] = {}

        for record in self._records:
            summary.total_calls += 1
            summary.total_input_tokens += record.tokens.input_tokens
            summary.total_output_tokens += record.tokens.output_tokens
            summary.total_tokens += record.tokens.total_tokens
            summary.total_cost_usd += record.cost_usd
            summary.total_duration_ms += record.duration_ms

            if record.tool_name not in by_tool:
                by_tool[record.tool_name] = {
                    "calls": 0,
                    "tokens": 0,
                    "cost_usd": Decimal("0"),
                }
            by_tool[record.tool_name]["calls"] += 1
            by_tool[record.tool_name]["tokens"] += record.tokens.total_tokens
            by_tool[record.tool_name]["cost_usd"] += record.cost_usd

        # Convert Decimal to string for JSON serialization
        for tool_data in by_tool.values():
            tool_data["cost_usd"] = str(tool_data["cost_usd"])

        summary.by_tool = by_tool
        return summary

    def get_summary(self) -> CostSummary:
        """Get aggregated cost summary.

        Returns:
            Cost summary with totals and per-tool breakdown.
        """
        with self._lock:
            return self._get_summary_unlocked()

    def get_records(self) -> list[CostRecord]:
        """Get all cost records.

        Returns:
            List of cost records.
        """
        with self._lock:
            return list(self._records)

    def to_task_budget(self, total: int, soft: bool = True) -> dict[str, Any]:
        """Render current usage as a Claude ``task_budget`` payload (v0.5.1+).

        Returns the dict expected by the Anthropic ``task-budgets-2026-03-13``
        beta (see ``agent_airlock.integrations.claude_task_budget`` for the
        canonical builder). Computes ``remaining_tokens`` as
        ``total - tracker.summary.total_tokens``, clamped to zero.

        Args:
            total: The per-task token budget to report to the model.
            soft: If True, policy is "soft" (model receives a countdown
                  but may overshoot). If False, policy is "hard".

        Returns:
            A dict of the shape
            ``{"task_budget": {"total_tokens", "remaining_tokens", "policy"}}``
            ready to be merged into an Anthropic Messages API request body.
        """
        summary = self.get_summary()
        remaining = max(0, total - summary.total_tokens)
        return {
            "task_budget": {
                "total_tokens": total,
                "remaining_tokens": remaining,
                "policy": "soft" if soft else "hard",
            }
        }

    def reset(self) -> None:
        """Reset all tracked costs."""
        with self._lock:
            self._records = []

    def track(self, tool_name: str) -> CostContext:
        """Create context manager for tracking a tool call.

        Args:
            tool_name: Name of the tool being tracked.

        Returns:
            Context manager for tracking.
        """
        return CostContext(self, tool_name)


class CostContext:
    """Context manager for tracking a single tool call."""

    def __init__(self, tracker: CostTracker, tool_name: str) -> None:
        self.tracker = tracker
        self.tool_name = tool_name
        self._input_tokens = 0
        self._output_tokens = 0
        self._metadata: dict[str, Any] = {}
        self._start_time: float = 0

    def set_tokens(
        self,
        input_tokens: int = 0,
        output_tokens: int = 0,
    ) -> None:
        """Set token counts for this call."""
        self._input_tokens = input_tokens
        self._output_tokens = output_tokens

    def add_metadata(self, **kwargs: Any) -> None:
        """Add metadata to this call."""
        self._metadata.update(kwargs)

    def __enter__(self) -> CostContext:
        self._start_time = time.time()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: Any,
    ) -> None:
        duration_ms = (time.time() - self._start_time) * 1000

        tokens = TokenUsage(
            input_tokens=self._input_tokens,
            output_tokens=self._output_tokens,
        )

        self._metadata["success"] = exc_val is None
        if exc_val is not None:
            self._metadata["error"] = str(exc_val)

        try:
            self.tracker.record(
                tool_name=self.tool_name,
                tokens=tokens,
                duration_ms=duration_ms,
                metadata=self._metadata,
            )
        except BudgetExceededError:
            # Re-raise budget errors
            raise
        except Exception:
            logger.exception("cost_tracking_error", tool=self.tool_name)

        # Don't suppress exceptions (return None = don't suppress)


# Global tracker instance
_global_tracker: CostTracker | None = None


def get_global_tracker() -> CostTracker:
    """Get or create the global cost tracker."""
    global _global_tracker
    if _global_tracker is None:
        _global_tracker = CostTracker()
    return _global_tracker


def set_global_tracker(tracker: CostTracker) -> None:
    """Set the global cost tracker."""
    global _global_tracker
    _global_tracker = tracker


def _reset_tracker() -> None:
    """Reset the global cost tracker for testing.

    This function should only be used in tests to ensure isolation
    between test cases.
    """
    global _global_tracker
    if _global_tracker is not None:
        _global_tracker.reset()
    _global_tracker = None


# --------------------------------------------------------------------------
# V0.8.7 — Per-model-tier cost budget primitive (ModelTierBudget).
#
# Distinct from:
#   * BudgetConfig (above): flat per-call / per-session caps, no tier dimension.
#   * ModelCapabilityTier (capabilities.py): risk-tier classification for
#     capability gating (STANDARD / OFFENSIVE_CYBER_CAPABLE / ...) — different
#     namespace.
#   * AgentSDKCreditBudget (budget/agent_sdk_credit.py): monthly subscription
#     credit caps tied to Anthropic billing tiers, not per-call cost.
#
# ModelTierBudget exists for routers that fan calls across model tiers
# ("frontier" / "mid" / "small") and want a per-call cost cap that varies by
# tier, evaluated *before* the call lands. Untagged calls fall back to the
# configured ``strict_tier`` (deny-by-default).
# --------------------------------------------------------------------------


class UnknownTierError(AirlockError):
    """Raised when a tier label is not present in a ModelTierBudget's tiers."""

    def __init__(self, tier_label: str, known: list[str]) -> None:
        self.tier_label = tier_label
        self.known = known
        super().__init__(f"Unknown model-tier label {tier_label!r}; known tiers: {sorted(known)}")


class AirlockBudgetExceeded(AirlockError):
    """Raised pre-execute when a per-call model-tier budget would be breached.

    Carries the tier label, the cap that was violated, and the worst-case
    estimated cost in cents so the calling layer can build a structured
    ``AirlockResponse`` with ``block_reason="budget_exceeded"``.
    """

    def __init__(
        self,
        message: str,
        *,
        tier: str,
        cap: TierBudget,
        estimated_cost_cents: int,
        estimated_output_tokens: int,
        budget_type: Literal["cost", "tokens"],
        model_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.tier = tier
        self.cap = cap
        self.estimated_cost_cents = estimated_cost_cents
        self.estimated_output_tokens = estimated_output_tokens
        self.budget_type = budget_type
        self.model_id = model_id

    def to_block_metadata(self) -> dict[str, Any]:
        """Serialize to a JSON-safe dict for AirlockResponse.blocked_response(metadata=...)."""
        return {
            "tier": self.tier,
            "cap": asdict(self.cap),
            "estimated_cost_cents": self.estimated_cost_cents,
            "estimated_output_tokens": self.estimated_output_tokens,
            "budget_type": self.budget_type,
            "model_id": self.model_id,
        }


@dataclass(frozen=True)
class TierBudget:
    """Per-call cap for one model tier.

    Either ``max_cost_cents`` or ``max_output_tokens`` (or both) may be set.
    If neither is set, the tier is effectively unlimited at the per-call layer
    (callers who want a session-wide cap should layer ``BudgetConfig`` on top).

    Attributes:
        max_cost_cents: Worst-case per-call cost ceiling, in USD cents.
            The check computes worst-case cost as
            ``input_tokens * input_price + max_output_tokens * output_price``
            (worst-case output = ``max_output_tokens`` when set, else just
            input_tokens contribute). When ``max_cost_cents`` is set but
            ``max_output_tokens`` is None, the estimate is a lower bound
            (input cost only) and still blocks when that exceeds the cap.
        max_output_tokens: Hard cap on output tokens. Pre-execute this caps
            the worst-case cost estimate; post-execute reconciliation logs
            (but does not raise) when the actual output exceeds it.
    """

    max_cost_cents: int | None = None
    max_output_tokens: int | None = None

    def __post_init__(self) -> None:
        if self.max_cost_cents is not None and self.max_cost_cents < 0:
            raise ValueError(
                f"TierBudget.max_cost_cents must be non-negative, got {self.max_cost_cents}"
            )
        if self.max_output_tokens is not None and self.max_output_tokens < 0:
            raise ValueError(
                f"TierBudget.max_output_tokens must be non-negative, got {self.max_output_tokens}"
            )


@dataclass(frozen=True)
class BudgetEstimate:
    """Result of a successful pre-execute budget check.

    Threaded through ``_post_execution`` so the actual cost can be reconciled
    against the worst-case estimate. ``estimated_output_tokens`` is the
    worst-case output assumed by the estimator (the tier's ``max_output_tokens``,
    or zero when no token cap is configured).
    """

    tier: str
    cap: TierBudget
    estimated_cost_cents: int
    estimated_output_tokens: int
    input_tokens: int
    model_id: str | None


@dataclass(frozen=True)
class ReconciliationRecord:
    """Result of post-execute reconciliation of actual vs estimated cost.

    Observability-only — emitted as a structlog event but never raised.
    Users who want a hard session cap should layer ``BudgetConfig.max_cost_per_session``
    on top.
    """

    tier: str
    estimated_cost_cents: int
    actual_cost_cents: int
    delta_cents: int  # actual - estimated; negative = under-estimated (good)
    input_tokens: int
    output_tokens: int
    output_tokens_over_cap: bool


def _usd_to_cents(usd: Decimal) -> int:
    """Convert a USD Decimal to integer cents, rounding half-up."""
    return int((usd * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP))


@dataclass
class ModelTierBudget:
    """Per-model-tier cost-budget primitive (v0.8.7).

    Maps a caller-defined tier label (e.g. ``"frontier"``, ``"mid"``,
    ``"small"``) to a per-call :class:`TierBudget`. The check fires
    pre-execute (in ``core.py``'s ``_pre_execution`` seam) and blocks
    calls whose worst-case estimated cost would exceed the tier's cap.

    Deny-by-default: an untagged call falls back to ``strict_tier``
    (which must be one of the configured tiers).

    The caller's router decides the tier — agent-airlock does not maintain
    a vendor-locked model→tier table. Two routes are supported:

    1. The router tags each call by passing ``_airlock_tier="frontier"``
       as a kwarg (or by setting ``context.metadata["airlock_tier"]``).
    2. The router passes a ``model_id`` (via
       ``context.metadata["model_id"]``) and configures a
       ``tier_resolver: Callable[[str], str]`` that maps model IDs to
       tier labels. The router stays in the router; airlock just calls
       the callback.

    Example:
        budget = ModelTierBudget(
            tiers={
                "frontier": TierBudget(max_cost_cents=50, max_output_tokens=4000),
                "mid":      TierBudget(max_cost_cents=10, max_output_tokens=2000),
                "small":    TierBudget(max_cost_cents=2,  max_output_tokens=1000),
            },
            strict_tier="small",  # untagged → cheapest tier (deny-by-default)
        )

    Attributes:
        tiers: Mapping from tier label to :class:`TierBudget`. Must contain
            at least one entry, and must contain ``strict_tier``.
        strict_tier: The tier used when a call is untagged. Acts as the
            deny-by-default fallback. Must exist in ``tiers``.
        tier_resolver: Optional callback mapping model_id strings to tier
            labels. Invoked only when a call is otherwise untagged AND a
            model_id is supplied via ``context.metadata["model_id"]``.
            Returning an unknown label triggers fallback to ``strict_tier``.
    """

    tiers: dict[str, TierBudget]
    strict_tier: str
    tier_resolver: Callable[[str], str] | None = None

    def __post_init__(self) -> None:
        if not self.tiers:
            raise ValueError("ModelTierBudget requires at least one tier")
        if self.strict_tier not in self.tiers:
            raise ValueError(
                f"strict_tier {self.strict_tier!r} must be one of {sorted(self.tiers)}"
            )

    def resolve_tier(
        self,
        *,
        explicit: str | None = None,
        model_id: str | None = None,
    ) -> str:
        """Resolve which tier label applies to this call.

        Priority: ``explicit`` > ``tier_resolver(model_id)`` > ``strict_tier``.

        An explicit tier that doesn't exist in ``tiers`` raises
        :class:`UnknownTierError` (a typo in caller code should fail loudly,
        not silently degrade to strict). A resolver that returns an unknown
        label silently falls back to ``strict_tier`` (the router callback
        may legitimately not know every model).
        """
        if explicit is not None:
            if explicit not in self.tiers:
                raise UnknownTierError(explicit, list(self.tiers))
            return explicit
        if model_id is not None and self.tier_resolver is not None:
            try:
                label = self.tier_resolver(model_id)
            except Exception:
                logger.exception(
                    "tier_resolver_error",
                    model_id=model_id,
                    fallback=self.strict_tier,
                )
                return self.strict_tier
            if label in self.tiers:
                return label
            logger.debug(
                "tier_resolver_unknown_label",
                model_id=model_id,
                label=label,
                fallback=self.strict_tier,
            )
        return self.strict_tier

    def cap_for(self, tier_label: str) -> TierBudget:
        """Return the TierBudget for ``tier_label`` or raise UnknownTierError."""
        try:
            return self.tiers[tier_label]
        except KeyError as exc:
            raise UnknownTierError(tier_label, list(self.tiers)) from exc

    def check_pre_execute(
        self,
        *,
        tier_label: str,
        input_tokens: int,
        cost_tracker: CostTracker,
        model_id: str | None = None,
    ) -> BudgetEstimate:
        """Compute the worst-case cost estimate and raise if over-budget.

        Args:
            tier_label: Resolved tier label (use :meth:`resolve_tier` first).
            input_tokens: Best estimate of the input tokens the call will
                consume. May be 0 if unknown — the estimate then covers
                only the worst-case output cost.
            cost_tracker: Cost tracker carrying the per-model pricing table
                (reuses :meth:`CostTracker.calculate_cost` so we don't
                duplicate the pricing surface).
            model_id: Optional model identifier, attached to the estimate
                and the exception for telemetry.

        Returns:
            :class:`BudgetEstimate` carrying the tier, cap, and worst-case
            cost. Pass this to :meth:`reconcile_post_execute` after the
            call completes.

        Raises:
            AirlockBudgetExceeded: If the worst-case estimate exceeds
                the tier's ``max_cost_cents`` cap.
            UnknownTierError: If ``tier_label`` is not configured.
        """
        cap = self.cap_for(tier_label)
        if input_tokens < 0:
            raise ValueError(f"input_tokens must be non-negative, got {input_tokens}")

        # Worst-case output = tier cap when set, else 0 (estimate covers input only).
        worst_case_output = cap.max_output_tokens if cap.max_output_tokens is not None else 0
        worst_case_usage = TokenUsage(
            input_tokens=input_tokens,
            output_tokens=worst_case_output,
        )
        estimated_cost_usd = cost_tracker.calculate_cost(worst_case_usage)
        estimated_cost_cents = _usd_to_cents(estimated_cost_usd)

        if cap.max_cost_cents is not None and estimated_cost_cents > cap.max_cost_cents:
            raise AirlockBudgetExceeded(
                f"Tier {tier_label!r} cost cap exceeded: worst-case "
                f"{estimated_cost_cents}¢ > cap {cap.max_cost_cents}¢ "
                f"(input_tokens={input_tokens}, "
                f"worst_case_output_tokens={worst_case_output})",
                tier=tier_label,
                cap=cap,
                estimated_cost_cents=estimated_cost_cents,
                estimated_output_tokens=worst_case_output,
                budget_type="cost",
                model_id=model_id,
            )

        logger.debug(
            "tier_budget_pre_check_passed",
            tier=tier_label,
            input_tokens=input_tokens,
            worst_case_output=worst_case_output,
            estimated_cost_cents=estimated_cost_cents,
            cap_cents=cap.max_cost_cents,
            model_id=model_id,
        )
        return BudgetEstimate(
            tier=tier_label,
            cap=cap,
            estimated_cost_cents=estimated_cost_cents,
            estimated_output_tokens=worst_case_output,
            input_tokens=input_tokens,
            model_id=model_id,
        )

    def reconcile_post_execute(
        self,
        *,
        estimate: BudgetEstimate,
        actual: TokenUsage,
        cost_tracker: CostTracker,
    ) -> ReconciliationRecord:
        """Reconcile actual vs estimated cost. Never raises.

        Records the actual cost via ``cost_tracker.record()`` (which feeds
        the session-level :class:`BudgetConfig` checks, if any). Emits a
        structlog ``tier_budget_reconciled`` event with the delta. Does
        NOT raise on over-cap actuals — a call that estimates 5¢ and
        actually costs 50¢ is logged but its return value still flows
        back to the caller. Users who want a hard session cap should
        configure ``BudgetConfig.max_cost_per_session`` on the tracker.
        """
        actual_cost_usd = cost_tracker.calculate_cost(actual)
        actual_cost_cents = _usd_to_cents(actual_cost_usd)
        delta_cents = actual_cost_cents - estimate.estimated_cost_cents
        cap = estimate.cap
        over_tokens = (
            cap.max_output_tokens is not None and actual.output_tokens > cap.max_output_tokens
        )
        logger.info(
            "tier_budget_reconciled",
            tier=estimate.tier,
            estimated_cost_cents=estimate.estimated_cost_cents,
            actual_cost_cents=actual_cost_cents,
            delta_cents=delta_cents,
            input_tokens=actual.input_tokens,
            output_tokens=actual.output_tokens,
            output_tokens_over_cap=over_tokens,
            model_id=estimate.model_id,
        )
        return ReconciliationRecord(
            tier=estimate.tier,
            estimated_cost_cents=estimate.estimated_cost_cents,
            actual_cost_cents=actual_cost_cents,
            delta_cents=delta_cents,
            input_tokens=actual.input_tokens,
            output_tokens=actual.output_tokens,
            output_tokens_over_cap=over_tokens,
        )

    def canonical_payload(self) -> dict[str, Any]:
        """Return a JSON-stable serialization for SecurityPolicy._canonical_bytes()."""
        return {
            "tiers": {
                label: {
                    "max_cost_cents": cap.max_cost_cents,
                    "max_output_tokens": cap.max_output_tokens,
                }
                for label, cap in sorted(self.tiers.items())
            },
            "strict_tier": self.strict_tier,
            # tier_resolver is a Callable — excluded from the digest by design
            # (its identity changes across processes; freeze() covers config,
            # not behavior).
            "has_tier_resolver": self.tier_resolver is not None,
        }
