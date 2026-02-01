"""Cost tracking for Agent-Airlock.

Provides hooks for tracking token usage and costs per tool call,
with callback interface for external systems.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Protocol

import structlog

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
    ) -> bool:
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

        return False  # Don't suppress exceptions


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
