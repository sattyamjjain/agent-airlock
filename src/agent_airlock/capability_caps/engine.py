"""``CapabilityCapEngine`` — deny-by-default capability ledger."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Literal

import structlog

from ..exceptions import AirlockError
from .enums import Capability
from .store import CapabilityLedgerStore, SQLiteCapabilityLedgerStore

logger = structlog.get_logger("agent-airlock.capability_caps.engine")

Window = Literal["minute", "hour", "day", "week"]
"""Same window taxonomy as ``agent_commerce_caps`` — kept identical for
operator muscle memory and shared dashboards."""


_WINDOW_SECONDS: dict[Window, int] = {
    "minute": 60,
    "hour": 3600,
    "day": 86_400,
    "week": 7 * 86_400,
}


class CapabilityCapExceeded(AirlockError):
    """Raised when an attempted capability use would exceed its cap."""

    def __init__(
        self,
        message: str,
        *,
        agent_id: str,
        capability: Capability,
        target: str,
        already_used: int,
        attempted: int,
        cap_amount: int,
        window: Window,
    ) -> None:
        self.agent_id = agent_id
        self.capability = capability
        self.target = target
        self.already_used = already_used
        self.attempted = attempted
        self.cap_amount = cap_amount
        self.window = window
        super().__init__(message)


@dataclass(frozen=True)
class CapabilityRule:
    """One capability cap row."""

    capability: Capability
    amount: int
    window: Window = "hour"
    target_glob: str = "*"
    """Target predicate. ``*`` matches any target; concrete values match
    by exact equality. Glob extension (full fnmatch) is intentionally
    deferred — operators should add explicit rows rather than rely on
    pattern surprise."""


@dataclass(frozen=True)
class CapabilityRulesConfig:
    """Configuration for the engine — the set of rules to evaluate."""

    rules: tuple[CapabilityRule, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class CapabilityDecision:
    """Result of one ``check_and_use`` invocation."""

    allowed: bool
    event_id: int | None
    matched_rule: CapabilityRule | None
    already_used: int
    reason: str


class CapabilityCapEngine:
    """Capability cap engine.

    The engine is **deny-by-default** for ``SIGN_CONTRACT``: if no rule
    matches, ``check_and_use`` denies. For other capabilities it allows
    through (the dollar-cap layer / RBAC enforces the ceiling). The
    asymmetry is deliberate — contract signing is the one capability
    where "no rule" cannot mean "okay, proceed".
    """

    _DENY_BY_DEFAULT: frozenset[Capability] = frozenset({Capability.SIGN_CONTRACT})

    def __init__(
        self,
        config: CapabilityRulesConfig,
        store: CapabilityLedgerStore | None = None,
    ) -> None:
        self.config = config
        self.store: CapabilityLedgerStore = store or SQLiteCapabilityLedgerStore()

    # ------------------------------------------------------------------
    # Grant / revoke
    # ------------------------------------------------------------------

    def grant(
        self,
        agent_id: str,
        capability: Capability,
        target: str,
        amount: int = 1,
    ) -> int:
        """Record a grant event. Used for audit, not consumed by checks
        — checks measure ``kind='use'`` events against the rule cap.
        """
        return self.store.append_event(
            agent_id=agent_id,
            capability=capability,
            target=target,
            amount=amount,
            kind="grant",
            ts_epoch=time.time(),
        )

    def revoke(
        self,
        agent_id: str,
        capability: Capability,
        target: str = "*",
    ) -> int:
        """Record a revoke event. Subsequent ``check_and_use`` calls
        within the same window will be denied while the revoke is in
        effect (revoke ts > window start)."""
        return self.store.append_event(
            agent_id=agent_id,
            capability=capability,
            target=target,
            amount=0,
            kind="revoke",
            ts_epoch=time.time(),
        )

    # ------------------------------------------------------------------
    # Check
    # ------------------------------------------------------------------

    def check_and_use(
        self,
        agent_id: str,
        capability: Capability,
        target: str,
        amount: int = 1,
    ) -> CapabilityDecision:
        """Atomically check the cap, append a ``use`` event if allowed.

        Concurrency: serialised through ``store.begin_immediate()`` so
        100 racing callers cannot collectively over-spend.
        """
        with self.store.begin_immediate():
            now = time.time()
            rule = self._match_rule(capability, target)
            window_start = now - _WINDOW_SECONDS[rule.window if rule else "hour"]

            # Revoke check — most-recent revoke since the window start
            # blocks all use events for the rest of the window.
            if hasattr(self.store, "latest_revocation_ts"):
                latest_revoke = self.store.latest_revocation_ts(
                    agent_id, capability
                )
                if latest_revoke is not None and latest_revoke >= window_start:
                    return CapabilityDecision(
                        allowed=False,
                        event_id=None,
                        matched_rule=rule,
                        already_used=0,
                        reason=(
                            f"capability {capability.value!r} for agent "
                            f"{agent_id!r} is revoked within the current window"
                        ),
                    )

            if rule is None:
                if capability in self._DENY_BY_DEFAULT:
                    return CapabilityDecision(
                        allowed=False,
                        event_id=None,
                        matched_rule=None,
                        already_used=0,
                        reason=(
                            f"capability {capability.value!r} is deny-by-default "
                            f"and no explicit grant is configured"
                        ),
                    )
                # Permissive default for the non-cross-agent caps.
                event_id = self.store.append_event(
                    agent_id=agent_id,
                    capability=capability,
                    target=target,
                    amount=amount,
                    kind="use",
                    ts_epoch=now,
                )
                return CapabilityDecision(
                    allowed=True,
                    event_id=event_id,
                    matched_rule=None,
                    already_used=0,
                    reason="no rule matched; permissive default",
                )

            already_used = self.store.total_used(
                agent_id=agent_id,
                capability=capability,
                target=target if rule.target_glob != "*" else None,
                since_epoch=window_start,
            )
            if already_used + amount > rule.amount:
                return CapabilityDecision(
                    allowed=False,
                    event_id=None,
                    matched_rule=rule,
                    already_used=already_used,
                    reason=(
                        f"capability cap breach: capability={capability.value} "
                        f"window={rule.window} used={already_used} + "
                        f"attempt={amount} > cap={rule.amount}"
                    ),
                )
            event_id = self.store.append_event(
                agent_id=agent_id,
                capability=capability,
                target=target,
                amount=amount,
                kind="use",
                ts_epoch=now,
            )
            logger.info(
                "capability_use",
                agent_id=agent_id,
                capability=capability.value,
                target=target,
                amount=amount,
                event_id=event_id,
            )
            return CapabilityDecision(
                allowed=True,
                event_id=event_id,
                matched_rule=rule,
                already_used=already_used,
                reason="within cap",
            )

    def check_and_use_or_raise(
        self,
        agent_id: str,
        capability: Capability,
        target: str,
        amount: int = 1,
    ) -> CapabilityDecision:
        d = self.check_and_use(agent_id, capability, target, amount)
        if not d.allowed:
            raise CapabilityCapExceeded(
                d.reason,
                agent_id=agent_id,
                capability=capability,
                target=target,
                already_used=d.already_used,
                attempted=amount,
                cap_amount=d.matched_rule.amount if d.matched_rule else 0,
                window=d.matched_rule.window if d.matched_rule else "hour",
            )
        return d

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _match_rule(
        self, capability: Capability, target: str
    ) -> CapabilityRule | None:
        """Return the most-specific rule for ``(capability, target)``.

        Specific target matches win over wildcard. First-write wins on
        ties.
        """
        wildcard: CapabilityRule | None = None
        for rule in self.config.rules:
            if rule.capability != capability:
                continue
            if rule.target_glob == target:
                return rule
            if rule.target_glob == "*":
                if wildcard is None:
                    wildcard = rule
        return wildcard


__all__ = [
    "CapabilityCapEngine",
    "CapabilityCapExceeded",
    "CapabilityDecision",
    "CapabilityRule",
    "CapabilityRulesConfig",
    "Window",
]
