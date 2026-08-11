"""``CapabilityCapEngine`` — deny-by-default capability ledger."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

from .._log import structlog
from ..exceptions import AirlockError
from .enums import Capability
from .store import CapabilityLedgerStore, SQLiteCapabilityLedgerStore
from .union import (
    EXFILTRATION_BOUNDARY,
    CapabilityUnionDeniedError,
    Lease,
    UnionBoundary,
    UnionGrantDecision,
    UnionOverride,
    evaluate_union_grant,
)

if TYPE_CHECKING:
    from ..conformance.decision_log import DecisionLog

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
        # Runtime capability-union registry: the leases each agent currently holds. Distinct
        # from the SQLite cap ledger (which meters `use` events by the coarse Capability enum)
        # — this tracks category-tagged Leases so grant_lease can evaluate the union boundary.
        self._active_leases: dict[str, list[Lease]] = {}

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
    # Capability-union leases (grant-time union boundary)
    # ------------------------------------------------------------------

    def held_leases(self, agent_id: str) -> tuple[Lease, ...]:
        """The capability leases ``agent_id`` currently holds."""
        return tuple(self._active_leases.get(agent_id, ()))

    def grant_lease(
        self,
        agent_id: str,
        lease: Lease,
        *,
        boundaries: tuple[UnionBoundary, ...] = (EXFILTRATION_BOUNDARY,),
        override: UnionOverride | None = None,
        decision_log: DecisionLog | None = None,
    ) -> UnionGrantDecision:
        """Issue a capability lease, checking the *union* it would create at grant time.

        Evaluates the union of the leases ``agent_id`` already holds plus ``lease`` against
        ``boundaries``. **Deny-by-default**: if granting ``lease`` would complete a forbidden
        union with a distinct prior lease, this raises :class:`CapabilityUnionDeniedError`
        (whose message names that prior lease) — unless ``override`` is supplied, in which case
        the grant is allowed and recorded **loudly**: a ``warn`` record is written to
        ``decision_log`` (if given) with the granting identity, and a ``structlog`` warning is
        emitted.

        On allow, the lease is added to the agent's held set. Returns the decision.

        Raises:
            CapabilityUnionDeniedError: if the union crosses a boundary and no override is set.
        """
        held = self._active_leases.get(agent_id, [])
        decision = evaluate_union_grant(held, lease, boundaries=boundaries, override=override)

        if not decision.allowed:
            logger.warning(
                "capability_union_denied",
                agent_id=agent_id,
                lease_id=lease.lease_id,
                capability=lease.capability,
                boundary=decision.boundary.name if decision.boundary else None,
                triggering_leases=[lease_.lease_id for lease_ in decision.triggering_leases],
            )
            raise CapabilityUnionDeniedError(decision, lease)

        if decision.overridden and override is not None:
            # Loud, non-repudiable record of the escape hatch.
            logger.warning(
                "capability_union_override",
                agent_id=agent_id,
                lease_id=lease.lease_id,
                capability=lease.capability,
                boundary=decision.boundary.name if decision.boundary else None,
                triggering_leases=[lease_.lease_id for lease_ in decision.triggering_leases],
                override_identity=override.identity,
                override_reason=override.reason,
            )
            if decision_log is not None:
                decision_log.append(
                    stage="policy",
                    tool_name=lease.capability,
                    decision="warn",
                    reason=(
                        f"capability-union override [{decision.boundary.name if decision.boundary else '?'}] "
                        f"by {override.identity}: {override.reason}"
                    ),
                    agent_id=agent_id,
                )

        self._active_leases.setdefault(agent_id, []).append(lease)
        return decision

    def revoke_lease(self, agent_id: str, lease_id: str) -> bool:
        """Drop a held lease so it no longer counts toward the union. Returns True if removed."""
        leases = self._active_leases.get(agent_id)
        if not leases:
            return False
        remaining = [lease for lease in leases if lease.lease_id != lease_id]
        removed = len(remaining) != len(leases)
        self._active_leases[agent_id] = remaining
        return removed

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
                latest_revoke = self.store.latest_revocation_ts(agent_id, capability)
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

    def _match_rule(self, capability: Capability, target: str) -> CapabilityRule | None:
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
