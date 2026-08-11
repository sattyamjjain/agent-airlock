"""Runtime capability-union boundary check at grant time.

agent-audit-kit does the **static** scan (flagging risky capability unions in a skill set
*before load*). This is the **runtime** half, and it is a different mechanism: airlock grants
and revokes leases, and at the point it issues a lease it evaluates the *union* of capability
the calling context would hold **if this lease were granted** — not just the capability in the
lease itself — and denies by default when the union crosses a configured boundary.

Default boundary (the same shape as the static side): ``{filesystem read OR credential access}``
combined with ``{non-allowlisted network egress}`` is an exfiltration path, and is denied even
when each individual lease is independently permitted. The denial names the **specific prior
lease** that combined with the new one to trigger it. An explicit :class:`UnionOverride` is
available and is recorded loudly in the decision log with the identity that granted it (see
:meth:`agent_airlock.capability_caps.engine.CapabilityCapEngine.grant_lease`).

The check is over-**union-across-leases**: a single lease that intrinsically confers both a
source and a sink (e.g. a legitimate ``upload_file(path, url)`` declared with
``FILESYSTEM_READ | NETWORK_HTTPS``) is one reviewed unit and is not denied here — the danger
this closes is *combining two individually-permitted leases* into an exfiltration chain.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any

from ..exceptions import AirlockError

__all__ = [
    "EXFILTRATION_BOUNDARY",
    "CapabilityCategory",
    "CapabilityUnionDeniedError",
    "Lease",
    "UnionBoundary",
    "UnionGrantDecision",
    "UnionOverride",
    "evaluate_union_grant",
]


class CapabilityCategory(str, Enum):
    """Exfiltration-relevant capability categories a lease can confer.

    Deliberately small and explicit (not a mirror of every ``Capability`` flag) so the union
    boundary is auditable: these are the categories that participate in the default rule.
    """

    FILESYSTEM_READ = "filesystem_read"
    CREDENTIAL_ACCESS = "credential_access"
    NETWORK_EGRESS = "network_egress"


@dataclass(frozen=True)
class Lease:
    """One capability lease the calling context holds (or is requesting)."""

    lease_id: str
    capability: str
    """Human label for the lease, e.g. ``"read_config"`` / ``"fetch_url"``."""
    categories: frozenset[CapabilityCategory]
    granted_by: str = "unknown"
    target: str = "*"
    network_allowlisted: bool = False
    """A ``NETWORK_EGRESS`` lease whose destination is on the policy allowlist. Egress to a
    trusted destination is not an exfiltration *sink*, so an allowlisted egress lease does not
    trigger the boundary."""


@dataclass(frozen=True)
class UnionBoundary:
    """A forbidden capability union: any ``sources`` category held together with a ``sink``."""

    name: str
    sources: frozenset[CapabilityCategory]
    sink: frozenset[CapabilityCategory]


#: The default exfiltration boundary — the same shape as the static side. A filesystem-read or
#: credential-access source, combined with a non-allowlisted network-egress sink, is an
#: exfiltration path and is denied by default.
EXFILTRATION_BOUNDARY = UnionBoundary(
    name="exfiltration",
    sources=frozenset({CapabilityCategory.FILESYSTEM_READ, CapabilityCategory.CREDENTIAL_ACCESS}),
    sink=frozenset({CapabilityCategory.NETWORK_EGRESS}),
)


@dataclass(frozen=True)
class UnionOverride:
    """An explicit, logged override of a union denial."""

    identity: str
    reason: str


@dataclass(frozen=True)
class UnionGrantDecision:
    """Result of evaluating whether a lease may be granted."""

    allowed: bool
    reason: str
    boundary: UnionBoundary | None = None
    triggering_leases: tuple[Lease, ...] = ()
    overridden: bool = False
    override: UnionOverride | None = None

    @property
    def audit_event(self) -> dict[str, Any]:
        """Structured, machine-readable description for the audit / decision log."""
        return {
            "event": "capability_union.decision",
            "allowed": self.allowed,
            "reason": self.reason,
            "boundary": self.boundary.name if self.boundary else None,
            "triggering_leases": [lease.lease_id for lease in self.triggering_leases],
            "overridden": self.overridden,
            "override_identity": self.override.identity if self.override else None,
        }


class CapabilityUnionDeniedError(AirlockError):
    """Raised when granting a lease would cross a capability-union boundary."""

    def __init__(self, decision: UnionGrantDecision, new_lease: Lease) -> None:
        self.decision = decision
        self.new_lease = new_lease
        self.triggering_leases = decision.triggering_leases
        self.boundary = decision.boundary
        self.audit_event = decision.audit_event
        super().__init__(decision.reason)


def _is_source(lease: Lease, boundary: UnionBoundary) -> bool:
    return bool(lease.categories & boundary.sources)


def _is_sink(lease: Lease, boundary: UnionBoundary) -> bool:
    if not (lease.categories & boundary.sink):
        return False
    # A network-egress sink only counts if it is NOT allowlisted.
    if CapabilityCategory.NETWORK_EGRESS in (lease.categories & boundary.sink):
        return not lease.network_allowlisted
    return True


def evaluate_union_grant(
    held: Sequence[Lease],
    new: Lease,
    *,
    boundaries: Iterable[UnionBoundary] = (EXFILTRATION_BOUNDARY,),
    override: UnionOverride | None = None,
) -> UnionGrantDecision:
    """Decide whether granting ``new`` (given the leases already ``held``) is allowed.

    **Deny-by-default** when granting ``new`` would complete a cross-lease boundary: ``new``
    supplies one side (source or sink) and a **distinct prior lease** supplies the other. The
    decision names the specific prior lease(s). A lease that supplies both sides by itself is a
    single reviewed unit and is allowed. An ``override`` flips a denial to allowed
    (``overridden=True``) so the caller can record it loudly.

    Args:
        held: leases the calling context already holds.
        new: the lease being requested.
        boundaries: forbidden unions to evaluate (default: :data:`EXFILTRATION_BOUNDARY`).
        override: an explicit override that allows an otherwise-denied grant.

    Returns:
        A :class:`UnionGrantDecision`.
    """
    for boundary in boundaries:
        new_source = _is_source(new, boundary)
        new_sink = _is_sink(new, boundary)
        if not (new_source or new_sink):
            continue  # the new lease does not participate in this boundary

        # Cross-lease crossing: new supplies one side, a DISTINCT prior lease the other.
        other = tuple(lease for lease in held if _is_sink(lease, boundary)) if new_source else ()
        if not other and new_sink:
            other = tuple(lease for lease in held if _is_source(lease, boundary))

        if not other:
            continue  # no distinct prior lease completes the union

        side_new = "source" if new_source else "sink"
        names = ", ".join(f"{lease.lease_id!r} ({lease.capability})" for lease in other)
        reason = (
            f"granting lease {new.lease_id!r} ({new.capability}) as the {side_new} would "
            f"complete the {boundary.name!r} capability union with prior lease(s): {names}"
        )
        if override is not None:
            return UnionGrantDecision(
                allowed=True,
                reason=f"{reason} — OVERRIDDEN by {override.identity!r}: {override.reason}",
                boundary=boundary,
                triggering_leases=other,
                overridden=True,
                override=override,
            )
        return UnionGrantDecision(
            allowed=False,
            reason=f"{reason} — denied by default (exfiltration path)",
            boundary=boundary,
            triggering_leases=other,
        )

    return UnionGrantDecision(allowed=True, reason="no capability-union boundary crossed")
