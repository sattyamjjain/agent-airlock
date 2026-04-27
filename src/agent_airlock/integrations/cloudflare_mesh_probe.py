"""Cloudflare Mesh detection + policy de-duplication (v0.5.8+).

Motivation
----------
[Cloudflare Mesh launched 2026-04-23](https://www.cloudflare.com/press/press-releases/2026/cloudflare-launches-mesh-to-secure-the-ai-agent-lifecycle/)
during Agents Week 2026 with direct overlap on the agent-runtime
firewall surface. agent-airlock's wedge is **OSS-founder-built**;
its compatibility story is "runs alongside Mesh without
double-applying egress policies."

This probe inspects request headers for the canonical Mesh markers,
returns a typed :class:`MeshContext` if present, and provides a
:func:`dedupe_policies` helper that removes overlapping egress
policies while keeping airlock-only guards (manifest-only mode,
PR-metadata guard, agent-commerce caps, etc. — none of which Mesh
ships today).

Header surface is held in a **single constant** so it can be
versioned cleanly when Cloudflare iterates.

Source: https://www.cloudflare.com/press/press-releases/2026/cloudflare-launches-mesh-to-secure-the-ai-agent-lifecycle/
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

import structlog

logger = structlog.get_logger("agent-airlock.integrations.cloudflare_mesh_probe")


# Header set Cloudflare Mesh injects on requests it has already
# processed. Versioned: when Cloudflare iterates, bump
# ``MESH_HEADER_SCHEMA_VERSION`` and pin a new list. The probe
# is intentionally case-insensitive on the lookup side.
MESH_HEADER_SCHEMA_VERSION = 1
"""Bump when the header set changes upstream."""

MESH_MARKER_HEADERS: frozenset[str] = frozenset(
    {
        "cf-mesh-policy-id",
        "cf-mesh-tenant",
        "cf-mesh-trace-id",
        "cf-mesh-applied-policies",
    }
)


# Egress-policy categories that Mesh covers natively. agent-airlock
# guards in this set are safe to dedupe when Mesh is upstream — Mesh
# already enforced. Categories outside this set (manifest-only,
# pr_metadata, agent-commerce, sampling, OAuth audit, etc.) are
# airlock-only and stay regardless.
_MESH_OVERLAPPING_CATEGORIES: frozenset[str] = frozenset(
    {
        "egress_allowlist",
        "rate_limit",
        "tls_termination",
    }
)


# -----------------------------------------------------------------------------
# Types
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class MeshContext:
    """The headers Mesh injected. Empty fields are valid (Mesh may not set all)."""

    policy_id: str
    tenant: str
    trace_id: str
    applied_policies: tuple[str, ...]


@dataclass(frozen=True)
class PolicyChain:
    """A list of policy categories the local guard chain enforces."""

    categories: tuple[str, ...]


# -----------------------------------------------------------------------------
# Probe
# -----------------------------------------------------------------------------


def _normalise_headers(headers: dict[str, str] | None) -> dict[str, str]:
    if not headers:
        return {}
    return {k.lower(): v for k, v in headers.items() if isinstance(v, str)}


def detect_mesh(headers: dict[str, str] | None) -> MeshContext | None:
    """Return a :class:`MeshContext` if Mesh markers are present, else None."""
    norm = _normalise_headers(headers)
    has_marker = any(h in norm for h in MESH_MARKER_HEADERS)
    if not has_marker:
        return None
    applied = norm.get("cf-mesh-applied-policies", "")
    applied_tuple = tuple(p.strip() for p in applied.split(",") if p.strip())
    ctx = MeshContext(
        policy_id=norm.get("cf-mesh-policy-id", ""),
        tenant=norm.get("cf-mesh-tenant", ""),
        trace_id=norm.get("cf-mesh-trace-id", ""),
        applied_policies=applied_tuple,
    )
    logger.debug(
        "cloudflare_mesh_detected",
        policy_id=ctx.policy_id,
        tenant=ctx.tenant,
        applied_count=len(applied_tuple),
    )
    return ctx


def dedupe_policies(
    local: PolicyChain,
    mesh: MeshContext | None,
) -> PolicyChain:
    """Remove categories Mesh already covers, keep airlock-only guards.

    Args:
        local: The categories the local airlock would have enforced.
        mesh: ``None`` when Mesh isn't upstream; pass-through happens.

    Returns:
        A reduced :class:`PolicyChain`. Categories outside the
        overlapping set always remain.
    """
    if mesh is None:
        return local
    mesh_active = set(mesh.applied_policies) | _MESH_OVERLAPPING_CATEGORIES
    keep: list[str] = []
    for cat in local.categories:
        if cat in _MESH_OVERLAPPING_CATEGORIES and cat in mesh_active:
            continue
        keep.append(cat)
    return PolicyChain(categories=tuple(keep))


def airlock_only_categories(local: Iterable[str]) -> tuple[str, ...]:
    """Subset of categories that Mesh does NOT cover (always airlock-enforced)."""
    return tuple(c for c in local if c not in _MESH_OVERLAPPING_CATEGORIES)


__all__ = [
    "MESH_HEADER_SCHEMA_VERSION",
    "MESH_MARKER_HEADERS",
    "MeshContext",
    "PolicyChain",
    "airlock_only_categories",
    "detect_mesh",
    "dedupe_policies",
]
