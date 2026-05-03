"""``agent_airlock.runtime`` — runtime enforcement primitives (v0.6.1+).

The ``runtime`` package holds enforcement helpers that run at the point
where a hosted MCP server is about to spawn a subprocess (or refuse).
Today it ships :func:`enforce_allowlist` — a fail-closed argv allowlist
gate sourced from the v0.5.7 signed-manifest registry. The motivation
is the OX/BackBox 2026-05-01 re-publication of the 200K-server
MCP-STDIO matrix: callers want a single CLI entrypoint that exits 2
on any argv outside the manifest, suitable for CI use.
"""

from __future__ import annotations

from .manifest_only_allowlist import (
    AllowlistVerdict,
    AllowlistVerdictReason,
    enforce_allowlist,
)

__all__ = [
    "AllowlistVerdict",
    "AllowlistVerdictReason",
    "enforce_allowlist",
]
