"""``agent_airlock.runtime`` — runtime enforcement primitives (v0.6.1+).

The ``runtime`` package holds enforcement helpers that run at the point
where a hosted MCP server is about to spawn a subprocess (or refuse).
It ships :func:`enforce_allowlist` — a fail-closed argv allowlist
gate sourced from the v0.5.7 signed-manifest registry. The motivation
is the OX/BackBox 2026-05-01 re-publication of the 200K-server
MCP-STDIO matrix: callers want a single CLI entrypoint that exits 2
on any argv outside the manifest, suitable for CI use.

Since v0.10.27 it also ships :func:`check_startup_hooks`, which lists the
executable ``.pth`` lines and the ``sitecustomize`` / ``usercustomize``
modules of the running interpreter (see :mod:`.startup_hooks`).
"""

from __future__ import annotations

from .manifest_only_allowlist import (
    AllowlistVerdict,
    AllowlistVerdictReason,
    enforce_allowlist,
)
from .startup_hooks import (
    StartupHookFinding,
    StartupHookKind,
    StartupHookReport,
    check_startup_hooks,
)

__all__ = [
    "AllowlistVerdict",
    "AllowlistVerdictReason",
    "StartupHookFinding",
    "StartupHookKind",
    "StartupHookReport",
    "check_startup_hooks",
    "enforce_allowlist",
]
