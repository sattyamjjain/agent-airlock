"""Capability-cap layer (v0.5.9+).

Parallel to ``integrations.agent_commerce_caps`` (dollar caps). The
Anthropic Project Deal surface (2026-04-25) exposes capability
primitives — sign-contract, delegate-to-agent, invoke-tool, write-
file, network-egress — with no built-in cap. This package layers a
deny-by-default capability ledger so an agent cannot exceed its
allotted budget for any of those primitives without an explicit grant.

The engine shares the SQLite-WAL durability discipline from the
dollar-cap layer (``BEGIN IMMEDIATE`` + ``threading.Lock`` + WAL
journal mode) so concurrent grant / revoke / check operations
serialise at the write boundary and survive SIGKILL mid-grant.

Reference
---------
* Anthropic Project Deal (2026-04-25):
  https://www.anthropic.com/features/project-deal
"""

from __future__ import annotations

from .engine import (
    CapabilityCapEngine,
    CapabilityCapExceeded,
    CapabilityDecision,
    CapabilityRule,
    CapabilityRulesConfig,
)
from .enums import Capability
from .store import CapabilityLedgerStore, SQLiteCapabilityLedgerStore

__all__ = [
    "Capability",
    "CapabilityCapEngine",
    "CapabilityCapExceeded",
    "CapabilityDecision",
    "CapabilityLedgerStore",
    "CapabilityRule",
    "CapabilityRulesConfig",
    "SQLiteCapabilityLedgerStore",
]
