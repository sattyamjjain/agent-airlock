"""Network-wide kill-switch for airlock-protected agents (v0.5.9+).

Operators arm the switch with one or more shared keys, then trigger
a signed broadcast that every airlock-protected agent honours within
5 s by halting all new tool calls and capability grants. Resetting
requires a multi-key quorum so a single compromised key cannot
unilaterally re-enable agents.

Reference
---------
* Feature spec: docs/kill-switch.md (shipped 2026-04-28).
"""

from __future__ import annotations

from .broadcast import (
    KillSwitchBroadcast,
    KillSwitchListener,
    KillSwitchState,
)
from .quorum import QuorumError, ResetQuorum
from .signer import HMACBroadcastSigner, InvalidBroadcastSignature
from .transports import (
    BroadcastTransport,
    InMemoryTransport,
    NATSTransportStub,
    RedisTransportStub,
    S3TransportStub,
)

__all__ = [
    "BroadcastTransport",
    "HMACBroadcastSigner",
    "InMemoryTransport",
    "InvalidBroadcastSignature",
    "KillSwitchBroadcast",
    "KillSwitchListener",
    "KillSwitchState",
    "NATSTransportStub",
    "QuorumError",
    "RedisTransportStub",
    "ResetQuorum",
    "S3TransportStub",
]
