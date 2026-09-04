"""Network-wide kill-switch for airlock-protected agents (v0.5.9+).

Operators trigger a signed broadcast; every process that installed a
:class:`KillSwitchListener` halts new tool calls within its poll interval
(5 s by default). Resetting requires a multi-key quorum so a single
compromised key cannot unilaterally re-enable agents.

Wiring it up
------------
Two steps, both required — this was one step short of working until v0.8.86,
when nothing in the library consulted the listener::

    from agent_airlock.kill_switch import (
        HMACBroadcastSigner, KillSwitchListener, registry,
    )
    from agent_airlock.kill_switch.transports import RedisStreamTransport

    listener = KillSwitchListener(
        signers=(HMACBroadcastSigner(keyid="ops-a", key=KEY),),
        transport=RedisStreamTransport.from_url("redis://localhost:6379/0"),
    )
    registry.install(listener)   # <- without this, @Airlock never asks

After ``install``, ``@Airlock`` checks the switch before every other gate.

Reference
---------
* ``docs/cli/kill-switch.md`` — commands, scope, and what is not covered.
"""

from __future__ import annotations

from . import registry
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
    "registry",
]
