"""Kill-switch broadcaster + listener."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal

import structlog

from .quorum import QuorumError, ResetQuorum
from .signer import HMACBroadcastSigner, InvalidBroadcastSignature
from .transports import BroadcastTransport

logger = structlog.get_logger("agent-airlock.kill_switch.broadcast")

BROADCAST_VERSION = 1
"""Bumped only on incompatible payload changes."""


class KillSwitchState(str, Enum):
    """Lifecycle states a listener exposes."""

    DISARMED = "disarmed"
    ARMED = "armed"
    TRIGGERED = "triggered"


Action = Literal["trigger", "reset"]


@dataclass(frozen=True)
class _Envelope:
    """Internal canonical envelope before signing."""

    version: int
    action: Action
    keyid: str
    reason: str
    ts_epoch: float


def _serialise(envelope: _Envelope) -> bytes:
    return json.dumps(
        {
            "version": envelope.version,
            "action": envelope.action,
            "keyid": envelope.keyid,
            "reason": envelope.reason,
            "ts_epoch": envelope.ts_epoch,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _deserialise(buf: bytes) -> tuple[_Envelope, str]:
    payload = json.loads(buf.decode("utf-8"))
    if not isinstance(payload, dict):
        raise InvalidBroadcastSignature("broadcast payload is not a JSON object")
    sig = payload.pop("signature", None)
    if not isinstance(sig, str):
        raise InvalidBroadcastSignature("broadcast missing 'signature' field")
    return (
        _Envelope(
            version=int(payload.get("version", 0)),
            action=payload["action"],
            keyid=str(payload["keyid"]),
            reason=str(payload["reason"]),
            ts_epoch=float(payload["ts_epoch"]),
        ),
        sig,
    )


@dataclass
class KillSwitchBroadcast:
    """Operator-side broadcaster."""

    signer: HMACBroadcastSigner
    transport: BroadcastTransport

    def trigger(self, reason: str) -> None:
        """Emit a signed ``trigger`` broadcast."""
        env = _Envelope(
            version=BROADCAST_VERSION,
            action="trigger",
            keyid=self.signer.keyid,
            reason=reason,
            ts_epoch=time.time(),
        )
        self._publish(env)

    def reset(self, reason: str) -> None:
        """Emit a signed ``reset`` broadcast (after the quorum gate)."""
        env = _Envelope(
            version=BROADCAST_VERSION,
            action="reset",
            keyid=self.signer.keyid,
            reason=reason,
            ts_epoch=time.time(),
        )
        self._publish(env)

    def _publish(self, env: _Envelope) -> None:
        canonical = _serialise(env)
        sig = self.signer.sign(canonical)
        wire = json.dumps(
            {
                "version": env.version,
                "action": env.action,
                "keyid": env.keyid,
                "reason": env.reason,
                "ts_epoch": env.ts_epoch,
                "signature": sig,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        self.transport.publish(wire)
        logger.info(
            "kill_switch_publish",
            action=env.action,
            keyid=env.keyid,
            reason=env.reason,
        )


@dataclass
class KillSwitchListener:
    """Per-process listener.

    Calls ``poll()`` on a configurable interval (5 s default per
    spec); each accepted broadcast updates ``state``. Verifying any
    one of the registered signers' MACs is sufficient.
    """

    signers: tuple[HMACBroadcastSigner, ...]
    transport: BroadcastTransport
    reset_quorum_threshold: int = 2
    reset_quorum_total: int = 3
    state: KillSwitchState = KillSwitchState.DISARMED
    last_action_ts: float = 0.0
    last_reason: str = ""
    _quorum: ResetQuorum = field(init=False)

    def __post_init__(self) -> None:
        self._quorum = ResetQuorum(
            threshold=self.reset_quorum_threshold,
            total=self.reset_quorum_total,
        )

    def is_frozen(self) -> bool:
        """Whether agents must halt new tool calls right now."""
        return self.state == KillSwitchState.TRIGGERED

    def poll(self) -> int:
        """Read all pending messages and update state. Returns count."""
        n = 0
        for buf in self.transport.consume():
            try:
                env, sig = _deserialise(buf)
            except (InvalidBroadcastSignature, KeyError, ValueError, json.JSONDecodeError) as exc:
                logger.warning("kill_switch_bad_envelope", error=str(exc))
                continue
            canonical = _serialise(env)
            if not any(s.verify(canonical, sig) for s in self.signers):
                logger.warning("kill_switch_signature_rejected", keyid=env.keyid)
                continue
            n += 1
            if env.action == "trigger":
                self.state = KillSwitchState.TRIGGERED
                self.last_action_ts = env.ts_epoch
                self.last_reason = env.reason
                self._quorum.reset()
            elif env.action == "reset":
                if self._quorum.submit(env.keyid):
                    self.state = KillSwitchState.DISARMED
                    self.last_action_ts = env.ts_epoch
                    self.last_reason = env.reason
                    self._quorum.reset()
                # else: still need more signers — stays TRIGGERED.
        return n

    def quorum_progress(self) -> tuple[int, int]:
        return (len(self._quorum.votes), self._quorum.threshold)


__all__ = [
    "Action",
    "BROADCAST_VERSION",
    "KillSwitchBroadcast",
    "KillSwitchListener",
    "KillSwitchState",
    "QuorumError",
]
