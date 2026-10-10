"""Kill-switch broadcaster + listener.

One signed ``trigger`` freezes every listener that holds the signing key. Releasing the
freeze takes a ``reset`` quorum of distinct configured signers.

Since 0.10.24 the listener counts a reset vote under the signer whose key verified it, never
under the keyid the envelope claims, and counts it only while frozen and only when it is
ordered after the active freeze. Until then one key signing resets under two keyids met the
default 2-of-3 quorum alone, and the resets that ended one incident, replayed off the stream,
released the next freeze. Replays are recognised by signature, not by age, and no sender's
clock can push the reset window out of reach: a stamp is ordered no later than the
listener's own clock plus ``max_clock_skew_seconds``. ``docs/cli/kill-switch.md`` states
the rules and their residuals.
"""

from __future__ import annotations

import json
import math
import re
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal

from .._log import structlog
from .quorum import QuorumError, ResetQuorum
from .signer import HMACBroadcastSigner, InvalidBroadcastSignature
from .transports import BroadcastTransport

logger = structlog.get_logger("agent-airlock.kill_switch.broadcast")

BROADCAST_VERSION = 1
"""Bumped only on incompatible payload changes."""

#: An HMAC-SHA256 hex digest, the only signature :meth:`HMACBroadcastSigner.sign` emits.
#: Anything else is refused before verification: ``hmac.compare_digest`` raises on a
#: non-ASCII string, and until 0.10.24 that exception escaped
#: :meth:`KillSwitchListener.poll` and dropped every broadcast queued behind the bad frame.
_SIGNATURE_RE = re.compile(r"[0-9a-f]{64}")

#: How many applied or seen broadcast signatures a listener remembers to recognise replays.
_SEEN_LIMIT = 4096

_ts_lock = threading.Lock()
_last_ts = 0.0


def _next_ts_epoch() -> float:
    """``time.time()``, nudged so two broadcasts from one process never share a stamp.

    A reset counts only when it was signed strictly after the active trigger, so a trigger
    and a reset published within one clock tick of each other must still be ordered.
    """
    global _last_ts
    with _ts_lock:
        now = time.time()
        if now <= _last_ts:
            now = math.nextafter(_last_ts, math.inf)
        _last_ts = now
        return now


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
    if not _SIGNATURE_RE.fullmatch(sig):
        raise InvalidBroadcastSignature("broadcast 'signature' is not an HMAC-SHA256 hex digest")
    ts_epoch = float(payload["ts_epoch"])
    if not math.isfinite(ts_epoch):
        # A NaN stamp compares false both ways, so it would pass every ordering check.
        raise InvalidBroadcastSignature("broadcast 'ts_epoch' is not a finite number")
    return (
        _Envelope(
            version=int(payload.get("version", 0)),
            action=payload["action"],
            keyid=str(payload["keyid"]),
            reason=str(payload["reason"]),
            ts_epoch=ts_epoch,
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
            ts_epoch=_next_ts_epoch(),
        )
        self._publish(env)

    def reset(self, reason: str) -> None:
        """Emit a signed ``reset`` broadcast: one vote toward the listeners' quorum."""
        env = _Envelope(
            version=BROADCAST_VERSION,
            action="reset",
            keyid=self.signer.keyid,
            reason=reason,
            ts_epoch=_next_ts_epoch(),
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

    A broadcast is applied only when one of the registered signers' MACs verifies it, and
    then as that signer. Its signed ``ts_epoch`` orders it, clamped to no later than this
    listener's ``clock()`` plus ``max_clock_skew_seconds``, so no sender's clock, fast by
    accident or on purpose, sets the window for everyone else.

    * A ``trigger`` always freezes, whatever its stamp: refusing a freeze fails open.
    * A ``reset`` is one vote for the signer whose key verified it, whatever keyid the
      envelope claims, so one key is one vote however many keyids it signs under; an
      envelope that claims another keyid is refused as a vote. A vote counts only while
      the listener is frozen and only when its stamp is later than the freeze's threshold:
      the highest stamp this listener had applied when the freeze began, so votes captured
      from an earlier incident cannot release a later one, even one triggered from a slow
      clock.
    * A frame whose signature this listener has already seen is a replay and is ignored,
      so a captured trigger cannot re-freeze a fleet that was reset and a replay of the
      active trigger cannot wipe the votes already cast.
    * One frame the listener cannot read is logged and skipped; it never stops the rest of
      the batch.

    A listener holding fewer signers than ``reset_quorum_threshold`` can be frozen but never
    reset: give every listener every operator's key. It is not refused at construction, so
    the CLI's single-key read-only listeners keep working.

    :meth:`poll` reads every pending message unconditionally, while :meth:`poll_if_due`
    respects ``poll_interval_seconds`` and is what the ``@Airlock`` call path uses so a
    transport read does not land on every tool call.

    Register one with ``agent_airlock.kill_switch.registry.install`` to have ``@Airlock``
    consult it. Constructing a listener alone changes nothing — through v0.8.85 nothing in
    the library ever did.

    Raises:
        QuorumError: Two signers share a keyid or a key, so their votes could not be told
            apart, or the quorum itself is impossible.
    """

    signers: tuple[HMACBroadcastSigner, ...]
    transport: BroadcastTransport
    reset_quorum_threshold: int = 2
    reset_quorum_total: int = 3
    state: KillSwitchState = KillSwitchState.DISARMED
    last_action_ts: float = 0.0
    last_reason: str = ""
    poll_interval_seconds: float = 5.0
    """Minimum seconds between transport reads driven by :meth:`poll_if_due`.

    5 s is the interval the original feature spec named and never implemented. A freeze
    therefore takes effect within one interval, not instantly; set it to 0 to poll on
    every call.
    """
    max_clock_skew_seconds: float = 300.0
    """How far ahead of :attr:`clock` a signed stamp may sit and still be ordered as signed.

    A stamp further ahead is ordered as ``clock() + max_clock_skew_seconds``. The broadcast
    still applies (a far-future trigger freezes at once), but its votes then count once
    they are signed after that bound, rather than after a date a fast clock picked.
    """
    clock: Callable[[], float] = field(default=time.time, repr=False, compare=False)
    """Wall clock the stamp clamp reads. Injectable so tests can move time."""
    _quorum: ResetQuorum = field(init=False)
    _last_poll: float = field(init=False, default=0.0)
    _trigger_ts: float | None = field(init=False, default=None)
    """Threshold a vote's stamp must exceed; ``None`` while not frozen by a broadcast.

    The highest of the active trigger's clamped stamp and every stamp applied before it,
    so it never moves backward: a slow-clock trigger cannot reopen the window to votes
    that ended an earlier incident.
    """
    _high_water: float = field(init=False, default=-math.inf)
    """Highest clamped stamp among every broadcast applied: triggers and counted votes."""
    _seen: set[str] = field(init=False, default_factory=set, repr=False, compare=False)
    _seen_order: deque[str] = field(init=False, default_factory=deque, repr=False, compare=False)
    _lock: threading.Lock = field(
        init=False, default_factory=threading.Lock, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        self._quorum = ResetQuorum(
            threshold=self.reset_quorum_threshold,
            total=self.reset_quorum_total,
        )
        self._last_poll = 0.0
        self._refuse_indistinct_signers()

    def _refuse_indistinct_signers(self) -> None:
        """Refuse signers whose votes could not be told apart.

        Two signers under one keyid would count two keys as one vote; two keyids on one key
        name one key twice. Either way the quorum stops meaning distinct keys.
        """
        keyids = [signer.keyid for signer in self.signers]
        repeated = sorted({keyid for keyid in keyids if keyids.count(keyid) > 1})
        if repeated:
            raise QuorumError(
                f"kill-switch signers repeat keyid(s) {repeated}: one keyid must name one key"
            )
        by_key: dict[bytes, list[str]] = {}
        for signer in self.signers:
            key = getattr(signer, "key", None)
            if isinstance(key, bytes):
                by_key.setdefault(key, []).append(signer.keyid)
        shared = sorted(keyids_ for keyids_ in by_key.values() if len(keyids_) > 1)
        if shared:
            raise QuorumError(
                f"kill-switch signers {shared} share one key: a reset signed with it is one "
                "vote, so configure one key per keyid"
            )

    def is_frozen(self) -> bool:
        """Whether agents must halt new tool calls right now."""
        return self.state == KillSwitchState.TRIGGERED

    def poll(self) -> int:
        """Read all pending messages and update state.

        Returns:
            How many broadcasts were applied: a trigger that froze the listener, or a reset
            vote that was counted. A rejected, replayed or unreadable broadcast is logged and
            skipped, and never stops the rest of the batch from being read.
        """
        applied = 0
        with self._lock:
            for buf in self.transport.consume():
                try:
                    env, sig = _deserialise(buf)
                    signer = self._verifying_signer(_serialise(env), sig)
                except Exception as exc:  # noqa: BLE001 - one bad frame must not drop the batch
                    logger.warning("kill_switch_bad_envelope", error=str(exc))
                    continue
                if signer is None:
                    logger.warning("kill_switch_signature_rejected", keyid=env.keyid)
                    continue
                if not self._first_sighting(sig):
                    logger.warning(
                        "kill_switch_replay_ignored", action=str(env.action), keyid=signer.keyid
                    )
                    continue
                stamp = self._ordering_stamp(env)
                if env.action == "trigger":
                    applied += self._apply_trigger(env, signer, stamp)
                elif env.action == "reset":
                    applied += self._apply_reset(env, signer, stamp)
                else:
                    logger.warning(
                        "kill_switch_unknown_action", action=str(env.action), keyid=signer.keyid
                    )
        return applied

    def _verifying_signer(self, canonical: bytes, sig: str) -> HMACBroadcastSigner | None:
        """The configured signer whose key produced ``sig``, or None."""
        for signer in self.signers:
            if signer.verify(canonical, sig):
                return signer
        return None

    def _first_sighting(self, sig: str) -> bool:
        """Remember ``sig``; False when it was already seen (a replay).

        Bounded to the last :data:`_SEEN_LIMIT` signatures. A fresh listener replaying a
        stream's history sees each broadcast once, in order, which rebuilds the same state.
        """
        if sig in self._seen:
            return False
        if len(self._seen_order) >= _SEEN_LIMIT:
            self._seen.discard(self._seen_order.popleft())
        self._seen.add(sig)
        self._seen_order.append(sig)
        return True

    def _ordering_stamp(self, env: _Envelope) -> float:
        """``env``'s signed stamp, clamped to no later than ``clock() + max_clock_skew_seconds``."""
        bound = self.clock() + self.max_clock_skew_seconds
        if env.ts_epoch > bound:
            logger.warning(
                "kill_switch_stamp_clamped",
                action=str(env.action),
                ts_epoch=env.ts_epoch,
                ordered_as=bound,
            )
            return bound
        return env.ts_epoch

    def _apply_trigger(self, env: _Envelope, signer: HMACBroadcastSigner, stamp: float) -> int:
        if env.keyid != signer.keyid:
            # The MAC proves a configured key signed it. A freeze is never refused over a
            # label: that would be the fail-open direction for a kill switch.
            logger.warning(
                "kill_switch_keyid_mismatch",
                action="trigger",
                claimed_keyid=env.keyid,
                signer_keyid=signer.keyid,
                applied=True,
            )
        floor = self._high_water
        if self._trigger_ts is not None:
            floor = max(floor, self._trigger_ts)
        self.state = KillSwitchState.TRIGGERED
        self._trigger_ts = max(stamp, floor)
        self._high_water = max(self._high_water, stamp)
        self.last_action_ts = env.ts_epoch
        self.last_reason = env.reason
        self._quorum.reset()
        return 1

    def _apply_reset(self, env: _Envelope, signer: HMACBroadcastSigner, stamp: float) -> int:
        if self.state is not KillSwitchState.TRIGGERED or self._trigger_ts is None:
            logger.warning("kill_switch_reset_ignored", reason="not_frozen", keyid=signer.keyid)
            return 0
        if stamp <= self._trigger_ts:
            logger.warning(
                "kill_switch_reset_ignored",
                reason="not_after_the_active_freeze",
                keyid=signer.keyid,
                ts_epoch=env.ts_epoch,
                threshold=self._trigger_ts,
            )
            return 0
        if env.keyid != signer.keyid:
            logger.warning(
                "kill_switch_keyid_mismatch",
                action="reset",
                claimed_keyid=env.keyid,
                signer_keyid=signer.keyid,
                applied=False,
            )
            return 0
        self._high_water = max(self._high_water, stamp)
        if self._quorum.submit(signer.keyid):
            self.state = KillSwitchState.DISARMED
            self.last_action_ts = env.ts_epoch
            self.last_reason = env.reason
            self._trigger_ts = None
            self._quorum.reset()
        # else: still need more signers — stays TRIGGERED.
        return 1

    def poll_if_due(self) -> int:
        """Poll only if ``poll_interval_seconds`` has elapsed since the last read.

        Returns:
            The number of broadcasts applied, or 0 when the interval has not elapsed.
        """
        now = time.monotonic()
        if self._last_poll and (now - self._last_poll) < self.poll_interval_seconds:
            return 0
        self._last_poll = now
        return self.poll()

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
