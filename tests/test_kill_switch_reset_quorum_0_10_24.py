"""Regressions for 0.10.24: a kill-switch freeze could be released, or suppressed, without a quorum.

- ``KillSwitchListener.poll`` accepted a broadcast when any configured signer's MAC verified
  it, then counted a reset vote under the keyid the envelope *claimed*. One key signing two
  resets under two keyids met the default 2-of-3 quorum alone, against the package's own
  promise that a single compromised key cannot re-enable a fleet.
- ``ts_epoch`` was signed and never compared, so the two resets that ended one incident,
  captured off the stream, released the next freeze: no key needed, only write access to
  the transport.
- A frame the listener could not read raised out of ``poll`` (``int(None)``, ``float([])``,
  a non-ASCII signature reaching ``hmac.compare_digest``). The transport had already handed
  over the whole batch, so a real trigger queued behind that frame was lost and the fleet
  never froze. That needed no key either.
- Ordering by the sender's stamp alone let one clock set the window. A trigger stamped ten
  years ahead could not be reset by an honest quorum, and a trigger from a slow clock was
  dropped as stale. Stamps are now clamped to the listener's clock plus
  ``max_clock_skew_seconds``, replays are recognised by signature, a distinct trigger always
  freezes, and a vote must beat the highest stamp applied before the freeze.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from agent_airlock import Airlock
from agent_airlock.kill_switch import (
    HMACBroadcastSigner,
    InMemoryTransport,
    KillSwitchBroadcast,
    KillSwitchListener,
    KillSwitchState,
    QuorumError,
    registry,
)
from agent_airlock.kill_switch import broadcast as broadcast_module
from agent_airlock.kill_switch.broadcast import BROADCAST_VERSION, _Envelope, _serialise

KEY_A = b"a" * 32
KEY_B = b"b" * 32
KEY_C = b"c" * 32


@pytest.fixture(autouse=True)
def _no_leaked_switch() -> Any:
    """The registry is process-global; a leaked listener would freeze unrelated tests."""
    registry.clear()
    yield
    registry.clear()


@pytest.fixture
def ops() -> tuple[HMACBroadcastSigner, HMACBroadcastSigner, HMACBroadcastSigner]:
    return (
        HMACBroadcastSigner(keyid="ops-a", key=KEY_A),
        HMACBroadcastSigner(keyid="ops-b", key=KEY_B),
        HMACBroadcastSigner(keyid="ops-c", key=KEY_C),
    )


@pytest.fixture
def bus() -> InMemoryTransport:
    return InMemoryTransport()


def _listener(bus: InMemoryTransport, signers: tuple[HMACBroadcastSigner, ...]) -> Any:
    return KillSwitchListener(signers=signers, transport=bus, poll_interval_seconds=0)


def _wire(
    signer: HMACBroadcastSigner,
    *,
    action: str,
    ts: float,
    keyid: str | None = None,
    reason: str = "r",
) -> bytes:
    """A broadcast signed with ``signer``'s key, claiming ``keyid``, stamped ``ts``."""
    env = _Envelope(
        version=BROADCAST_VERSION,
        action=action,  # type: ignore[arg-type]
        keyid=signer.keyid if keyid is None else keyid,
        reason=reason,
        ts_epoch=ts,
    )
    body = json.loads(_serialise(env))
    body["signature"] = signer.sign(_serialise(env))
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


@Airlock()
def deploy(target: str) -> str:
    return f"deployed to {target}"


def _blocked(result: Any) -> bool:
    return isinstance(result, dict) and result.get("block_reason") == "kill_switch"


class TestOneKeyIsOneVote:
    """The vote belongs to the key that verified it, never to the keyid it claims."""

    def test_a_second_keyid_on_the_same_key_is_not_a_second_vote(self, bus, ops) -> None:
        listener = _listener(bus, ops)
        bus.publish(_wire(ops[0], action="trigger", ts=100.0))
        bus.publish(_wire(ops[0], action="reset", ts=110.0))
        bus.publish(_wire(ops[0], action="reset", ts=111.0, keyid="anything"))
        listener.poll()
        assert listener.is_frozen(), "one key under two keyids met the 2-of-3 quorum"
        assert listener.quorum_progress() == (1, 2)

    def test_claiming_another_operators_keyid_is_not_their_vote(self, bus, ops) -> None:
        listener = _listener(bus, ops)
        bus.publish(_wire(ops[0], action="trigger", ts=100.0))
        bus.publish(_wire(ops[0], action="reset", ts=110.0))
        bus.publish(_wire(ops[0], action="reset", ts=111.0, keyid="ops-b"))
        listener.poll()
        assert listener.is_frozen()
        assert listener.quorum_progress() == (1, 2)

    def test_many_labels_on_one_key_stay_one_vote(self, bus, ops) -> None:
        listener = _listener(bus, ops)
        bus.publish(_wire(ops[0], action="trigger", ts=100.0))
        for i, keyid in enumerate(("ops-a", "ops-b", "ops-c", "x", "y")):
            bus.publish(_wire(ops[0], action="reset", ts=110.0 + i, keyid=keyid))
        listener.poll()
        assert listener.is_frozen()
        assert listener.quorum_progress() == (1, 2)

    def test_an_honest_two_of_three_still_resets(self, bus, ops) -> None:
        listener = _listener(bus, ops)
        bus.publish(_wire(ops[0], action="trigger", ts=100.0))
        bus.publish(_wire(ops[0], action="reset", ts=110.0))
        bus.publish(_wire(ops[1], action="reset", ts=111.0))
        listener.poll()
        assert not listener.is_frozen()
        assert listener.state is KillSwitchState.DISARMED

    def test_a_freeze_is_never_refused_over_a_label(self, bus, ops) -> None:
        """The MAC proves a configured key signed it; refusing would fail open."""
        listener = _listener(bus, ops)
        bus.publish(_wire(ops[0], action="trigger", ts=100.0, keyid="ops-b"))
        listener.poll()
        assert listener.is_frozen()


class TestSignersWhoseVotesCannotBeToldApartAreRefused:
    def test_a_repeated_keyid_is_refused(self, bus) -> None:
        with pytest.raises(QuorumError, match="repeat keyid"):
            _listener(
                bus,
                (
                    HMACBroadcastSigner(keyid="ops-a", key=KEY_A),
                    HMACBroadcastSigner(keyid="ops-a", key=KEY_B),
                ),
            )

    def test_a_shared_key_is_refused_without_printing_it(self, bus) -> None:
        with pytest.raises(QuorumError, match="share one key") as excinfo:
            _listener(
                bus,
                (
                    HMACBroadcastSigner(keyid="ops-a", key=KEY_A),
                    HMACBroadcastSigner(keyid="ops-b", key=KEY_A),
                ),
            )
        assert KEY_A.decode() not in str(excinfo.value)

    def test_fewer_signers_than_the_threshold_freezes_but_never_resets(self, bus, ops) -> None:
        """Documented, not refused: the CLI builds single-key read-only listeners."""
        listener = _listener(bus, (ops[0],))
        bus.publish(_wire(ops[0], action="trigger", ts=100.0))
        bus.publish(_wire(ops[0], action="reset", ts=110.0))
        bus.publish(_wire(ops[0], action="reset", ts=111.0, keyid="ops-b"))
        listener.poll()
        assert listener.is_frozen()


class TestAReplayedResetCannotReleaseALaterFreeze:
    def test_resets_captured_from_an_earlier_incident_do_not_count(self, bus, ops) -> None:
        listener = _listener(bus, ops)
        old_votes = [
            _wire(ops[0], action="reset", ts=110.0),
            _wire(ops[1], action="reset", ts=111.0),
        ]
        bus.publish(_wire(ops[0], action="trigger", ts=100.0))
        for vote in old_votes:
            bus.publish(vote)
        listener.poll()
        assert not listener.is_frozen(), "incident 1 was legitimately reset"

        bus.publish(_wire(ops[2], action="trigger", ts=200.0, reason="incident 2"))
        listener.poll()
        for vote in old_votes:  # an attacker with write access to the stream, no key
            bus.publish(vote)
        listener.poll()
        assert listener.is_frozen(), "replayed incident-1 resets released incident 2"
        assert listener.quorum_progress() == (0, 2)

        bus.publish(_wire(ops[0], action="reset", ts=210.0))
        bus.publish(_wire(ops[1], action="reset", ts=211.0))
        listener.poll()
        assert not listener.is_frozen()

    def test_a_vote_signed_before_the_active_trigger_does_not_count(self, bus, ops) -> None:
        listener = _listener(bus, ops)
        bus.publish(_wire(ops[0], action="trigger", ts=100.0))
        bus.publish(_wire(ops[0], action="reset", ts=90.0))
        bus.publish(_wire(ops[1], action="reset", ts=100.0))
        listener.poll()
        assert listener.is_frozen()
        assert listener.quorum_progress() == (0, 2)

    def test_a_reset_while_not_frozen_is_not_banked(self, bus, ops) -> None:
        listener = _listener(bus, ops)
        bus.publish(_wire(ops[0], action="reset", ts=110.0))
        bus.publish(_wire(ops[1], action="reset", ts=111.0))
        assert listener.poll() == 0
        bus.publish(_wire(ops[2], action="trigger", ts=200.0))
        listener.poll()
        assert listener.is_frozen()
        assert listener.quorum_progress() == (0, 2)


class TestAReplayedTriggerIsIgnored:
    """An exact replay is recognised by its signature; a distinct older trigger still freezes."""

    def test_replaying_an_old_trigger_after_its_reset_does_not_refreeze(self, bus, ops) -> None:
        listener = _listener(bus, ops)
        old_trigger = _wire(ops[0], action="trigger", ts=100.0)
        bus.publish(old_trigger)
        bus.publish(_wire(ops[0], action="reset", ts=110.0))
        bus.publish(_wire(ops[1], action="reset", ts=111.0))
        listener.poll()
        assert not listener.is_frozen()

        bus.publish(old_trigger)
        assert listener.poll() == 0
        assert not listener.is_frozen(), "a replayed trigger re-froze the fleet without a key"

        bus.publish(_wire(ops[1], action="trigger", ts=300.0))
        listener.poll()
        assert listener.is_frozen(), "a fresh trigger must still freeze"

    def test_replaying_the_active_trigger_does_not_wipe_the_votes(self, bus, ops) -> None:
        listener = _listener(bus, ops)
        trigger = _wire(ops[0], action="trigger", ts=100.0)
        bus.publish(trigger)
        bus.publish(_wire(ops[0], action="reset", ts=110.0))
        bus.publish(trigger)
        listener.poll()
        assert listener.quorum_progress() == (1, 2)

        bus.publish(_wire(ops[1], action="reset", ts=120.0))
        listener.poll()
        assert not listener.is_frozen()

    def test_a_newer_trigger_during_a_freeze_restarts_the_vote(self, bus, ops) -> None:
        listener = _listener(bus, ops)
        bus.publish(_wire(ops[0], action="trigger", ts=100.0))
        bus.publish(_wire(ops[0], action="reset", ts=110.0))
        bus.publish(_wire(ops[1], action="trigger", ts=120.0, reason="worse"))
        bus.publish(_wire(ops[1], action="reset", ts=130.0))
        listener.poll()
        assert listener.is_frozen()
        assert listener.quorum_progress() == (1, 2)
        assert listener.last_reason == "worse"

    def test_a_vote_from_a_clock_running_ahead_does_not_disable_later_freezes(
        self, bus, ops
    ) -> None:
        """Staleness is judged on trigger stamps, never on the votes that cleared one.

        Comparing a new trigger with the newest vote let one honest operator whose clock ran
        ten years ahead, voting in an ordinary reset, make every freeze for ten years ignored.
        """
        listener = _listener(bus, ops)
        bus.publish(_wire(ops[0], action="trigger", ts=100.0))
        bus.publish(_wire(ops[0], action="reset", ts=110.0))
        bus.publish(_wire(ops[1], action="reset", ts=100.0 + 10 * 365 * 86400))
        listener.poll()
        assert not listener.is_frozen()

        bus.publish(_wire(ops[2], action="trigger", ts=200.0, reason="incident 2"))
        listener.poll()
        assert listener.is_frozen(), "a future-dated vote pushed the next freeze out of reach"

    def test_a_trigger_signed_during_the_reset_still_refreezes(self, bus, ops) -> None:
        """A freeze signed between the votes and applied after the reset is not a replay."""
        listener = _listener(bus, ops)
        bus.publish(_wire(ops[0], action="trigger", ts=100.0))
        bus.publish(_wire(ops[0], action="reset", ts=110.0))
        bus.publish(_wire(ops[1], action="reset", ts=120.0))
        listener.poll()
        assert not listener.is_frozen()

        bus.publish(_wire(ops[2], action="trigger", ts=115.0, reason="late but real"))
        listener.poll()
        assert listener.is_frozen()


class TestOneBadFrameDoesNotDropTheBatch:
    """Each of these used to raise out of ``poll`` and lose the trigger queued behind it."""

    @pytest.mark.parametrize(
        ("signature", "version", "ts_epoch"),
        [
            ("0" * 64, None, 1.0),  # int(None)
            ("0" * 64, 1, []),  # float([])
            ("é", 1, 1.0),  # hmac.compare_digest refuses non-ASCII
        ],
        ids=["version-null", "ts-list", "non-ascii-signature"],
    )
    def test_a_real_trigger_behind_a_malformed_frame_still_freezes(
        self, bus, ops, signature: str, version: Any, ts_epoch: Any
    ) -> None:
        listener = _listener(bus, ops)
        frame = {
            "action": "trigger",
            "keyid": "ops-a",
            "reason": "junk",
            "signature": signature,
            "ts_epoch": ts_epoch,
            "version": version,
        }
        bus.publish(json.dumps(frame).encode("utf-8"))
        KillSwitchBroadcast(signer=ops[0], transport=bus).trigger(reason="real incident")
        assert listener.poll() == 1
        assert listener.is_frozen()
        assert listener.last_reason == "real incident"

    def test_bytes_that_are_not_json_are_skipped(self, bus, ops) -> None:
        listener = _listener(bus, ops)
        bus.publish(b"\xff\xfe not json")
        KillSwitchBroadcast(signer=ops[0], transport=bus).trigger(reason="real incident")
        assert listener.poll() == 1
        assert listener.is_frozen()

    @pytest.mark.parametrize("stamp", [float("inf"), float("-inf"), float("nan")])
    def test_a_non_finite_stamp_is_refused_even_when_signed(self, bus, ops, stamp: float) -> None:
        """A NaN stamp compares false both ways, so it would pass every ordering check."""
        listener = _listener(bus, ops)
        bus.publish(_wire(ops[0], action="trigger", ts=stamp))
        assert listener.poll() == 0
        assert not listener.is_frozen()

        bus.publish(_wire(ops[0], action="trigger", ts=100.0))
        bus.publish(_wire(ops[0], action="reset", ts=stamp))
        bus.publish(_wire(ops[1], action="reset", ts=stamp))
        listener.poll()
        assert listener.is_frozen()
        assert listener.quorum_progress() == (0, 2)


class TestBroadcastsFromOneProcessAreOrdered:
    def test_a_reset_in_the_same_clock_tick_as_the_trigger_still_counts(
        self, bus, ops, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A reset counts only when signed after the trigger, so one tick must not tie."""
        monkeypatch.setattr(broadcast_module.time, "time", lambda: 1_700_000_000.0)
        listener = _listener(bus, ops)
        KillSwitchBroadcast(signer=ops[0], transport=bus).trigger(reason="x")
        KillSwitchBroadcast(signer=ops[0], transport=bus).reset(reason="clear")
        KillSwitchBroadcast(signer=ops[1], transport=bus).reset(reason="clear")
        listener.poll()
        assert not listener.is_frozen()


class TestTheDecoratedToolFollowsTheQuorum:
    def test_only_a_fresh_honest_quorum_lets_the_tool_run(self, bus, ops) -> None:
        listener = _listener(bus, ops)
        registry.install(listener)
        assert deploy(target="prod") == "deployed to prod"

        incident_1 = [
            _wire(ops[0], action="trigger", ts=100.0),
            _wire(ops[0], action="reset", ts=110.0),
            _wire(ops[1], action="reset", ts=111.0),
        ]
        for frame in incident_1:
            bus.publish(frame)
        assert deploy(target="prod") == "deployed to prod"

        bus.publish(_wire(ops[2], action="trigger", ts=200.0, reason="incident 2"))
        assert _blocked(deploy(target="prod"))

        bus.publish(_wire(ops[0], action="reset", ts=210.0))
        bus.publish(_wire(ops[0], action="reset", ts=211.0, keyid="ops-c"))
        assert _blocked(deploy(target="prod")), "one key with a forged keyid released it"

        for frame in incident_1[1:]:
            bus.publish(frame)
        assert _blocked(deploy(target="prod")), "replayed incident-1 resets released it"

        bus.publish(_wire(ops[1], action="reset", ts=212.0))
        assert deploy(target="prod") == "deployed to prod"


NOW = 1_800_000_000.0
TEN_YEARS = 10 * 365 * 86400.0


class _Clock:
    """A wall clock a test can move."""

    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def _listener_at(
    bus: InMemoryTransport, signers: tuple[HMACBroadcastSigner, ...], clock: _Clock
) -> Any:
    return KillSwitchListener(signers=signers, transport=bus, poll_interval_seconds=0, clock=clock)


class TestNoSendersClockSetsTheWindow:
    """A stamp is ordered no later than the listener's clock plus ``max_clock_skew_seconds``."""

    def test_a_far_future_trigger_freezes_and_an_honest_quorum_still_releases_it(
        self, bus, ops
    ) -> None:
        clock = _Clock(NOW)
        listener = _listener_at(bus, ops, clock)
        bus.publish(_wire(ops[0], action="trigger", ts=NOW + TEN_YEARS))
        listener.poll()
        assert listener.is_frozen(), "a far-future trigger must still freeze at once"

        clock.now = NOW + 10
        bus.publish(_wire(ops[1], action="reset", ts=NOW + 10))
        bus.publish(_wire(ops[2], action="reset", ts=NOW + 11))
        listener.poll()
        assert listener.is_frozen(), "votes inside the skew allowance must not count yet"
        assert listener.quorum_progress() == (0, 2)

        clock.now = NOW + 400
        bus.publish(_wire(ops[1], action="reset", ts=NOW + 350))
        bus.publish(_wire(ops[2], action="reset", ts=NOW + 351))
        listener.poll()
        assert not listener.is_frozen(), "a ten-year stamp held the freeze past the allowance"

        clock.now = NOW + 500
        bus.publish(_wire(ops[0], action="trigger", ts=NOW + 500, reason="incident 2"))
        listener.poll()
        assert listener.is_frozen(), "after the release a genuine trigger must freeze again"

    def test_a_future_dated_vote_does_not_push_later_freezes_out_of_reach(self, bus, ops) -> None:
        clock = _Clock(NOW)
        listener = _listener_at(bus, ops, clock)
        bus.publish(_wire(ops[0], action="trigger", ts=NOW))
        bus.publish(_wire(ops[0], action="reset", ts=NOW + 1))
        bus.publish(_wire(ops[1], action="reset", ts=NOW + TEN_YEARS))
        listener.poll()
        assert not listener.is_frozen()

        clock.now = NOW + 10
        bus.publish(_wire(ops[2], action="trigger", ts=NOW + 10, reason="incident 2"))
        listener.poll()
        assert listener.is_frozen(), "a future-dated vote suppressed the next freeze"

        clock.now = NOW + 400
        bus.publish(_wire(ops[0], action="reset", ts=NOW + 350))
        bus.publish(_wire(ops[1], action="reset", ts=NOW + 351))
        listener.poll()
        assert not listener.is_frozen(), "the vote delayed the next reset past the allowance"


class TestASlowClockTriggerStillFreezes:
    def test_a_slow_clock_trigger_while_disarmed_freezes(self, bus, ops) -> None:
        listener = _listener(bus, ops)
        bus.publish(_wire(ops[0], action="trigger", ts=100.0))
        bus.publish(_wire(ops[0], action="reset", ts=110.0))
        bus.publish(_wire(ops[1], action="reset", ts=120.0))
        listener.poll()
        assert not listener.is_frozen()

        bus.publish(_wire(ops[2], action="trigger", ts=90.0, reason="slow clock"))
        assert listener.poll() == 1
        assert listener.is_frozen(), "a distinct trigger was dropped for its stamp"
        assert listener.last_reason == "slow clock"

    def test_replayed_votes_cannot_release_a_slow_clock_freeze(
        self, bus, ops, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With the replay memory evicted, the high-water threshold still refuses them."""
        monkeypatch.setattr(broadcast_module, "_SEEN_LIMIT", 1)
        listener = _listener(bus, ops)
        old_votes = [
            _wire(ops[0], action="reset", ts=110.0),
            _wire(ops[1], action="reset", ts=120.0),
        ]
        bus.publish(_wire(ops[0], action="trigger", ts=100.0))
        for vote in old_votes:
            bus.publish(vote)
        listener.poll()
        assert not listener.is_frozen()

        bus.publish(_wire(ops[2], action="trigger", ts=90.0, reason="slow clock"))
        listener.poll()
        for vote in old_votes:
            bus.publish(vote)
        listener.poll()
        assert listener.is_frozen(), "votes from the last incident released a slow-clock freeze"
        assert listener.quorum_progress() == (0, 2)

        bus.publish(_wire(ops[0], action="reset", ts=130.0))
        bus.publish(_wire(ops[1], action="reset", ts=131.0))
        listener.poll()
        assert not listener.is_frozen()


class TestAFreshListenerRebuildsTheSameState:
    @pytest.mark.parametrize("end_frozen", [True, False], ids=["ends-frozen", "ends-released"])
    def test_replaying_the_full_history_matches_the_live_listener(
        self, ops, end_frozen: bool
    ) -> None:
        history = [
            _wire(ops[0], action="trigger", ts=100.0),
            _wire(ops[0], action="reset", ts=110.0),
            _wire(ops[1], action="reset", ts=111.0),
            _wire(ops[2], action="trigger", ts=200.0, reason="incident 2"),
            _wire(ops[0], action="reset", ts=210.0),
            _wire(ops[0], action="reset", ts=211.0, keyid="ops-c"),
        ]
        history.append(history[1])  # a captured vote, replayed onto the stream
        if not end_frozen:
            history.append(_wire(ops[1], action="reset", ts=212.0))

        live_bus = InMemoryTransport()
        live = _listener(live_bus, ops)
        for frame in history:
            live_bus.publish(frame)
            live.poll()

        replay_bus = InMemoryTransport()
        fresh = _listener(replay_bus, ops)
        for frame in history:
            replay_bus.publish(frame)
        fresh.poll()

        assert fresh.is_frozen() is live.is_frozen() is end_frozen
        assert fresh.quorum_progress() == live.quorum_progress()
        assert fresh.last_reason == live.last_reason
