"""Triggering the kill switch must actually stop a decorated tool.

Through v0.8.85 it did not. ``KillSwitchListener`` was never constructed inside the
library — the only references outside ``kill_switch/`` were the CLI and the CLI dispatcher
table — so the HMAC signing, the envelope, the state machine and the quorum were all
correct and all inert. The README called it a "cluster-wide freeze"; nothing in the
``@Airlock`` call path asked whether the fleet was frozen.

These tests hold the seam open. The first one is the whole feature: trigger, then call a
decorated function, and get refused.
"""

from __future__ import annotations

from typing import Any

import pytest

from agent_airlock import Airlock
from agent_airlock.kill_switch import (
    HMACBroadcastSigner,
    InMemoryTransport,
    KillSwitchBroadcast,
    KillSwitchListener,
    KillSwitchState,
    registry,
)

KEY_A = b"a" * 32
KEY_B = b"b" * 32


@pytest.fixture(autouse=True)
def _no_leaked_switch() -> Any:
    """The registry is process-global; a leaked listener would freeze unrelated tests."""
    registry.clear()
    yield
    registry.clear()


@pytest.fixture
def bus() -> InMemoryTransport:
    return InMemoryTransport()


@pytest.fixture
def signers() -> tuple[HMACBroadcastSigner, HMACBroadcastSigner]:
    return (
        HMACBroadcastSigner(keyid="ops-a", key=KEY_A),
        HMACBroadcastSigner(keyid="ops-b", key=KEY_B),
    )


def _install(bus: InMemoryTransport, signers: tuple[HMACBroadcastSigner, ...], **kw: Any):
    listener = KillSwitchListener(signers=signers, transport=bus, poll_interval_seconds=0, **kw)
    registry.install(listener)
    return listener


@Airlock()
def deploy(target: str) -> str:
    return f"deployed to {target}"


def _blocked(result: Any) -> bool:
    return isinstance(result, dict) and result.get("status") == "blocked"


class TestTheSwitchActuallyStopsCalls:
    """The regression that matters. If these pass while the wiring is gone, they are fake."""

    def test_a_triggered_switch_blocks_a_decorated_tool(self, bus, signers) -> None:
        _install(bus, signers)
        assert deploy(target="prod") == "deployed to prod"

        KillSwitchBroadcast(signer=signers[0], transport=bus).trigger(reason="incident 412")
        result = deploy(target="prod")
        assert _blocked(result), "the kill switch did not stop the call"
        assert result["block_reason"] == "kill_switch"

    def test_the_operator_reason_reaches_the_caller(self, bus, signers) -> None:
        """An agent that is refused should be able to say why, not just that it was."""
        _install(bus, signers)
        KillSwitchBroadcast(signer=signers[0], transport=bus).trigger(reason="incident 412")
        result = deploy(target="prod")
        assert "incident 412" in result["error"]

    def test_no_switch_installed_is_a_no_op(self, bus, signers) -> None:
        """The switch is opt-in; an unconfigured process must be unaffected."""
        assert registry.get() is None
        assert deploy(target="prod") == "deployed to prod"

    def test_installing_without_triggering_does_not_block(self, bus, signers) -> None:
        _install(bus, signers)
        assert deploy(target="prod") == "deployed to prod"

    def test_clear_releases_the_freeze(self, bus, signers) -> None:
        _install(bus, signers)
        KillSwitchBroadcast(signer=signers[0], transport=bus).trigger(reason="x")
        assert _blocked(deploy(target="prod"))
        registry.clear()
        assert deploy(target="prod") == "deployed to prod"

    def test_it_runs_before_ghost_argument_validation(self, bus, signers) -> None:
        """A freeze means stop, not "stop after checking the arguments"."""
        _install(bus, signers)
        KillSwitchBroadcast(signer=signers[0], transport=bus).trigger(reason="x")
        result = deploy(target="prod", hallucinated="yes")
        assert result["block_reason"] == "kill_switch", (
            "ghost-arg validation ran first; the freeze must be the outermost gate"
        )


class TestQuorumThroughTheCallPath:
    """One key freezes; one key must not unfreeze."""

    def test_a_single_reset_does_not_release_the_freeze(self, bus, signers) -> None:
        _install(bus, signers)
        KillSwitchBroadcast(signer=signers[0], transport=bus).trigger(reason="x")
        KillSwitchBroadcast(signer=signers[0], transport=bus).reset(reason="clear")
        assert _blocked(deploy(target="prod"))

    def test_the_same_key_voting_twice_is_still_one_vote(self, bus, signers) -> None:
        """Otherwise a single compromised key could unilaterally re-enable the fleet."""
        _install(bus, signers)
        KillSwitchBroadcast(signer=signers[0], transport=bus).trigger(reason="x")
        for _ in range(5):
            KillSwitchBroadcast(signer=signers[0], transport=bus).reset(reason="clear")
        assert _blocked(deploy(target="prod"))

    def test_two_distinct_keys_release_it(self, bus, signers) -> None:
        _install(bus, signers)
        KillSwitchBroadcast(signer=signers[0], transport=bus).trigger(reason="x")
        KillSwitchBroadcast(signer=signers[0], transport=bus).reset(reason="clear")
        KillSwitchBroadcast(signer=signers[1], transport=bus).reset(reason="clear")
        assert deploy(target="prod") == "deployed to prod"

    def test_a_forged_trigger_is_ignored(self, bus, signers) -> None:
        """Acceptance is decided by the MAC, not the claimed keyid."""
        _install(bus, signers)
        intruder = HMACBroadcastSigner(keyid="ops-a", key=b"z" * 32)
        KillSwitchBroadcast(signer=intruder, transport=bus).trigger(reason="forged")
        assert deploy(target="prod") == "deployed to prod"


class TestPollingIsBounded:
    """A transport read on every tool call would put the switch on the hot path."""

    def test_installed_listener_moves_to_armed(self, bus, signers) -> None:
        """ARMED was defined and never assigned before v0.8.86."""
        listener = _install(bus, signers)
        assert listener.state is KillSwitchState.ARMED
        assert not listener.is_frozen()

    def test_poll_if_due_skips_inside_the_interval(self, bus, signers) -> None:
        listener = KillSwitchListener(signers=signers, transport=bus, poll_interval_seconds=3600)
        registry.install(listener)
        listener.poll_if_due()  # first call always polls and starts the clock
        KillSwitchBroadcast(signer=signers[0], transport=bus).trigger(reason="x")
        assert listener.poll_if_due() == 0, "polled again inside the interval"
        assert deploy(target="prod") == "deployed to prod"

    def test_a_zero_interval_polls_every_time(self, bus, signers) -> None:
        listener = _install(bus, signers)
        KillSwitchBroadcast(signer=signers[0], transport=bus).trigger(reason="x")
        assert listener.poll_if_due() >= 0
        assert _blocked(deploy(target="prod"))


class TestTransportFailureDoesNotCrashTheCall:
    """A kill switch whose transport hiccups must not take the fleet down with it."""

    class _Exploding(InMemoryTransport):
        def consume(self):  # type: ignore[override]
            raise RuntimeError("redis is down")

    def test_default_keeps_the_last_known_state(self, signers) -> None:
        registry.install(
            KillSwitchListener(
                signers=signers, transport=self._Exploding(), poll_interval_seconds=0
            )
        )
        assert deploy(target="prod") == "deployed to prod"

    def test_strict_mode_freezes_instead(self, signers) -> None:
        """For deployments where a stalled switch is worse than an outage."""
        registry.install(
            KillSwitchListener(
                signers=signers, transport=self._Exploding(), poll_interval_seconds=0
            ),
            strict=True,
        )
        assert _blocked(deploy(target="prod"))


class TestRedisStreamTransportCrossesProcesses:
    """The stub transports never left the process, which is why "cluster-wide" was false."""

    def test_the_stub_is_still_process_local(self) -> None:
        """Documented, not fixed: the deprecated alias must not look like it works."""
        from agent_airlock.kill_switch import RedisTransportStub

        a, b = RedisTransportStub(), RedisTransportStub()
        a.publish(b"hello")
        assert list(b.consume()) == [], "the stub appears to cross processes; it does not"

    def test_a_worker_starting_after_the_trigger_still_freezes(self, signers) -> None:
        """The property Redis pub/sub would not give: durable, replayable state."""
        fakeredis = pytest.importorskip("fakeredis")
        from agent_airlock.kill_switch.transports import RedisStreamTransport

        server = fakeredis.FakeServer()

        def transport() -> RedisStreamTransport:
            return RedisStreamTransport(fakeredis.FakeStrictRedis(server=server))

        KillSwitchBroadcast(signer=signers[0], transport=transport()).trigger(reason="x")
        latecomer = KillSwitchListener(
            signers=signers, transport=transport(), poll_interval_seconds=0
        )
        latecomer.poll()
        assert latecomer.is_frozen(), "a cold-starting worker missed an active freeze"

    def test_each_process_has_its_own_cursor(self, signers) -> None:
        fakeredis = pytest.importorskip("fakeredis")
        from agent_airlock.kill_switch.transports import RedisStreamTransport

        server = fakeredis.FakeServer()
        reader = RedisStreamTransport(fakeredis.FakeStrictRedis(server=server))
        writer = RedisStreamTransport(fakeredis.FakeStrictRedis(server=server))
        writer.publish(b"one")
        assert list(reader.consume()) == [b"one"]
        assert list(reader.consume()) == [], "re-read a message it had already consumed"
