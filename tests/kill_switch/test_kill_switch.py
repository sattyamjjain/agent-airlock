"""Tests for airlock kill-switch (signer + transport + broadcast + listener)."""

from __future__ import annotations

import secrets

import pytest

from agent_airlock.kill_switch import (
    HMACBroadcastSigner,
    InMemoryTransport,
    InvalidBroadcastSignature,
    KillSwitchBroadcast,
    KillSwitchListener,
    KillSwitchState,
    NATSTransportStub,
    QuorumError,
    RedisTransportStub,
    ResetQuorum,
    S3TransportStub,
)


def _key() -> bytes:
    return secrets.token_bytes(32)


class TestSigner:
    def test_short_key_rejected(self) -> None:
        with pytest.raises(InvalidBroadcastSignature):
            HMACBroadcastSigner(keyid="x", key=b"short")

    def test_round_trip(self) -> None:
        signer = HMACBroadcastSigner(keyid="x", key=_key())
        sig = signer.sign(b"hello")
        assert signer.verify(b"hello", sig) is True

    def test_tampered_payload_fails(self) -> None:
        signer = HMACBroadcastSigner(keyid="x", key=_key())
        sig = signer.sign(b"hello")
        assert signer.verify(b"goodbye", sig) is False


class TestQuorum:
    def test_threshold_must_not_exceed_total(self) -> None:
        with pytest.raises(QuorumError):
            ResetQuorum(threshold=4, total=3)

    def test_two_of_three_reaches_threshold(self) -> None:
        q = ResetQuorum(threshold=2, total=3)
        assert q.submit("k1") is False
        assert q.submit("k2") is True
        assert q.satisfied is True

    def test_duplicate_keyid_doesnt_double_count(self) -> None:
        q = ResetQuorum(threshold=2, total=3)
        q.submit("k1")
        assert q.submit("k1") is False  # same key, no progress
        assert q.submit("k2") is True


class TestTriggerListener:
    def test_unsigned_message_ignored(self) -> None:
        signer = HMACBroadcastSigner(keyid="op-1", key=_key())
        transport = InMemoryTransport()
        # Listener has no signer -> always rejects.
        listener = KillSwitchListener(signers=(), transport=transport)
        broadcaster = KillSwitchBroadcast(signer=signer, transport=transport)
        broadcaster.trigger(reason="test")
        assert listener.poll() == 0  # signature rejected
        assert listener.is_frozen() is False

    def test_trigger_freezes_listener(self) -> None:
        key = _key()
        signer = HMACBroadcastSigner(keyid="op-1", key=key)
        listener_signer = HMACBroadcastSigner(keyid="op-1", key=key)
        transport = InMemoryTransport()
        listener = KillSwitchListener(
            signers=(listener_signer,), transport=transport
        )
        broadcaster = KillSwitchBroadcast(signer=signer, transport=transport)

        broadcaster.trigger(reason="rogue spend detected")
        assert listener.poll() == 1
        assert listener.state == KillSwitchState.TRIGGERED
        assert listener.is_frozen() is True
        assert "rogue spend detected" in listener.last_reason

    def test_tampered_envelope_rejected(self) -> None:
        key = _key()
        signer = HMACBroadcastSigner(keyid="op-1", key=key)
        transport = InMemoryTransport()
        listener = KillSwitchListener(
            signers=(HMACBroadcastSigner(keyid="op-1", key=key),),
            transport=transport,
        )
        broadcaster = KillSwitchBroadcast(signer=signer, transport=transport)
        broadcaster.trigger(reason="test")
        # Mutate the queued message.
        original = transport._queue.pop()  # type: ignore[attr-defined]
        tampered = original.replace(b"\"reason\":\"test\"", b"\"reason\":\"FAKE\"")
        transport._queue.append(tampered)  # type: ignore[attr-defined]
        assert listener.poll() == 0
        assert listener.is_frozen() is False


class TestQuorumReset:
    def test_one_signer_does_not_reset(self) -> None:
        keys = [_key() for _ in range(3)]
        signers = [
            HMACBroadcastSigner(keyid=f"op-{i}", key=k)
            for i, k in enumerate(keys, 1)
        ]
        transport = InMemoryTransport()
        listener = KillSwitchListener(
            signers=tuple(signers),
            transport=transport,
            reset_quorum_threshold=2,
            reset_quorum_total=3,
        )
        # Trigger first.
        KillSwitchBroadcast(signer=signers[0], transport=transport).trigger(
            "first"
        )
        listener.poll()
        # Single reset attempt — must not unfreeze.
        KillSwitchBroadcast(signer=signers[0], transport=transport).reset("op-1")
        assert listener.poll() == 1
        assert listener.is_frozen() is True
        assert listener.quorum_progress() == (1, 2)

    def test_two_of_three_resets(self) -> None:
        keys = [_key() for _ in range(3)]
        signers = [
            HMACBroadcastSigner(keyid=f"op-{i}", key=k)
            for i, k in enumerate(keys, 1)
        ]
        transport = InMemoryTransport()
        listener = KillSwitchListener(
            signers=tuple(signers),
            transport=transport,
            reset_quorum_threshold=2,
            reset_quorum_total=3,
        )
        KillSwitchBroadcast(signer=signers[0], transport=transport).trigger("t")
        listener.poll()
        KillSwitchBroadcast(signer=signers[0], transport=transport).reset("op-1")
        KillSwitchBroadcast(signer=signers[1], transport=transport).reset("op-2")
        listener.poll()
        assert listener.is_frozen() is False
        assert listener.state == KillSwitchState.DISARMED


class TestTransportStubs:
    def test_stub_round_trip(self) -> None:
        for cls in (NATSTransportStub, RedisTransportStub, S3TransportStub):
            t = cls()
            t.publish(b"x")
            assert list(t.consume()) == [b"x"]
