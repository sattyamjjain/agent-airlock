"""Pluggable transport layer for kill-switch broadcasts.

The core ships :class:`InMemoryTransport` (process-local) and, under the ``[redis]``
extra, :class:`RedisStreamTransport` — a real durable cross-process transport. NATS and
S3 remain stubs.

**The stubs do not leave the process.** ``NATSTransportStub``, ``RedisTransportStub`` and
``S3TransportStub`` all delegate to an in-process queue, which is why the kill switch
could not freeze a fleet before v0.8.86. ``RedisTransportStub`` is now a deprecated alias
kept for import compatibility; use :class:`RedisStreamTransport`.
"""

from __future__ import annotations

import threading
from collections import deque
from collections.abc import Iterable
from typing import Protocol


class BroadcastTransport(Protocol):
    """Minimum surface for a kill-switch broadcast transport."""

    def publish(self, message: bytes) -> None: ...

    def consume(self) -> Iterable[bytes]: ...


class InMemoryTransport:
    """Process-local pub-sub useful for tests and single-host setups."""

    def __init__(self) -> None:
        self._queue: deque[bytes] = deque()
        self._lock = threading.Lock()

    def publish(self, message: bytes) -> None:
        with self._lock:
            self._queue.append(message)

    def consume(self) -> Iterable[bytes]:
        with self._lock:
            messages = list(self._queue)
            self._queue.clear()
        return messages


class _StubTransport:
    """Base for transport stubs that ship without a runtime dep."""

    name: str = "stub"

    def __init__(self) -> None:
        self._fallback = InMemoryTransport()

    def publish(self, message: bytes) -> None:
        self._fallback.publish(message)

    def consume(self) -> Iterable[bytes]:
        return self._fallback.consume()


class NATSTransportStub(_StubTransport):
    """NATS transport stub. Replace ``publish`` / ``consume`` with a NATS client."""

    name = "nats"


class RedisTransportStub(_StubTransport):
    """Deprecated: does NOT leave the process. Use :class:`RedisStreamTransport`.

    Kept so existing imports do not break. It delegates to an in-process queue, so a
    fleet wired to it is not actually connected.
    """

    name = "redis"


class S3TransportStub(_StubTransport):
    """S3 object-poll transport stub."""

    name = "s3"


def __getattr__(name: str) -> object:
    """Lazily expose the optional Redis transport without importing redis at load."""
    if name == "RedisStreamTransport":
        from .redis_stream import RedisStreamTransport

        return RedisStreamTransport
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "BroadcastTransport",
    "InMemoryTransport",
    "RedisStreamTransport",
    "NATSTransportStub",
    "RedisTransportStub",
    "S3TransportStub",
]
