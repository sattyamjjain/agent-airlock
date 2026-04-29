"""Pluggable transport layer for kill-switch broadcasts.

The runtime ships only an in-memory transport plus stubs for NATS /
Redis / S3. Real transports require optional deps the runtime never
forces; users implement the protocol with their preferred client.
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
    """Redis pub/sub transport stub."""

    name = "redis"


class S3TransportStub(_StubTransport):
    """S3 object-poll transport stub."""

    name = "s3"


__all__ = [
    "BroadcastTransport",
    "InMemoryTransport",
    "NATSTransportStub",
    "RedisTransportStub",
    "S3TransportStub",
]
