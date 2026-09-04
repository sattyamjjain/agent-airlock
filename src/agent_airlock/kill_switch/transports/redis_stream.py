"""Redis Streams transport for kill-switch broadcasts (v0.8.86+).

Why a stream and not pub/sub
----------------------------
Redis pub/sub is fire-and-forget: a worker that starts *after* the trigger never sees it,
so a fleet mid-rollout would come back up unfrozen while the incident is still open. That
is the exact failure a kill switch exists to prevent.

A stream is durable and ordered, so a process joining late replays from ``0-0``, sees the
trigger, and freezes itself. Replay is safe because the listener's state machine is
idempotent: ``trigger`` sets ``TRIGGERED`` however many times it is seen, and ``reset``
submits a *keyid* into a set, so re-reading one operator's vote never advances the quorum
on its own.

Through v0.8.85 this package shipped ``RedisTransportStub``, which subclassed a stub base
that delegated to an in-process queue — so "cluster-wide freeze" travelled exactly as far
as one process. That name is kept as a deprecated alias; this is the real one.

Optional dependency
-------------------
Install with ``pip install "agent-airlock[redis]"``. The core stays Pydantic-only: this
module is imported lazily and importing it without ``redis`` raises a message that says
what to install.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

from ..._log import structlog

if TYPE_CHECKING:  # pragma: no cover
    pass

logger = structlog.get_logger("agent-airlock.kill_switch.redis")

#: Default stream key. One stream per fleet; separate fleets need separate keys.
DEFAULT_STREAM_KEY = "airlock:killswitch"

#: Approximate cap on retained broadcasts. A kill switch is low-volume, and the listener
#: only needs enough history for a cold-starting worker to learn the current state.
DEFAULT_MAXLEN = 1000


class RedisStreamTransport:
    """Durable cross-process transport backed by a Redis stream.

    Each process keeps its own cursor, so ``consume()`` returns only what it has not seen.
    A freshly constructed transport starts at ``0-0`` and therefore replays the whole
    retained history on its first poll — which is how a new worker discovers an active
    freeze.

    Args:
        client: A ``redis.Redis`` instance. Passing one explicitly (rather than a URL)
            keeps connection-pool ownership with the caller and makes ``fakeredis`` usable
            in tests without a live server.
        stream_key: Stream to publish to and read from.
        maxlen: Approximate retention, applied via ``XADD ... MAXLEN ~``.
        replay_history: When False the cursor starts at "now" and existing broadcasts are
            skipped. Leave it True unless you specifically want a worker to ignore an
            in-flight freeze.
    """

    name = "redis-stream"

    def __init__(
        self,
        client: Any,
        *,
        stream_key: str = DEFAULT_STREAM_KEY,
        maxlen: int = DEFAULT_MAXLEN,
        replay_history: bool = True,
    ) -> None:
        self._client = client
        self._key = stream_key
        self._maxlen = maxlen
        self._cursor: str = "0-0"
        if not replay_history:
            self._cursor = self._latest_id()

    @classmethod
    def from_url(cls, url: str, **kwargs: Any) -> RedisStreamTransport:
        """Build a transport from a Redis URL.

        Raises:
            RuntimeError: If the ``redis`` package is not installed.
        """
        try:
            import redis  # noqa: PLC0415
        except ImportError as exc:  # pragma: no cover - exercised by the bare-install job
            raise RuntimeError(
                'RedisStreamTransport needs the redis package: pip install "agent-airlock[redis]"'
            ) from exc
        return cls(redis.Redis.from_url(url), **kwargs)

    def _latest_id(self) -> str:
        entries = self._client.xrevrange(self._key, count=1)
        if not entries:
            return "0-0"
        raw = entries[0][0]
        return raw.decode() if isinstance(raw, bytes) else str(raw)

    def publish(self, message: bytes) -> None:
        """Append one signed broadcast to the stream."""
        self._client.xadd(self._key, {"m": message}, maxlen=self._maxlen, approximate=True)

    def consume(self) -> Iterable[bytes]:
        """Return broadcasts appended since this process last read, advancing the cursor."""
        entries = self._client.xrange(self._key, min=f"({self._cursor}", max="+")
        out: list[bytes] = []
        for entry_id, fields in entries:
            self._cursor = entry_id.decode() if isinstance(entry_id, bytes) else str(entry_id)
            payload = fields.get(b"m") or fields.get("m")
            if payload is None:
                continue
            out.append(payload if isinstance(payload, bytes) else str(payload).encode("utf-8"))
        return out


__all__ = ["DEFAULT_MAXLEN", "DEFAULT_STREAM_KEY", "RedisStreamTransport"]
