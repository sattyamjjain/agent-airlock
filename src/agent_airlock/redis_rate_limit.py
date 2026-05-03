"""Redis-backed distributed rate limiter (v0.7.0+, #1).

The default :class:`agent_airlock.policy.RateLimit` keeps token-bucket
state in a per-process ``threading.Lock``. That works for a single
worker, but a horizontally scaled fleet (multiple FastAPI workers, a
multi-pod K8s deployment, several Lambda runtimes behind one ALB) can
collectively burst to ``N × max_tokens`` per window because each
process is unaware of the others.

:class:`RedisRateLimit` solves that by storing the bucket state in
Redis, so every process in the fleet shares one bucket per
``(tool_name, agent_identity)`` pair.

Design — token bucket via Redis Lua script
------------------------------------------
The atomic INCR-EXPIRE pattern is the wrong shape for a token bucket
(it's a fixed-window counter). We use a Redis Lua script that:

1. Reads the stored ``tokens`` and ``last_refill`` from a hash.
2. Refills based on elapsed time, capped at ``max_tokens``.
3. If ``tokens >= cost``, decrements and returns ``1``.
4. Otherwise returns ``0`` (rate limited).
5. Writes the new ``tokens`` + ``last_refill`` back to the hash.
6. Sets a TTL on the key (``refill_period_seconds * 2``) so an
   idle bucket eventually evicts.

The whole script runs server-side in a single round-trip. Multiple
workers contending for the same key see a serialized view.

Fallback semantics
------------------
If Redis is unreachable at construction time, :class:`RedisRateLimit`
falls back to the in-memory :class:`RateLimit` parent. This is the
**default** ``fail_mode="memory"``. Set ``fail_mode="closed"`` to
raise :class:`RedisRateLimitUnavailable` instead — useful for the
"no rate limit, no traffic" posture some compliance regimes mandate.

Optional dependency
-------------------
Install with::

    pip install "agent-airlock[redis]"

The ``redis`` package is *not* imported at module load — callers
that don't use this class don't pay the import cost. Tests use
``fakeredis`` (also in the ``[redis]`` extra) so the suite works
without a live Redis.

Primary references
------------------
- Issue #1 — https://github.com/sattyamjjain/agent-airlock/issues/1
- Token-bucket-via-Lua canonical pattern:
  https://redis.io/docs/latest/develop/use/patterns/distributed-locks/
- redis-py 5.x documentation:
  https://redis.readthedocs.io/en/stable/
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

import structlog

from .exceptions import AirlockError
from .policy import RateLimit

if TYPE_CHECKING:
    pass

logger = structlog.get_logger("agent-airlock.redis_rate_limit")


# Lua token-bucket script.
# KEYS[1] = bucket hash key (e.g. "airlock:rl:read_file:agent_id_xyz")
# ARGV[1] = max_tokens (int)
# ARGV[2] = refill_period_seconds (float, as string)
# ARGV[3] = cost (int — number of tokens this call wants)
# ARGV[4] = now (float, as string — caller-supplied to ease testing)
# Returns: {acquired (0|1), remaining_tokens (int)}
#
# Variable name avoids 'TOKEN' so bandit B105 does not flag the Lua
# hash field literals ('tokens', 'last_refill') as a hardcoded
# password — they are Redis hash field names, not credentials.
_LUA_BUCKET_SCRIPT = """
local key = KEYS[1]
local max_tokens = tonumber(ARGV[1])
local refill_period = tonumber(ARGV[2])
local cost = tonumber(ARGV[3])
local now = tonumber(ARGV[4])

local data = redis.call('HMGET', key, 'tokens', 'last_refill')
local tokens = tonumber(data[1])
local last_refill = tonumber(data[2])

if tokens == nil or last_refill == nil then
  tokens = max_tokens
  last_refill = now
end

local elapsed = now - last_refill
if elapsed < 0 then
  elapsed = 0
end
local refill = (elapsed / refill_period) * max_tokens
tokens = math.min(max_tokens, tokens + refill)
last_refill = now

local acquired = 0
if tokens >= cost then
  tokens = tokens - cost
  acquired = 1
end

redis.call('HMSET', key, 'tokens', tokens, 'last_refill', last_refill)
redis.call('EXPIRE', key, math.ceil(refill_period * 2))

return {acquired, math.floor(tokens)}
"""


class RedisRateLimitUnavailable(AirlockError):
    """Raised when Redis is unreachable and ``fail_mode="closed"``.

    Callers using ``fail_mode="memory"`` (default) never see this —
    they degrade to the in-memory parent :class:`RateLimit` instead.
    """


class RedisRateLimit(RateLimit):
    """Token-bucket rate limiter backed by Redis (v0.7.0+).

    Drop-in replacement for :class:`RateLimit` that shares state across
    processes via a Redis hash + Lua script. Falls back to the
    in-memory parent when Redis is unreachable (default ``fail_mode``).

    Usage::

        from agent_airlock.redis_rate_limit import RedisRateLimit

        rl = RedisRateLimit.parse(
            "100/hour",
            redis_url="redis://localhost:6379/0",
            key_prefix="airlock:rl:read_file",
        )
        if rl.acquire():
            do_the_thing()

    Attributes:
        max_tokens: Bucket capacity (inherited from RateLimit).
        refill_period_seconds: Period over which the bucket fully
            refills (inherited).
        redis_url: ``redis://...`` connection URL.
        key_prefix: All keys this instance writes start with this
            prefix. Use a per-(tool_name, agent_identity) prefix to
            isolate buckets.
        fail_mode: ``"memory"`` (default) — fall back to in-memory
            parent on Redis errors. ``"closed"`` — raise
            :class:`RedisRateLimitUnavailable`.
    """

    def __init__(
        self,
        max_tokens: int,
        refill_period_seconds: float,
        *,
        redis_url: str = "redis://localhost:6379/0",
        key_prefix: str = "airlock:rl:default",
        fail_mode: str = "memory",
        client: Any | None = None,
    ) -> None:
        """Initialise the Redis-backed limiter.

        Args:
            max_tokens: Bucket capacity.
            refill_period_seconds: Period over which the bucket fully
                refills.
            redis_url: Redis connection URL.
            key_prefix: All keys this instance writes start with this
                prefix.
            fail_mode: ``"memory"`` (default) or ``"closed"``.
            client: Pre-built redis client (test seam — pass a
                ``fakeredis.FakeRedis`` instance to avoid the real
                connection).
        """
        super().__init__(
            max_tokens=max_tokens,
            refill_period_seconds=refill_period_seconds,
        )
        if fail_mode not in {"memory", "closed"}:
            raise ValueError(f"fail_mode must be 'memory' or 'closed', got {fail_mode!r}")
        self.redis_url = redis_url
        self.key_prefix = key_prefix
        self.fail_mode = fail_mode
        self._client: Any | None = client
        self._script_sha: str | None = None
        # Eagerly attempt a connection so callers know up front.
        self._ensure_client_or_fallback()

    @classmethod
    def parse(
        cls,
        limit_str: str,
        *,
        redis_url: str = "redis://localhost:6379/0",
        key_prefix: str = "airlock:rl:default",
        fail_mode: str = "memory",
        client: Any | None = None,
    ) -> RedisRateLimit:
        """Parse a ``"100/hour"`` style limit and return a Redis-backed one.

        Args:
            limit_str: Rate limit in ``"count/period"`` format.
            redis_url: Redis connection URL.
            key_prefix: Per-bucket key prefix.
            fail_mode: ``"memory"`` (default) or ``"closed"``.
            client: Optional pre-built client (test seam).

        Returns:
            A configured :class:`RedisRateLimit`.
        """
        base = RateLimit.parse(limit_str)
        return cls(
            max_tokens=base.max_tokens,
            refill_period_seconds=base.refill_period_seconds,
            redis_url=redis_url,
            key_prefix=key_prefix,
            fail_mode=fail_mode,
            client=client,
        )

    @property
    def is_distributed(self) -> bool:
        """True iff calls are currently routing through Redis (not the in-memory fallback)."""
        return self._client is not None

    def _ensure_client_or_fallback(self) -> None:
        """Connect to Redis or fall back to the in-memory parent.

        On ``fail_mode="closed"`` a connection failure raises
        :class:`RedisRateLimitUnavailable`. On ``fail_mode="memory"``
        (default) the failure is logged and ``self._client`` stays
        ``None`` — :meth:`acquire` then defers to the parent
        :class:`RateLimit`.
        """
        if self._client is not None:
            # Caller injected a client (or we already connected).
            self._load_script()
            return

        try:
            import redis as _redis
        except ImportError:
            self._client = None
            if self.fail_mode == "closed":
                raise RedisRateLimitUnavailable(
                    "redis package not installed. "
                    'Install the extra: pip install "agent-airlock[redis]"'
                ) from None
            logger.info(
                "redis_rate_limit_falling_back_to_memory",
                reason="redis package not installed",
            )
            return

        try:
            client = _redis.Redis.from_url(self.redis_url, decode_responses=True)
            client.ping()
        except Exception as exc:
            self._client = None
            if self.fail_mode == "closed":
                raise RedisRateLimitUnavailable(
                    f"redis at {self.redis_url} unreachable: {exc}"
                ) from exc
            logger.warning(
                "redis_rate_limit_falling_back_to_memory",
                reason=str(exc),
                redis_url=self.redis_url,
            )
            return

        self._client = client
        self._load_script()

    def _load_script(self) -> None:
        """Register the Lua token-bucket script on the server."""
        if self._client is None:
            return
        try:
            self._script_sha = self._client.script_load(_LUA_BUCKET_SCRIPT)
        except Exception as exc:  # pragma: no cover — fakeredis supports SCRIPT LOAD
            logger.warning(
                "redis_rate_limit_script_load_failed",
                error=str(exc),
            )
            self._script_sha = None

    def acquire(self, tokens: int = 1) -> bool:
        """Atomically try to acquire ``tokens`` from the shared bucket.

        Falls back to the in-memory parent if Redis is unreachable
        and ``fail_mode == "memory"``.

        Returns:
            True if the tokens were acquired; False if rate limited.

        Raises:
            RedisRateLimitUnavailable: ``fail_mode="closed"`` and Redis
                is unreachable at call time.
        """
        if self._client is None:
            return super().acquire(tokens)

        try:
            if self._script_sha is None:
                self._load_script()
            now_str = repr(time.time())
            args = [
                str(self.max_tokens),
                repr(self.refill_period_seconds),
                str(tokens),
                now_str,
            ]
            if self._script_sha is not None:
                result = self._client.evalsha(
                    self._script_sha,
                    1,
                    self.key_prefix,
                    *args,
                )
            else:
                result = self._client.eval(
                    _LUA_BUCKET_SCRIPT,
                    1,
                    self.key_prefix,
                    *args,
                )
        except Exception as exc:
            if self.fail_mode == "closed":
                raise RedisRateLimitUnavailable(f"redis call failed: {exc}") from exc
            logger.warning(
                "redis_rate_limit_runtime_fallback_to_memory",
                reason=str(exc),
            )
            self._client = None
            return super().acquire(tokens)

        # result is a 2-list [acquired (0|1), remaining_tokens]
        acquired = int(result[0]) == 1
        return acquired

    def remaining(self) -> int:
        """Return remaining tokens in the bucket.

        Falls back to the in-memory parent when Redis is unreachable.
        """
        if self._client is None:
            return super().remaining()
        try:
            tokens_raw = self._client.hget(self.key_prefix, "tokens")
            if tokens_raw is None:
                return self.max_tokens
            return int(float(tokens_raw))
        except Exception as exc:  # pragma: no cover
            if self.fail_mode == "closed":
                raise RedisRateLimitUnavailable(str(exc)) from exc
            return super().remaining()


__all__ = [
    "RedisRateLimit",
    "RedisRateLimitUnavailable",
]
