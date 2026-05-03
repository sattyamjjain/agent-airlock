"""Tests for v0.7.0 RedisRateLimit (#1)."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    pass

# Optional dep — skip the whole module if the extra isn't installed.
fakeredis = pytest.importorskip("fakeredis")

from agent_airlock.redis_rate_limit import (  # noqa: E402
    RedisRateLimit,
    RedisRateLimitUnavailable,
)


def _client() -> fakeredis.FakeRedis:
    """Build a fresh fakeredis client with decoded responses."""
    return fakeredis.FakeRedis(decode_responses=True)


class TestRedisRateLimit:
    """Distributed-bucket regression coverage."""

    def test_acquire_under_limit_succeeds(self) -> None:
        rl = RedisRateLimit.parse("5/second", key_prefix="t:basic", client=_client())
        for _ in range(5):
            assert rl.acquire() is True

    def test_acquire_over_limit_returns_false(self) -> None:
        rl = RedisRateLimit.parse("3/second", key_prefix="t:over", client=_client())
        assert rl.acquire() is True
        assert rl.acquire() is True
        assert rl.acquire() is True
        assert rl.acquire() is False

    def test_two_instances_share_one_bucket(self) -> None:
        """Distributed semantics — two instances on the same key drain together."""
        client = _client()
        a = RedisRateLimit.parse("3/second", key_prefix="t:shared", client=client)
        b = RedisRateLimit.parse("3/second", key_prefix="t:shared", client=client)
        assert a.acquire() is True
        assert a.acquire() is True
        assert b.acquire() is True
        # Bucket drained — both instances see the same denial.
        assert a.acquire() is False
        assert b.acquire() is False

    def test_independent_keys_independent_buckets(self) -> None:
        """Keys with different prefixes do not share state."""
        client = _client()
        a = RedisRateLimit.parse("1/second", key_prefix="t:keyA", client=client)
        b = RedisRateLimit.parse("1/second", key_prefix="t:keyB", client=client)
        assert a.acquire() is True
        assert a.acquire() is False
        # Different prefix — fresh bucket.
        assert b.acquire() is True

    def test_refill_after_period(self) -> None:
        """After the refill period elapses, the bucket replenishes."""
        rl = RedisRateLimit.parse("2/second", key_prefix="t:refill", client=_client())
        assert rl.acquire() is True
        assert rl.acquire() is True
        assert rl.acquire() is False
        time.sleep(1.1)
        # After ~1s with 2/second, the bucket should have refilled.
        assert rl.acquire() is True

    def test_remaining_reflects_state(self) -> None:
        rl = RedisRateLimit.parse("10/second", key_prefix="t:remaining", client=_client())
        # Remaining is fetched from Redis lazily; before any acquire it
        # reports max_tokens (no key yet → "no record" → max_tokens).
        assert rl.remaining() == 10
        rl.acquire(3)
        assert rl.remaining() == 7

    def test_fallback_to_memory_when_no_client_and_redis_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No client + no redis package + fail_mode='memory' → in-memory parent."""
        import sys

        monkeypatch.setitem(sys.modules, "redis", None)
        rl = RedisRateLimit(
            max_tokens=2,
            refill_period_seconds=1.0,
            fail_mode="memory",
        )
        assert rl.is_distributed is False
        assert rl.acquire() is True
        assert rl.acquire() is True
        assert rl.acquire() is False  # in-memory parent enforces

    def test_fail_closed_when_no_redis_and_closed_mode(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import sys

        monkeypatch.setitem(sys.modules, "redis", None)
        with pytest.raises(RedisRateLimitUnavailable):
            RedisRateLimit(
                max_tokens=2,
                refill_period_seconds=1.0,
                fail_mode="closed",
            )

    def test_invalid_fail_mode_rejected(self) -> None:
        with pytest.raises(ValueError, match="fail_mode"):
            RedisRateLimit(
                max_tokens=1,
                refill_period_seconds=1.0,
                fail_mode="bogus",
                client=_client(),
            )

    def test_runtime_fallback_when_redis_dies_mid_flight(self) -> None:
        """A live client that starts erroring should not raise on memory mode."""

        class _DeadClient:
            def script_load(self, _: str) -> str:
                return "sha-x"

            def evalsha(self, *args: object, **kw: object) -> None:
                raise RuntimeError("redis went away")

            def eval(self, *args: object, **kw: object) -> None:
                raise RuntimeError("redis went away")

            def hget(self, *args: object, **kw: object) -> None:
                raise RuntimeError("redis went away")

            def ping(self) -> bool:
                return True

        rl = RedisRateLimit(
            max_tokens=5,
            refill_period_seconds=1.0,
            fail_mode="memory",
            client=_DeadClient(),
        )
        # First call: redis errors → fallback path; we lose the
        # distributed bucket but the in-memory parent still allows the call.
        assert rl.acquire() is True
        # Subsequent calls run through the in-memory parent directly.
        assert rl.is_distributed is False

    def test_runtime_fail_closed_raises_on_redis_error(self) -> None:
        class _DeadClient:
            def script_load(self, _: str) -> str:
                return "sha-y"

            def evalsha(self, *a: object, **kw: object) -> None:
                raise RuntimeError("boom")

            def eval(self, *a: object, **kw: object) -> None:
                raise RuntimeError("boom")

            def ping(self) -> bool:
                return True

        rl = RedisRateLimit(
            max_tokens=5,
            refill_period_seconds=1.0,
            fail_mode="closed",
            client=_DeadClient(),
        )
        with pytest.raises(RedisRateLimitUnavailable):
            rl.acquire()

    def test_parse_factory_returns_configured_instance(self) -> None:
        rl = RedisRateLimit.parse(
            "100/hour",
            key_prefix="t:parse",
            client=_client(),
        )
        assert rl.max_tokens == 100
        assert rl.refill_period_seconds == 3600.0
        assert rl.key_prefix == "t:parse"
