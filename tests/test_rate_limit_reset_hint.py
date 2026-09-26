"""A rate-limit refusal names the real wait (fixed in 0.10.18).

The limiter never reported when a token would be back, so the refusal told the model to
wait a flat 60 seconds whatever the limit: a "1/hour" tool was retried 59 times too early,
and ``on_rate_limit`` received the same 60.
"""

from __future__ import annotations

import pytest

from agent_airlock import Airlock, AirlockConfig, SecurityPolicy
from agent_airlock.policy import RateLimit


def _exhaust(limit: str, config: AirlockConfig | None = None) -> dict:
    @Airlock(policy=SecurityPolicy(rate_limits={"*": limit}), config=config)
    def tool() -> str:
        return "ok"

    for _ in range(int(limit.split("/")[0])):
        assert tool() == "ok"
    refused = tool()
    assert isinstance(refused, dict)
    return refused


class TestTheWaitMatchesTheLimit:
    @pytest.mark.parametrize(
        ("limit", "wait", "hint"),
        [
            ("1/hour", 3600, "Wait 3600 seconds before retrying"),
            ("100/hour", 36, "Wait 36 seconds before retrying"),
            ("10/minute", 6, "Wait 6 seconds before retrying"),
            ("2/second", 1, "Wait 1 second before retrying"),
        ],
    )
    def test_the_hint_and_the_metadata(self, limit: str, wait: int, hint: str) -> None:
        refused = _exhaust(limit)

        assert refused["block_reason"] == "rate_limit"
        # Exact on any machine that makes the calls within a second of each other; the
        # bucket refills while they run, so a slower one reports a slightly shorter wait.
        reported = refused["metadata"]["reset_seconds"]
        assert wait - 5 <= reported <= wait
        if reported == wait:
            assert refused["fix_hints"] == [f"Rate limit is {limit}", hint]

    def test_on_rate_limit_gets_the_same_wait(self) -> None:
        seen: list[tuple[str, int]] = []
        config = AirlockConfig(on_rate_limit=lambda name, wait: seen.append((name, wait)))

        refused = _exhaust("1/hour", config)

        assert seen == [("tool", refused["metadata"]["reset_seconds"])]
        assert 3595 <= seen[0][1] <= 3600


class TestSecondsUntilAvailable:
    def test_a_full_bucket_is_available_now(self) -> None:
        assert RateLimit.parse("5/minute").seconds_until_available() == 0

    def test_an_empty_bucket_waits_one_tokens_refill(self) -> None:
        limit = RateLimit.parse("4/minute")
        for _ in range(4):
            assert limit.acquire()

        assert limit.seconds_until_available() == 15

    def test_a_zero_capacity_bucket_reports_its_period(self) -> None:
        assert RateLimit.parse("0/minute").seconds_until_available() == 60

    def test_the_redis_bucket_reads_its_shared_count(self) -> None:
        fakeredis = pytest.importorskip("fakeredis")
        from agent_airlock.redis_rate_limit import RedisRateLimit

        limit = RedisRateLimit.parse(
            "1/hour",
            key_prefix="airlock:rl:test-wait",
            client=fakeredis.FakeRedis(decode_responses=True),
        )
        assert limit.acquire()
        assert not limit.acquire()

        assert limit.seconds_until_available() == 3600
