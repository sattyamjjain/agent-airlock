"""Regression tests for three bug claims in the April 2026 deep analysis.

Two of the three are real bugs that this PR fixes; the third is documented
as UNVERIFIED and asserted to match the current (correct) behaviour so a
future regression would still trip the suite.

Tracked in `docs/research-log.md#2026-04-18-—-deep-analysis-bug-triage`.
"""

from __future__ import annotations

import functools
from collections.abc import Generator
from typing import Any

from agent_airlock.capabilities import Capability, get_required_capabilities, requires
from agent_airlock.config import AirlockConfig
from agent_airlock.core import _filter_sensitive_keys
from agent_airlock.streaming import StreamingAirlock

# =============================================================================
# Bug 1: sensitive-param filter misses custom names — REAL BUG
# =============================================================================


class TestSensitiveParamFilterCustomNames:
    """`_filter_sensitive_keys` must catch compound names like `my_api_key`.

    Previously the filter did an exact lookup in a hard-coded frozenset, so
    `my_api_key`, `user_password`, `db_token`, `aws_secret_key`, and
    `session_cookie` all leaked to debug logs. The fix scans for any
    registered sensitive substring.
    """

    def test_exact_match_still_filters(self) -> None:
        """The original behaviour — exact matches — is preserved."""
        assert _filter_sensitive_keys(["password", "normal"]) == ["normal"]

    def test_filters_custom_prefix_name(self) -> None:
        """`user_password` — `password` appears as a substring."""
        assert "user_password" not in _filter_sensitive_keys(["user_password", "normal"])

    def test_filters_custom_suffix_name(self) -> None:
        """`my_api_key` — `api_key` appears as a substring."""
        assert "my_api_key" not in _filter_sensitive_keys(["my_api_key", "normal"])

    def test_filters_aws_secret_key(self) -> None:
        assert "aws_secret_key" not in _filter_sensitive_keys(["aws_secret_key", "normal"])

    def test_filters_session_cookie(self) -> None:
        assert "session_cookie" not in _filter_sensitive_keys(["session_cookie", "normal"])

    def test_filters_case_insensitive_custom(self) -> None:
        """Uppercase variant of a compound name is also filtered."""
        assert "MyApiKey" not in _filter_sensitive_keys(["MyApiKey", "normal"])

    def test_non_sensitive_passthrough(self) -> None:
        """Names without any sensitive substring stay in the list."""
        passthrough = ["path", "url", "query", "limit", "offset"]
        assert _filter_sensitive_keys(passthrough) == passthrough


# =============================================================================
# Bug 2: streaming sanitizer double-counts tokens on re-entry — UNVERIFIED
# =============================================================================
#
# The claim in the deep-analysis brief was "streaming sanitizer double-counts
# tokens on re-entry." I could not reproduce a double-count by any path I
# traced through `StreamingAirlock`:
#
# - `wrap_generator` calls `self.reset()` before iterating, clearing state.
# - `create_streaming_wrapper` constructs ONE `StreamingAirlock` per decorated
#   function but every call to the wrapper goes through `wrap_generator`,
#   which resets.
# - `_sanitize_chunk` increments `sanitized_count` once per chunk; no
#   internal path re-invokes it on the same chunk.
#
# The regression below asserts the CURRENT (correct) behaviour so that a
# future change that accidentally introduces a double-count trips the
# suite. Flagged UNVERIFIED in docs/research-log.md.


class TestStreamingSanitizerNoDoubleCount:
    """Re-entry does not double-count sanitization detections."""

    def _make_streamer(self) -> StreamingAirlock:
        return StreamingAirlock(
            AirlockConfig(sanitize_output=True, mask_pii=True),
            tool_name="t",
        )

    def test_single_stream_with_pii(self) -> None:
        """One stream containing 2 emails → sanitized_count == 2."""
        streamer = self._make_streamer()

        def gen() -> Generator[str, None, None]:
            yield "chunk one has foo@example.com"
            yield "chunk two has bar@example.com"

        list(streamer.wrap_generator(gen()))
        assert streamer.state.sanitized_count == 2

    def test_reuse_streamer_instance(self) -> None:
        """Second wrap_generator call resets — counts do not accumulate."""
        streamer = self._make_streamer()

        def gen_a() -> Generator[str, None, None]:
            yield "first foo@example.com"

        def gen_b() -> Generator[str, None, None]:
            yield "second bar@example.com"
            yield "third baz@example.com"

        list(streamer.wrap_generator(gen_a()))
        assert streamer.state.sanitized_count == 1

        list(streamer.wrap_generator(gen_b()))
        # State was reset before the second call; only counts from gen_b.
        assert streamer.state.sanitized_count == 2

    def test_zero_pii_stream_zero_count(self) -> None:
        streamer = self._make_streamer()

        def gen() -> Generator[str, None, None]:
            yield "boring chunk one"
            yield "boring chunk two"

        list(streamer.wrap_generator(gen()))
        assert streamer.state.sanitized_count == 0


# =============================================================================
# Bug 3: capability-gating bypass with non-wraps outer decorators — REAL BUG
# =============================================================================
#
# The original claim was framed around `@functools.wraps`. On inspection,
# `functools.wraps` actually PRESERVES `__airlock_capabilities__` via its
# `WRAPPER_UPDATES = ('__dict__',)` merge. The real bug is when an outer
# decorator wraps `@requires` WITHOUT using `functools.wraps`. The fix makes
# `get_required_capabilities` walk the `__wrapped__` chain so that any
# intermediate wrapper — whether it uses `functools.wraps` or not —
# still surfaces the capability attribute.


def _naive_outer(func: Any) -> Any:
    """A decorator that does NOT use functools.wraps (the failure mode)."""

    def wrapper(*args: Any, **kwargs: Any) -> Any:
        return func(*args, **kwargs)

    # Preserve __wrapped__ so get_required_capabilities can walk to `func`.
    wrapper.__wrapped__ = func  # type: ignore[attr-defined]
    return wrapper


def _wraps_outer(func: Any) -> Any:
    """A decorator that DOES use functools.wraps (the success mode)."""

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        return func(*args, **kwargs)

    return wrapper


class TestCapabilityWrappingOrder:
    """Capability attribute survives intermediate wrappers."""

    def test_wraps_decorator_preserves_capability(self) -> None:
        """`functools.wraps` merges __dict__; capability survives."""

        @_wraps_outer
        @requires(Capability.FILESYSTEM_READ)
        def tool_a(path: str) -> str:
            return path

        assert get_required_capabilities(tool_a) == Capability.FILESYSTEM_READ

    def test_naive_wrapper_preserves_via_unwrap_chain(self) -> None:
        """A naive decorator (no functools.wraps) MUST still surface the capability."""

        @_naive_outer
        @requires(Capability.FILESYSTEM_READ)
        def tool_b(path: str) -> str:
            return path

        # Before the fix, this returned Capability.NONE because the naive
        # wrapper didn't copy `__airlock_capabilities__`. After the fix,
        # `get_required_capabilities` walks `__wrapped__` to find it.
        assert get_required_capabilities(tool_b) == Capability.FILESYSTEM_READ

    def test_requires_stacked_on_wraps_decorator(self) -> None:
        """`@requires` on top of a functools.wraps decorator works."""

        @requires(Capability.FILESYSTEM_READ)
        @_wraps_outer
        def tool_c(path: str) -> str:
            return path

        assert get_required_capabilities(tool_c) == Capability.FILESYSTEM_READ

    def test_combined_capabilities_survive_naive_wrap(self) -> None:
        """Combined flags (|) also survive the chain walk."""

        @_naive_outer
        @requires(Capability.FILESYSTEM_READ, Capability.NETWORK_HTTPS)
        def tool_d(path: str, url: str) -> str:
            return path + url

        got = get_required_capabilities(tool_d)
        expected = Capability.FILESYSTEM_READ | Capability.NETWORK_HTTPS
        assert got == expected

    def test_no_capability_on_plain_function(self) -> None:
        """A function with no `@requires` still returns NONE."""

        def plain(path: str) -> str:
            return path

        assert get_required_capabilities(plain) == Capability.NONE
