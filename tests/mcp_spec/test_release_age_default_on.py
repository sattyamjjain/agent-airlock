"""The preset's release-age check is on by default (0.10.37).

On 25 Nov 2026 GitHub published five Critical malware advisories, none in the 2026-11-20
malware snapshot the preset ships:

- GHSA-jxr7-4663-2qrm, ``mcp-sysinfo-tools`` 1.0.0 (PyPI)
- GHSA-7vxr-6h54-ww37, ``mcp-runtime-report`` 1.0.0 (PyPI)
- GHSA-5gwx-j786-m4mq, ``mcp-env-report`` 1.0.0 (PyPI)
- GHSA-3fgm-7pvj-pj4r, ``mcp-diag-7f3a`` 1.0.0, 1.1.0 and 1.2.0 (PyPI)
- GHSA-4c46-v99r-6h9r, ``create-ai-agent-setup`` 2.0.0-alpha.0, 2.0.0 and 2.1.0 (npm)

On 099fcef0 a guard built from ``npm_oidc_publish_window_guard_defaults(installs_from=...)``
allowed every one of them: the release-age check (GHSA-h82f-cjm4-g22r, 0.10.36) was opt-in,
and the preset left it off. It is now on at ``DEFAULT_MIN_RELEASE_AGE_HOURS`` (168), so a
release that new is refused before any advisory names it.

https://github.com/advisories/GHSA-jxr7-4663-2qrm
https://github.com/advisories/GHSA-7vxr-6h54-ww37
https://github.com/advisories/GHSA-5gwx-j786-m4mq
https://github.com/advisories/GHSA-3fgm-7pvj-pj4r
https://github.com/advisories/GHSA-4c46-v99r-6h9r

The clock is pinned and every lookup is a stub: no test touches the network.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from agent_airlock import policy_presets
from agent_airlock.mcp_spec import malware_advisory_feed
from agent_airlock.mcp_spec import oidc_publish_window_guard as guard_module
from agent_airlock.mcp_spec.oidc_publish_window_guard import (
    OIDCPublishWindowGuard,
    OIDCPublishWindowVerdict,
)
from agent_airlock.policy_presets import (
    DEFAULT_MIN_RELEASE_AGE_HOURS,
    npm_oidc_publish_window_guard_defaults,
)

V = OIDCPublishWindowVerdict
SNAPSHOT = "malware_blast_2026_11_20.json"
# When GitHub published the four PyPI advisories.
NOW = datetime(2026, 11, 25, 18, 30, tzinfo=timezone.utc)

# (installs_from, the call's arguments, what the lookup is asked)
CALLS: list[tuple[str, dict[str, str], tuple[str, str, str]]] = [
    ("pypi", {"package": "mcp-sysinfo-tools==1.0.0"}, ("pypi", "mcp-sysinfo-tools", "1.0.0")),
    ("pypi", {"package": "mcp-runtime-report==1.0.0"}, ("pypi", "mcp-runtime-report", "1.0.0")),
    ("pypi", {"package": "mcp-env-report==1.0.0"}, ("pypi", "mcp-env-report", "1.0.0")),
    ("pypi", {"package": "mcp-diag-7f3a==1.2.0"}, ("pypi", "mcp-diag-7f3a", "1.2.0")),
    (
        "pypi",
        {"package": "mcp-diag-7f3a", "version": "1.2.0"},
        ("pypi", "mcp-diag-7f3a", "1.2.0"),
    ),
    (
        "npm",
        {"package": "create-ai-agent-setup@2.1.0"},
        ("npm", "create-ai-agent-setup", "2.1.0"),
    ),
]


def _call_id(call: tuple[str, dict[str, str], tuple[str, str, str]]) -> str:
    return " ".join(call[1].values())


class _Lookup:
    """Answers every question with one publish time and records what it was asked."""

    def __init__(self, published: datetime | None) -> None:
        self.published = published
        self.asked: list[tuple[str, str, str | None]] = []

    def __call__(self, kind: str, name: str, version: str | None) -> datetime | None:
        self.asked.append((kind, name, version))
        return self.published


class _Events:
    """Stands in for the guard module's logger and records every event it is given."""

    def __init__(self) -> None:
        self.records: list[tuple[str, str, dict[str, Any]]] = []

    def __getattr__(self, level: str) -> Any:
        def record(event: str, **fields: Any) -> None:
            self.records.append((level, event, fields))

        return record

    def named(self, event: str) -> list[dict[str, Any]]:
        return [fields for _, name, fields in self.records if name == event]


@pytest.fixture(autouse=True)
def snapshot_2026_11_20(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """The 2026-11-20 snapshot, which lists none of the five, whatever ships later."""
    monkeypatch.setattr(malware_advisory_feed, "_newest_snapshot_name", lambda root: SNAPSHOT)
    malware_advisory_feed.load_malware_blast_snapshot.cache_clear()
    yield
    malware_advisory_feed.load_malware_blast_snapshot.cache_clear()


@pytest.fixture
def events(monkeypatch: pytest.MonkeyPatch) -> _Events:
    """The guard module's logger, recorded, with the once-per-process latch reset."""
    recorder = _Events()
    monkeypatch.setattr(guard_module, "logger", recorder)
    monkeypatch.setattr(guard_module, "_release_age_off_warned", False)
    return recorder


def _guard(cfg: dict[str, Any]) -> OIDCPublishWindowGuard:
    """The guard from every key the preset returns, as its docstring builds it."""
    return OIDCPublishWindowGuard(
        blast_list=cfg["blast_list"],
        blocked_packages=cfg["blocked_packages"],
        advisories=cfg["advisories"],
        installs_from=cfg["installs_from"],
        rescoped_names=cfg["rescoped_names"],
        min_release_age=cfg["min_release_age"],
        release_time_lookup=cfg["release_time_lookup"],
        unknown_release_age=cfg["unknown_release_age"],
        release_age_allow=cfg["release_age_allow"],
        clock=lambda: NOW,
    )


class TestTheDefault:
    def test_it_is_seven_days(self) -> None:
        assert DEFAULT_MIN_RELEASE_AGE_HOURS == 168
        assert "DEFAULT_MIN_RELEASE_AGE_HOURS" in policy_presets.__all__

    def test_the_preset_turns_it_on_with_the_registry_lookup(self) -> None:
        cfg = npm_oidc_publish_window_guard_defaults()
        assert cfg["min_release_age"] == timedelta(hours=168)
        assert callable(cfg["release_time_lookup"])
        assert cfg["unknown_release_age"] == "deny"
        assert cfg["release_age_allow"] == frozenset()

    def test_a_lookup_of_your_own_replaces_the_registry(self) -> None:
        lookup = _Lookup(NOW)
        cfg = npm_oidc_publish_window_guard_defaults(release_time_lookup=lookup)
        assert cfg["min_release_age"] == timedelta(hours=168)
        assert cfg["release_time_lookup"] is lookup


class TestTheFiveReleasesOf25November:
    @pytest.mark.parametrize("call", CALLS, ids=_call_id)
    def test_before_the_default_each_was_allowed(
        self, call: tuple[str, dict[str, str], tuple[str, str, str]]
    ) -> None:
        installs_from, args, _ = call
        cfg = npm_oidc_publish_window_guard_defaults(
            installs_from=installs_from, min_release_age_hours=None
        )
        assert _guard(cfg).evaluate(args).allowed is True

    @pytest.mark.parametrize("call", CALLS, ids=_call_id)
    def test_twelve_hours_old_each_is_too_new(
        self, call: tuple[str, dict[str, str], tuple[str, str, str]]
    ) -> None:
        installs_from, args, asked = call
        lookup = _Lookup(NOW - timedelta(hours=12))
        cfg = npm_oidc_publish_window_guard_defaults(
            installs_from=installs_from, release_time_lookup=lookup
        )
        decision = _guard(cfg).evaluate(args)
        assert decision.verdict is V.DENY_RELEASE_TOO_NEW
        assert "the policy requires 7 d" in decision.detail
        assert lookup.asked == [asked]

    @pytest.mark.parametrize("call", CALLS, ids=_call_id)
    def test_two_hundred_days_old_each_is_allowed(
        self, call: tuple[str, dict[str, str], tuple[str, str, str]]
    ) -> None:
        """The age decided, not the name: no list names these releases."""
        installs_from, args, _ = call
        lookup = _Lookup(NOW - timedelta(days=200))
        cfg = npm_oidc_publish_window_guard_defaults(
            installs_from=installs_from, release_time_lookup=lookup
        )
        assert _guard(cfg).evaluate(args).allowed is True

    def test_an_old_release_of_something_else_is_allowed(self) -> None:
        lookup = _Lookup(NOW - timedelta(days=400))
        cfg = npm_oidc_publish_window_guard_defaults(
            installs_from="npm", release_time_lookup=lookup
        )
        assert _guard(cfg).evaluate({"package": "left-pad@1.3.0"}).allowed is True


class TestAnUnknownAge:
    def test_it_is_refused(self) -> None:
        cfg = npm_oidc_publish_window_guard_defaults(
            installs_from="pypi", release_time_lookup=_Lookup(None)
        )
        decision = _guard(cfg).evaluate({"package": "mcp-sysinfo-tools==1.0.0"})
        assert decision.verdict is V.DENY_RELEASE_AGE_UNKNOWN

    def test_unknown_release_age_allow_admits_it(self) -> None:
        cfg = npm_oidc_publish_window_guard_defaults(
            installs_from="pypi", release_time_lookup=_Lookup(None), unknown_release_age="allow"
        )
        assert cfg["unknown_release_age"] == "allow"
        assert _guard(cfg).evaluate({"package": "mcp-sysinfo-tools==1.0.0"}).allowed is True

    def test_a_name_on_release_age_allow_is_not_asked(self) -> None:
        lookup = _Lookup(NOW - timedelta(hours=1))
        cfg = npm_oidc_publish_window_guard_defaults(
            installs_from="npm",
            release_time_lookup=lookup,
            release_age_allow=frozenset({"@yourco/internal-tool"}),
        )
        guard = _guard(cfg)
        assert guard.evaluate({"package": "@yourco/internal-tool@1.0.0"}).allowed is True
        assert lookup.asked == []
        assert guard.evaluate({"package": "@yourco/other@1.0.0"}).verdict is (
            V.DENY_RELEASE_TOO_NEW
        )


class TestTurningItOff:
    def test_none_turns_it_off(self) -> None:
        cfg = npm_oidc_publish_window_guard_defaults(
            installs_from="pypi", min_release_age_hours=None
        )
        assert cfg["min_release_age"] is None
        assert cfg["release_time_lookup"] is None
        assert _guard(cfg).evaluate({"package": "mcp-sysinfo-tools==1.0.0"}).allowed is True

    def test_a_guard_without_it_warns_once_per_process(self, events: _Events) -> None:
        cfg = npm_oidc_publish_window_guard_defaults(
            installs_from="pypi", min_release_age_hours=None
        )
        _guard(cfg)
        OIDCPublishWindowGuard(installs_from="npm")
        [warned] = events.named("oidc_publish_window_release_age_off")
        assert warned["installs_from"] == "pypi"
        assert "DEFAULT_MIN_RELEASE_AGE_HOURS (168 h)" in warned["detail"]
        assert [level for level, _, _ in events.records] == ["warning"]

    def test_a_guard_with_it_does_not_warn(self, events: _Events) -> None:
        _guard(npm_oidc_publish_window_guard_defaults(installs_from="npm"))
        assert events.named("oidc_publish_window_release_age_off") == []

    def test_a_guard_for_no_registry_does_not_warn(self, events: _Events) -> None:
        OIDCPublishWindowGuard(blast_list=frozenset({("npm", "x", "1.0.0")}))
        assert events.named("oidc_publish_window_release_age_off") == []

    def test_the_guard_s_own_default_is_unchanged(self) -> None:
        guard = OIDCPublishWindowGuard(installs_from="npm")
        assert guard.evaluate({"package": "create-ai-agent-setup@2.1.0"}).allowed is True


class TestThePassthroughKeywords:
    @pytest.mark.parametrize(
        ("kwargs", "error"),
        [
            ({"unknown_release_age": "maybe"}, ValueError),
            ({"unknown_release_age": 1}, TypeError),
            ({"release_age_allow": ["@yourco/internal-tool"]}, TypeError),
            ({"release_age_allow": frozenset({1})}, TypeError),
        ],
    )
    def test_a_wrong_value_raises(self, kwargs: dict[str, Any], error: type[Exception]) -> None:
        with pytest.raises(error):
            npm_oidc_publish_window_guard_defaults(**kwargs)
