"""Release-age gate in the publish-window guard (v0.10.36, GHSA-h82f-cjm4-g22r).

``@guicai777/mcp-doctor`` 1.0.1 was published 2026-11-16T11:15:51Z and its advisory
2026-11-20T13:00:09Z: about four days in which no blast list could name it. On 881b66ce the
guard built from ``npm_oidc_publish_window_guard_defaults(installs_from="npm")`` allowed both
``@guicai777/mcp-doctor@1.0.1`` and the bare name. A minimum release age refuses a version
that new whatever the lists say.

https://github.com/advisories/GHSA-h82f-cjm4-g22r

Times come from ``tests/fixtures/malware/release_age_mcp_doctor.json`` (the npm registry's
``time`` map) and the clock is pinned. No test touches the network: the registry lookup gets
a stub opener that returns recorded bodies.
"""

from __future__ import annotations

import json
import urllib.error
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from agent_airlock.mcp_spec import malware_advisory_feed
from agent_airlock.mcp_spec.oidc_publish_window_guard import (
    OIDCPublishWindowGuard,
    OIDCPublishWindowVerdict,
)
from agent_airlock.mcp_spec.release_age import (
    CACHE_ENTRIES,
    parse_release_time,
    registry_release_time_lookup,
)

V = OIDCPublishWindowVerdict
FIXTURE = json.loads(
    (
        Path(__file__).resolve().parent.parent
        / "fixtures"
        / "malware"
        / "release_age_mcp_doctor.json"
    ).read_text(encoding="utf-8")
)
DOCTOR = FIXTURE["package"]
SEVEN_DAYS = timedelta(days=7)
SNAPSHOT = "malware_blast_2026_11_20.json"


def _at(point: str) -> datetime:
    when = parse_release_time(FIXTURE["clock"][point])
    assert when is not None
    return when


def _fixture_lookup(kind: str, name: str, version: str | None) -> datetime | None:
    """npm's time map as the fixture records it, latest as it stood before the advisory."""
    if kind == "npm" and name == DOCTOR:
        wanted = version or FIXTURE["dist_tags_before_advisory"]["latest"]
        return parse_release_time(FIXTURE["time"].get(wanted))
    if kind == "npm" and name == "left-pad":
        return datetime(2021, 3, 4, 12, 0, tzinfo=timezone.utc)
    return None


@pytest.fixture
def snapshot_2026_11_20(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Load the 2026-11-20 snapshot, which does not list mcp-doctor, whatever ships later."""
    monkeypatch.setattr(malware_advisory_feed, "_newest_snapshot_name", lambda root: SNAPSHOT)
    malware_advisory_feed.load_malware_blast_snapshot.cache_clear()
    yield
    malware_advisory_feed.load_malware_blast_snapshot.cache_clear()


def _guard(
    at: datetime | None = None,
    *,
    installs_from: str = "npm",
    min_release_age: timedelta | None = SEVEN_DAYS,
    lookup: Any = _fixture_lookup,
    **kwargs: Any,
) -> OIDCPublishWindowGuard:
    from agent_airlock.policy_presets import npm_oidc_publish_window_guard_defaults

    config = npm_oidc_publish_window_guard_defaults(installs_from=installs_from)
    when = at or _at("before_the_advisory")
    return OIDCPublishWindowGuard(
        blast_list=config["blast_list"],
        blocked_packages=config["blocked_packages"],
        advisories=config["advisories"],
        installs_from=config["installs_from"],
        rescoped_names=config["rescoped_names"],
        min_release_age=min_release_age,
        release_time_lookup=lookup if min_release_age is not None else None,
        clock=lambda: when,
        **kwargs,
    )


@pytest.mark.usefixtures("snapshot_2026_11_20")
class TestMcpDoctorBeforeItsAdvisory:
    def test_the_snapshot_does_not_list_it(self) -> None:
        snapshot = malware_advisory_feed.load_malware_blast_snapshot()
        assert snapshot.as_of == "2026-11-20"
        assert not any(name == DOCTOR for _, name, _ in snapshot.pairs)
        assert ("npm", DOCTOR) not in snapshot.packages

    def test_1_0_1_before_the_advisory_is_too_new(self) -> None:
        decision = _guard().evaluate({"package": f"{DOCTOR}@1.0.1"})
        assert decision.verdict is V.DENY_RELEASE_TOO_NEW
        assert decision.detail == (
            "@guicai777/mcp-doctor@1.0.1 was published 2026-11-16T11:15:51Z, 4 d 0 h before "
            "this call; the policy requires 7 d"
        )
        assert (decision.matched_ecosystem, decision.matched_package) == ("npm", DOCTOR)
        assert decision.matched_version == "1.0.1"

    def test_two_days_after_it_was_published_it_is_refused_too(self) -> None:
        decision = _guard(_at("four_days_after")).evaluate({"package": f"{DOCTOR}@1.0.1"})
        assert decision.verdict is V.DENY_RELEASE_TOO_NEW

    def test_eight_days_after_it_is_allowed(self) -> None:
        guard = _guard(_at("eight_days_after"))
        assert guard.evaluate({"package": f"{DOCTOR}@1.0.1"}).verdict is V.ALLOW

    def test_the_bare_name_resolves_latest_and_is_judged_the_same(self) -> None:
        for args in ({"package": DOCTOR}, {"package": DOCTOR, "version": "latest"}):
            assert _guard().evaluate(args).verdict is V.DENY_RELEASE_TOO_NEW, args
            assert _guard(_at("eight_days_after")).evaluate(args).verdict is V.ALLOW, args

    def test_the_version_field_is_read_like_an_embedded_one(self) -> None:
        decision = _guard().evaluate({"package": DOCTOR, "version": "1.0.1"})
        assert decision.verdict is V.DENY_RELEASE_TOO_NEW
        assert decision.matched_version == "1.0.1"

    def test_its_tarball_url_is_judged_too(self) -> None:
        url = "https://registry.npmjs.org/@guicai777/mcp-doctor/-/mcp-doctor-1.0.1.tgz"
        for args in ({"url": url}, {"package": url}):
            decision = _guard().evaluate(args)
            assert decision.verdict is V.DENY_RELEASE_TOO_NEW, args
            assert decision.matched_version == "1.0.1"

    def test_an_unknown_age_is_refused_unless_told_otherwise(self) -> None:
        def nothing(kind: str, name: str, version: str | None) -> datetime | None:
            return None

        decision = _guard(lookup=nothing).evaluate({"package": f"{DOCTOR}@1.0.1"})
        assert decision.verdict is V.DENY_RELEASE_AGE_UNKNOWN
        relaxed = _guard(lookup=nothing, unknown_release_age="allow")
        assert relaxed.evaluate({"package": f"{DOCTOR}@1.0.1"}).verdict is V.ALLOW

    def test_a_lookup_that_raises_is_an_unknown_age(self) -> None:
        def broken(kind: str, name: str, version: str | None) -> datetime | None:
            raise RuntimeError("registry down")

        decision = _guard(lookup=broken).evaluate({"package": f"{DOCTOR}@1.0.1"})
        assert decision.verdict is V.DENY_RELEASE_AGE_UNKNOWN

    def test_release_age_allow_skips_the_check(self) -> None:
        guard = _guard(release_age_allow=frozenset({"@GUICAI777/mcp-doctor"}))
        assert guard.evaluate({"package": f"{DOCTOR}@1.0.1"}).verdict is V.ALLOW

    def test_a_listed_release_reports_its_own_verdict(self) -> None:
        decision = _guard().evaluate({"package": "@fdcasj_dfew/md-doc-mcp@1.0.0"})
        assert decision.verdict is V.DENY_BLAST_LIST_PAIR

    def test_an_old_release_is_allowed(self) -> None:
        assert _guard().evaluate({"package": "left-pad@1.3.0"}).verdict is V.ALLOW

    def test_without_min_release_age_both_specs_are_allowed_as_before(self) -> None:
        guard = _guard(min_release_age=None)
        for args in ({"package": f"{DOCTOR}@1.0.1"}, {"package": DOCTOR}):
            assert guard.evaluate(args).verdict is V.ALLOW, args

    @pytest.mark.parametrize(
        "spec",
        [
            "github:guicai777/mcp-doctor",
            "guicai777/mcp-doctor",
            "./vendor/mcp-doctor",
            "file:../mcp-doctor",
            "git+https://github.com/guicai777/mcp-doctor.git",
            "https://example.test/mcp-doctor-1.0.1.tgz",
            f"{DOCTOR}@github:guicai777/mcp-doctor",
        ],
    )
    def test_git_path_and_non_registry_specs_are_not_looked_up(self, spec: str) -> None:
        asked: list[tuple[str, str, str | None]] = []

        def recording(kind: str, name: str, version: str | None) -> datetime | None:
            asked.append((kind, name, version))
            return None

        assert _guard(lookup=recording).evaluate({"package": spec}).verdict is V.ALLOW
        assert asked == []


class TestOtherRegistries:
    def test_a_pypi_pin_a_day_old_is_refused(self) -> None:
        at = _at("before_the_advisory")
        asked: list[tuple[str, str, str | None]] = []

        def one_day_old(kind: str, name: str, version: str | None) -> datetime | None:
            asked.append((kind, name, version))
            return at - timedelta(days=1)

        guard = OIDCPublishWindowGuard(
            installs_from="pypi",
            min_release_age=SEVEN_DAYS,
            release_time_lookup=one_day_old,
            clock=lambda: at,
        )
        decision = guard.evaluate({"package": "mcp-aevo-server==0.2.0"})
        assert decision.verdict is V.DENY_RELEASE_TOO_NEW
        assert decision.matched_ecosystem == "pypi"
        assert decision.detail.startswith("mcp-aevo-server==0.2.0 was published")
        assert asked == [("pypi", "mcp-aevo-server", "0.2.0")]

    def test_a_pypi_range_is_judged_by_the_latest_release(self) -> None:
        asked: list[tuple[str, str, str | None]] = []
        at = _at("before_the_advisory")

        def old(kind: str, name: str, version: str | None) -> datetime | None:
            asked.append((kind, name, version))
            return at - timedelta(days=400)

        guard = OIDCPublishWindowGuard(
            installs_from="pypi",
            min_release_age=SEVEN_DAYS,
            release_time_lookup=old,
            clock=lambda: at,
        )
        assert guard.evaluate({"package": "Some_Pkg[extra]>=1.0"}).verdict is V.ALLOW
        assert asked == [("pypi", "some-pkg", None)]

    def test_with_no_installs_from_a_bare_name_is_judged_by_its_youngest_registry(self) -> None:
        at = _at("before_the_advisory")

        def both(kind: str, name: str, version: str | None) -> datetime | None:
            return at - (timedelta(days=1) if kind == "pypi" else timedelta(days=400))

        guard = OIDCPublishWindowGuard(
            min_release_age=SEVEN_DAYS, release_time_lookup=both, clock=lambda: at
        )
        decision = guard.evaluate({"package": "shared-name", "version": "1.0.0"})
        assert decision.verdict is V.DENY_RELEASE_TOO_NEW
        assert decision.matched_ecosystem == "pypi"


class TestConstruction:
    @pytest.mark.parametrize(
        ("kwargs", "error"),
        [
            (
                {"min_release_age": timedelta(days=-1), "release_time_lookup": _fixture_lookup},
                ValueError,
            ),
            ({"min_release_age": SEVEN_DAYS}, ValueError),
            ({"min_release_age": 7, "release_time_lookup": _fixture_lookup}, TypeError),
            ({"release_time_lookup": "registry"}, TypeError),
            ({"unknown_release_age": "maybe"}, ValueError),
            ({"unknown_release_age": True}, TypeError),
            ({"release_age_allow": {"x"}}, TypeError),
            ({"release_age_allow": frozenset({1})}, TypeError),
            ({"clock": "now"}, TypeError),
        ],
    )
    def test_a_wrong_keyword_raises(self, kwargs: dict[str, Any], error: type[Exception]) -> None:
        with pytest.raises(error):
            OIDCPublishWindowGuard(**kwargs)

    def test_the_verdict_values_are_stable(self) -> None:
        assert V.DENY_RELEASE_TOO_NEW.value == "deny_release_too_new"
        assert V.DENY_RELEASE_AGE_UNKNOWN.value == "deny_release_age_unknown"


class TestThePreset:
    def test_it_is_off_by_default(self) -> None:
        from agent_airlock.policy_presets import npm_oidc_publish_window_guard_defaults

        config = npm_oidc_publish_window_guard_defaults()
        assert config["min_release_age"] is None
        assert config["release_time_lookup"] is None

    def test_hours_turn_it_on_with_the_registry_lookup(self) -> None:
        from agent_airlock.policy_presets import npm_oidc_publish_window_guard_defaults

        config = npm_oidc_publish_window_guard_defaults(min_release_age_hours=168)
        assert config["min_release_age"] == SEVEN_DAYS
        assert callable(config["release_time_lookup"])
        mine = npm_oidc_publish_window_guard_defaults(
            min_release_age_hours=24, release_time_lookup=_fixture_lookup
        )
        assert mine["release_time_lookup"] is _fixture_lookup

    @pytest.mark.parametrize(
        ("hours", "error"), [(-1, ValueError), (1.5, TypeError), (True, TypeError)]
    )
    def test_bad_hours_raise(self, hours: Any, error: type[Exception]) -> None:
        from agent_airlock.policy_presets import npm_oidc_publish_window_guard_defaults

        with pytest.raises(error):
            npm_oidc_publish_window_guard_defaults(min_release_age_hours=hours)


def _opener(responses: dict[str, Any]) -> tuple[Any, list[str]]:
    """A stub opener: a URL maps to a body (dict), an exception to raise, or is missing (404)."""
    seen: list[str] = []

    def open_url(url: str, timeout: float) -> bytes:
        seen.append(url)
        answer = responses.get(url)
        if isinstance(answer, BaseException):
            raise answer
        if answer is None:
            raise urllib.error.HTTPError(url, 404, "Not Found", None, None)  # type: ignore[arg-type]
        return json.dumps(answer).encode("utf-8")

    return open_url, seen


NPM_URL = "https://registry.npmjs.org/@guicai777%2fmcp-doctor"
PYPI_URL = FIXTURE["pypi_release"]["request"]


class TestRegistryReleaseTimeLookup:
    def test_npm_reads_the_time_map(self) -> None:
        opener, seen = _opener({NPM_URL: FIXTURE["npm_packument"]})
        lookup = registry_release_time_lookup(opener=opener)
        assert lookup("npm", DOCTOR, "1.0.1") == datetime(
            2026, 11, 16, 11, 15, 51, 940000, tzinfo=timezone.utc
        )
        assert seen == [NPM_URL]

    def test_npm_with_no_version_reads_the_latest_dist_tag(self) -> None:
        # The recorded packument's latest is npm's security holding, 0.0.1-security.
        opener, _ = _opener({NPM_URL: FIXTURE["npm_packument"]})
        lookup = registry_release_time_lookup(opener=opener)
        assert lookup("npm", DOCTOR, None) == parse_release_time(FIXTURE["time"]["0.0.1-security"])

    def test_pypi_reads_the_earliest_upload(self) -> None:
        opener, seen = _opener({PYPI_URL: FIXTURE["pypi_release"]["body"]})
        lookup = registry_release_time_lookup(opener=opener)
        assert lookup("pypi", "mcp", "1.0.0") == datetime(
            2024, 11, 25, 14, 27, 34, 367301, tzinfo=timezone.utc
        )
        assert seen == [PYPI_URL]

    def test_pypi_with_no_version_reads_the_project_document(self) -> None:
        opener, seen = _opener({"https://pypi.org/pypi/mcp/json": FIXTURE["pypi_release"]["body"]})
        lookup = registry_release_time_lookup(opener=opener)
        assert lookup("pypi", "mcp", None) is not None
        assert seen == ["https://pypi.org/pypi/mcp/json"]

    def test_a_404_a_timeout_and_a_bad_body_are_none(self) -> None:
        opener, _ = _opener(
            {
                "https://pypi.org/pypi/slow/1.0/json": TimeoutError("timed out"),
                "https://pypi.org/pypi/odd/1.0/json": FIXTURE["pypi_not_found"],
            }
        )
        lookup = registry_release_time_lookup(opener=opener)
        assert lookup("pypi", "mcp-aevo-server", "0.2.0") is None  # 404
        assert lookup("pypi", "slow", "1.0") is None
        assert lookup("pypi", "odd", "1.0") is None
        assert lookup("npm", DOCTOR, "9.9.9") is None
        assert lookup("cargo", "serde", "1.0.0") is None

    def test_a_name_that_is_not_a_package_name_is_never_requested(self) -> None:
        opener, seen = _opener({})
        lookup = registry_release_time_lookup(opener=opener)
        for name in ("../../-/whoami", "a?b", "@scope/../x", ""):
            assert lookup("npm", name, "1.0.0") is None
            assert lookup("pypi", name, "1.0.0") is None
        assert lookup("pypi", "mcp", "1.0/../../x") is None
        assert seen == []

    def test_an_exact_version_is_asked_once_and_latest_every_time(self) -> None:
        opener, seen = _opener({NPM_URL: FIXTURE["npm_packument"]})
        lookup = registry_release_time_lookup(opener=opener)
        for _ in range(3):
            lookup("npm", DOCTOR, "1.0.1")
            lookup("npm", DOCTOR, None)
        assert seen.count(NPM_URL) == 4  # one exact-version miss, three latest reads
        assert CACHE_ENTRIES == 1024

    def test_bad_arguments_raise(self) -> None:
        with pytest.raises(ValueError):
            registry_release_time_lookup(timeout=0)
        with pytest.raises(TypeError):
            registry_release_time_lookup(timeout="3")  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            registry_release_time_lookup(opener="urlopen")  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            (
                "2026-11-16T11:15:51.940Z",
                datetime(2026, 11, 16, 11, 15, 51, 940000, tzinfo=timezone.utc),
            ),
            ("2026-11-16T12:15:51+01:00", datetime(2026, 11, 16, 11, 15, 51, tzinfo=timezone.utc)),
            ("2026-11-16T11:15:51", datetime(2026, 11, 16, 11, 15, 51, tzinfo=timezone.utc)),
            ("not a time", None),
            ("", None),
            (None, None),
        ],
    )
    def test_parse_release_time(self, text: Any, expected: datetime | None) -> None:
        assert parse_release_time(text) == expected
