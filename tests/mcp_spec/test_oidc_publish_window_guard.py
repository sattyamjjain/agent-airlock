"""Tests for the v0.7.6 OIDC publish-window guard (TanStack postmortem 2026-05-11).

The TanStack 2026-05-11 postmortem disclosed that an attacker extracted
the runner's OIDC token directly from ``/proc/<pid>/maps`` and
``/proc/<pid>/mem`` of the Runner.Worker process and used it to
republish 42 packages × 84 versions outside the workflow's own publish
step. The npm trusted-publisher binding has no per-publish review, so
any code path in the workflow could mint a publish-capable token.

Airlock's runtime surface for this class is "agent that fetches /
runs just-mutated package versions should reject blast-list pairs".
This guard fails-closed on a known-bad blast list and a registry
tarball URL pattern.

Primary sources
---------------
- TanStack postmortem (2026-05-11):
  https://tanstack.com/blog/npm-supply-chain-compromise-postmortem
- Aikido — Mini Shai-Hulud Is Back (2026-05-11, cross-ecosystem):
  https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from agent_airlock.mcp_spec.oidc_publish_window_guard import (
    OIDCPublishWindowDecision,
    OIDCPublishWindowGuard,
    OIDCPublishWindowVerdict,
    load_blast_list_from_2026_05_11,
)


class TestCVE_TanStack_2026_05_11_BlastList:
    """A package+version pair on the blast list is denied at any tool boundary."""

    def test_blocks_known_blast_pkg_version_pair(self) -> None:
        """The CVE class — `@tanstack/react-router` at a blast-list version."""
        guard = OIDCPublishWindowGuard(
            blast_list=frozenset(
                {("npm", "@tanstack/react-router", "1.146.0-compromised-2026-05-11")}
            )
        )
        decision = guard.evaluate(
            {"package": "@tanstack/react-router", "version": "1.146.0-compromised-2026-05-11"}
        )
        assert isinstance(decision, OIDCPublishWindowDecision)
        assert decision.allowed is False
        assert decision.verdict == OIDCPublishWindowVerdict.DENY_BLAST_LIST_PAIR
        assert decision.matched_ecosystem == "npm"
        assert decision.matched_package == "@tanstack/react-router"
        assert "tanstack" in decision.detail.lower() or "blast" in decision.detail.lower()


class TestBenignPackageVersion:
    """Clean pkg+version pairs are not denied — no false-positives."""

    def test_allows_clean_pkg(self) -> None:
        guard = OIDCPublishWindowGuard(
            blast_list=frozenset(
                {("npm", "@tanstack/react-router", "1.146.0-compromised-2026-05-11")}
            )
        )
        decision = guard.evaluate(
            {"package": "@tanstack/react-router", "version": "1.0.0-pre-incident"}
        )
        assert decision.allowed is True
        assert decision.verdict == OIDCPublishWindowVerdict.ALLOW
        assert decision.matched_package is None

    def test_none_args_allowed(self) -> None:
        guard = OIDCPublishWindowGuard()
        decision = guard.evaluate(None)
        assert decision.allowed is True


class TestRegistryTarballUrlPattern:
    """Tarball URLs targeting blast-list pairs are denied — captures the wget/fetch path."""

    def test_blocks_registry_tarball_url(self) -> None:
        """A direct npm-registry tarball URL for a blast pair must be denied."""
        guard = OIDCPublishWindowGuard(
            blast_list=frozenset(
                {("npm", "@tanstack/react-router", "1.146.0-compromised-2026-05-11")}
            )
        )
        decision = guard.evaluate(
            {
                "url": (
                    "https://registry.npmjs.org/@tanstack/react-router/-/"
                    "react-router-1.146.0-compromised-2026-05-11.tgz"
                )
            }
        )
        assert decision.allowed is False
        assert decision.verdict == OIDCPublishWindowVerdict.DENY_BLAST_LIST_TARBALL_URL
        assert decision.matched_package == "@tanstack/react-router"

    def test_allows_tarball_url_for_clean_version(self) -> None:
        guard = OIDCPublishWindowGuard(
            blast_list=frozenset(
                {("npm", "@tanstack/react-router", "1.146.0-compromised-2026-05-11")}
            )
        )
        decision = guard.evaluate(
            {
                "url": (
                    "https://registry.npmjs.org/@tanstack/react-router/-/"
                    "react-router-1.0.0-pre-incident.tgz"
                )
            }
        )
        assert decision.allowed is True

    def test_unrelated_url_allowed(self) -> None:
        guard = OIDCPublishWindowGuard(
            blast_list=frozenset(
                {("npm", "@tanstack/react-router", "1.146.0-compromised-2026-05-11")}
            )
        )
        decision = guard.evaluate({"url": "https://example.com/some/page"})
        assert decision.allowed is True


class TestFixtureLoadsFromPackagedData:
    """The 2026-05-11 fixture is shipped with the package and importlib-resources-loadable."""

    def test_fixture_loads_from_importlib_resources(self) -> None:
        entries = load_blast_list_from_2026_05_11()
        assert isinstance(entries, frozenset)
        # ≥84 floor per spec (42 TanStack pkgs × min 2 versions each was the
        # postmortem blast radius). Reality may be larger; we assert the floor.
        assert len(entries) >= 84, (
            f"blast-list fixture must carry at least 84 entries (got {len(entries)})"
        )
        # Each entry is (ecosystem, name, version) — type-tight.
        for ecosystem, name, version in entries:
            assert isinstance(ecosystem, str)
            assert isinstance(name, str)
            assert isinstance(version, str)
            assert ecosystem in {"npm", "pypi"}

    def test_fixture_is_the_advisorys_affected_version_table(self) -> None:
        """0.10.28: the list is GHSA-g7cv-rxg3-hmpx's table, as the registry published it.

        The superseded 2026-05-11 snapshot spelled 90 of 93 versions with a synthetic
        ``-compromised-2026-05-11`` suffix no install carries, named @tanstack/react-query
        (the postmortem lists it clean) and held three PyPI rows neither cited source
        names. This pinned that last claim; it now pins the advisory's shape instead.
        """
        entries = load_blast_list_from_2026_05_11()
        assert len(entries) == 84
        assert {eco for eco, _, _ in entries} == {"npm"}
        assert len({name for _, name, _ in entries}) == 42
        assert not any("compromised" in version for _, _, version in entries)
        assert ("npm", "@tanstack/react-router", "1.169.5") in entries
        assert ("npm", "@tanstack/history", "1.161.9") in entries
        assert not any(name.startswith("@tanstack/react-query") for _, name, _ in entries)

    def test_fixture_json_source_field_records_url(self) -> None:
        from importlib.resources import files

        from agent_airlock.mcp_spec.oidc_publish_window_guard import (
            _FIXTURE_PACKAGE,
            _FIXTURE_RESOURCE_NAME,
        )

        raw = (files(_FIXTURE_PACKAGE) / _FIXTURE_RESOURCE_NAME).read_text(encoding="utf-8")
        payload = json.loads(raw)
        assert payload["source"] == "https://github.com/advisories/GHSA-g7cv-rxg3-hmpx"
        assert "tanstack.com" in payload["postmortem"]
        assert payload["as_of"].startswith("2026-10-28")
        assert payload["supersedes"] == "oidc_publish_blast_2026_05_11.json"
        assert "entries" in payload
        assert isinstance(payload["entries"], list)


class TestFactoryShape:
    """`policy_presets.npm_oidc_publish_window_guard_defaults` factory parity."""

    def test_factory_returns_expected_config_shape(self) -> None:
        from agent_airlock.policy_presets import npm_oidc_publish_window_guard_defaults

        config = npm_oidc_publish_window_guard_defaults()
        assert config["preset_id"] == "npm_oidc_publish_window_guard_2026_05_11"
        assert config["severity"] == "critical"
        assert config["default_action"] == "deny"
        assert "tanstack.com" in config["advisory_url"]
        assert isinstance(config["blast_list"], frozenset)
        assert len(config["blast_list"]) >= 84

    def test_factory_supports_caller_supplied_blast_list(self) -> None:
        from agent_airlock.policy_presets import npm_oidc_publish_window_guard_defaults

        custom = frozenset({("npm", "@example/pkg", "1.0.0")})
        config = npm_oidc_publish_window_guard_defaults(blast_list=custom)
        assert config["blast_list"] == custom


class TestBadConstruction:
    """Construction-time validation rejects nonsense inputs."""

    def test_non_frozenset_blast_list_rejected(self) -> None:
        with pytest.raises(TypeError, match="frozenset"):
            OIDCPublishWindowGuard(blast_list=[("npm", "x", "1")])  # type: ignore[arg-type]

    def test_malformed_blast_list_entry_rejected(self) -> None:
        with pytest.raises(TypeError, match="tuple"):
            OIDCPublishWindowGuard(blast_list=frozenset({"not-a-tuple"}))  # type: ignore[arg-type]


class TestTheShippedListMatchesRealInstalls:
    """0.10.28: a compromised release is refused as the registry spells it."""

    @pytest.mark.parametrize(
        "args",
        [
            {"package": "@tanstack/react-router", "version": "1.169.5"},
            {"package": "@tanstack/react-router@1.169.8"},
            {"url": "https://registry.npmjs.org/@tanstack/history/-/history-1.161.9.tgz"},
        ],
    )
    def test_a_compromised_release_is_refused(self, args: dict[str, str]) -> None:
        guard = OIDCPublishWindowGuard(blast_list=load_blast_list_from_2026_05_11())
        assert guard.evaluate(args).allowed is False

    @pytest.mark.parametrize(
        "args",
        [
            {"package": "@tanstack/react-router", "version": "1.169.9"},
            {"package": "@tanstack/react-query", "version": "5.78.0"},
        ],
    )
    def test_control_the_patched_release_and_a_clean_package_pass(
        self, args: dict[str, str]
    ) -> None:
        guard = OIDCPublishWindowGuard(blast_list=load_blast_list_from_2026_05_11())
        assert guard.evaluate(args).allowed is True

    def test_the_superseded_snapshot_stays_in_data(self) -> None:
        from importlib.resources import files

        assert (files("agent_airlock.data") / "oidc_publish_blast_2026_05_11.json").is_file()


class TestEveryInstallSpellingIsRead:
    """0.10.28 review: every spelling npm, Yarn and Node resolve to a listed tarball.

    npm reads a bare tarball URL, or ``name@<url>``, as a remote spec (npm-package-arg,
    https://github.com/npm/npm-package-arg). Node's ``new URL()`` turns a backslash into a
    path separator and resolves ``.`` / ``..`` segments, percent-encoded ones included
    (https://url.spec.whatwg.org/#double-dot-path-segment). Yarn and pnpm write a
    registry version, or an alias, in the version field as ``npm:...``.
    """

    @staticmethod
    def _spellings(version: str) -> list[dict[str, str]]:
        tarball = f"history-{version}.tgz"
        url = f"https://registry.npmjs.org/@tanstack/history/-/{tarball}"
        return [
            {"package": url},
            {"package": f"@tanstack/history@{url}"},
            {"url": f"https://registry.npmjs.org/@tanstack/x/../history/-/{tarball}"},
            {"url": f"https://registry.npmjs.org/@tanstack/x/%2E%2e/history/-/{tarball}"},
            {"url": f"https://registry.npmjs.org/@tanstack/history/-/./{tarball}"},
            {"url": f"https://registry.npmjs.org\\@tanstack/history/-/{tarball}"},
            {"package": "@tanstack/history", "version": f"npm:{version}"},
            {"package": "history", "version": f"npm:@tanstack/history@{version}"},
        ]

    def test_a_listed_release_is_refused_in_every_spelling(self) -> None:
        guard = OIDCPublishWindowGuard(blast_list=load_blast_list_from_2026_05_11())
        for args in self._spellings("1.161.9"):
            assert guard.evaluate(args).allowed is False, args

    def test_control_an_unlisted_release_passes_in_every_spelling(self) -> None:
        guard = OIDCPublishWindowGuard(blast_list=load_blast_list_from_2026_05_11())
        for args in self._spellings("1.0.0"):
            assert guard.evaluate(args).allowed is True, args


_RESCOPED = json.loads(
    (
        Path(__file__).resolve().parent.parent / "fixtures" / "malware" / "rescoped_md_doc_mcp.json"
    ).read_text(encoding="utf-8")
)


@pytest.fixture
def snapshot_2026_11_14(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Load ``malware_blast_2026_11_14.json``, taken before GHSA-m5xq-h2p4-962g existed.

    The rescoped-name check must catch ``@fdcasj_dfew/md-doc-mcp`` from the list as it stood
    before any advisory named that scope; the 2026-11-20 snapshot lists it outright.
    """
    from agent_airlock.mcp_spec import malware_advisory_feed

    monkeypatch.setattr(
        malware_advisory_feed, "_newest_snapshot_name", lambda root: _RESCOPED["snapshot"]
    )
    malware_advisory_feed.load_malware_blast_snapshot.cache_clear()
    yield
    malware_advisory_feed.load_malware_blast_snapshot.cache_clear()


def _preset_guard(
    *, match_rescoped: bool = True, rescope_allow: frozenset[str] = frozenset()
) -> OIDCPublishWindowGuard:
    from agent_airlock.policy_presets import npm_oidc_publish_window_guard_defaults

    config = npm_oidc_publish_window_guard_defaults(
        installs_from="npm", match_rescoped=match_rescoped
    )
    return OIDCPublishWindowGuard(
        blast_list=config["blast_list"],
        blocked_packages=config["blocked_packages"],
        advisories=config["advisories"],
        installs_from=config["installs_from"],
        rescoped_names=config["rescoped_names"],
        rescope_allow=rescope_allow,
    )


def _call_id(call: dict[str, Any]) -> str:
    suffix = " (rescope_allow)" if call.get("rescope_allow") else ""
    return json.dumps(call["args"], sort_keys=True) + suffix


@pytest.mark.usefixtures("snapshot_2026_11_14")
class TestRescopedMalwareName:
    """GHSA-m5xq-h2p4-962g: ``@fdcasj_dfew/md-doc-mcp``, the ``@ifasn`` family rescoped.

    https://github.com/advisories/GHSA-m5xq-h2p4-962g
    """

    def test_the_snapshot_loaded_is_the_one_before_the_advisory(self) -> None:
        from agent_airlock.mcp_spec.malware_advisory_feed import load_malware_blast_snapshot

        snapshot = load_malware_blast_snapshot()
        assert snapshot.as_of == "2026-11-14"
        assert not any(name == "@fdcasj_dfew/md-doc-mcp" for _, name, _ in snapshot.pairs)

    @pytest.mark.parametrize("call", _RESCOPED["calls"], ids=_call_id)
    def test_each_call_gets_its_verdict(self, call: dict[str, Any]) -> None:
        guard = _preset_guard(rescope_allow=frozenset(call.get("rescope_allow", ())))
        decision = guard.evaluate(call["args"])
        assert decision.verdict.value == call["verdict"]
        if "listed" in call:
            assert decision.matched_package == call["listed"]

    @pytest.mark.parametrize("call", _RESCOPED["calls"], ids=_call_id)
    def test_match_rescoped_off_gives_the_verdicts_before(self, call: dict[str, Any]) -> None:
        guard = _preset_guard(match_rescoped=False)
        assert guard.evaluate(call["args"]).verdict.value == call["before"]

    def test_the_refusal_names_the_listed_package_and_its_advisory(self) -> None:
        decision = _preset_guard().evaluate({"package": "@fdcasj_dfew/md-doc-mcp@1.0.0"})
        assert decision.verdict is OIDCPublishWindowVerdict.DENY_RESCOPED_MALWARE_NAME
        assert decision.detail.startswith(
            "@fdcasj_dfew/md-doc-mcp shares the basename of @ifasn/md-doc-mcp, GHSA-rvw8-22w3-342v"
        )
        assert decision.matched_version is None

    def test_every_version_and_spelling_is_refused(self) -> None:
        guard = _preset_guard()
        for args in (
            {"package": "@fdcasj_dfew/md-doc-mcp@99.0.0"},
            {"package": "@FDCASJ_DFEW/MD-DOC-MCP"},
            {"package": "alias@npm:@fdcasj_dfew/md-doc-mcp@1.0.0"},
            {"package": "md-docs", "version": "npm:@fdcasj_dfew/md-doc-mcp@1.0.0"},
        ):
            verdict = guard.evaluate(args).verdict
            assert verdict is OIDCPublishWindowVerdict.DENY_RESCOPED_MALWARE_NAME, args

    @pytest.mark.parametrize(
        "url",
        [
            "https://registry.npmjs.org/@fdcasj_dfew/md-doc-mcp/-/md-doc-mcp-1.0.0.tgz",
            "https://registry.yarnpkg.com/@fdcasj_dfew%2fmd-doc-mcp/-/md-doc-mcp-1.0.1.tgz",
        ],
    )
    def test_a_tarball_url_for_it_is_refused(self, url: str) -> None:
        guard = _preset_guard()
        for args in ({"url": url}, {"package": url}):
            verdict = guard.evaluate(args).verdict
            assert verdict is OIDCPublishWindowVerdict.DENY_RESCOPED_MALWARE_NAME, args

    def test_an_unscoped_copy_and_a_listed_name_s_other_version_are_not_rescopes(self) -> None:
        guard = _preset_guard()
        assert guard.evaluate({"package": "md-doc-mcp@1.0.0"}).allowed is True
        assert guard.evaluate({"package": "@ifasn/md-doc-mcp@9.9.9"}).allowed is True


class TestRescopedNamesConstruction:
    def test_without_the_keyword_nothing_changes(self) -> None:
        guard = OIDCPublishWindowGuard()
        assert guard.evaluate({"package": "@x/md-doc-mcp@1.0.0"}).allowed is True

    def test_a_rescope_needs_no_installs_from(self) -> None:
        guard = OIDCPublishWindowGuard(
            rescoped_names={"md-doc-mcp": ("@ifasn/md-doc-mcp", "GHSA-rvw8-22w3-342v")}
        )
        decision = guard.evaluate({"package": "@x/md-doc-mcp@1.0.0"})
        assert decision.verdict is OIDCPublishWindowVerdict.DENY_RESCOPED_MALWARE_NAME

    @pytest.mark.parametrize(
        "kwargs",
        [
            {"rescoped_names": [("md-doc-mcp", ("@a/md-doc-mcp", "GHSA-x"))]},
            {"rescoped_names": {"md-doc-mcp": "@a/md-doc-mcp"}},
            {"rescoped_names": {1: ("@a/md-doc-mcp", "GHSA-x")}},
            {"rescope_allow": {"@a/md-doc-mcp"}},
            {"rescope_allow": frozenset({1})},
        ],
    )
    def test_wrong_types_raise_type_error(self, kwargs: dict[str, Any]) -> None:
        with pytest.raises(TypeError):
            OIDCPublishWindowGuard(**kwargs)

    def test_the_verdict_value_is_stable(self) -> None:
        assert OIDCPublishWindowVerdict.DENY_RESCOPED_MALWARE_NAME.value == (
            "deny_rescoped_malware_name"
        )


class TestAVersionFieldThatInstallsAnotherPackage:
    """``version`` beside ``package`` can name another package (an alias) or a tarball.

    Until 0.10.36 an alias with no version was read as a version of ``package`` and a tarball
    URL as a version that matched nothing, so both walked past every list.
    """

    GUARD = OIDCPublishWindowGuard(
        blast_list=frozenset({("npm", "listed", "1.2.3")}),
        blocked_packages=frozenset({("npm", "evil"), ("npm", "@bad/pkg")}),
        rescoped_names={"md-doc-mcp": ("@ifasn/md-doc-mcp", "GHSA-rvw8-22w3-342v")},
        installs_from="npm",
    )

    @pytest.mark.parametrize(
        ("version", "verdict"),
        [
            ("npm:evil", OIDCPublishWindowVerdict.DENY_BLAST_LIST_PAIR),
            ("NPM:Evil", OIDCPublishWindowVerdict.DENY_BLAST_LIST_PAIR),
            ("npm:evil@", OIDCPublishWindowVerdict.DENY_BLAST_LIST_PAIR),
            ("npm:@bad/pkg", OIDCPublishWindowVerdict.DENY_BLAST_LIST_PAIR),
            ("npm:@bad/pkg@1.0.0", OIDCPublishWindowVerdict.DENY_BLAST_LIST_PAIR),
            ("npm:@x/md-doc-mcp", OIDCPublishWindowVerdict.DENY_RESCOPED_MALWARE_NAME),
            (
                "https://registry.npmjs.org/evil/-/evil-1.0.0.tgz",
                OIDCPublishWindowVerdict.DENY_BLAST_LIST_TARBALL_URL,
            ),
            (
                "https://registry.npmjs.org/listed/-/listed-1.2.3.tgz",
                OIDCPublishWindowVerdict.DENY_BLAST_LIST_TARBALL_URL,
            ),
        ],
    )
    def test_it_is_refused(self, version: str, verdict: OIDCPublishWindowVerdict) -> None:
        for args in (
            {"package": "safe", "version": version},
            {"package": "safe", "version": ["1.0.0", version]},
        ):
            assert self.GUARD.evaluate(args).verdict is verdict, args

    @pytest.mark.parametrize(
        "version",
        ["npm:1.2.3", "npm:^1.2", "npm:1.x", "npm:latest", "npm:*", "latest", "npm:fine", "npm:"],
    )
    def test_a_version_or_another_package_passes(self, version: str) -> None:
        decision = self.GUARD.evaluate({"package": "safe", "version": version})
        assert decision.verdict is OIDCPublishWindowVerdict.ALLOW

    def test_the_outer_packages_own_pair_is_still_read_through_npm(self) -> None:
        decision = self.GUARD.evaluate({"package": "listed", "version": "npm:1.2.3"})
        assert decision.verdict is OIDCPublishWindowVerdict.DENY_BLAST_LIST_PAIR
