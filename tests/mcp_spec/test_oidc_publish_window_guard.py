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

    def test_fixture_contains_cross_ecosystem_entries(self) -> None:
        """The Aikido 2026-05-11 cross-ecosystem entries must be present."""
        entries = load_blast_list_from_2026_05_11()
        ecosystems = {eco for eco, _, _ in entries}
        # PyPI cross-ecosystem (pytorch-lightning, etc.) confirmed in Aikido blog.
        assert "pypi" in ecosystems, (
            "cross-ecosystem PyPI entries from Aikido 2026-05-11 must be in fixture"
        )

    def test_fixture_json_source_field_records_url(self) -> None:
        from importlib.resources import files

        from agent_airlock.mcp_spec.oidc_publish_window_guard import (
            _FIXTURE_PACKAGE,
            _FIXTURE_RESOURCE_NAME,
        )

        raw = (files(_FIXTURE_PACKAGE) / _FIXTURE_RESOURCE_NAME).read_text(encoding="utf-8")
        payload = json.loads(raw)
        assert "tanstack.com" in payload["source"]
        assert payload["as_of"].startswith("2026-05-11")
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
