"""The registry-parity gate must actually fire.

``scripts/check_registry_parity.py`` exists because on 2026-08-31 the repo declared
``0.8.83`` in ``pyproject.toml``, in ``agent_airlock.__version__``, in the README badge and
in a written CHANGELOG section, while PyPI served ``0.8.82`` — and nothing was red. Every
version gate the repo owned compared one repo-internal surface to another, so a repo that
was perfectly consistent about an uninstallable version passed all of them.

A gate nobody has watched fail is the same failure class it was built to prevent, so these
tests seed synthetic versions rather than only asserting that today's real pair passes.
Today's pair will be equal for most of the repo's life, which makes the live check a weak
witness: it would pass just as happily if ``evaluate`` were ``return []``.

Nothing here touches the network. ``registry_version`` is patched in every test that
reaches ``main``; a gate whose test suite depends on PyPI being up is a gate that gets
switched off the first time PyPI is down.
"""

from __future__ import annotations

import pytest
from scripts.check_registry_parity import (
    MAX_RELEASES_AHEAD,
    MAX_UNPUBLISHED_DAYS,
    evaluate,
    parse_version,
    releases_ahead,
)

from scripts import check_registry_parity as gate

#: The exact state of the world this gate was written for.
SHIPPED_REPO = "0.8.83"
SHIPPED_REGISTRY = "0.8.82"


class TestTheConditionThatShipped:
    """The 2026-08-31 state must fail. This is the regression test; the rest is coverage."""

    def test_declared_ahead_and_stale_fails(self) -> None:
        failures = evaluate(SHIPPED_REPO, SHIPPED_REGISTRY, MAX_UNPUBLISHED_DAYS + 2)
        assert failures, (
            "repo 0.8.83 / PyPI 0.8.82, five days unpublished — the exact condition that "
            "went unnoticed. If this passes, the gate is decorative."
        )
        assert SHIPPED_REPO in failures[0] and SHIPPED_REGISTRY in failures[0]

    def test_the_failure_says_how_to_fix_it(self) -> None:
        """A gate that fails without naming the remedy gets worked around, not obeyed."""
        (message,) = evaluate(SHIPPED_REPO, SHIPPED_REGISTRY, MAX_UNPUBLISHED_DAYS + 2)
        assert "gh release create" in message
        assert f"v{SHIPPED_REPO}" in message

    def test_it_passes_once_published(self) -> None:
        assert evaluate(SHIPPED_REPO, SHIPPED_REPO, 99) == []


class TestAge:
    """One release ahead is normal for hours and suspicious for days."""

    def test_fresh_bump_is_a_release_in_flight_not_drift(self) -> None:
        assert evaluate("0.8.83", "0.8.82", 0) == []

    @pytest.mark.parametrize("days", [1, MAX_UNPUBLISHED_DAYS])
    def test_inside_the_window_passes(self, days: int) -> None:
        assert evaluate("0.8.83", "0.8.82", days) == []

    def test_one_day_past_the_window_fails(self) -> None:
        assert evaluate("0.8.83", "0.8.82", MAX_UNPUBLISHED_DAYS + 1)

    def test_unknown_age_does_not_fail(self) -> None:
        """A shallow checkout has no bump commit to date. Indeterminate is not drift."""
        assert evaluate("0.8.83", "0.8.82", None) == []


class TestDistance:
    """Being two releases ahead means an earlier version was declared and never published."""

    def test_two_patches_ahead_fails_even_when_fresh(self) -> None:
        failures = evaluate("0.8.84", "0.8.82", 0)
        assert failures and "2 releases" in failures[0]

    def test_a_skipped_minor_fails(self) -> None:
        """0.10.0 over 0.8.83 means every 0.9.x was declared and never shipped."""
        assert evaluate("0.10.0", "0.8.83", 0)

    def test_registry_ahead_of_repo_fails(self) -> None:
        failures = evaluate("0.8.82", "0.8.83", 0)
        assert failures and "AHEAD of the repo" in failures[0]

    @pytest.mark.parametrize(
        ("repo", "registry"),
        [("0.9.0", "0.8.83"), ("1.0.0", "0.9.4")],
    )
    def test_a_clean_rollover_is_one_release_not_a_gap(self, repo: str, registry: str) -> None:
        """A minor or major bump is still a single release. Failing it would make this
        gate wrong in the direction that gets it deleted."""
        assert releases_ahead(parse_version(repo), parse_version(registry)) == 1
        assert evaluate(repo, registry, 0) == []


class TestDistanceOnlyCannotDeadlockPublish:
    """``--distance-only`` exists so publish.yml cannot block its own remedy.

    At publish time the repo is always ahead of the registry — that is what publishing
    means. An age check there would fail the release that resolves the staleness.
    """

    def test_the_stale_case_passes_with_the_age_check_off(self) -> None:
        assert evaluate(SHIPPED_REPO, SHIPPED_REGISTRY, 90, check_age=False) == []

    def test_but_a_real_gap_still_fails(self) -> None:
        assert evaluate("0.8.84", "0.8.82", 0, check_age=False)


class TestMainSeedsAndFails:
    """End-to-end through ``main``: the wiring, not only the arithmetic."""

    def test_seeded_ahead_version_exits_1(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(gate, "declared_version", lambda: SHIPPED_REPO)
        monkeypatch.setattr(gate, "registry_version", lambda: SHIPPED_REGISTRY)
        monkeypatch.setattr(gate, "bump_age_days", lambda _v: MAX_UNPUBLISHED_DAYS + 2)
        assert gate.main([]) == 1

    def test_same_seed_passes_with_distance_only(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(gate, "declared_version", lambda: SHIPPED_REPO)
        monkeypatch.setattr(gate, "registry_version", lambda: SHIPPED_REGISTRY)
        monkeypatch.setattr(gate, "bump_age_days", lambda _v: MAX_UNPUBLISHED_DAYS + 2)
        assert gate.main(["--distance-only"]) == 0

    def test_matching_versions_exit_0(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(gate, "declared_version", lambda: SHIPPED_REPO)
        monkeypatch.setattr(gate, "registry_version", lambda: SHIPPED_REPO)
        monkeypatch.setattr(gate, "bump_age_days", lambda _v: 0)
        assert gate.main([]) == 0


class TestLenientWhenIndeterminate:
    """A registry outage must not turn the repo red — that is how a gate gets deleted."""

    def test_unreachable_registry_passes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(gate, "registry_version", lambda: None)
        assert gate.main([]) == 0

    def test_unparseable_registry_version_passes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(gate, "declared_version", lambda: SHIPPED_REPO)
        monkeypatch.setattr(gate, "registry_version", lambda: "not-a-version")
        monkeypatch.setattr(gate, "bump_age_days", lambda _v: 0)
        assert gate.main([]) == 0

    def test_registry_fetch_swallows_network_errors(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _boom(*_args: object, **_kwargs: object) -> None:
            raise OSError("no route to host")

        monkeypatch.setattr(gate.urllib.request, "urlopen", _boom)
        assert gate.registry_version() is None


class TestParsing:
    def test_parses_a_plain_triple(self) -> None:
        assert parse_version("0.8.83") == (0, 8, 83)

    def test_rejects_garbage(self) -> None:
        with pytest.raises(ValueError, match="unparseable version"):
            parse_version("main")


class TestLiveRepoState:
    """The real pair, asserted last and for what it is worth.

    This passes trivially whenever the repo is published, which is why every test above
    seeds its own versions instead of relying on it.
    """

    def test_declared_version_is_parseable(self) -> None:
        assert parse_version(gate.declared_version())

    def test_constants_are_the_documented_thresholds(self) -> None:
        assert MAX_RELEASES_AHEAD == 1
        assert MAX_UNPUBLISHED_DAYS == 3
