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
    MAX_DOCUMENTED_AHEAD,
    MAX_RELEASES_AHEAD,
    MAX_UNPUBLISHED_DAYS,
    evaluate,
    evaluate_documented_vs_tagged,
    newest_documented_version,
    newest_tagged_version,
    parse_version,
    releases_ahead,
)

from scripts import check_registry_parity as gate

#: The exact state of the world this gate was written for.
SHIPPED_REPO = "0.8.83"
SHIPPED_REGISTRY = "0.8.82"

#: A CHANGELOG that documents a release the tags never reached. ``0.8.85`` is written and
#: dated while the newest tag is still ``v0.8.83``, which means ``0.8.84`` was written up
#: and never cut. This is the 2026-09-02 failure, one cycle later — the point at which it
#: becomes visible.
CHANGELOG_AHEAD = """\
# Changelog

All notable changes to Agent-Airlock are documented here.

---

## [Unreleased]

(no entries yet)

## [0.8.85] - 2026-09-03

### Added

- A bidirectional version guard.

## [0.8.84] - 2026-09-02

### Added

- Tool-definition pinning.

## [0.8.83] - 2026-08-26

### Fixed

- An older thing.
"""

#: Raw ``git tag --list`` output for a repo whose tags stop at 0.8.83. Deliberately mixed
#: with non-release refs: the parser must ignore them rather than choke.
TAGS_BEHIND = "nightly\nv0.8.81\nv0.8.82\nv0.8.83\nv0.8.9\n"


@pytest.fixture(autouse=True)
def _neutral_changelog_tag_pair(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the CHANGELOG-vs-tag condition to "indeterminate" for tests not about it.

    ``main`` gained a third condition that reads the real repository. Without this, every
    test that reaches ``main`` would silently also assert something about today's CHANGELOG,
    and a real drift would redden tests that are not about it. The tests that *are* about
    condition 3 set their own values, which win over this fixture.
    """
    monkeypatch.setattr(gate, "documented_version", lambda: None)
    monkeypatch.setattr(gate, "tagged_version", lambda: None)


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


class TestChangelogAheadOfTags:
    """Condition 3: the CHANGELOG documented a release that was never tagged.

    On 2026-09-02 the repo wrote and dated a full ``## [0.8.84] - 2026-09-02`` section and
    never cut the tag. Nothing was red: ``check_version_tagged.py`` grants a one-commit
    grace and the bump *was* HEAD, ``check_changelog_heading.py`` found its heading and
    stopped, and this gate's distance check saw the one release of separation that is
    normal between a bump and a release.

    The lesson generalises past the incident: a guard that only checks one direction of
    drift is a guard against one kind of mistake.
    """

    def test_a_changelog_ahead_of_the_tags_fails(self) -> None:
        """The fixture CHANGELOG documents 0.8.85 while tags stop at 0.8.83."""
        documented = newest_documented_version(CHANGELOG_AHEAD)
        tagged = newest_tagged_version(TAGS_BEHIND)
        assert (documented, tagged) == ("0.8.85", "0.8.83")

        failures = evaluate_documented_vs_tagged(documented, tagged)
        assert failures, (
            "CHANGELOG documents 0.8.85 with tags stopping at v0.8.83 — 0.8.84 was written "
            "up and never cut. If this passes, condition 3 is decorative."
        )

    def test_the_failure_names_both_surfaces_and_the_remedy(self) -> None:
        """A gate that fails without naming the remedy gets worked around, not obeyed."""
        (message,) = evaluate_documented_vs_tagged("0.8.85", "0.8.83")
        assert "0.8.85" in message and "v0.8.83" in message
        assert "git tag -a v0.8.85" in message
        assert "gh release create" in message
        assert "[Unreleased]" in message, "the roll-back path must be offered too"

    def test_main_exits_1_on_that_pair(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """End-to-end through main: the wiring, not only the arithmetic."""
        monkeypatch.setattr(gate, "declared_version", lambda: "0.8.85")
        monkeypatch.setattr(gate, "registry_version", lambda: "0.8.85")
        monkeypatch.setattr(gate, "bump_age_days", lambda _v: 0)
        monkeypatch.setattr(gate, "documented_version", lambda: "0.8.85")
        monkeypatch.setattr(gate, "tagged_version", lambda: "0.8.83")
        assert gate.main([]) == 1

    def test_it_fails_at_publish_time_too(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Unlike the age check, this condition cannot deadlock its own remedy.

        Tagging is what fixes it, and the tag exists before publish.yml runs, so the
        condition is safe to enforce in ``--distance-only`` mode.
        """
        monkeypatch.setattr(gate, "declared_version", lambda: "0.8.85")
        monkeypatch.setattr(gate, "registry_version", lambda: "0.8.85")
        monkeypatch.setattr(gate, "bump_age_days", lambda _v: 0)
        monkeypatch.setattr(gate, "documented_version", lambda: "0.8.85")
        monkeypatch.setattr(gate, "tagged_version", lambda: "0.8.83")
        assert gate.main(["--distance-only"]) == 1


class TestChangelogConditionBoundary:
    """Where condition 3 deliberately stops, so the boundary is a decision on the record."""

    def test_one_cycle_ahead_passes_by_design(self) -> None:
        """The 2026-09-02 state itself passes — and that is the documented threshold.

        One dated section ahead of the newest tag is the ordinary state for the minutes
        between writing the release commit and pushing the tag. A gate firing there would
        fire on every release and be switched off within a week. The single-cycle case is
        condition 2's age check; this one catches the release *after* it.
        """
        assert evaluate_documented_vs_tagged("0.8.84", "0.8.83") == []

    def test_equal_passes(self) -> None:
        assert evaluate_documented_vs_tagged("0.8.84", "0.8.84") == []

    def test_a_clean_minor_rollover_is_one_release_not_a_gap(self) -> None:
        assert evaluate_documented_vs_tagged("0.9.0", "0.8.83") == []

    def test_a_rollover_that_also_skips_a_patch_fails(self) -> None:
        assert evaluate_documented_vs_tagged("0.9.1", "0.8.83")

    def test_a_tag_ahead_of_the_changelog_is_not_this_gates_seam(self) -> None:
        """check_changelog_heading.py owns that direction; two gates, one owner is worse."""
        assert evaluate_documented_vs_tagged("0.8.83", "0.8.84") == []


class TestChangelogConditionIsLenient:
    """Indeterminate must never mean red — that is how a gate gets switched off."""

    @pytest.mark.parametrize(
        ("documented", "tagged"),
        [(None, "0.8.83"), ("0.8.85", None), (None, None)],
    )
    def test_missing_surfaces_pass(self, documented: str | None, tagged: str | None) -> None:
        assert evaluate_documented_vs_tagged(documented, tagged) == []

    def test_a_tagless_checkout_passes(self) -> None:
        """publish.yml checks out without fetch-tags, so this is its routine state."""
        assert newest_tagged_version("") is None
        assert evaluate_documented_vs_tagged("0.8.85", newest_tagged_version("")) == []

    def test_unparseable_versions_pass(self) -> None:
        assert evaluate_documented_vs_tagged("main", "0.8.83") == []


class TestChangelogParsing:
    def test_unreleased_is_not_a_documented_release(self) -> None:
        """An undated [Unreleased] section makes no claim to have shipped."""
        assert newest_documented_version("## [Unreleased]\n\n(no entries yet)\n") is None

    def test_it_picks_the_newest_not_the_first(self) -> None:
        out_of_order = (
            "## [0.8.83] - 2026-08-26\n## [0.8.85] - 2026-09-03\n## [0.8.84] - 2026-09-02\n"
        )
        assert newest_documented_version(out_of_order) == "0.8.85"

    def test_a_four_component_hotfix_outranks_its_base(self) -> None:
        """0.5.7.1 and 0.5.6.1 shipped; truncating to a triple would tie them."""
        assert (
            newest_documented_version("## [0.5.7] - 2026-01-01\n## [0.5.7.1] - 2026-01-02\n")
            == "0.5.7.1"
        )

    def test_non_release_refs_are_ignored(self) -> None:
        assert newest_tagged_version(TAGS_BEHIND) == "0.8.83"

    def test_no_headings_at_all(self) -> None:
        assert newest_documented_version("# Changelog\n\nnothing here\n") is None


class TestLiveChangelogTagPair:
    """The real pair, asserted last and for what it is worth."""

    def test_the_repo_is_not_currently_documenting_an_untagged_release(self) -> None:
        assert evaluate_documented_vs_tagged(gate.documented_version(), gate.tagged_version()) == []

    def test_the_threshold_is_the_documented_one(self) -> None:
        assert MAX_DOCUMENTED_AHEAD == 1
