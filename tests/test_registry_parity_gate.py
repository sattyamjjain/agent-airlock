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
    GRANDFATHERED_UNTAGGED,
    MAX_DOCUMENTED_AHEAD,
    MAX_RELEASES_AHEAD,
    MAX_UNPUBLISHED_DAYS,
    MAX_UNRELEASED_AHEAD,
    documented_versions,
    evaluate,
    evaluate_declared_vs_tagged,
    evaluate_documented_vs_tagged,
    has_dated_heading,
    newest_documented_version,
    newest_tagged_version,
    parse_version,
    releases_ahead,
    tagged_versions,
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
    monkeypatch.setattr(gate, "repo_documented_versions", list)
    monkeypatch.setattr(gate, "repo_tagged_versions", set)


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
    """Condition 3: a dated CHANGELOG heading with no tag behind it.

    Two incidents, one shape. On 2026-09-02 the repo wrote and dated a full
    ``## [0.8.84] - 2026-09-02`` section and never cut the tag. Nothing was red:
    ``check_version_tagged.py`` grants a one-commit grace and the bump *was* HEAD,
    ``check_changelog_heading.py`` found its heading and stopped, and this gate's
    then-distance check saw the one release of separation that reads as normal.

    On 2026-09-03 the commit that added condition 3 did it again at ``0.8.85`` — and
    passed its own gate, because ``MAX_DOCUMENTED_AHEAD`` was 1. Both states are asserted
    here, because the threshold that let the second one through was the reason for the
    third.
    """

    def test_todays_exact_state_fails(self) -> None:
        """2026-09-04 08:30 UTC: dated [0.8.85], newest tag v0.8.84. This must be red.

        The state a human had to notice, on the second consecutive morning. If this
        passes, the gate is decorative and the next recurrence is also invisible.
        """
        failures = evaluate_documented_vs_tagged(["0.8.85", "0.8.84"], {"0.8.84", "0.8.83"})
        assert failures, "the state that recurred twice must fail"
        assert "0.8.85" in failures[0]

    def test_yesterdays_state_fails_too(self) -> None:
        """2026-09-02: dated [0.8.84], newest tag v0.8.83 — the original incident.

        Under the old distance threshold this passed. It is the same shape as today's,
        which is the whole argument for checking existence instead of distance.
        """
        assert evaluate_documented_vs_tagged(["0.8.84", "0.8.83"], {"0.8.83"})

    def test_a_changelog_ahead_of_the_tags_fails(self) -> None:
        """The fixture CHANGELOG dates 0.8.85 and 0.8.84 while tags stop at v0.8.83."""
        documented = documented_versions(CHANGELOG_AHEAD)
        tagged = tagged_versions(TAGS_BEHIND)
        assert documented[:2] == ["0.8.85", "0.8.84"]
        assert newest_tagged_version(TAGS_BEHIND) == "0.8.83"

        failures = evaluate_documented_vs_tagged(documented, tagged)
        assert failures, "two dated sections have no tag; if this passes, condition 3 is dead"

    def test_it_names_every_untagged_version_not_just_the_newest(self) -> None:
        """A gate that reports one of two holes sends you round the loop twice."""
        (message,) = evaluate_documented_vs_tagged(["0.8.85", "0.8.84"], {"0.8.83"})
        assert "0.8.85" in message and "0.8.84" in message

    def test_the_failure_names_both_surfaces_and_the_remedy(self) -> None:
        """A gate that fails without naming the remedy gets worked around, not obeyed."""
        (message,) = evaluate_documented_vs_tagged(["0.8.85"], {"0.8.83"})
        assert "0.8.85" in message and "v0.8.83" in message
        assert "git tag -a v0.8.85" in message
        assert "git push --atomic" in message, "the atomic push is how you avoid tripping it"
        assert "gh release create" in message
        assert "[Unreleased]" in message, "the roll-back path must be offered too"

    def test_main_exits_1_on_that_pair(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """End-to-end through main: the wiring, not only the arithmetic."""
        monkeypatch.setattr(gate, "declared_version", lambda: "0.8.85")
        monkeypatch.setattr(gate, "registry_version", lambda: "0.8.85")
        monkeypatch.setattr(gate, "bump_age_days", lambda _v: 0)
        monkeypatch.setattr(gate, "repo_documented_versions", lambda: ["0.8.85", "0.8.84"])
        monkeypatch.setattr(gate, "repo_tagged_versions", lambda: {"0.8.83"})
        assert gate.main([]) == 1

    def test_it_fails_at_publish_time_too(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Unlike the age check, this condition cannot deadlock its own remedy.

        Tagging is what fixes it, and the tag exists before publish.yml runs, so the
        condition is safe to enforce in ``--distance-only`` mode.
        """
        monkeypatch.setattr(gate, "declared_version", lambda: "0.8.85")
        monkeypatch.setattr(gate, "registry_version", lambda: "0.8.85")
        monkeypatch.setattr(gate, "bump_age_days", lambda _v: 0)
        monkeypatch.setattr(gate, "repo_documented_versions", lambda: ["0.8.85"])
        monkeypatch.setattr(gate, "repo_tagged_versions", lambda: {"0.8.83"})
        assert gate.main(["--distance-only"]) == 1


class TestTheThresholdIsZero:
    """The boundary, on the record, because moving it is what caused the recurrence."""

    def test_one_cycle_ahead_no_longer_passes(self) -> None:
        """The regression test for the fix itself.

        This exact assertion was inverted on 2026-09-03 — it asserted ``== []`` and was
        named ``test_one_cycle_ahead_passes_by_design``. The design was wrong, so the
        assertion flipped rather than being deleted: the record of what changed is the
        point.
        """
        assert evaluate_documented_vs_tagged(["0.8.84"], {"0.8.83"})

    def test_the_threshold_is_zero(self) -> None:
        assert MAX_DOCUMENTED_AHEAD == 0

    def test_equal_passes(self) -> None:
        assert evaluate_documented_vs_tagged(["0.8.84"], {"0.8.84"}) == []

    def test_every_dated_section_tagged_passes(self) -> None:
        assert evaluate_documented_vs_tagged(["0.8.84", "0.8.83"], {"0.8.84", "0.8.83"}) == []

    def test_a_clean_minor_rollover_still_needs_its_tag(self) -> None:
        """Rollover leniency belongs to the distance conditions, not to an existence check."""
        assert evaluate_documented_vs_tagged(["0.9.0"], {"0.8.83"})
        assert evaluate_documented_vs_tagged(["0.9.0"], {"0.9.0", "0.8.83"}) == []

    def test_a_tag_ahead_of_the_changelog_is_not_this_gates_seam(self) -> None:
        """check_changelog_heading.py owns that direction; two gates, one owner is worse."""
        assert evaluate_documented_vs_tagged(["0.8.83"], {"0.8.84", "0.8.83"}) == []

    def test_a_mid_history_hole_fails_not_only_the_newest(self) -> None:
        """The old condition compared maxima, so a gap under the tag line was invisible."""
        assert evaluate_documented_vs_tagged(["0.8.85", "0.8.84"], {"0.8.85", "0.8.83"})


class TestUnreleasedIsWhereTheAllowanceLives:
    """pyproject may run ahead of the tags only while its section is still [Unreleased]."""

    def test_one_ahead_while_unreleased_passes(self) -> None:
        """The in-flight state the strict threshold depends on being available."""
        assert evaluate_declared_vs_tagged("0.8.86", {"0.8.85"}, declared_is_dated=False) == []

    def test_two_ahead_while_unreleased_fails(self) -> None:
        """A version in between was never cut."""
        assert evaluate_declared_vs_tagged("0.8.87", {"0.8.85"}, declared_is_dated=False)

    def test_a_dated_declared_version_is_the_other_conditions_business(self) -> None:
        """Once dated, the existence check owns it — no distance allowance applies."""
        assert evaluate_declared_vs_tagged("0.8.86", {"0.8.85"}, declared_is_dated=True) == []

    def test_the_unreleased_allowance_is_one(self) -> None:
        assert MAX_UNRELEASED_AHEAD == 1

    def test_no_tags_passes(self) -> None:
        assert evaluate_declared_vs_tagged("0.8.86", set(), declared_is_dated=False) == []

    def test_unparseable_declared_version_passes(self) -> None:
        assert evaluate_declared_vs_tagged("main", {"0.8.85"}, declared_is_dated=False) == []

    def test_the_two_conditions_compose_on_the_real_release_shape(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Feature work: bumped, undated, one ahead, all tags present. Must be green."""
        monkeypatch.setattr(gate, "declared_version", lambda: "0.8.86")
        monkeypatch.setattr(gate, "registry_version", lambda: "0.8.85")
        monkeypatch.setattr(gate, "bump_age_days", lambda _v: 0)
        monkeypatch.setattr(gate, "repo_documented_versions", lambda: ["0.8.85", "0.8.84"])
        monkeypatch.setattr(gate, "repo_tagged_versions", lambda: {"0.8.85", "0.8.84"})
        assert gate.main([]) == 0


class TestGrandfatheredHistory:
    """Three versions predate consistent tagging. The exception is named, not silent."""

    def test_the_known_untagged_history_passes(self) -> None:
        assert evaluate_documented_vs_tagged(["0.3.0", "0.1.1", "0.1.0"], {"0.4.0"}) == []

    def test_grandfather_list_is_closed(self) -> None:
        """If this fails, someone widened the exception instead of cutting a release.

        A grandfather list that grows is a gate being switched off one entry at a time,
        so the contents are pinned rather than merely the behaviour.
        """
        assert sorted(GRANDFATHERED_UNTAGGED) == ["0.1.0", "0.1.1", "0.3.0"]

    def test_a_new_untagged_version_is_not_covered_by_it(self) -> None:
        assert evaluate_documented_vs_tagged(["0.8.85", "0.3.0"], {"0.8.84"})


class TestChangelogConditionIsLenient:
    """Indeterminate must never mean red — that is how a gate gets switched off."""

    @pytest.mark.parametrize(
        ("documented", "tagged"),
        [([], {"0.8.83"}), (["0.8.85"], set()), ([], set())],
    )
    def test_missing_surfaces_pass(self, documented: list[str], tagged: set[str]) -> None:
        assert evaluate_documented_vs_tagged(documented, tagged) == []

    def test_a_tagless_checkout_passes(self) -> None:
        """publish.yml checks out without fetch-tags, so this is its routine state."""
        assert tagged_versions("") == set()
        assert evaluate_documented_vs_tagged(["0.8.85"], tagged_versions("")) == []


class TestChangelogParsing:
    def test_unreleased_is_not_a_documented_release(self) -> None:
        """An undated [Unreleased] section makes no claim to have shipped."""
        assert documented_versions("## [Unreleased]\n\n(no entries yet)\n") == []
        assert newest_documented_version("## [Unreleased]\n\n(no entries yet)\n") is None

    def test_it_returns_newest_first_not_file_order(self) -> None:
        out_of_order = (
            "## [0.8.83] - 2026-08-26\n## [0.8.85] - 2026-09-03\n## [0.8.84] - 2026-09-02\n"
        )
        assert documented_versions(out_of_order) == ["0.8.85", "0.8.84", "0.8.83"]

    def test_a_four_component_hotfix_outranks_its_base(self) -> None:
        """0.5.7.1 and 0.5.6.1 shipped; truncating to a triple would tie them."""
        assert documented_versions("## [0.5.7] - 2026-01-01\n## [0.5.7.1] - 2026-01-02\n") == [
            "0.5.7.1",
            "0.5.7",
        ]

    def test_non_release_refs_are_ignored(self) -> None:
        assert tagged_versions(TAGS_BEHIND) == {"0.8.81", "0.8.82", "0.8.83", "0.8.9"}
        assert newest_tagged_version(TAGS_BEHIND) == "0.8.83"

    def test_no_headings_at_all(self) -> None:
        assert documented_versions("# Changelog\n\nnothing here\n") == []

    def test_has_dated_heading_separates_dated_from_unreleased(self) -> None:
        """The [Unreleased]/dated distinction the whole allowance rests on."""
        text = "## [Unreleased]\n\n- a thing\n\n## [0.8.85] - 2026-09-03\n"
        assert has_dated_heading(text, "0.8.85")
        assert not has_dated_heading(text, "0.8.86")


class TestLiveRepoChangelogTagPair:
    """The real repository, asserted last. This is the check that would have caught it."""

    def test_no_dated_section_is_currently_untagged(self) -> None:
        """Reads the actual CHANGELOG and the actual tags — no fixtures, no monkeypatch."""
        failures = evaluate_documented_vs_tagged(
            gate.repo_documented_versions(), gate.repo_tagged_versions()
        )
        assert failures == [], failures

    def test_the_declared_version_is_within_its_allowance(self) -> None:
        declared = gate.declared_version()
        documented = gate.repo_documented_versions()
        assert (
            evaluate_declared_vs_tagged(
                declared,
                gate.repo_tagged_versions(),
                declared_is_dated=declared in set(documented),
            )
            == []
        )
