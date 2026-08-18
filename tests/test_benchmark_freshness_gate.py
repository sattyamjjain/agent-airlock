"""The benchmark-freshness gate must actually fire.

`scripts/check_benchmark_freshness.py` exists because the README's five benchmark rows —
one of them a competitive claim against a named third-party product at a pinned version —
were kept honest only by a human remembering to re-run. The 2026-07-16 gateway claim sat a
month past its run before anyone noticed.

A gate nobody has watched fail is the same failure class it was built to prevent, so these
tests drive it against synthetic READMEs rather than only asserting that today's real one
passes.

The two modes are tested separately because the split is the design:

* **default** is structural — a row must carry *some* date. It never flaps on a calendar
  boundary, so it is safe on every commit.
* **``--release``** additionally enforces the 30-day window. It is a pre-tag gate because a
  stale claim matters when it is published, and failing unrelated commits for weeks is how
  a gate gets switched off.
"""

from __future__ import annotations

import datetime as _dt
from pathlib import Path

import pytest
from scripts.check_benchmark_freshness import BENCHMARKS, MAX_AGE_DAYS, main

_ROOT = Path(__file__).resolve().parents[1]


def _today() -> _dt.date:
    return _dt.datetime.now(_dt.timezone.utc).date()


def _readme_with(
    gateway_date: _dt.date,
    *,
    drop_marker_for: str | None = None,
) -> str:
    """A synthetic README carrying one line per identifier the gate knows about.

    Derived from ``BENCHMARKS`` rather than hardcoding today's rows, so adding a seventh
    benchmark cannot silently break these tests — which is exactly what happened when the
    injection row became the sixth.

    Args:
        gateway_date: Date to stamp on the gateway row (the one aged in staleness tests).
        drop_marker_for: Identifier to emit *without* a date, for the structural test.
    """
    fresh = _today().isoformat()
    lines = []
    for identifier in BENCHMARKS:
        if identifier == drop_marker_for:
            lines.append(f"| row for `{identifier}` with no date |")
            continue
        date = gateway_date if "vs_gateway" in identifier else _today()
        marker = "re-measured live" if "vs_gateway" in identifier else "last verified"
        lines.append(f"| row · _{marker} {date.isoformat()}_ · `{identifier}` |")
    assert fresh  # keeps the helper honest if BENCHMARKS is ever emptied
    return "\n".join(lines)


@pytest.fixture
def patched_readme(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    """Point the gate at a synthetic README."""

    def _install(content: str) -> None:
        path = tmp_path / "README.md"
        path.write_text(content, encoding="utf-8")
        monkeypatch.setattr("scripts.check_benchmark_freshness._README", path)

    return _install


class TestTheGateFiresWhenItShould:
    """The assertions that matter. Each one is a way the claim could go stale."""

    def test_release_mode_fails_on_a_stale_claim(self, patched_readme, capsys) -> None:
        stale = _today() - _dt.timedelta(days=MAX_AGE_DAYS + 1)
        patched_readme(_readme_with(stale))

        assert main(["--release"]) == 1
        err = capsys.readouterr().err
        assert "older than 30 days" in err
        assert "Gateway" in err or "gateway" in err.lower()

    def test_the_failure_names_how_to_re_run_it(self, patched_readme, capsys) -> None:
        """An actionable failure. 'Something is stale' with no next step gets ignored."""
        patched_readme(_readme_with(_today() - _dt.timedelta(days=90)))

        main(["--release"])
        assert "regen" in capsys.readouterr().err, "the failure did not say how to re-run"

    def test_default_mode_fails_on_a_missing_date(self, patched_readme, capsys) -> None:
        patched_readme(_readme_with(_today(), drop_marker_for="benchmarks.blockrate"))

        assert main([]) == 1
        assert "no freshness marker" in capsys.readouterr().err


class TestTheGateStaysQuietWhenItShould:
    """A gate that cries wolf gets switched off, which is worse than not having one."""

    def test_fresh_rows_pass_both_modes(self, patched_readme) -> None:
        patched_readme(_readme_with(_today()))
        assert main([]) == 0
        assert main(["--release"]) == 0

    def test_default_mode_does_not_flap_on_a_stale_date(self, patched_readme) -> None:
        """The load-bearing distinction: staleness is a *release* concern, not a push one.

        Without this, the gate would turn CI red on a calendar boundary with no code
        change, on every unrelated commit, until someone re-ran a benchmark that may need
        API keys and real money. That is the shape of a gate people delete.
        """
        patched_readme(_readme_with(_today() - _dt.timedelta(days=365)))
        assert main([]) == 0, "default mode flapped on an old date"
        assert main(["--release"]) == 1, "release mode missed a year-old claim"

    def test_a_row_exactly_at_the_boundary_passes(self, patched_readme) -> None:
        patched_readme(_readme_with(_today() - _dt.timedelta(days=MAX_AGE_DAYS)))
        assert main(["--release"]) == 0


class TestTheGateCoversTheRealReadme:
    """Structural checks against the shipped README, not a synthetic one."""

    def test_every_known_benchmark_is_found_in_the_readme(self) -> None:
        """Guards against a row being renamed and quietly dropping out of coverage."""
        readme = (_ROOT / "README.md").read_text(encoding="utf-8")
        missing = [ident for ident in BENCHMARKS if ident not in readme]
        assert missing == [], f"gate identifiers no longer present in README.md: {missing}"

    def test_the_shipped_readme_passes_the_structural_gate(self) -> None:
        assert main([]) == 0
