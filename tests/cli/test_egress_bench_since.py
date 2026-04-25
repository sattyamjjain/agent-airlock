"""Tests for the ``--since`` flag on the egress-bench walker (v0.5.6+).

Imports the script as a module via ``importlib.util`` so we can call
``walk()``, ``_parse_iso_date()``, and ``_require_disclosed_at()``
directly without spawning a subprocess.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from datetime import date
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPT = ROOT / "scripts" / "egress_bench.py"

_spec = importlib.util.spec_from_file_location("egress_bench_test_module", SCRIPT)
assert _spec is not None
egress_bench = importlib.util.module_from_spec(_spec)
# Register in sys.modules before exec — dataclass decorator looks up
# cls.__module__ during class construction.
sys.modules["egress_bench_test_module"] = egress_bench
assert _spec.loader is not None
_spec.loader.exec_module(egress_bench)


def _write_fixture(path: Path, content: dict) -> None:
    path.write_text(json.dumps(content), encoding="utf-8")


@pytest.fixture
def tmp_fixture_dir(tmp_path: Path) -> Path:
    """Build a synthetic fixture dir with three dated files."""
    d = tmp_path / "fixtures"
    d.mkdir()
    _write_fixture(
        d / "old_cve.json",
        {
            "disclosed_at": "2025-12-15",
            "destructive_tools": [{"name": "delete_pod"}],
        },
    )
    _write_fixture(
        d / "mid_cve.json",
        {
            "disclosed_at": "2026-04-09",
            "destructive_tools": [{"name": "drop_db"}],
        },
    )
    _write_fixture(
        d / "fresh_cve.json",
        {
            "disclosed_at": "2026-04-24",
            "cves": [{"id": "CVE-2026-99999", "source": "https://example.com"}],
        },
    )
    return d


class TestParseIsoDate:
    @pytest.mark.parametrize(
        "value,expected",
        [
            ("2026", date(2026, 1, 1)),
            ("2026-04", date(2026, 4, 1)),
            ("2026-04-25", date(2026, 4, 25)),
        ],
    )
    def test_valid_dates(self, value: str, expected: date) -> None:
        assert egress_bench._parse_iso_date(value) == expected

    @pytest.mark.parametrize("value", ["2026/04/25", "April 25 2026", "2026-4-25", ""])
    def test_invalid_dates(self, value: str) -> None:
        with pytest.raises(egress_bench.FixtureValidationError):
            egress_bench._parse_iso_date(value)


class TestSinceFilter:
    def test_no_filter_returns_all(self, tmp_fixture_dir: Path) -> None:
        rows = egress_bench.walk(tmp_fixture_dir)
        # Three files; non-dispatched ones still get rows (skip status).
        assert len(rows) == 3

    def test_since_filters_old_entries(self, tmp_fixture_dir: Path) -> None:
        rows = egress_bench.walk(tmp_fixture_dir, since=date(2026, 4, 20))
        # All three files are still listed (so the report stays
        # complete) — but two are now `skip` with the since-filter
        # reason rather than actually walked. The fresh fixture
        # passes the date filter; with no dispatcher registered for
        # synthetic test fixture names, it lands in the "no
        # dispatcher" skip branch instead.
        since_filtered = [r for r in rows if "since" in r.reason]
        no_dispatcher = [r for r in rows if "no dispatcher" in r.reason]
        assert len(since_filtered) == 2  # old_cve + mid_cve
        assert len(no_dispatcher) == 1  # fresh_cve passed filter, no handler
        assert all(r.status == "skip" for r in rows)

    def test_since_in_far_future_skips_everything(self, tmp_fixture_dir: Path) -> None:
        rows = egress_bench.walk(tmp_fixture_dir, since=date(2099, 1, 1))
        assert all(r.status == "skip" for r in rows)
        assert all("since" in r.reason for r in rows if "no dispatcher" not in r.reason)


class TestFixtureValidation:
    def test_missing_disclosed_at_raises(self, tmp_path: Path) -> None:
        d = tmp_path / "fixtures"
        d.mkdir()
        _write_fixture(
            d / "no_date.json",
            {"destructive_tools": [{"name": "x"}]},
        )
        with pytest.raises(egress_bench.FixtureValidationError, match="disclosed_at"):
            egress_bench.walk(d)


class TestJsonOutput:
    def test_json_output_includes_filter_metadata(self) -> None:
        rows = [
            egress_bench.Row(
                cve_id="X",
                payload_count=1,
                blocked=1,
                unblocked=0,
                status="pass",
                disclosed_at="2026-04-20",
            )
        ]
        out = egress_bench._emit_json(rows, since=date(2026, 4, 1))
        parsed = json.loads(out)
        assert parsed["filter"]["since"] == "2026-04-01"
        assert parsed["rows"][0]["disclosed_at"] == "2026-04-20"

    def test_json_output_no_filter_meta_field_present(self) -> None:
        rows = [
            egress_bench.Row(
                cve_id="X",
                payload_count=0,
                blocked=0,
                unblocked=0,
                status="skip",
                disclosed_at=None,
            )
        ]
        out = egress_bench._emit_json(rows, since=None)
        parsed = json.loads(out)
        assert parsed["filter"]["since"] is None


class TestRealRepoFixtures:
    """Integration: run the walker against the real ``tests/cves/fixtures/`` dir."""

    def test_real_fixtures_all_have_disclosed_at(self) -> None:
        # Every fixture must satisfy the v0.5.6 requirement, otherwise
        # walk() would raise.
        rows = egress_bench.walk(ROOT / "tests" / "cves" / "fixtures")
        assert rows  # at least one fixture
        for row in rows:
            # Either the fixture validated and we got a real row, or
            # it's the dispatcher-skip case — both have disclosed_at.
            if row.status != "fail":
                assert row.disclosed_at is not None

    def test_since_filter_against_real_fixtures(self) -> None:
        rows = egress_bench.walk(
            ROOT / "tests" / "cves" / "fixtures",
            since=date(2026, 4, 20),
        )
        # The OX umbrella dossier is dated 2026-04-20 exactly so it
        # passes (>= since).
        ox = next(r for r in rows if r.cve_id == "OX-DOSSIER-2026-04")
        assert ox.status == "pass"
