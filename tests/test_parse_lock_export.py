"""Regression test for the v0.7.1 parse_lock top-level re-export.

The v0.6.0/v0.6.1/v0.7.0 release notes carried a "parse_lock not
re-exported" honesty note for three releases. v0.7.1 closes the gap;
this test makes sure the surface stays public and round-trippable.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import agent_airlock
from agent_airlock import (
    LockEntry,
    LockfileFormatError,
    PolicyBundleLock,
    build_lock,
    parse_lock,
    write_lock,
)
from agent_airlock.pack import render_lock
from agent_airlock.pack.lock import parse_lock as _canonical_parse_lock


class TestParseLockTopLevelExport:
    """parse_lock is reachable from the top-level package."""

    def test_top_level_import_succeeds(self) -> None:
        from agent_airlock import parse_lock as imported  # noqa: PLC0415

        assert callable(imported)

    def test_top_level_alias_is_canonical_callable(self) -> None:
        """``agent_airlock.parse_lock is agent_airlock.pack.lock.parse_lock``."""
        assert parse_lock is _canonical_parse_lock

    def test_parse_lock_in_dunder_all(self) -> None:
        assert "parse_lock" in agent_airlock.__all__

    def test_round_trip_write_then_parse(self, tmp_path: Path) -> None:
        """write_lock(...) → parse_lock(read text) returns an equivalent lock."""
        from agent_airlock.pack.lock import LOCK_SCHEMA_VERSION

        original = PolicyBundleLock(
            schema_version=LOCK_SCHEMA_VERSION,
            airlock_version="0.7.1",
            generated_at="2026-05-04T00:00:00Z",
            entries=(
                LockEntry(
                    preset_id="example_preset",
                    content_sha256="0" * 64,
                ),
            ),
        )
        path = tmp_path / "policy_bundle.lock"
        write_lock(original, path)

        text = path.read_text(encoding="utf-8")
        round_tripped = parse_lock(text)

        # Field-by-field comparison — sha256 + preset_id must survive
        # the write → parse leg.
        assert round_tripped.airlock_version == original.airlock_version
        assert round_tripped.generated_at == original.generated_at
        assert len(round_tripped.entries) == 1
        assert round_tripped.entries[0].preset_id == "example_preset"
        assert round_tripped.entries[0].content_sha256 == "0" * 64

    def test_parse_lock_rejects_garbage(self) -> None:
        with pytest.raises(LockfileFormatError):
            parse_lock("this is not a valid lockfile\nrubbish line")

    def test_render_lock_then_parse_lock_round_trip(self) -> None:
        """``parse_lock(render_lock(build_lock(...)))`` is idempotent on entries."""
        lock = build_lock(preset_data={}, airlock_version="0.7.1")
        rendered = render_lock(lock)
        round_tripped = parse_lock(rendered)
        assert round_tripped.entries == lock.entries
        assert round_tripped.airlock_version == "0.7.1"
