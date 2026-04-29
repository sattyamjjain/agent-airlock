"""Tests for ``policy_bundle.lock`` (hash-pinned policy bundles)."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_airlock.exceptions import AirlockError
from agent_airlock.pack.lock import (
    LOCK_SCHEMA_VERSION,
    LockfileDriftError,
    LockfileFormatError,
    build_lock,
    hash_preset,
    parse_lock,
    read_lock,
    render_lock,
    verify_lock,
    write_lock,
)


@pytest.fixture
def sample_presets() -> dict[str, dict]:
    return {
        "mcp_stdio_meta_cve_2026_04": {
            "preset_id": "mcp_stdio_meta_cve_2026_04",
            "severity": "critical",
            "default_action": "block",
        },
        "mcp_elicitation_guard_2026_04": {
            "preset_id": "mcp_elicitation_guard_2026_04",
            "severity": "high",
            "default_action": "block",
        },
    }


class TestErrorHierarchy:
    def test_drift_subclasses_airlock_error(self) -> None:
        assert issubclass(LockfileDriftError, AirlockError)

    def test_format_subclasses_airlock_error(self) -> None:
        assert issubclass(LockfileFormatError, AirlockError)


class TestHashing:
    def test_hash_is_deterministic(self) -> None:
        a = hash_preset({"x": 1, "y": [3, 2, 1]})
        b = hash_preset({"y": [3, 2, 1], "x": 1})
        assert a == b

    def test_hash_changes_on_value_drift(self) -> None:
        a = hash_preset({"x": 1})
        b = hash_preset({"x": 2})
        assert a != b

    def test_hash_handles_frozenset(self) -> None:
        a = hash_preset({"set": frozenset({"a", "b"})})
        b = hash_preset({"set": frozenset({"b", "a"})})
        assert a == b


class TestBuildAndRender:
    def test_build_lock_pins_every_preset(self, sample_presets: dict[str, dict]) -> None:
        lock = build_lock(sample_presets, airlock_version="0.6.0")
        assert lock.schema_version == LOCK_SCHEMA_VERSION
        assert lock.airlock_version == "0.6.0"
        assert {e.preset_id for e in lock.entries} == set(sample_presets)

    def test_render_round_trip(self, sample_presets: dict[str, dict]) -> None:
        lock = build_lock(sample_presets, airlock_version="0.6.0")
        rendered = render_lock(lock)
        parsed = parse_lock(rendered)
        assert parsed.entries == lock.entries
        assert parsed.airlock_version == lock.airlock_version

    def test_render_byte_stable(self, sample_presets: dict[str, dict]) -> None:
        lock = build_lock(sample_presets, airlock_version="0.6.0")
        a = render_lock(lock)
        b = render_lock(lock)
        assert a == b

    def test_entries_sorted_by_preset_id(self, sample_presets: dict[str, dict]) -> None:
        lock = build_lock(sample_presets, airlock_version="0.6.0")
        ids = [e.preset_id for e in lock.entries]
        assert ids == sorted(ids)


class TestFileIO:
    def test_write_and_read(self, sample_presets: dict[str, dict], tmp_path: Path) -> None:
        path = tmp_path / "policy_bundle.lock"
        lock = build_lock(sample_presets, airlock_version="0.6.0")
        write_lock(lock, path)
        loaded = read_lock(path)
        assert loaded.entries == lock.entries

    def test_read_missing_path_raises(self, tmp_path: Path) -> None:
        with pytest.raises(LockfileFormatError):
            read_lock(tmp_path / "missing.lock")


class TestVerification:
    def test_no_drift_passes(self, sample_presets: dict[str, dict]) -> None:
        lock = build_lock(sample_presets, airlock_version="0.6.0")
        verify_lock(lock, sample_presets)

    def test_value_drift_raises(self, sample_presets: dict[str, dict]) -> None:
        lock = build_lock(sample_presets, airlock_version="0.6.0")
        drifted = {**sample_presets}
        drifted["mcp_stdio_meta_cve_2026_04"] = {
            **sample_presets["mcp_stdio_meta_cve_2026_04"],
            "default_action": "warn",
        }
        with pytest.raises(LockfileDriftError) as excinfo:
            verify_lock(lock, drifted)
        assert excinfo.value.preset_id == "mcp_stdio_meta_cve_2026_04"

    def test_extra_preset_in_bundle_raises(self, sample_presets: dict[str, dict]) -> None:
        lock = build_lock(sample_presets, airlock_version="0.6.0")
        extended = {**sample_presets, "new_preset": {"preset_id": "new_preset"}}
        with pytest.raises(LockfileDriftError) as excinfo:
            verify_lock(lock, extended)
        assert excinfo.value.preset_id == "new_preset"

    def test_missing_preset_in_bundle_raises(self, sample_presets: dict[str, dict]) -> None:
        lock = build_lock(sample_presets, airlock_version="0.6.0")
        partial = {"mcp_stdio_meta_cve_2026_04": sample_presets["mcp_stdio_meta_cve_2026_04"]}
        with pytest.raises(LockfileDriftError):
            verify_lock(lock, partial)


class TestParseRobustness:
    def test_parse_rejects_unknown_schema_version(self) -> None:
        text = (
            "schema_version = 999\n"
            'airlock_version = "0.6.0"\n'
            'generated_at = "2026-04-29T00:00:00Z"\n'
        )
        with pytest.raises(LockfileFormatError):
            parse_lock(text)

    def test_parse_rejects_missing_header(self) -> None:
        text = '[[preset]]\npreset_id = "x"\ncontent_sha256 = "y"\n'
        with pytest.raises(LockfileFormatError):
            parse_lock(text)

    def test_parse_rejects_preset_missing_hash(self) -> None:
        text = (
            "schema_version = 1\n"
            'airlock_version = "0.6.0"\n'
            'generated_at = "2026-04-29T00:00:00Z"\n'
            "[[preset]]\n"
            'preset_id = "x"\n'
        )
        with pytest.raises(LockfileFormatError):
            parse_lock(text)
