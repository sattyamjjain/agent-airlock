"""Tests for the v0.5.7 declarative preset YAML loader.

Covers schema validation, the OX-MCP composite preset round-trip, and
the missing-CVE-field rejection path. The loader uses a stdlib-only
restricted-grammar parser; tests confirm the grammar handles the
shapes the v1 schema actually allows.

Primary source for the OX umbrella preset:
  https://www.ox.security/blog/mother-of-all-ai-supply-chains-2026-04-20
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_airlock.preset_loader import (
    LoadedPreset,
    PresetParseError,
    compose_preset_factories,
    load_yaml_preset,
)

ROOT = Path(__file__).resolve().parent.parent.parent
OX_PRESET = ROOT / "presets" / "ox-mcp-2026-04.yaml"


class TestSchemaValidation:
    def test_real_ox_preset_loads(self) -> None:
        loaded = load_yaml_preset(OX_PRESET)
        assert isinstance(loaded, LoadedPreset)
        assert loaded.preset_id == "ox-mcp-2026-04"
        assert loaded.schema_version == 1
        assert "ox.security" in loaded.primary_source
        assert loaded.disclosed_at == "2026-04-15"
        assert len(loaded.presets) == 9
        for entry in loaded.presets:
            assert entry["id"]
            assert entry["factory"]
            assert entry["primary_source"].startswith("https://")

    def test_missing_required_field_rejected(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.yaml"
        f.write_text(
            "schema_version: 1\npreset_id: bad\nprimary_source: https://x\ndisclosed_at: 2026-04\n",
            encoding="utf-8",
        )
        with pytest.raises(PresetParseError, match="presets"):
            load_yaml_preset(f)

    def test_wrong_schema_version_rejected(self, tmp_path: Path) -> None:
        f = tmp_path / "wrong-version.yaml"
        f.write_text(
            "schema_version: 99\n"
            "preset_id: bad\n"
            "primary_source: https://x\n"
            "disclosed_at: 2026-04\n"
            "presets:\n"
            "  - id: x\n"
            "    factory: y\n"
            "    primary_source: https://x\n",
            encoding="utf-8",
        )
        with pytest.raises(PresetParseError, match="schema_version"):
            load_yaml_preset(f)

    def test_preset_entry_missing_factory_rejected(self, tmp_path: Path) -> None:
        f = tmp_path / "no-factory.yaml"
        f.write_text(
            "schema_version: 1\n"
            "preset_id: bad\n"
            "primary_source: https://x\n"
            "disclosed_at: 2026-04\n"
            "presets:\n"
            "  - id: orphan\n"
            "    primary_source: https://x\n",
            encoding="utf-8",
        )
        with pytest.raises(PresetParseError, match="factory"):
            load_yaml_preset(f)

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(PresetParseError, match="not found"):
            load_yaml_preset(tmp_path / "does-not-exist.yaml")


class TestCompose:
    def test_ox_preset_composes(self) -> None:
        loaded = load_yaml_preset(OX_PRESET)
        composed = compose_preset_factories(loaded)
        assert "stdio_guard_ox_defaults" in composed
        for entry_id in (
            "gitpilot_mcp_cve_2026_6980",
            "windsurf_cve_2026_30615",
            "mcpjam_cve_2026_23744",
            "azure_mcp_cve_2026_32211",
            "unit42_mcp_sampling",
            "archived_mcp_server_advisory",
        ):
            assert entry_id in composed, f"{entry_id!r} missing from composed preset"

    def test_unknown_factory_raises(self, tmp_path: Path) -> None:
        f = tmp_path / "unknown-factory.yaml"
        f.write_text(
            "schema_version: 1\n"
            "preset_id: bad\n"
            "primary_source: https://x\n"
            "disclosed_at: 2026-04\n"
            "presets:\n"
            "  - id: orphan\n"
            "    factory: this_factory_does_not_exist\n"
            "    primary_source: https://x\n",
            encoding="utf-8",
        )
        loaded = load_yaml_preset(f)
        with pytest.raises(PresetParseError, match="unknown factory"):
            compose_preset_factories(loaded)


class TestParserGrammar:
    def test_quoted_multi_word_string(self, tmp_path: Path) -> None:
        f = tmp_path / "quoted.yaml"
        f.write_text(
            "schema_version: 1\n"
            "preset_id: bad\n"
            'description: "this is a quoted multi-word value"\n'
            "primary_source: https://x\n"
            "disclosed_at: 2026-04\n"
            "presets:\n"
            "  - id: x\n"
            "    factory: y\n"
            "    primary_source: https://x\n",
            encoding="utf-8",
        )
        loaded = load_yaml_preset(f)
        assert loaded.description == "this is a quoted multi-word value"

    def test_comment_lines_ignored(self, tmp_path: Path) -> None:
        f = tmp_path / "comments.yaml"
        f.write_text(
            "# top-level comment\n"
            "schema_version: 1  # inline comment\n"
            "preset_id: bad\n"
            "primary_source: https://x\n"
            "disclosed_at: 2026-04\n"
            "presets:\n"
            "  # comment in list\n"
            "  - id: x\n"
            "    factory: y\n"
            "    primary_source: https://x\n",
            encoding="utf-8",
        )
        loaded = load_yaml_preset(f)
        assert loaded.schema_version == 1
        assert len(loaded.presets) == 1
