"""Tests for the v0.5.8 ``airlock pack`` surface."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_airlock.exceptions import AirlockError
from agent_airlock.pack import (
    PackInstaller,
    PackManifest,
    PackVerificationError,
    load_manifest,
    sign_manifest,
    verify_manifest,
)
from agent_airlock.pack.installer import (
    discover_shipped_packs,
    find_shipped_pack,
)
from agent_airlock.pack.manifest import PackManifestError, manifest_sha256

KEY = b"test-fixture-key-0123456789abcdef"


class TestShippedPacks:
    """All three v0 packs ship and parse cleanly."""

    def test_three_packs_discovered(self) -> None:
        paths = discover_shipped_packs()
        ids = sorted(load_manifest(p).pack_id for p in paths)
        assert ids == ["claude-code-ci", "copilot-agent-ci", "gemini-cli-ci"]

    def test_claude_code_ci_loads(self) -> None:
        path = find_shipped_pack("claude-code-ci")
        assert path is not None
        manifest = load_manifest(path)
        assert manifest.pack_id == "claude-code-ci"
        assert manifest.version == "2026.04"
        # Every entry has factory + primary_source.
        for entry in manifest.presets:
            assert entry.factory
            assert entry.primary_source.startswith("https://")


class TestSigning:
    def test_sign_then_verify_round_trip(self) -> None:
        path = find_shipped_pack("claude-code-ci")
        assert path is not None
        manifest = load_manifest(path)
        sig = sign_manifest(manifest, signing_key=KEY)
        verify_manifest(manifest, sig, signing_key=KEY)  # no raise

    def test_verify_with_wrong_key_raises(self) -> None:
        path = find_shipped_pack("claude-code-ci")
        assert path is not None
        manifest = load_manifest(path)
        sig = sign_manifest(manifest, signing_key=KEY)
        with pytest.raises(PackVerificationError):
            verify_manifest(
                manifest,
                sig,
                signing_key=b"different-key-0123456789abcdefXX",
            )

    def test_tampered_manifest_breaks_signature(self, tmp_path: Path) -> None:
        path = find_shipped_pack("claude-code-ci")
        assert path is not None
        manifest = load_manifest(path)
        sig = sign_manifest(manifest, signing_key=KEY)

        # Reconstruct with a tampered preset list.
        tampered = PackManifest(
            pack_id=manifest.pack_id,
            version=manifest.version,
            description=manifest.description,
            primary_source=manifest.primary_source,
            presets=manifest.presets[:-1],
        )
        with pytest.raises(PackVerificationError):
            verify_manifest(tampered, sig, signing_key=KEY)


class TestInstaller:
    def test_install_claude_code_ci(self) -> None:
        path = find_shipped_pack("claude-code-ci")
        assert path is not None
        manifest = load_manifest(path)
        installed = PackInstaller().install(manifest)
        # claude_code_security_review_cnc_2026_04 + lan_unauth_mcp_guard +
        # archived_mcp_server_advisory_defaults + stdio_guard_ox_defaults
        # all callable nullary → should compose.
        assert "claude_code_security_review_cnc_2026_04" in installed.composed
        assert "lan_unauth_mcp_guard" in installed.composed

    def test_unknown_factory_raises(self, tmp_path: Path) -> None:
        manifest_text = (
            "pack_id: bogus\n"
            "version: 0.0.1\n"
            "description: bogus pack\n"
            "primary_source: https://example.com\n"
            "presets:\n"
            "  - factory: this_factory_does_not_exist\n"
            "    primary_source: https://example.com\n"
        )
        f = tmp_path / "manifest.yaml"
        f.write_text(manifest_text, encoding="utf-8")
        manifest = load_manifest(f)
        with pytest.raises(PackManifestError, match="unknown factory"):
            PackInstaller().install(manifest)


class TestSHA256:
    def test_manifest_sha256_stable(self) -> None:
        path = find_shipped_pack("claude-code-ci")
        assert path is not None
        manifest = load_manifest(path)
        assert len(manifest_sha256(manifest)) == 64
        assert manifest_sha256(manifest) == manifest_sha256(manifest)


class TestErrorHierarchy:
    def test_subclasses_airlock_error(self) -> None:
        assert issubclass(PackManifestError, AirlockError)
        assert issubclass(PackVerificationError, AirlockError)


class TestCLI:
    def test_pack_list_subcommand(self, capsys: pytest.CaptureFixture) -> None:
        from agent_airlock.cli import pack as pcli

        rc = pcli.main(["list"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "claude-code-ci" in out
        assert "gemini-cli-ci" in out
        assert "copilot-agent-ci" in out

    def test_pack_install_unknown(self, capsys: pytest.CaptureFixture) -> None:
        from agent_airlock.cli import pack as pcli

        rc = pcli.main(["install", "no-such-pack"])
        assert rc == 2

    def test_pack_install_claude_code_ci(self, capsys: pytest.CaptureFixture) -> None:
        from agent_airlock.cli import pack as pcli

        rc = pcli.main(["--format", "json", "install", "claude-code-ci"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "claude-code-ci" in out
