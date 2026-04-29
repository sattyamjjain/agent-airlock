"""Tests for ``ConfigPathGuard`` and the CVE-2026-31402 preset."""

from __future__ import annotations

import secrets
from pathlib import Path

import pytest

from agent_airlock.exceptions import AirlockError
from agent_airlock.mcp_spec.config_path_guard import (
    ConfigPathGuard,
    ConfigPathTraversalError,
)
from agent_airlock.policy_presets import (
    mcp_config_path_traversal_cve_2026_31402,
)


@pytest.fixture
def host_root(tmp_path: Path) -> Path:
    root = tmp_path / "host_root"
    root.mkdir()
    (root / "ok.bin").write_text("placeholder", encoding="utf-8")
    return root


@pytest.fixture
def guard(host_root: Path) -> ConfigPathGuard:
    return ConfigPathGuard(host_root=host_root, platform="posix")


class TestErrorHierarchy:
    def test_subclasses_airlock_error(self) -> None:
        assert issubclass(ConfigPathTraversalError, AirlockError)


class TestTraversalClasses:
    """All eight documented traversal classes block."""

    @pytest.mark.parametrize(
        ("name", "value"),
        [
            ("dot_dot_posix", "../../../etc/passwd"),
            ("dot_dot_relative_in_args", "../sensitive.bin"),
            ("encoded_dot_dot", "%2e%2e/%2e%2e/etc/passwd"),
            ("double_encoded", "%252e%252e/%252e%252e/etc/passwd"),
            ("null_byte", "ok\x00/../etc/passwd"),
            ("absolute_outside_host_root", "/etc/passwd"),
        ],
    )
    def test_blocks(self, guard: ConfigPathGuard, name: str, value: str) -> None:
        result = guard.evaluate({"command": "uvx", "args": [value]})
        assert result.verdict == "block", name
        assert result.findings


class TestWindowsTraversal:
    def test_dot_dot_backslash_blocks(self, host_root: Path) -> None:
        win_guard = ConfigPathGuard(host_root=host_root, platform="windows")
        result = win_guard.evaluate(
            {"command": "node", "args": ["..\\..\\Windows\\System32\\cmd.exe"]}
        )
        assert result.verdict == "block"

    def test_unc_blocks(self, host_root: Path) -> None:
        win_guard = ConfigPathGuard(host_root=host_root, platform="windows")
        result = win_guard.evaluate({"args": ["\\\\?\\C:\\Windows\\notepad.exe"]})
        assert result.verdict == "block"


class TestLegitimatePaths:
    def test_basename_command_allowed(self, guard: ConfigPathGuard) -> None:
        result = guard.evaluate({"command": "uvx", "args": ["mcp-foo"]})
        assert result.verdict == "allow"

    def test_args_basename_allowed(self, guard: ConfigPathGuard) -> None:
        result = guard.evaluate({"command": "node", "args": ["server.js", "--port", "8080"]})
        assert result.verdict == "allow"

    def test_working_directory_inside_host_root_allowed(
        self, guard: ConfigPathGuard, host_root: Path
    ) -> None:
        result = guard.evaluate({"workingDirectory": str(host_root / "ok.bin")})
        assert result.verdict == "allow"

    def test_working_directory_outside_host_root_blocks(
        self, guard: ConfigPathGuard, tmp_path: Path
    ) -> None:
        outside = tmp_path / "elsewhere"
        outside.mkdir()
        result = guard.evaluate({"workingDirectory": str(outside)})
        assert result.verdict == "block"


class TestEnvFiltering:
    def test_env_path_traversal_blocks(self, guard: ConfigPathGuard) -> None:
        result = guard.evaluate(
            {"command": "uvx", "args": ["mcp-foo"], "env": {"PATH": "../../../etc"}}
        )
        assert result.verdict == "block"

    def test_env_non_path_value_allowed(self, guard: ConfigPathGuard) -> None:
        result = guard.evaluate({"command": "uvx", "args": ["mcp-foo"], "env": {"DEBUG": "1"}})
        assert result.verdict == "allow"


class TestSymlinkEscape:
    def test_symlink_to_outside_blocks(self, host_root: Path, tmp_path: Path) -> None:
        if not hasattr(Path, "symlink_to"):  # pragma: no cover
            pytest.skip("symlink unsupported on this platform")
        outside = tmp_path / "secret.bin"
        outside.write_text("secret", encoding="utf-8")
        link = host_root / "link"
        try:
            link.symlink_to(outside)
        except OSError:
            pytest.skip("symlink creation refused on this platform")
        guard = ConfigPathGuard(host_root=host_root, platform="posix")
        # The symlink resolves outside host_root; absolute_outside_host_root
        # fires before the symlink check.
        result = guard.evaluate({"workingDirectory": str(link)})
        assert result.verdict == "block"


class TestEvaluateOrRaise:
    def test_block_raises_typed(self, guard: ConfigPathGuard) -> None:
        with pytest.raises(ConfigPathTraversalError) as excinfo:
            guard.evaluate_or_raise({"args": ["../../etc/passwd"]})
        assert "etc/passwd" in excinfo.value.offending_path
        assert excinfo.value.rule

    def test_allow_returns_inspection(self, guard: ConfigPathGuard) -> None:
        result = guard.evaluate_or_raise({"command": "uvx", "args": ["mcp-foo"]})
        assert result.verdict == "allow"


class TestFuzzNoEscape:
    """10K-fuzz harness: 0 escapes from host_root."""

    def test_random_paths_never_escape(self, guard: ConfigPathGuard, host_root: Path) -> None:
        # Build random path-shaped strings and assert that no allow
        # verdict produces a path resolving outside host_root.
        for _ in range(10_000):
            tokens = []
            for _ in range(secrets.randbelow(5) + 1):
                kind = secrets.randbelow(6)
                if kind == 0:
                    tokens.append("..")
                elif kind == 1:
                    tokens.append("a" * (secrets.randbelow(8) + 1))
                elif kind == 2:
                    tokens.append("%2e%2e")
                elif kind == 3:
                    tokens.append("ok")
                elif kind == 4:
                    tokens.append("%2fok")
                else:
                    tokens.append("legit")
            value = "/".join(tokens)
            result = guard.evaluate({"args": [value]})
            if result.verdict == "allow":
                # Allowed values must not refer to anything outside host_root.
                # Basenames + relative non-traversal tokens are fine; we just
                # assert that no allowed value contains the literal "../" or
                # decodes to one — the deeper invariant the guard claims.
                assert "../" not in value
                from urllib.parse import unquote

                decoded = unquote(value)
                assert "../" not in decoded
                assert ".." not in decoded.split("/")


class TestPresetWiring:
    def test_preset_constructs(self) -> None:
        preset = mcp_config_path_traversal_cve_2026_31402()
        assert preset["preset_id"] == "mcp_config_path_traversal_cve_2026_31402"
        assert preset["severity"] == "critical"
        assert "CVE-2026-31402" in preset["advisory_url"]

    def test_preset_drives_guard(self, host_root: Path) -> None:
        preset = mcp_config_path_traversal_cve_2026_31402()
        guard = ConfigPathGuard(
            host_root=host_root,
            platform=preset["platform"],
            allow_symlinks=preset["allow_symlinks"],
        )
        result = guard.evaluate({"args": ["../../etc/passwd"]})
        assert result.verdict == "block"
