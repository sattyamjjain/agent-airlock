"""Tests for the filesystem security module (V0.3.0)."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from agent_airlock.filesystem import (
    RESTRICTIVE_FILESYSTEM_POLICY,
    SANDBOX_FILESYSTEM_POLICY,
    FilesystemPolicy,
    PathValidationError,
    is_path_within_roots,
    validate_path,
)


class TestFilesystemPolicy:
    """Tests for FilesystemPolicy dataclass."""

    def test_default_policy(self) -> None:
        """Test default policy values."""
        policy = FilesystemPolicy()
        assert policy.allowed_roots == []
        assert policy.allow_symlinks is False
        assert policy.deny_patterns == []
        assert policy.max_path_depth == 20

    def test_policy_with_roots(self) -> None:
        """Test policy with allowed roots."""
        policy = FilesystemPolicy(
            allowed_roots=[Path("/app/data"), Path("/tmp")],
        )
        # Roots should be resolved to absolute paths
        assert len(policy.allowed_roots) == 2
        assert all(root.is_absolute() for root in policy.allowed_roots)

    def test_policy_with_deny_patterns(self) -> None:
        """Test policy with deny patterns."""
        policy = FilesystemPolicy(
            deny_patterns=["*.env", "**/.git/**"],
        )
        assert "*.env" in policy.deny_patterns
        assert "**/.git/**" in policy.deny_patterns

    def test_predefined_restrictive_policy(self) -> None:
        """Test the predefined restrictive policy."""
        policy = RESTRICTIVE_FILESYSTEM_POLICY
        assert "*.env" in policy.deny_patterns
        assert "*.pem" in policy.deny_patterns
        assert policy.allow_symlinks is False
        assert policy.max_path_depth == 15

    def test_predefined_sandbox_policy(self) -> None:
        """Test the predefined sandbox policy."""
        policy = SANDBOX_FILESYSTEM_POLICY
        assert len(policy.allowed_roots) == 2
        assert policy.max_path_depth == 10


class TestIsPathWithinRoots:
    """Tests for is_path_within_roots function."""

    def test_path_within_root(self) -> None:
        """Test path that is within allowed root."""
        roots = [Path("/app")]
        assert is_path_within_roots(Path("/app/data/file.txt"), roots) is True

    def test_path_outside_root(self) -> None:
        """Test path that is outside allowed roots."""
        roots = [Path("/app")]
        assert is_path_within_roots(Path("/etc/passwd"), roots) is False

    def test_empty_roots_allows_all(self) -> None:
        """Test that empty roots list allows all paths."""
        roots: list[Path] = []
        assert is_path_within_roots(Path("/any/path"), roots) is True

    def test_multiple_roots(self) -> None:
        """Test with multiple allowed roots."""
        roots = [Path("/app"), Path("/tmp")]
        assert is_path_within_roots(Path("/app/data"), roots) is True
        assert is_path_within_roots(Path("/tmp/file"), roots) is True
        assert is_path_within_roots(Path("/etc/file"), roots) is False

    def test_exact_root_match(self) -> None:
        """Test path that exactly matches a root."""
        roots = [Path("/app")]
        assert is_path_within_roots(Path("/app"), roots) is True

    def test_traversal_attempt(self) -> None:
        """Test that traversal attempts outside root are rejected."""
        roots = [Path("/app/data")]
        # This would resolve to /app if not properly handled
        # But the resolved path is what matters
        resolved = Path("/app/config")
        assert is_path_within_roots(resolved, roots) is False


class TestValidatePath:
    """Tests for validate_path function."""

    def test_valid_path_no_restrictions(self) -> None:
        """Test valid path with no restrictions."""
        # Use allow_symlinks=True since /tmp may be a symlink on macOS
        policy = FilesystemPolicy(allow_symlinks=True)
        # Use a real path that exists
        result = validate_path("/tmp", policy)
        assert result.is_absolute()

    def test_valid_path_within_root(self) -> None:
        """Test valid path within allowed root."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Use resolved path and allow symlinks to handle macOS /tmp -> /private/tmp
            resolved_tmpdir = Path(tmpdir).resolve()
            policy = FilesystemPolicy(
                allowed_roots=[resolved_tmpdir],
                allow_symlinks=True,
            )
            test_file = resolved_tmpdir / "test.txt"
            test_file.touch()

            result = validate_path(str(test_file), policy, must_exist=True)
            assert str(result).startswith(str(resolved_tmpdir))

    def test_path_outside_allowed_roots(self) -> None:
        """Test path outside allowed roots raises error."""
        # Use allow_symlinks=True to avoid symlink errors and test the actual root check
        policy = FilesystemPolicy(
            allowed_roots=[Path("/nonexistent/root")],
            allow_symlinks=True,
        )

        with pytest.raises(PathValidationError) as exc_info:
            validate_path("/etc/passwd", policy)

        assert exc_info.value.violation_type == "outside_allowed_roots"
        assert exc_info.value.path == "/etc/passwd"

    def test_denied_pattern_env_file(self) -> None:
        """Test that .env files are denied."""
        with tempfile.TemporaryDirectory() as tmpdir:
            resolved_tmpdir = Path(tmpdir).resolve()
            policy = FilesystemPolicy(
                allowed_roots=[resolved_tmpdir],
                deny_patterns=["*.env"],
                allow_symlinks=True,
            )
            env_file = resolved_tmpdir / ".env"
            env_file.touch()

            with pytest.raises(PathValidationError) as exc_info:
                validate_path(str(env_file), policy)

            assert exc_info.value.violation_type == "denied_pattern"

    def test_denied_pattern_git_directory(self) -> None:
        """Test that .git directories are denied."""
        with tempfile.TemporaryDirectory() as tmpdir:
            resolved_tmpdir = Path(tmpdir).resolve()
            policy = FilesystemPolicy(
                allowed_roots=[resolved_tmpdir],
                deny_patterns=["**/.git/**", ".git"],
                allow_symlinks=True,
            )
            git_dir = resolved_tmpdir / ".git"
            git_dir.mkdir()
            git_file = git_dir / "config"
            git_file.touch()

            with pytest.raises(PathValidationError) as exc_info:
                validate_path(str(git_file), policy)

            assert exc_info.value.violation_type == "denied_pattern"

    def test_max_path_depth_exceeded(self) -> None:
        """Test that paths exceeding max depth are rejected."""
        policy = FilesystemPolicy(max_path_depth=3)

        with pytest.raises(PathValidationError) as exc_info:
            validate_path("/a/b/c/d/e/f/g/h", policy)

        assert exc_info.value.violation_type == "max_depth_exceeded"

    def test_must_exist_nonexistent_file(self) -> None:
        """Test must_exist flag with nonexistent file."""
        policy = FilesystemPolicy()

        with pytest.raises(PathValidationError) as exc_info:
            validate_path("/nonexistent/file.txt", policy, must_exist=True)

        assert exc_info.value.violation_type == "path_not_found"

    def test_symlink_detection(self) -> None:
        """Test that symlinks are detected when not allowed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            policy = FilesystemPolicy(
                allowed_roots=[Path(tmpdir)],
                allow_symlinks=False,
            )

            # Create a real file and a symlink to it
            real_file = Path(tmpdir) / "real.txt"
            real_file.touch()
            symlink = Path(tmpdir) / "link.txt"
            symlink.symlink_to(real_file)

            with pytest.raises(PathValidationError) as exc_info:
                validate_path(str(symlink), policy, must_exist=True)

            assert exc_info.value.violation_type == "symlink_detected"

    def test_symlink_allowed_when_enabled(self) -> None:
        """Test that symlinks are allowed when policy permits."""
        with tempfile.TemporaryDirectory() as tmpdir:
            policy = FilesystemPolicy(
                allowed_roots=[Path(tmpdir)],
                allow_symlinks=True,
            )

            # Create a real file and a symlink to it
            real_file = Path(tmpdir) / "real.txt"
            real_file.touch()
            symlink = Path(tmpdir) / "link.txt"
            symlink.symlink_to(real_file)

            # Should not raise
            result = validate_path(str(symlink), policy, must_exist=True)
            assert result.exists()

    def test_relative_path_resolution(self) -> None:
        """Test that relative paths are resolved correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            policy = FilesystemPolicy(allowed_roots=[Path(tmpdir)])

            # Create a file
            test_file = Path(tmpdir) / "test.txt"
            test_file.touch()

            # Change to tmpdir and use relative path
            original_dir = os.getcwd()
            try:
                os.chdir(tmpdir)
                result = validate_path("test.txt", policy)
                assert result.is_absolute()
                assert "test.txt" in str(result)
            finally:
                os.chdir(original_dir)


class TestPathTraversalAttacks:
    """Tests for directory traversal attack prevention."""

    def test_dot_dot_slash_attack(self) -> None:
        """Test that ../ traversal is blocked."""
        with tempfile.TemporaryDirectory() as tmpdir:
            policy = FilesystemPolicy(allowed_roots=[Path(tmpdir) / "data"])

            # Create the data subdirectory
            (Path(tmpdir) / "data").mkdir()

            # Attempt traversal
            malicious_path = str(Path(tmpdir) / "data" / ".." / "secret.txt")

            with pytest.raises(PathValidationError) as exc_info:
                validate_path(malicious_path, policy)

            assert exc_info.value.violation_type == "outside_allowed_roots"

    def test_encoded_traversal(self) -> None:
        """Test that URL-encoded traversal doesn't bypass checks."""
        policy = FilesystemPolicy(allowed_roots=[Path("/app/data")])

        # This is already decoded when passed as a string
        # The important thing is that resolved paths are checked
        malicious_path = "/app/data/../etc/passwd"

        with pytest.raises(PathValidationError):
            validate_path(malicious_path, policy)

    def test_absolute_path_escape(self) -> None:
        """Test that absolute paths can't escape roots."""
        with tempfile.TemporaryDirectory() as tmpdir:
            policy = FilesystemPolicy(allowed_roots=[Path(tmpdir)])

            # Try to access /etc directly
            with pytest.raises(PathValidationError):
                validate_path("/etc/passwd", policy)


class TestPathValidationError:
    """Tests for PathValidationError exception."""

    def test_error_attributes(self) -> None:
        """Test error has correct attributes."""
        error = PathValidationError(
            message="Path is blocked",
            path="/etc/passwd",
            violation_type="denied",
            details={"pattern": "*.passwd"},
        )

        assert error.message == "Path is blocked"
        assert error.path == "/etc/passwd"
        assert error.violation_type == "denied"
        assert error.details == {"pattern": "*.passwd"}
        assert str(error) == "Path is blocked"

    def test_error_without_details(self) -> None:
        """Test error without optional details."""
        error = PathValidationError(
            message="Path not found",
            path="/missing.txt",
            violation_type="not_found",
        )

        assert error.details == {}


class TestEdgeCases:
    """Tests for edge cases and unusual inputs."""

    def test_empty_path(self) -> None:
        """Test handling of empty path."""
        policy = FilesystemPolicy()

        # Empty path should resolve to current directory
        result = validate_path("", policy)
        assert result.is_absolute()

    def test_path_with_spaces(self) -> None:
        """Test path with spaces in name."""
        with tempfile.TemporaryDirectory() as tmpdir:
            resolved_tmpdir = Path(tmpdir).resolve()
            policy = FilesystemPolicy(
                allowed_roots=[resolved_tmpdir],
                allow_symlinks=True,
            )

            # Create file with space in name
            spaced_file = resolved_tmpdir / "my file.txt"
            spaced_file.touch()

            result = validate_path(str(spaced_file), policy)
            assert "my file.txt" in str(result)

    def test_unicode_path(self) -> None:
        """Test path with Unicode characters."""
        with tempfile.TemporaryDirectory() as tmpdir:
            resolved_tmpdir = Path(tmpdir).resolve()
            policy = FilesystemPolicy(
                allowed_roots=[resolved_tmpdir],
                allow_symlinks=True,
            )

            # Create file with Unicode name
            unicode_file = resolved_tmpdir / "文件.txt"
            unicode_file.touch()

            result = validate_path(str(unicode_file), policy)
            assert "文件.txt" in str(result)

    def test_very_long_path(self) -> None:
        """Test handling of very long paths."""
        policy = FilesystemPolicy(max_path_depth=5)

        # Create a very deep path
        long_path = "/a" + "/b" * 100

        with pytest.raises(PathValidationError) as exc_info:
            validate_path(long_path, policy)

        assert exc_info.value.violation_type == "max_depth_exceeded"

    def test_path_object_input(self) -> None:
        """Test that Path objects are accepted."""
        with tempfile.TemporaryDirectory() as tmpdir:
            resolved_tmpdir = Path(tmpdir).resolve()
            policy = FilesystemPolicy(
                allowed_roots=[resolved_tmpdir],
                allow_symlinks=True,
            )

            test_file = resolved_tmpdir / "test.txt"
            test_file.touch()

            # Pass Path object instead of string
            result = validate_path(test_file, policy)
            assert result.exists()

    def test_multiple_deny_patterns(self) -> None:
        """Test multiple deny patterns."""
        with tempfile.TemporaryDirectory() as tmpdir:
            policy = FilesystemPolicy(
                allowed_roots=[Path(tmpdir)],
                deny_patterns=["*.env", "*.pem", "*.key"],
            )

            for ext in [".env", ".pem", ".key"]:
                test_file = Path(tmpdir) / f"test{ext}"
                test_file.touch()

                with pytest.raises(PathValidationError):
                    validate_path(str(test_file), policy)

    def test_case_sensitivity(self) -> None:
        """Test case sensitivity of deny patterns."""
        with tempfile.TemporaryDirectory() as tmpdir:
            policy = FilesystemPolicy(
                allowed_roots=[Path(tmpdir)],
                deny_patterns=["*.ENV"],  # Uppercase pattern
            )

            # Create lowercase file
            test_file = Path(tmpdir) / "test.env"
            test_file.touch()

            # Pattern matching should be case-sensitive by default
            # This test documents current behavior
            # Note: fnmatch is case-sensitive on Unix, case-insensitive on Windows
            try:
                result = validate_path(str(test_file), policy)
                # On Unix, lowercase file won't match uppercase pattern
                assert result.exists()
            except PathValidationError:
                # On Windows, might match
                pass
