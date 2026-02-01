"""Tests for safe_types module (V0.4.0)."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import BaseModel, ValidationError

from agent_airlock.safe_types import (
    DEFAULT_PATH_DENY_PATTERNS,
    SafePath,
    SafePathValidationError,
    SafePathValidator,
    SafeURL,
    SafeURLAllowHttp,
    SafeURLValidationError,
    SafeURLValidator,
)


class TestSafePathValidator:
    """Test the SafePathValidator class."""

    def test_default_deny_patterns_set(self) -> None:
        """Test that default deny patterns are set."""
        validator = SafePathValidator()
        assert len(validator.deny_patterns) > 0

    def test_valid_path(self) -> None:
        """Test validation of a valid path."""
        validator = SafePathValidator()
        result = validator("/app/data/file.txt")
        assert isinstance(result, Path)

    def test_directory_traversal_blocked(self) -> None:
        """Test that directory traversal is blocked."""
        validator = SafePathValidator()
        with pytest.raises(SafePathValidationError, match="traversal"):
            validator("/app/data/../../../etc/passwd")

    def test_home_directory_blocked(self) -> None:
        """Test that home directory reference is blocked."""
        validator = SafePathValidator()
        with pytest.raises(SafePathValidationError, match="Home"):
            validator("~/.ssh/id_rsa")

    def test_env_file_blocked(self) -> None:
        """Test that .env files are blocked."""
        validator = SafePathValidator()
        with pytest.raises(SafePathValidationError, match="denied"):
            validator("/app/.env")

    def test_with_root_directory(self) -> None:
        """Test validation with root directory."""
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            validator = SafePathValidator(root_dir=Path(tmpdir))
            result = validator(f"{tmpdir}/subdir/file.txt")
            assert isinstance(result, Path)

    def test_path_outside_root_blocked(self) -> None:
        """Test that paths outside root are blocked."""
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            validator = SafePathValidator(root_dir=Path(tmpdir))
            with pytest.raises(SafePathValidationError, match="denied"):
                validator("/etc/passwd")

    def test_custom_deny_patterns(self) -> None:
        """Test validation with custom deny patterns."""
        validator = SafePathValidator(deny_patterns=["*.secret"])
        with pytest.raises(SafePathValidationError, match="denied"):
            validator("/app/config.secret")

    def test_empty_deny_patterns_allows_all(self) -> None:
        """Test validation with no deny patterns."""
        validator = SafePathValidator(deny_patterns=[])
        # Should allow .env when deny patterns are empty
        result = validator("/app/.env")
        assert isinstance(result, Path)


class TestSafeURLValidator:
    """Test the SafeURLValidator class."""

    def test_valid_https_url(self) -> None:
        """Test validation of a valid HTTPS URL."""
        validator = SafeURLValidator()
        result = validator("https://example.com/api")
        assert result == "https://example.com/api"

    def test_http_blocked_by_default(self) -> None:
        """Test that HTTP is blocked by default."""
        validator = SafeURLValidator()
        with pytest.raises(SafeURLValidationError, match="not allowed"):
            validator("http://example.com/api")

    def test_http_allowed_when_configured(self) -> None:
        """Test that HTTP can be allowed."""
        validator = SafeURLValidator(allowed_schemes=["http", "https"])
        result = validator("http://example.com/api")
        assert result == "http://example.com/api"

    def test_file_url_blocked(self) -> None:
        """Test that file:// URLs are blocked."""
        validator = SafeURLValidator()
        with pytest.raises(SafeURLValidationError, match="file"):
            validator("file:///etc/passwd")

    def test_metadata_url_blocked(self) -> None:
        """Test that cloud metadata URLs are blocked."""
        # Need to allow http scheme to test metadata blocking
        validator = SafeURLValidator(allowed_schemes=["http", "https"])
        with pytest.raises(SafeURLValidationError, match="blocked"):
            validator("http://169.254.169.254/latest/meta-data/")

    def test_localhost_blocked(self) -> None:
        """Test that localhost is blocked."""
        validator = SafeURLValidator()
        with pytest.raises(SafeURLValidationError, match="localhost"):
            validator("https://localhost/api")

    def test_allowed_hosts(self) -> None:
        """Test validation with allowed hosts."""
        validator = SafeURLValidator(allowed_hosts=["api.company.com"])
        result = validator("https://api.company.com/v1/data")
        assert result == "https://api.company.com/v1/data"


class TestDefaultDenyPatterns:
    """Test the default deny patterns constant."""

    def test_contains_essential_patterns(self) -> None:
        """Test that essential patterns are included."""
        assert "~" in DEFAULT_PATH_DENY_PATTERNS
        assert ".." in DEFAULT_PATH_DENY_PATTERNS
        assert ".env" in DEFAULT_PATH_DENY_PATTERNS
        assert ".ssh" in DEFAULT_PATH_DENY_PATTERNS
        assert ".git" in DEFAULT_PATH_DENY_PATTERNS


class TestSafePathTypeAlias:
    """Test the SafePath type alias."""

    def test_safe_path_validation(self) -> None:
        """Test SafePath type validates correctly."""

        class PathModel(BaseModel):
            path: SafePath

        model = PathModel(path="/app/data/file.txt")
        assert isinstance(model.path, Path)

    def test_safe_path_rejects_traversal(self) -> None:
        """Test SafePath rejects directory traversal."""

        class PathModel(BaseModel):
            path: SafePath

        with pytest.raises(ValidationError):
            PathModel(path="/app/../etc/passwd")


class TestSafeURLTypeAlias:
    """Test the SafeURL type alias."""

    def test_safe_url_validation(self) -> None:
        """Test SafeURL validates correctly."""

        class URLModel(BaseModel):
            url: SafeURL

        model = URLModel(url="https://example.com/api")
        assert model.url == "https://example.com/api"

    def test_safe_url_rejects_http(self) -> None:
        """Test SafeURL rejects HTTP."""

        class URLModel(BaseModel):
            url: SafeURL

        with pytest.raises(ValidationError):
            URLModel(url="http://example.com/api")


class TestSafeURLAllowHttpTypeAlias:
    """Test the SafeURLAllowHttp type alias."""

    def test_allows_http(self) -> None:
        """Test SafeURLAllowHttp allows HTTP."""

        class URLModel(BaseModel):
            url: SafeURLAllowHttp

        model = URLModel(url="http://example.com/api")
        assert model.url == "http://example.com/api"


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_url(self) -> None:
        """Test validation of empty URL."""
        validator = SafeURLValidator()
        with pytest.raises(SafeURLValidationError):
            validator("")

    def test_url_without_scheme(self) -> None:
        """Test validation of URL without scheme."""
        validator = SafeURLValidator()
        with pytest.raises(SafeURLValidationError):
            validator("example.com/api")
