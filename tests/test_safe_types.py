"""Tests for safe_types module (V0.4.0)."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import BaseModel, ValidationError

from agent_airlock.safe_types import (
    AGENT_CONFIG_DENY_PATTERNS,
    DEFAULT_PATH_DENY_PATTERNS,
    PERSISTENCE_DENY_PATTERNS,
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


# Paths a prompt-injected agent writes to persist or to change what its host runs next
# (V0.10.30). Each was admitted by the default validator in 0.10.29.
_PERSISTENCE_PATHS = [
    "/Users/u/Library/LaunchAgents/com.apple.sysmond.plist",
    "/Users/u/Library/LaunchAgents",
    "/Library/LaunchAgents/x.plist",
    "/Library/LaunchDaemons/x.plist",
    "/System/Library/LaunchDaemons/x.plist",
    "Library/LaunchAgents/x.plist",
    "/var/spool/cron/crontabs/u",
    "/var/spool/cron/u",
    "/var/at/tabs/u",
    "/usr/lib/cron/tabs/u",
    "/etc/crontab",
    "/etc/cron.d/x",
    "/etc/cron.daily/x",
    "/etc/systemd/system/x.service",
    "/etc/systemd/system/multi-user.target.wants/x.service",
    "/usr/lib/systemd/system/x.service",
    "/home/u/.config/systemd/user/x.service",
    "/home/u/.local/share/systemd/user/x.service",
    "C:\\Users\\u\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\x.bat",
    "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\x.lnk",
    "/home/u/.bashrc",
    "/home/u/.bash_profile",
    "/home/u/.profile",
    "/home/u/.zshrc",
    "/home/u/.zprofile",
    "/home/u/.zshenv",
    "/home/u/.config/fish/config.fish",
    "/etc/profile.d/x.sh",
    "/home/u/.ssh/authorized_keys",
    "/etc/ssh/authorized_keys/u",
]

_AGENT_CONFIG_PATHS = [
    "/repo/.mcp.json",
    ".mcp.json",
    "/home/u/.claude.json",
    "/repo/.claude/settings.json",
    "/repo/.claude/settings.local.json",
    "/repo/.cursor/mcp.json",
    "/repo/.vscode/mcp.json",
    "/repo/.vscode/tasks.json",
    "C:\\repo\\.vscode\\tasks.json",
    "/home/u/.gitconfig",
    "/home/u/.config/git/config",
]

# Names that only look like the ones above.
_LOOKALIKE_PATHS = [
    "/app/data/report.txt",
    "/app/data/bashrc_notes.txt",
    "/app/src/launch_agents.py",
    "/app/data/startup.md",
    "/app/data/system",
    "/app/docs/mcp.json.md",
    "/app/src/claude/settings.py",
]


class TestPersistenceAndAgentConfigDeny:
    """The default validator refuses OS persistence and agent config paths."""

    @pytest.mark.parametrize("path", _PERSISTENCE_PATHS)
    def test_persistence_path_refused(self, path: str) -> None:
        with pytest.raises(SafePathValidationError) as exc_info:
            SafePathValidator()(path)
        assert exc_info.value.pattern in PERSISTENCE_DENY_PATTERNS + [".ssh", "*/.ssh/*"]

    @pytest.mark.parametrize("path", _AGENT_CONFIG_PATHS)
    def test_agent_config_path_refused(self, path: str) -> None:
        with pytest.raises(SafePathValidationError) as exc_info:
            SafePathValidator()(path)
        assert exc_info.value.pattern in AGENT_CONFIG_DENY_PATTERNS

    @pytest.mark.parametrize(
        "path",
        [
            "/Users/u/library/launchagents/x.plist",
            "/USERS/U/LIBRARY/LAUNCHDAEMONS/X.PLIST",
            "/home/u/.BashRC",
            "/home/u/.ssh/Authorized_Keys",
            "C:\\Users\\u\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup\\x.bat",
            "/repo/.MCP.json",
            "/repo/.Claude/Settings.json",
            "/repo/.VSCode/Tasks.json",
        ],
    )
    def test_matched_whatever_the_case(self, path: str) -> None:
        with pytest.raises(SafePathValidationError):
            SafePathValidator()(path)

    @pytest.mark.parametrize("path", _LOOKALIKE_PATHS)
    def test_lookalike_names_allowed(self, path: str) -> None:
        assert SafePathValidator()(path) == Path(path)

    def test_older_patterns_keep_their_case(self) -> None:
        # "SYSTEM" (the Windows registry hive) stays case-sensitive, so a file named
        # "system" is not refused.
        assert SafePathValidator()("/app/data/system") == Path("/app/data/system")

    def test_empty_deny_patterns_still_allows_everything(self) -> None:
        validator = SafePathValidator(deny_patterns=[])
        for path in _PERSISTENCE_PATHS + _AGENT_CONFIG_PATHS + _LOOKALIKE_PATHS:
            assert validator(path) == Path(path)

    def test_lists_are_part_of_the_defaults(self) -> None:
        for pattern in PERSISTENCE_DENY_PATTERNS + AGENT_CONFIG_DENY_PATTERNS:
            assert pattern in DEFAULT_PATH_DENY_PATTERNS

    def test_lists_exported_from_the_package(self) -> None:
        import agent_airlock

        assert agent_airlock.PERSISTENCE_DENY_PATTERNS is PERSISTENCE_DENY_PATTERNS
        assert agent_airlock.AGENT_CONFIG_DENY_PATTERNS is AGENT_CONFIG_DENY_PATTERNS
        assert "PERSISTENCE_DENY_PATTERNS" in agent_airlock.__all__
        assert "AGENT_CONFIG_DENY_PATTERNS" in agent_airlock.__all__

    def test_lists_alone_match_case_insensitively(self) -> None:
        validator = SafePathValidator(deny_patterns=list(PERSISTENCE_DENY_PATTERNS))
        with pytest.raises(SafePathValidationError):
            validator("/Users/u/library/launchagents/x.plist")

    def test_safe_path_type_refuses(self) -> None:
        class PathModel(BaseModel):
            path: SafePath

        with pytest.raises(ValidationError):
            PathModel(path="/Users/u/Library/LaunchAgents/com.apple.sysmond.plist")


class TestTrailingDotAndSpaceFold:
    """Deny patterns also match the path Windows opens: trailing dots and spaces dropped."""

    @pytest.mark.parametrize(
        ("path", "pattern"),
        [
            ("/home/u/.ssh./id_ed25519", "*/.ssh/*"),
            ("/home/u/.ssh./authorized_keys", "*/.ssh/*"),
            ("/home/u/.ssh /id_ed25519", "*/.ssh/*"),
            ("/repo/.mcp.json.", ".mcp.json"),
            ("/repo/.mcp.json. . ", ".mcp.json"),
            ("/repo/.env ", ".env"),
            ("/repo/.git./config", "*/.git/*"),
            ("C:\\repo\\.vscode.\\tasks.json", ".vscode/tasks.json"),
            ("/Users/u/Library/LaunchAgents./x.plist", "*/Library/LaunchAgents/*"),
        ],
    )
    def test_folded_path_refused(self, path: str, pattern: str) -> None:
        with pytest.raises(SafePathValidationError) as exc_info:
            SafePathValidator()(path)
        assert exc_info.value.pattern == pattern

    def test_refusal_names_the_path_as_written(self) -> None:
        with pytest.raises(SafePathValidationError) as exc_info:
            SafePathValidator()("/repo/.mcp.json.")
        assert exc_info.value.path == "/repo/.mcp.json."
        assert str(exc_info.value).endswith(": /repo/.mcp.json.")

    @pytest.mark.parametrize(
        "path",
        ["/app/data/report.txt.", "/app/v1.2./notes.md", "/app/data/report .txt"],
    )
    def test_folded_lookalikes_allowed(self, path: str) -> None:
        assert SafePathValidator()(path) == Path(path)

    def test_empty_deny_patterns_skips_the_fold_too(self) -> None:
        validator = SafePathValidator(deny_patterns=[])
        for path in ["/home/u/.ssh./id_ed25519", "/repo/.mcp.json.", "/repo/.env "]:
            assert validator(path) == Path(path)

    def test_custom_patterns_are_folded(self) -> None:
        validator = SafePathValidator(deny_patterns=["secrets.toml"])
        with pytest.raises(SafePathValidationError):
            validator("/app/secrets.toml.")

    def test_safe_path_type_refuses_a_trailing_dot(self) -> None:
        class PathModel(BaseModel):
            path: SafePath

        with pytest.raises(ValidationError):
            PathModel(path="/repo/.mcp.json.")


class TestPythonStartupHookDeny:
    """The default validator refuses Python startup hooks (CVE-2026-120338 persistence)."""

    @pytest.mark.parametrize(
        ("path", "pattern"),
        [
            ("/srv/app/.venv/lib/python3.12/site-packages/evil.pth", "*/site-packages/*.pth"),
            ("/usr/lib/python3/dist-packages/x.pth", "*/dist-packages/*.pth"),
            ("C:\\venv\\Lib\\site-packages\\x.pth", "*/site-packages/*.pth"),
            (
                "/home/u/.local/lib/python3.12/site-packages/x.pth",
                "*/site-packages/*.pth",
            ),
            (
                "/srv/app/.venv/lib/python3.12/site-packages/sitecustomize.py",
                "sitecustomize.py",
            ),
            ("/srv/app/usercustomize.py", "usercustomize.py"),
            # Trailing-dot form: Windows opens evil.pth, so the fold catches it.
            ("/srv/app/.venv/lib/python3.12/site-packages/evil.pth.", "*/site-packages/*.pth"),
        ],
    )
    def test_startup_hook_refused(self, path: str, pattern: str) -> None:
        with pytest.raises(SafePathValidationError) as exc_info:
            SafePathValidator()(path)
        assert exc_info.value.pattern == pattern

    @pytest.mark.parametrize(
        "path",
        [
            # A PyTorch checkpoint outside a site dir is a *.pth that must stay allowed.
            "/app/models/resnet50.pth",
            "/app/checkpoints/epoch_3.pth",
            "/app/src/site_customize_notes.md",
            "/app/data/sitecustomize_report.txt",
        ],
    )
    def test_model_and_lookalike_files_allowed(self, path: str) -> None:
        assert SafePathValidator()(path) == Path(path)

    def test_startup_hooks_in_the_persistence_list(self) -> None:
        from agent_airlock.safe_types import PERSISTENCE_DENY_PATTERNS

        for pattern in (
            "*/site-packages/*.pth",
            "*/dist-packages/*.pth",
            "sitecustomize.py",
            "usercustomize.py",
        ):
            assert pattern in PERSISTENCE_DENY_PATTERNS
            assert pattern in DEFAULT_PATH_DENY_PATTERNS

    def test_empty_deny_patterns_allows_startup_hooks(self) -> None:
        validator = SafePathValidator(deny_patterns=[])
        for path in (
            "/srv/app/.venv/lib/python3.12/site-packages/evil.pth",
            "/srv/app/usercustomize.py",
            "/app/models/resnet50.pth",
        ):
            assert validator(path) == Path(path)
