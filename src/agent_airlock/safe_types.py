"""Safe types for Agent-Airlock (V0.4.0).

Provides built-in types that validate paths and URLs at the type level,
preventing directory traversal, secret access, and data exfiltration.

These types integrate with Pydantic validation and can be used directly
in function signatures of Airlock-protected tools.

Usage:
    from agent_airlock import SafePath, SafeURL

    @Airlock()
    def read_config(path: SafePath) -> str:
        return Path(path).read_text()

    @Airlock()
    def fetch_data(url: SafeURL) -> str:
        return requests.get(url).text

The validators reject:
    - Directory traversal (../)
    - Home directory access (~)
    - Secret files (.env, .ssh, *.pem, *.key)
    - System files (/etc/passwd, /etc/shadow)
    - Metadata URLs (AWS/GCP)
    - File URLs (file://)
    - Private/link-local IPs
"""

from __future__ import annotations

import fnmatch
import ipaddress
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import urlparse

import structlog
from pydantic import AfterValidator

logger = structlog.get_logger("agent-airlock.safe_types")


# Default deny patterns for paths (can be customized)
DEFAULT_PATH_DENY_PATTERNS = [
    # Home directory
    "~",
    "~/*",
    # Parent traversal
    "..",
    "*/..*",
    "../*",
    "*/../*",
    # Environment and secrets
    ".env",
    "*.env",
    "*/.env",
    ".env.*",
    # SSH keys
    ".ssh",
    ".ssh/*",
    "*/.ssh/*",
    "*.ssh/*",
    # Git directory
    ".git",
    ".git/*",
    "*/.git/*",
    # Certificate and key files
    "*.pem",
    "*.key",
    "*.crt",
    "*.p12",
    "*.pfx",
    # AWS credentials
    ".aws",
    ".aws/*",
    "*/.aws/*",
    "credentials",
    # Docker secrets
    ".docker",
    ".docker/*",
    # System files
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/sudoers",
    "/proc/*",
    "/sys/*",
    # macOS/Windows secrets
    "*.keychain",
    "*.keychain-db",
    "ntds.dit",
    "SAM",
    "SYSTEM",
]


# URLs that should be blocked
BLOCKED_HOSTS = [
    # AWS metadata
    "169.254.169.254",
    "fd00:ec2::254",
    # GCP metadata
    "metadata.google.internal",
    "169.254.169.253",
    # Azure metadata
    "169.254.169.253",
    # Link-local
    "169.254.0.0/16",
]


class SafePathValidationError(ValueError):
    """Raised when a path fails safety validation."""

    def __init__(self, message: str, path: str, pattern: str | None = None) -> None:
        self.path = path
        self.pattern = pattern
        super().__init__(message)


class SafeURLValidationError(ValueError):
    """Raised when a URL fails safety validation."""

    def __init__(self, message: str, url: str, reason: str | None = None) -> None:
        self.url = url
        self.reason = reason
        super().__init__(message)


class SafePathValidator:
    """Validates paths are safe (no traversal, no secrets).

    This validator rejects paths that:
    - Contain parent traversal (..)
    - Access the home directory (~)
    - Match deny patterns (secrets, configs, etc.)
    - Are absolute paths (when not allowed)
    - Escape the root directory (when specified)

    Examples:
        # Basic validation
        validator = SafePathValidator()
        safe_path = validator("/app/data/file.txt")  # OK
        validator("~/.ssh/id_rsa")  # Raises SafePathValidationError

        # With root directory jail
        validator = SafePathValidator(root_dir=Path("/app/data"))
        validator("/app/data/subdir/file.txt")  # OK
        validator("/etc/passwd")  # Raises SafePathValidationError

        # Custom deny patterns
        validator = SafePathValidator(deny_patterns=["*.log", "*.tmp"])
    """

    def __init__(
        self,
        root_dir: Path | None = None,
        deny_patterns: list[str] | None = None,
        allow_absolute: bool = True,
        extra_deny_patterns: list[str] | None = None,
    ) -> None:
        """Initialize the path validator.

        Args:
            root_dir: If specified, paths must resolve within this directory.
            deny_patterns: Patterns to deny. Defaults to DEFAULT_PATH_DENY_PATTERNS.
                          Set to [] to disable default patterns.
            allow_absolute: Whether to allow absolute paths.
            extra_deny_patterns: Additional patterns to deny (appended to defaults).
        """
        self.root_dir = root_dir.resolve() if root_dir else None
        self.deny_patterns = (
            deny_patterns if deny_patterns is not None else DEFAULT_PATH_DENY_PATTERNS.copy()
        )
        if extra_deny_patterns:
            self.deny_patterns.extend(extra_deny_patterns)
        self.allow_absolute = allow_absolute

    def __call__(self, value: str | Path) -> Path:
        """Validate and return safe path.

        Args:
            value: Path to validate.

        Returns:
            Validated Path object.

        Raises:
            SafePathValidationError: If the path is unsafe.
        """
        path_str = str(value)
        path = Path(value)

        # Check for parent traversal in the string (before resolution)
        if ".." in path_str:
            raise SafePathValidationError(
                f"Path contains parent traversal: {path_str}",
                path=path_str,
                pattern="..",
            )

        # Check for home directory
        if path_str.startswith("~"):
            raise SafePathValidationError(
                f"Home directory access not allowed: {path_str}",
                path=path_str,
                pattern="~",
            )

        # Check absolute path
        if not self.allow_absolute and path.is_absolute():
            raise SafePathValidationError(
                f"Absolute paths not allowed: {path_str}",
                path=path_str,
            )

        # Check against deny patterns
        for pattern in self.deny_patterns:
            if self._matches_pattern(path_str, pattern):
                raise SafePathValidationError(
                    f"Path matches denied pattern '{pattern}': {path_str}",
                    path=path_str,
                    pattern=pattern,
                )

        # Check within root if specified
        if self.root_dir is not None:
            try:
                if path.is_absolute():
                    resolved = path.resolve()
                else:
                    resolved = (self.root_dir / path).resolve()

                # Use os.path.commonpath for CVE-resistant traversal check
                import os

                try:
                    common = os.path.commonpath([str(resolved), str(self.root_dir)])
                    if common != str(self.root_dir):
                        raise SafePathValidationError(
                            f"Path escapes root directory {self.root_dir}: {path_str}",
                            path=path_str,
                        )
                except ValueError:
                    # Different drives on Windows
                    raise SafePathValidationError(
                        f"Path escapes root directory {self.root_dir}: {path_str}",
                        path=path_str,
                    ) from None
            except OSError as e:
                raise SafePathValidationError(
                    f"Path resolution failed: {e}",
                    path=path_str,
                ) from e

        return path

    def _matches_pattern(self, path: str, pattern: str) -> bool:
        """Check if path matches a deny pattern."""
        # Normalize path separators
        path_normalized = path.replace("\\", "/")
        pattern_normalized = pattern.replace("\\", "/")

        # Check exact match
        if path_normalized == pattern_normalized:
            return True

        # Check if path ends with the pattern
        if path_normalized.endswith("/" + pattern_normalized):
            return True

        # Check filename match
        filename = Path(path_normalized).name
        if fnmatch.fnmatch(filename, pattern_normalized):
            return True

        # Check full path match with glob
        if fnmatch.fnmatch(path_normalized, pattern_normalized):
            return True

        return False


class SafeURLValidator:
    """Validates URLs are safe (no file://, no metadata, no private IPs).

    This validator rejects URLs that:
    - Use file:// scheme
    - Point to cloud metadata endpoints
    - Point to private/link-local IPs
    - Use non-allowed schemes
    - Point to non-allowed hosts

    Examples:
        # Basic validation
        validator = SafeURLValidator()
        safe_url = validator("https://api.example.com/data")  # OK
        validator("file:///etc/passwd")  # Raises SafeURLValidationError
        validator("http://169.254.169.254/latest/meta-data/")  # Raises

        # With host allowlist
        validator = SafeURLValidator(allowed_hosts=["api.company.com"])
        validator("https://api.company.com/data")  # OK
        validator("https://evil.com/data")  # Raises SafeURLValidationError
    """

    def __init__(
        self,
        allowed_schemes: list[str] | None = None,
        allowed_hosts: list[str] | None = None,
        block_private_ips: bool = True,
        block_metadata_urls: bool = True,
        extra_blocked_hosts: list[str] | None = None,
    ) -> None:
        """Initialize the URL validator.

        Args:
            allowed_schemes: Allowed URL schemes. Defaults to ["https"].
            allowed_hosts: If specified, only these hosts are allowed.
            block_private_ips: Block private/link-local IP addresses.
            block_metadata_urls: Block cloud metadata endpoints.
            extra_blocked_hosts: Additional hosts to block.
        """
        self.allowed_schemes = allowed_schemes or ["https"]
        self.allowed_hosts = allowed_hosts
        self.block_private_ips = block_private_ips
        self.block_metadata_urls = block_metadata_urls
        self.blocked_hosts = BLOCKED_HOSTS.copy()
        if extra_blocked_hosts:
            self.blocked_hosts.extend(extra_blocked_hosts)

    def __call__(self, value: str) -> str:
        """Validate and return safe URL.

        Args:
            value: URL to validate.

        Returns:
            Validated URL string.

        Raises:
            SafeURLValidationError: If the URL is unsafe.
        """
        try:
            parsed = urlparse(value)
        except Exception as e:
            raise SafeURLValidationError(
                f"Invalid URL: {e}",
                url=value,
                reason="parse_error",
            ) from e

        # Check scheme
        if parsed.scheme not in self.allowed_schemes:
            raise SafeURLValidationError(
                f"URL scheme '{parsed.scheme}' not allowed. Allowed: {self.allowed_schemes}",
                url=value,
                reason="invalid_scheme",
            )

        # Check for file:// scheme explicitly
        if parsed.scheme == "file":
            raise SafeURLValidationError(
                "file:// URLs are not allowed",
                url=value,
                reason="file_scheme",
            )

        hostname = parsed.hostname
        if not hostname:
            raise SafeURLValidationError(
                "URL must have a hostname",
                url=value,
                reason="missing_hostname",
            )

        # Check host allowlist
        if self.allowed_hosts is not None and hostname not in self.allowed_hosts:
            raise SafeURLValidationError(
                f"Host '{hostname}' not in allowed list: {self.allowed_hosts}",
                url=value,
                reason="host_not_allowed",
            )

        # Check blocked hosts
        if self.block_metadata_urls:
            for blocked in self.blocked_hosts:
                if hostname == blocked or hostname.endswith("." + blocked):
                    raise SafeURLValidationError(
                        f"URL points to blocked host: {hostname}",
                        url=value,
                        reason="metadata_url",
                    )

        # Check private IPs
        if self.block_private_ips:
            try:
                ip = ipaddress.ip_address(hostname)
                if ip.is_private or ip.is_loopback or ip.is_link_local:
                    raise SafeURLValidationError(
                        f"URL points to private/loopback/link-local IP: {hostname}",
                        url=value,
                        reason="private_ip",
                    )
            except ValueError:
                # Not an IP address, that's fine
                pass

            # Check for localhost aliases
            if hostname in ["localhost", "127.0.0.1", "::1", "0.0.0.0"]:  # nosec B104 - checking not binding
                raise SafeURLValidationError(
                    f"URL points to localhost: {hostname}",
                    url=value,
                    reason="localhost",
                )

        return value


# Pre-configured validators
_default_path_validator = SafePathValidator()
_strict_path_validator = SafePathValidator(allow_absolute=False)
_tmp_path_validator = SafePathValidator(root_dir=Path("/tmp/airlock"))  # nosec B108 - intentional
_default_url_validator = SafeURLValidator()
_http_url_validator = SafeURLValidator(allowed_schemes=["http", "https"])


def validate_safe_path(value: str | Path) -> Path:
    """Default path validator using DEFAULT_PATH_DENY_PATTERNS."""
    return _default_path_validator(value)


def validate_safe_path_strict(value: str | Path) -> Path:
    """Strict path validator that rejects absolute paths."""
    return _strict_path_validator(value)


def validate_safe_path_in_tmp(value: str | Path) -> Path:
    """Path validator that requires paths within /tmp/airlock."""
    return _tmp_path_validator(value)


def validate_safe_url(value: str) -> str:
    """Default URL validator (HTTPS only)."""
    return _default_url_validator(value)


def validate_safe_url_allow_http(value: str) -> str:
    """URL validator that allows both HTTP and HTTPS."""
    return _http_url_validator(value)


# Type aliases using Pydantic's Annotated pattern
SafePath = Annotated[Path, AfterValidator(validate_safe_path)]
"""Safe path type that validates against common attack patterns.

Rejects: traversal (..), home (~), .env, .ssh, *.pem, /etc/passwd, etc.
"""

SafePathStrict = Annotated[Path, AfterValidator(validate_safe_path_strict)]
"""Strict safe path that also rejects absolute paths."""

SafePathInTmp = Annotated[Path, AfterValidator(validate_safe_path_in_tmp)]
"""Safe path that must be within /tmp/airlock."""

SafeURL = Annotated[str, AfterValidator(validate_safe_url)]
"""Safe URL type that validates against exfiltration patterns.

Rejects: file://, metadata URLs, private IPs, localhost.
Only allows HTTPS.
"""

SafeURLAllowHttp = Annotated[str, AfterValidator(validate_safe_url_allow_http)]
"""Safe URL type that allows both HTTP and HTTPS."""


# Factory functions for custom validators
def create_safe_path_type(
    root_dir: Path | None = None,
    deny_patterns: list[str] | None = None,
    allow_absolute: bool = True,
    extra_deny_patterns: list[str] | None = None,
) -> Any:
    """Create a custom SafePath type with specific validation rules.

    Args:
        root_dir: If specified, paths must resolve within this directory.
        deny_patterns: Patterns to deny. Defaults to DEFAULT_PATH_DENY_PATTERNS.
        allow_absolute: Whether to allow absolute paths.
        extra_deny_patterns: Additional patterns to deny.

    Returns:
        An Annotated type that can be used in function signatures.

    Examples:
        # Create a type for paths within /app/data
        AppDataPath = create_safe_path_type(root_dir=Path("/app/data"))

        @Airlock()
        def read_data(path: AppDataPath) -> str:
            return Path(path).read_text()
    """
    validator = SafePathValidator(
        root_dir=root_dir,
        deny_patterns=deny_patterns,
        allow_absolute=allow_absolute,
        extra_deny_patterns=extra_deny_patterns,
    )
    return Annotated[Path, AfterValidator(validator)]


def create_safe_url_type(
    allowed_schemes: list[str] | None = None,
    allowed_hosts: list[str] | None = None,
    block_private_ips: bool = True,
    block_metadata_urls: bool = True,
    extra_blocked_hosts: list[str] | None = None,
) -> Any:
    """Create a custom SafeURL type with specific validation rules.

    Args:
        allowed_schemes: Allowed URL schemes.
        allowed_hosts: If specified, only these hosts are allowed.
        block_private_ips: Block private/link-local IP addresses.
        block_metadata_urls: Block cloud metadata endpoints.
        extra_blocked_hosts: Additional hosts to block.

    Returns:
        An Annotated type that can be used in function signatures.

    Examples:
        # Create a type for API URLs only
        ApiURL = create_safe_url_type(allowed_hosts=["api.company.com", "api.partner.com"])

        @Airlock()
        def call_api(url: ApiURL) -> str:
            return requests.get(url).text
    """
    validator = SafeURLValidator(
        allowed_schemes=allowed_schemes,
        allowed_hosts=allowed_hosts,
        block_private_ips=block_private_ips,
        block_metadata_urls=block_metadata_urls,
        extra_blocked_hosts=extra_blocked_hosts,
    )
    return Annotated[str, AfterValidator(validator)]
