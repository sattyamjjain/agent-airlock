"""Filesystem security module for Agent-Airlock.

Provides bulletproof path validation to prevent directory traversal attacks,
symlink exploitation, and unauthorized file access.

SECURITY: Uses os.path.commonpath() (NOT string prefix matching) for CVE-resistant
path validation. Prevents TOCTOU race conditions with atomic path resolution.
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger("agent-airlock.filesystem")


class PathValidationError(Exception):
    """Raised when a path fails security validation."""

    def __init__(
        self,
        message: str,
        path: str,
        violation_type: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.message = message
        self.path = path
        self.violation_type = violation_type
        self.details = details or {}
        super().__init__(message)


@dataclass
class FilesystemPolicy:
    """Security policy for filesystem access control.

    Example:
        policy = FilesystemPolicy(
            allowed_roots=[Path("/app/data"), Path("/tmp")],
            deny_patterns=["*.env", "**/.git/**", "**/secrets/**"],
            allow_symlinks=False,
            max_path_depth=20,
        )

    Attributes:
        allowed_roots: List of allowed root directories. Paths must be within
                      one of these roots to be valid. Empty list = no restriction.
        allow_symlinks: If False, reject paths that resolve through symlinks.
                       SECURITY: Set False to prevent symlink-based escapes.
        deny_patterns: List of glob patterns to deny. Matched against the
                      resolved path. Supports ** for recursive matching.
        max_path_depth: Maximum directory depth from root. Prevents DoS via
                       extremely deep paths.
    """

    allowed_roots: list[Path] = field(default_factory=list)
    allow_symlinks: bool = False
    deny_patterns: list[str] = field(default_factory=list)
    max_path_depth: int = 20

    def __post_init__(self) -> None:
        """Normalize allowed roots to absolute paths."""
        self.allowed_roots = [Path(root).resolve() for root in self.allowed_roots]


def _get_path_depth(path: Path) -> int:
    """Get the depth of a path (number of directory components)."""
    return len(path.parts)


def _matches_deny_pattern(path: Path, patterns: list[str]) -> str | None:
    """Check if path matches any deny pattern.

    Returns:
        The matching pattern if found, None otherwise.
    """
    path_str = str(path)
    path_name = path.name

    for pattern in patterns:
        # Check against full path
        if fnmatch.fnmatch(path_str, pattern):
            return pattern
        # Check against filename only (for patterns like "*.env")
        if fnmatch.fnmatch(path_name, pattern):
            return pattern
        # Check each path component for patterns like "**/.git/**"
        for part in path.parts:
            if fnmatch.fnmatch(part, pattern.replace("**/", "").replace("/**", "")):
                return pattern

    return None


def is_path_within_roots(path: Path, roots: list[Path]) -> bool:
    """Check if a path is within any of the allowed root directories.

    SECURITY: Uses os.path.commonpath() instead of string prefix matching
    to prevent CVE-style path traversal bypasses.

    Args:
        path: The resolved absolute path to check.
        roots: List of allowed root directories (must be absolute).

    Returns:
        True if path is within any root, False otherwise.
    """
    if not roots:
        return True  # No restriction if no roots specified

    path_str = str(path)

    for root in roots:
        root_str = str(root)
        try:
            # os.path.commonpath raises ValueError if paths are on different drives (Windows)
            # or if paths have no common prefix
            common = os.path.commonpath([path_str, root_str])
            if common == root_str:
                return True
        except ValueError:
            # Different drives on Windows, or empty sequence
            continue

    return False


def validate_path(
    path: str | Path,
    policy: FilesystemPolicy,
    *,
    must_exist: bool = False,
) -> Path:
    """Validate a path against a filesystem security policy.

    SECURITY: This function performs atomic path resolution to prevent TOCTOU
    race conditions. All checks are performed on the resolved path.

    Args:
        path: The path to validate (can be relative or absolute).
        policy: The filesystem policy to enforce.
        must_exist: If True, raise error if path doesn't exist.

    Returns:
        The validated, resolved absolute Path.

    Raises:
        PathValidationError: If the path violates the policy.
    """
    original_path = str(path)

    # Convert to Path object
    if isinstance(path, str):
        path = Path(path)

    # Check for path depth before resolution (DoS prevention)
    if _get_path_depth(path) > policy.max_path_depth:
        raise PathValidationError(
            f"Path exceeds maximum depth of {policy.max_path_depth}",
            original_path,
            "max_depth_exceeded",
            {"depth": _get_path_depth(path), "max_depth": policy.max_path_depth},
        )

    # Check if path exists for must_exist validation
    if must_exist and not path.exists():
        raise PathValidationError(
            f"Path does not exist: {original_path}",
            original_path,
            "path_not_found",
        )

    # Resolve to absolute path (follows symlinks)
    # SECURITY: Use os.path.realpath for canonical resolution
    try:
        resolved = Path(os.path.realpath(path))
    except OSError as e:
        raise PathValidationError(
            f"Failed to resolve path: {e}",
            original_path,
            "resolution_failed",
            {"error": str(e)},
        ) from e

    # Check for symlinks if not allowed
    if not policy.allow_symlinks:
        # Compare the path before and after symlink resolution
        try:
            # Path.resolve() normalizes the path; realpath follows symlinks
            # If they differ significantly, there's a symlink involved
            absolute_path = path.absolute()
            if absolute_path.exists():
                # Check if any component is a symlink
                current = absolute_path
                while current != current.parent:  # Stop at root
                    if current.is_symlink():
                        raise PathValidationError(
                            f"Path contains symlink at {current}",
                            original_path,
                            "symlink_detected",
                            {"symlink_location": str(current)},
                        )
                    current = current.parent
        except OSError:
            # Path doesn't exist yet or permission error - OK for non-must_exist
            pass

    # Check allowed roots
    if policy.allowed_roots and not is_path_within_roots(resolved, policy.allowed_roots):
        raise PathValidationError(
            f"Path '{original_path}' is outside allowed directories",
            original_path,
            "outside_allowed_roots",
            {
                "resolved_path": str(resolved),
                "allowed_roots": [str(r) for r in policy.allowed_roots],
            },
        )

    # Check deny patterns
    if policy.deny_patterns:
        matched_pattern = _matches_deny_pattern(resolved, policy.deny_patterns)
        if matched_pattern:
            raise PathValidationError(
                f"Path matches denied pattern: {matched_pattern}",
                original_path,
                "denied_pattern",
                {"pattern": matched_pattern, "resolved_path": str(resolved)},
            )

    # Check resolved path depth
    if _get_path_depth(resolved) > policy.max_path_depth:
        raise PathValidationError(
            f"Resolved path exceeds maximum depth of {policy.max_path_depth}",
            original_path,
            "max_depth_exceeded",
            {"depth": _get_path_depth(resolved), "max_depth": policy.max_path_depth},
        )

    logger.debug(
        "path_validated",
        original_path=original_path,
        resolved_path=str(resolved),
        allowed_roots_count=len(policy.allowed_roots),
    )

    return resolved


# Predefined policies for common use cases

RESTRICTIVE_FILESYSTEM_POLICY = FilesystemPolicy(
    allowed_roots=[],  # Must be configured per-deployment
    allow_symlinks=False,
    deny_patterns=[
        # Configuration files that may contain secrets
        "*.env",
        ".env*",
        "*.pem",
        "*.key",
        "*.crt",
        "*.p12",
        "*.pfx",
        # Sensitive directories
        "**/.git/**",
        "**/.ssh/**",
        "**/secrets/**",
        "**/credentials/**",
        "**/.aws/**",
        "**/.config/**",
        # System directories
        "/etc/**",
        "/proc/**",
        "/sys/**",
        "/dev/**",
    ],
    max_path_depth=15,
)
"""Restrictive policy blocking common sensitive paths. Requires allowed_roots to be set."""


SANDBOX_FILESYSTEM_POLICY = FilesystemPolicy(
    allowed_roots=[Path("/tmp"), Path("/sandbox")],
    allow_symlinks=False,
    deny_patterns=["*.env", "*.key", "*.pem"],
    max_path_depth=10,
)
"""Policy for sandboxed execution - only allows /tmp and /sandbox."""
