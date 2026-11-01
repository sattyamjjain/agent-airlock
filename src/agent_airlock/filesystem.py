"""Filesystem security module for Agent-Airlock.

Path validation against directory traversal, symlink escapes and unauthorized file
access, and an open that cannot be redirected after the check.

SECURITY: Uses os.path.commonpath() (NOT string prefix matching) for CVE-resistant
path validation. :func:`validate_path` checks a path as it resolves when it runs and holds
nothing open, so it is not atomic: a component swapped after the check (a directory
replaced by a symlink to outside the root, GHSA-52hc-jp32-qrr3) is followed by the tool's
own ``open()``. :func:`open_contained` closes that window: it walks the checked path from
the allowed root one component at a time, never following a symlink, so it opens what was
checked or refuses.
"""

from __future__ import annotations

import errno
import fnmatch
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any

from ._log import structlog

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
        bind_resolved_paths: If True, ``@Airlock`` hands the tool the absolute path each
                       top-level ``str`` or ``pathlib`` argument resolved to when it was
                       checked, rather than the value as passed, so a relative path or a
                       ``~`` the tool would resolve differently opens what was checked.
                       Nested values (inside a list, a dict or a model) are passed as
                       given. It does not make the open atomic: a component swapped after
                       the check is still followed, unless the tool opens through
                       :func:`open_contained`. Off by default.
    """

    allowed_roots: list[Path] = field(default_factory=list)
    allow_symlinks: bool = False
    deny_patterns: list[str] = field(default_factory=list)
    max_path_depth: int = 20
    bind_resolved_paths: bool = False

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


def _home_relative(path_text: str) -> str | None:
    """``path_text`` without leading whitespace when it begins with ``~``, else None."""
    stripped = path_text.lstrip()
    return stripped if stripped.startswith("~") else None


def _expand_home(original_path: str, home_relative: str) -> str:
    """The form a tool that calls ``os.path.expanduser`` would open.

    Raises:
        PathValidationError: The ``~`` prefix names no home directory this process can
            resolve (``~nosuchuser/...``, or no ``HOME`` and no password entry), so what
            a tool would open is unknown and the path is refused.
    """
    try:
        expanded = os.path.expanduser(home_relative)
    except (KeyError, OSError, ValueError) as exc:  # pragma: no cover - platform specific
        raise PathValidationError(
            "Path names a home directory that cannot be resolved",
            original_path,
            "unresolvable_home",
            {"reason": type(exc).__name__},
        ) from exc
    if expanded.startswith("~"):
        raise PathValidationError(
            "Path names a home directory that cannot be resolved",
            original_path,
            "unresolvable_home",
            {"reason": "no home directory for this ~ prefix"},
        )
    return expanded


def validate_path(
    path: str | Path,
    policy: FilesystemPolicy,
    *,
    must_exist: bool = False,
) -> Path:
    """Validate a path against a filesystem security policy.

    The path is checked as it resolves when this runs (``os.path.realpath``), and nothing
    is held open, so the check is not atomic: a component swapped between this check and
    the tool's own ``open()`` (a directory replaced by a symlink, GHSA-52hc-jp32-qrr3) is
    followed by that ``open()``. A tool that opens through :func:`open_contained` (or
    :func:`open_contained_file`) is not exposed to that window. All checks are performed
    on the resolved path.

    A path that begins with ``~`` (after any leading whitespace) is checked in **both**
    forms, and both must pass: the literal one, which is what ``open()`` and
    ``os.path.realpath`` see (``$CWD/~/...``), and the ``os.path.expanduser`` one, which is
    what a tool that expands ``~`` opens. Until 0.10.25 only the literal form was checked,
    so with the working directory inside an allowed root, ``~/.ssh/id_rsa`` passed and a
    tool that expanded it read the real key. A ``~user`` prefix this process cannot expand
    is refused, because what a tool would open is then unknown.

    Args:
        path: The path to validate (can be relative or absolute).
        policy: The filesystem policy to enforce.
        must_exist: If True, raise error if path doesn't exist. Applies to the literal
            form, as before.

    Returns:
        The validated, resolved absolute Path of the literal form.

    Raises:
        PathValidationError: If the path violates the policy.
    """
    original_path = str(path)

    # A NUL byte is never part of a real path, and os.stat / realpath raise ValueError on
    # one rather than OSError, which escaped as a raw exception until 0.10.24.
    if "\x00" in original_path:
        raise PathValidationError(
            "Path contains a NUL byte",
            original_path,
            "invalid_path",
        )

    home_relative = _home_relative(original_path)
    expanded = _expand_home(original_path, home_relative) if home_relative is not None else None

    resolved = _validate_form(
        Path(path) if isinstance(path, str) else path,
        original_path,
        policy,
        must_exist=must_exist,
    )
    if expanded is not None:
        _validate_form(Path(expanded), original_path, policy, must_exist=False, home_form=True)

    logger.debug(
        "path_validated",
        original_path=original_path,
        resolved_path=str(resolved),
        home_form_checked=expanded is not None,
        allowed_roots_count=len(policy.allowed_roots),
    )

    return resolved


def _validate_form(
    path: Path,
    original_path: str,
    policy: FilesystemPolicy,
    *,
    must_exist: bool,
    home_form: bool = False,
) -> Path:
    """Check one form of a path against ``policy`` and return its resolution.

    ``home_form`` marks the ``expanduser`` form of a ``~`` path. Its refusals say so and
    leave out the resolved path, which would tell the model the home directory.
    """
    form_details: dict[str, Any] = {"form": "home_expanded"} if home_form else {}

    def resolved_detail(resolved: Path) -> dict[str, Any]:
        return form_details if home_form else {"resolved_path": str(resolved)}

    # Check for path depth before resolution (DoS prevention)
    if _get_path_depth(path) > policy.max_path_depth:
        raise PathValidationError(
            f"Path exceeds maximum depth of {policy.max_path_depth}",
            original_path,
            "max_depth_exceeded",
            {"depth": _get_path_depth(path), "max_depth": policy.max_path_depth, **form_details},
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
    except (OSError, ValueError) as e:
        raise PathValidationError(
            f"Failed to resolve path: {e}",
            original_path,
            "resolution_failed",
            {"error": str(e)},
        ) from e

    # Check for symlinks if not allowed
    if not policy.allow_symlinks:
        _refuse_symlinked(path, original_path, form_details)

    # Check allowed roots
    if policy.allowed_roots and not is_path_within_roots(resolved, policy.allowed_roots):
        raise PathValidationError(
            f"Path '{original_path}' is outside allowed directories",
            original_path,
            "outside_allowed_roots",
            {
                **resolved_detail(resolved),
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
                {"pattern": matched_pattern, **resolved_detail(resolved)},
            )

    # Check resolved path depth
    if _get_path_depth(resolved) > policy.max_path_depth:
        raise PathValidationError(
            f"Resolved path exceeds maximum depth of {policy.max_path_depth}",
            original_path,
            "max_depth_exceeded",
            {
                "depth": _get_path_depth(resolved),
                "max_depth": policy.max_path_depth,
                **form_details,
            },
        )

    return resolved


def _refuse_symlinked(path: Path, original_path: str, form_details: dict[str, Any]) -> None:
    """Refuse ``path`` when any component of its absolute form is a symlink.

    Every component that exists is checked, the leaf's ancestors included when the leaf
    does not exist yet: until 0.10.29 the walk was skipped for a missing leaf, so
    ``ws/link/new.txt`` passed with ``link`` a symlink, and every ``OSError`` was
    swallowed. A component that does not exist has nothing to follow, so the walk moves
    on to its parent; any other error reading a component refuses the path, since the
    check cannot say what it would follow.

    ``form_details`` is empty for the literal form, whose refusal names the symlink, and
    marks the ``expanduser`` form, whose refusal leaves the location out.
    """
    current = path.absolute()
    while True:
        try:
            mode = os.lstat(current).st_mode
        except FileNotFoundError:
            mode = 0
        except OSError as exc:
            raise PathValidationError(
                "Path could not be checked for symlinks",
                original_path,
                "symlink_check_failed",
                {"error": type(exc).__name__, **form_details},
            ) from exc
        if stat.S_ISLNK(mode):
            raise PathValidationError(
                f"Path contains symlink at {current}",
                original_path,
                "symlink_detected",
                form_details or {"symlink_location": str(current)},
            )
        if current == current.parent:
            return
        current = current.parent


#: The access and creation flags each ``open()`` mode letter stands for.
_MODE_CREATION = {
    "r": 0,
    "w": os.O_CREAT | os.O_TRUNC,
    "a": os.O_CREAT | os.O_APPEND,
    "x": os.O_CREAT | os.O_EXCL,
}


def open_contained(
    path: str | os.PathLike[str],
    policy: FilesystemPolicy,
    flags: int = os.O_RDONLY,
    mode: int = 0o600,
) -> int:
    """Open ``path`` under ``policy`` without following a symlink, and return the descriptor.

    :func:`validate_path` checks a path as it resolves when it runs; a component swapped
    after that is followed by a later ``open()`` (GHSA-52hc-jp32-qrr3). This runs the same
    checks, then opens the path they resolved, starting from the allowed root that
    contains it: each directory below the root is opened relative to the one above it
    (``dir_fd``) with ``O_NOFOLLOW``, and the leaf with ``flags | O_NOFOLLOW``, so a
    component that is a symlink by the time it is opened is refused, and what is opened is
    what was checked, or nothing. With no ``allowed_roots`` the walk starts at the
    filesystem root. A policy that allows symlinks gets them resolved at check time, so the
    walk follows the path they resolved to and refuses one that appears later.

    Hard links and mount points are not symlinks, and are not detected.

    Args:
        path: The path to open, relative or absolute.
        policy: The filesystem policy it must pass.
        flags: ``os.open`` flags for the leaf, e.g. ``os.O_WRONLY | os.O_CREAT``.
        mode: Permission bits for a file ``flags`` creates.

    Returns:
        An open file descriptor, which the caller closes.

    Raises:
        PathValidationError: The path fails :func:`validate_path`; a component is a
            symlink when it is opened (``symlink_detected``); or this platform cannot open
            relative to a directory without following symlinks (``atomic_open_unsupported``,
            Windows), which is refused rather than answered with the racy open.
        OSError: The open failed for another reason: a directory that does not exist, a
            permission error, ``O_EXCL`` on a file that exists.
    """
    original_path = os.fsdecode(os.fspath(path))
    _require_atomic_open(original_path)
    resolved = validate_path(original_path, policy)
    root = _containing_root(resolved, policy)
    parts = _components(resolved, root, original_path)
    if not parts:
        return os.open(root, flags, mode)
    dir_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[:-1]:
            child = _open_component(
                part, dir_fd, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, 0, original_path
            )
            os.close(dir_fd)
            dir_fd = child
        return _open_component(parts[-1], dir_fd, flags | os.O_NOFOLLOW, mode, original_path)
    finally:
        os.close(dir_fd)


@contextmanager
def open_contained_file(
    path: str | os.PathLike[str],
    policy: FilesystemPolicy,
    mode: str = "r",
    *,
    encoding: str | None = None,
    errors: str | None = None,
    newline: str | None = None,
    create_mode: int = 0o600,
) -> Iterator[IO[Any]]:
    """:func:`open_contained` as a file object, closed when the block exits.

    Args:
        path: The path to open.
        policy: The filesystem policy it must pass.
        mode: An ``open()`` mode: one of ``r``, ``w``, ``a``, ``x``, optionally with ``+``
            and ``b`` or ``t``.
        encoding: Passed to ``open()`` for a text mode.
        errors: Passed to ``open()`` for a text mode.
        newline: Passed to ``open()`` for a text mode.
        create_mode: Permission bits for a file the mode creates.

    Yields:
        The open file object.

    Raises:
        ValueError: ``mode`` is not an ``open()`` mode.
        PathValidationError: As :func:`open_contained`.
    """
    fd = open_contained(path, policy, _flags_for_mode(mode), create_mode)
    try:
        handle = os.fdopen(fd, mode, encoding=encoding, errors=errors, newline=newline)
    except BaseException:
        os.close(fd)
        raise
    with handle:
        yield handle


def _flags_for_mode(mode: str) -> int:
    """The ``os.open`` flags an ``open()`` mode string stands for."""
    letters = [letter for letter in mode if letter in _MODE_CREATION]
    if (
        len(letters) != 1
        or set(mode) - set("rwaxbt+")
        or len(set(mode)) != len(mode)
        or {"b", "t"} <= set(mode)
    ):
        raise ValueError(f"invalid mode: {mode!r}")
    letter = letters[0]
    one_way = os.O_RDONLY if letter == "r" else os.O_WRONLY
    access = os.O_RDWR if "+" in mode else one_way
    return access | _MODE_CREATION[letter]


def _require_atomic_open(original_path: str) -> None:
    """Refuse on a platform that cannot open relative to a directory without following."""
    if (
        os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
    ):
        raise PathValidationError(
            "This platform cannot open a path relative to a directory without following "
            "symlinks, so open_contained refuses rather than fall back to a racy open",
            original_path,
            "atomic_open_unsupported",
        )


def _containing_root(resolved: Path, policy: FilesystemPolicy) -> Path:
    """The allowed root ``resolved`` lies in, or its filesystem root when there are none."""
    if not policy.allowed_roots:
        return Path(resolved.anchor)
    for root in policy.allowed_roots:
        if is_path_within_roots(resolved, [root]):
            return root
    raise PathValidationError(  # pragma: no cover - validate_path refused it already
        "Path is outside allowed directories",
        str(resolved),
        "outside_allowed_roots",
    )


def _components(resolved: Path, root: Path, original_path: str) -> tuple[str, ...]:
    """The names to walk from ``root`` to ``resolved``, refusing any that is not a name."""
    parts = resolved.relative_to(root).parts
    for part in parts:
        if part in ("", ".", "..") or os.sep in part or (os.altsep and os.altsep in part):
            raise PathValidationError(
                "Path has a component that is not a plain name",
                original_path,
                "invalid_path",
            )
    return parts


def _open_component(name: str, dir_fd: int, flags: int, mode: int, original_path: str) -> int:
    """``os.open(name, dir_fd=dir_fd)``, a symlink where one was not checked refused."""
    try:
        return os.open(name, flags, mode, dir_fd=dir_fd)
    except OSError as exc:
        # O_NOFOLLOW on a symlink: ELOOP for the leaf, ENOTDIR (macOS) or ELOOP (Linux)
        # with O_DIRECTORY. ENOTDIR also means a regular file, which is not a refusal.
        if exc.errno == errno.ELOOP or (
            exc.errno == errno.ENOTDIR and _is_symlink_at(name, dir_fd)
        ):
            raise PathValidationError(
                "Path changed after it was checked: a component is now a symlink",
                original_path,
                "symlink_detected",
                {"component": name},
            ) from exc
        raise


def _is_symlink_at(name: str, dir_fd: int) -> bool:
    """Whether ``name`` in the directory ``dir_fd`` is a symlink."""
    try:
        return stat.S_ISLNK(os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_mode)
    except OSError:
        return False


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
    allowed_roots=[Path("/tmp"), Path("/sandbox")],  # nosec B108 - intentional sandbox paths
    allow_symlinks=False,
    deny_patterns=["*.env", "*.key", "*.pem"],
    max_path_depth=10,
)
"""Policy for sandboxed execution - only allows /tmp and /sandbox."""
