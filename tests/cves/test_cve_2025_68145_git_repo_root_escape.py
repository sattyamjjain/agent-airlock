"""CVE-2025-68145 — mcp-server-git `--repository` root not enforced.

Vulnerability (from the public GHSA advisory):
    When anthropics/mcp-server-git (< 2025.12.18) is started with the
    `--repository` flag to declare an allowed repo root, the server
    fails to verify on each subsequent tool call that the `repo_path`
    argument stays inside that root. A crafted argument such as
    `/var/lib/otheruser/.git` lets the server operate on any repo the
    process user can read.

Advisory: https://github.com/advisories/GHSA-j22h-9j4x-23w5
NVD:      https://nvd.nist.gov/vuln/detail/CVE-2025-68145
CVSS:     7.1 (High)

Airlock fit: strong.
    `FilesystemPolicy` with an `allowed_roots` list is the canonical
    mitigation. `validate_path` uses `os.path.commonpath()` (not string
    prefix) so it catches the three common escape variants:

    - absolute path outside the root
    - relative path with `..` that would normalise outside the root
    - a symlink that points outside the root
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from agent_airlock.filesystem import FilesystemPolicy, PathValidationError, validate_path


class TestCVE2025_68145:
    """Enforce repo-root confinement on every tool call."""

    def test_blocks_absolute_path_outside_root(self, tmp_path: Path) -> None:
        repo_root = tmp_path / "my-repo"
        repo_root.mkdir()
        other = tmp_path / "other-repo"
        other.mkdir()

        policy = FilesystemPolicy(allowed_roots=[repo_root])
        with pytest.raises(PathValidationError):
            validate_path(str(other / ".git"), policy)

    def test_blocks_relative_traversal_escape(self, tmp_path: Path) -> None:
        repo_root = tmp_path / "my-repo"
        repo_root.mkdir()
        policy = FilesystemPolicy(allowed_roots=[repo_root])

        # Relative traversal string should be rejected either by the
        # validator's explicit traversal check or by the commonpath
        # resolution check.
        with pytest.raises(PathValidationError):
            validate_path("../other-repo/.git", policy)

    def test_blocks_symlink_escape(self, tmp_path: Path) -> None:
        repo_root = tmp_path / "my-repo"
        repo_root.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "secret").write_text("secret")

        # Create a symlink inside the repo that points to an outside dir.
        link = repo_root / "escape"
        os.symlink(str(outside), str(link))

        policy = FilesystemPolicy(allowed_roots=[repo_root], allow_symlinks=False)
        with pytest.raises(PathValidationError):
            validate_path(str(link / "secret"), policy)

    def test_allows_nested_path_inside_root(self, tmp_path: Path) -> None:
        repo_root = tmp_path / "my-repo"
        (repo_root / "src").mkdir(parents=True)
        policy = FilesystemPolicy(allowed_roots=[repo_root])

        validated = validate_path(str(repo_root / "src" / "main.py"), policy)
        assert str(validated).endswith(str(Path("src") / "main.py"))
