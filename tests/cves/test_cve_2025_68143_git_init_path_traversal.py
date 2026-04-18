"""CVE-2025-68143 — Anthropic mcp-server-git `git_init` path traversal.

Vulnerability (from the public GHSA advisory):
    The `git_init` tool of anthropics/mcp-server-git (< 2025.9.25 / 2025.12.18)
    accepts an arbitrary filesystem path as its `repo_path` argument without
    validating it against the configured repository root. An attacker who can
    prompt-inject the agent can therefore initialise a .git directory anywhere
    the server process can write, and — chained with a filesystem MCP — drop
    a malicious .git/config that achieves RCE on the next `git` invocation.

Advisory: https://github.com/advisories/GHSA-5cgr-j3jf-jw3v
NVD:      https://nvd.nist.gov/vuln/detail/CVE-2025-68143
CVSS:     8.2 (High)

Airlock fit: strong.
    This is the canonical `SafePath` / `FilesystemPolicy` defense. The fix
    upstream and the fix here are the same: reject any `repo_path` that
    escapes the configured repo root via `os.path.commonpath()`.

    We assert both:
    1. `SafePathValidator` with the bare defaults rejects traversal strings
       (the pre-normalisation defense).
    2. `FilesystemPolicy.validate_path` rejects paths outside the allowed
       root even when the path is syntactically clean (the post-resolution
       defense).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_airlock.filesystem import FilesystemPolicy, PathValidationError, validate_path
from agent_airlock.safe_types import SafePathValidationError, SafePathValidator


class TestCVE2025_68143:
    """git_init repo_path argument must not escape the configured root."""

    def test_safepath_blocks_traversal_in_repo_path(self) -> None:
        """A `repo_path` with `..` is rejected before the git command runs."""
        validator = SafePathValidator()
        with pytest.raises(SafePathValidationError):
            validator("../../../etc/new-repo")

    def test_safepath_blocks_home_directory_repo_path(self) -> None:
        """Initializing a repo inside the attacker's home dir is rejected."""
        validator = SafePathValidator()
        with pytest.raises(SafePathValidationError):
            validator("~/.cache/evil-repo")

    def test_filesystem_policy_blocks_repo_outside_root(self, tmp_path: Path) -> None:
        """Even a clean absolute path outside the repo root is rejected."""
        repo_root = tmp_path / "repos"
        repo_root.mkdir()
        policy = FilesystemPolicy(allowed_roots=[repo_root])

        outside = tmp_path / "other" / "evil-repo"
        outside.parent.mkdir(parents=True)

        with pytest.raises(PathValidationError):
            validate_path(str(outside), policy)

    def test_filesystem_policy_allows_repo_inside_root(self, tmp_path: Path) -> None:
        """The benign case — a repo inside the allowed root — passes."""
        repo_root = tmp_path / "repos"
        repo_root.mkdir()
        policy = FilesystemPolicy(allowed_roots=[repo_root])

        legit = repo_root / "project" / ".git"
        validated = validate_path(str(legit), policy)
        # Different OSes can give /tmp vs /private/tmp, hence the sub-check.
        assert str(legit).endswith(str(validated).split(str(repo_root))[-1])
