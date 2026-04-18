"""CVE-2026-27825 — mcp-atlassian arbitrary file write via download_path.

Vulnerability (from the GitLab advisory and the Pluto Security write-up):
    mcp-atlassian (< 0.17.0) exposes a `confluence_download_attachment`
    tool with a `download_path` argument. The tool writes the downloaded
    file to the provided path without boundary enforcement. An attacker
    who can prompt-inject the argument can therefore overwrite
    `~/.ssh/authorized_keys`, `~/.bashrc`, or any other file the server
    process can reach — and on the exposed HTTP transport deployment
    this requires no authentication.

Advisory:  https://advisories.gitlab.com/pkg/pypi/mcp-atlassian/CVE-2026-27825/
Write-up:  https://pluto.security/blog/mcpwnfluence-cve-2026-27825-critical/
NVD:       https://nvd.nist.gov/vuln/detail/CVE-2026-27825
CVSS:      9.1 (Critical)

Airlock fit: strong.
    `SafePath` + `FilesystemPolicy.allowed_roots` is the textbook
    mitigation. The upstream fix (in 0.17.0) introduces a
    `validate_safe_path` function — agent-airlock has had this since
    v0.3.0.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_airlock.filesystem import FilesystemPolicy, PathValidationError, validate_path
from agent_airlock.safe_types import SafePathValidationError, SafePathValidator


class TestCVE2026_27825:
    """`download_path` must not escape the configured download directory."""

    def test_safepath_blocks_authorized_keys(self) -> None:
        """The exact exploit from the Pluto write-up: overwrite ~/.ssh/authorized_keys."""
        validator = SafePathValidator()
        with pytest.raises(SafePathValidationError):
            validator("~/.ssh/authorized_keys")

    def test_safepath_blocks_bashrc(self) -> None:
        validator = SafePathValidator()
        with pytest.raises(SafePathValidationError):
            validator("~/.bashrc")

    def test_safepath_blocks_etc_overwrite_via_traversal(self) -> None:
        validator = SafePathValidator()
        with pytest.raises(SafePathValidationError):
            validator("../../../etc/cron.d/pwn")

    def test_filesystem_policy_blocks_write_outside_download_dir(self, tmp_path: Path) -> None:
        """Even a syntactically clean absolute path is rejected if it leaves the jail."""
        download_dir = tmp_path / "downloads"
        download_dir.mkdir()
        policy = FilesystemPolicy(allowed_roots=[download_dir])

        # An attacker tries to land the attachment at ~/.ssh/authorized_keys
        # (as an absolute path, bypassing the ~ check). It's outside the
        # download dir so FilesystemPolicy rejects it.
        attacker_path = tmp_path / "home" / "victim" / ".ssh" / "authorized_keys"
        with pytest.raises(PathValidationError):
            validate_path(str(attacker_path), policy)

    def test_filesystem_policy_allows_file_in_download_dir(self, tmp_path: Path) -> None:
        download_dir = tmp_path / "downloads"
        download_dir.mkdir()
        policy = FilesystemPolicy(allowed_roots=[download_dir])

        legit = download_dir / "report.pdf"
        validate_path(str(legit), policy)  # must not raise
