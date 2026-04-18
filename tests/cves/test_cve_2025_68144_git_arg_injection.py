"""CVE-2025-68144 — Anthropic mcp-server-git argument injection.

Vulnerability (from the public GHSA advisory):
    `git_diff` / `git_checkout` in anthropics/mcp-server-git (< 2025.12.18)
    pass user-controlled refs directly to the `git` CLI. A ref value
    starting with a hyphen (for example `--output=/etc/profile.d/rce.sh`)
    is interpreted by git as an OPTION rather than a ref, allowing
    arbitrary file overwrite through the resulting git subprocess call.

Advisory: https://github.com/advisories/GHSA-9xwc-hfwc-8w59
NVD:      https://nvd.nist.gov/vuln/detail/CVE-2025-68144
CVSS:     8.1 (High)

Airlock fit: strongest.
    The ghost/strict argument validator is exactly the primitive for
    "LLM passes a string that looks like a flag into a typed parameter."
    A Pydantic-strict model with a custom validator that rejects any ref
    beginning with `-` is a one-liner at the tool-decoration layer.

This test wraps a minimal `git_diff(ref: str)` stand-in with
`@Airlock(...)` and asserts that a hyphen-leading ref is blocked before
the function body runs.
"""

from __future__ import annotations

from typing import Annotated

import pytest
from pydantic import AfterValidator

from agent_airlock.core import Airlock


def _reject_flag_shaped(ref: str) -> str:
    """Reject any string that git would parse as an option."""
    if ref.startswith("-"):
        raise ValueError(
            f"Refs that start with '-' are interpreted by git as options; refusing: {ref!r}"
        )
    return ref


SafeGitRef = Annotated[str, AfterValidator(_reject_flag_shaped)]


class TestCVE2025_68144:
    """`git_diff(ref: SafeGitRef)` rejects flag-shaped refs."""

    def _make_tool(self) -> Airlock:
        @Airlock(return_dict=True)
        def git_diff(ref: SafeGitRef) -> str:
            return f"ran git diff {ref}"

        return git_diff  # type: ignore[return-value]

    def test_blocks_output_flag_injection(self) -> None:
        """The canonical exploit: `--output=/tmp/rce` used as a ref."""
        git_diff = self._make_tool()
        result = git_diff(ref="--output=/tmp/rce.sh")
        assert isinstance(result, dict)
        assert result.get("success") is False
        assert result.get("status") == "blocked"
        assert result.get("block_reason") == "validation_error"

    def test_blocks_bare_dash_flag(self) -> None:
        """Single-dash flags like `-oProxyCommand=...` also rejected."""
        git_diff = self._make_tool()
        result = git_diff(ref="-upload-pack=/tmp/pwn")
        assert isinstance(result, dict)
        assert result.get("success") is False
        assert result.get("status") == "blocked"

    def test_allows_valid_ref(self) -> None:
        """Benign git refs (branch names, SHAs) pass unmodified."""
        git_diff = self._make_tool()
        result = git_diff(ref="main")
        assert isinstance(result, dict)
        assert result.get("success") is True
        assert result.get("result") == "ran git diff main"

    def test_allows_commit_sha(self) -> None:
        git_diff = self._make_tool()
        result = git_diff(ref="abc123def456")
        assert isinstance(result, dict)
        assert result.get("success") is True
        assert result.get("result") == "ran git diff abc123def456"

    def test_pydantic_validator_raises_on_direct_use(self) -> None:
        """The validator itself raises the expected error out of band."""
        with pytest.raises(ValueError, match="interpreted by git as options"):
            _reject_flag_shaped("--malicious")
