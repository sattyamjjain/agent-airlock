"""Property tests for ``filesystem.validate_path``: deny-by-default on roots.

Any path outside the allowed roots after normalisation must be refused; ``..``
traversal that escapes a root must be refused; a NUL byte must be refused. Temp
roots are created with ``realpath`` so a macOS ``/var`` -> ``/private/var`` symlink
does not confuse the comparison.

Includes a property the current code FAILS: a path beginning with ``~`` whose
``expanduser`` form is outside the roots is admitted (the B7 tilde fail-open).
That test is ``xfail(strict=True)`` so it stays green now and fails loudly the day
``ws/library`` closes it — see this workstream's final report.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from agent_airlock.filesystem import FilesystemPolicy, PathValidationError, validate_path

_SEG = st.text(alphabet="abcdefghijklmnop", min_size=1, max_size=6)


def _policy(root: Path) -> FilesystemPolicy:
    return FilesystemPolicy(allowed_roots=[root], allow_symlinks=True)


@given(segments=st.lists(_SEG, min_size=1, max_size=4))
def test_inside_root_is_admitted(
    tmp_path_factory: pytest.TempPathFactory, segments: list[str]
) -> None:
    root = Path(os.path.realpath(tmp_path_factory.mktemp("allowed")))
    policy = _policy(root)
    inside = root.joinpath(*segments)
    resolved = validate_path(str(inside), policy)
    assert str(resolved).startswith(str(root))


@given(segments=st.lists(_SEG, min_size=1, max_size=4))
def test_absolute_outside_root_is_refused(
    tmp_path_factory: pytest.TempPathFactory, segments: list[str]
) -> None:
    root = Path(os.path.realpath(tmp_path_factory.mktemp("allowed")))
    other = Path(os.path.realpath(tmp_path_factory.mktemp("elsewhere")))
    policy = _policy(root)
    outside = other.joinpath(*segments)
    with pytest.raises(PathValidationError):
        validate_path(str(outside), policy)


@given(depth=st.integers(min_value=1, max_value=6), tail=_SEG)
def test_dotdot_traversal_out_of_root_is_refused(
    tmp_path_factory: pytest.TempPathFactory, depth: int, tail: str
) -> None:
    root = Path(os.path.realpath(tmp_path_factory.mktemp("allowed")))
    policy = _policy(root)
    escape = root.joinpath(*([".."] * (len(root.parts) + depth)), tail)
    with pytest.raises(PathValidationError):
        validate_path(str(escape), policy)


def test_nul_byte_is_refused(tmp_path: Path) -> None:
    policy = _policy(Path(os.path.realpath(tmp_path)))
    with pytest.raises(PathValidationError):
        validate_path("file\x00.txt", policy)


def test_deny_pattern_inside_root_is_refused(tmp_path: Path) -> None:
    root = Path(os.path.realpath(tmp_path))
    policy = FilesystemPolicy(allowed_roots=[root], allow_symlinks=True, deny_patterns=["*.env"])
    with pytest.raises(PathValidationError):
        validate_path(str(root / "secrets.env"), policy)


@pytest.mark.xfail(
    strict=True,
    reason="finding: tilde-expansion fail-open (B7); fixed in ws/library",
)
def test_tilde_outside_roots_is_refused(tmp_path: Path) -> None:
    """A ``~`` path whose expanduser form escapes the roots must be refused.

    The real home directory is outside this temp allowed root, so after
    ``expanduser`` the path is out of bounds and the call must be refused. Current
    code resolves the literal ``~`` under the CWD instead, so when the CWD sits
    inside an allowed root the call is ADMITTED — the fail-open. Marked
    ``xfail(strict=True)``: it will start passing (and flip this marker red) the
    day the expanduser fix lands.
    """
    root = Path(os.path.realpath(tmp_path))
    policy = _policy(root)
    tilde_path = "~/.ssh/id_rsa"
    assert os.path.realpath(os.path.expanduser(tilde_path)).startswith(str(root)) is False
    prior = Path.cwd()
    os.chdir(root)
    try:
        with pytest.raises(PathValidationError):
            validate_path(tilde_path, policy)
    finally:
        os.chdir(prior)
