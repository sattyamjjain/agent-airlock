"""Property tests for ghost-argument handling across UnknownArgsMode.

A hallucinated (ghost) argument the tool's signature does not declare must be
refused in ``BLOCK`` mode and stripped in ``STRIP_*`` modes — never silently
forwarded into the tool. Declared arguments must always survive.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from agent_airlock.validator import GhostArgumentError, strip_ghost_arguments

_ghost_names = st.text(alphabet="ghostxyz_", min_size=1, max_size=6).filter(
    lambda s: s not in {"n", "flag"}
)


def _tool(n: int, flag: bool) -> str:
    return f"{n}{flag}"


@given(ghosts=st.lists(_ghost_names, min_size=1, max_size=4, unique=True))
def test_block_mode_rejects_ghosts(ghosts: list[str]) -> None:
    kwargs = {"n": 1, "flag": True, **dict.fromkeys(ghosts, "x")}
    with pytest.raises(GhostArgumentError) as exc:
        strip_ghost_arguments(_tool, dict(kwargs), strict=True)
    assert set(exc.value.ghost_args) == set(ghosts)


@given(ghosts=st.lists(_ghost_names, min_size=1, max_size=4, unique=True))
def test_strip_mode_removes_ghosts_keeps_declared(ghosts: list[str]) -> None:
    kwargs = {"n": 1, "flag": True, **dict.fromkeys(ghosts, "x")}
    cleaned, stripped = strip_ghost_arguments(_tool, dict(kwargs), strict=False)
    assert set(stripped) == set(ghosts)
    assert cleaned == {"n": 1, "flag": True}
    for g in ghosts:
        assert g not in cleaned


@given(n=st.integers(), flag=st.booleans())
def test_no_ghosts_passes_through(n: int, flag: bool) -> None:
    cleaned, stripped = strip_ghost_arguments(_tool, {"n": n, "flag": flag}, strict=True)
    assert cleaned == {"n": n, "flag": flag}
    assert stripped == set()
