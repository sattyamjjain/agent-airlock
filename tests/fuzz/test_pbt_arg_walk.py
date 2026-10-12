"""Property tests for ``_arg_walk``: it reaches every leaf a reference walk does.

The deny-by-default contract depends on the value gates seeing *every* value a
call carries. ``iter_argument_values`` is that walk; this suite checks it reaches
the same leaves as an independent reference walk across nested mappings,
sequences, sets, namedtuples, dataclasses and pydantic models, and refuses input
nested past ``MAX_DEPTH`` or containing itself.
"""

from __future__ import annotations

import dataclasses
from collections import namedtuple
from collections.abc import Mapping

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import BaseModel

from agent_airlock._arg_walk import (
    MAX_DEPTH,
    ArgumentNestingError,
    bind_arguments,
    iter_argument_values,
    signature_of,
)

_hashable = st.one_of(st.text(max_size=5), st.integers(), st.booleans())
_scalars = st.one_of(st.text(max_size=5), st.integers(), st.booleans(), st.none())
_names = st.text(alphabet="abcdefghij_", min_size=1, max_size=6)

_structures = st.recursive(
    _scalars,
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.tuples(children, children),
        st.dictionaries(_names, children, max_size=4),
        st.sets(_hashable, max_size=4),
        st.frozensets(_hashable, max_size=4),
    ),
    max_leaves=25,
)


def _reference_leaf_count(value: object) -> int:
    """Independent leaf count mirroring ``iter_argument_values`` semantics.

    A str/bytes is one leaf. A mapping contributes one leaf per string/bytes key
    plus the walk of each value. A sequence/set walks its items. Everything else
    is a scalar leaf.
    """
    if isinstance(value, (str, bytes, bytearray)):
        return 1
    if isinstance(value, Mapping):
        total = 0
        for key, item in value.items():
            if isinstance(key, (str, bytes)):
                total += 1
            total += _reference_leaf_count(item)
        return total
    if isinstance(value, (list, tuple, set, frozenset)):
        return sum(_reference_leaf_count(item) for item in value)
    return 1


@given(args=st.dictionaries(_names, _structures, max_size=4))
def test_arg_walk_reaches_every_leaf(args: dict[str, object]) -> None:
    expected = sum(_reference_leaf_count(v) for v in args.values())
    got = list(iter_argument_values(args))
    assert len(got) == expected


def test_arg_walk_descends_dataclasses_and_models() -> None:
    @dataclasses.dataclass
    class Inner:
        path: str
        count: int

    class Model(BaseModel):
        url: str
        nested: list[str]

    args = {
        "dc": Inner(path="/etc/passwd", count=3),
        "model": Model(url="http://x/", nested=["a", "b"]),
    }
    values = [av.value for av in iter_argument_values(args)]
    assert "/etc/passwd" in values
    assert "http://x/" in values
    assert "a" in values and "b" in values


def test_arg_walk_reaches_namedtuple_fields() -> None:
    Point = namedtuple("Point", ["x", "y"])
    args = {"p": Point(x="/secret", y="ok")}
    values = [av.value for av in iter_argument_values(args)]
    assert "/secret" in values and "ok" in values


def test_arg_walk_reaches_mapping_keys() -> None:
    args = {"files": {"/etc/passwd": "data"}}
    paths = [av.value for av in iter_argument_values(args) if av.is_key]
    assert "/etc/passwd" in paths


def test_arg_walk_refuses_too_deep() -> None:
    node: dict[str, object] = {}
    cur = node
    for _ in range(MAX_DEPTH + 5):
        nxt: dict[str, object] = {}
        cur["k"] = nxt
        cur = nxt
    with pytest.raises(ArgumentNestingError):
        list(iter_argument_values({"deep": node}))


def test_arg_walk_refuses_self_containing() -> None:
    node: dict[str, object] = {}
    node["self"] = node
    with pytest.raises(ArgumentNestingError):
        list(iter_argument_values({"cycle": node}))


def test_bind_arguments_names_positionals() -> None:
    def tool(path: str, *extra: str, flag: bool = False) -> None: ...

    sig = signature_of(tool)
    bound = bind_arguments(sig, ("/a", "/b", "/c"), {"flag": True})
    assert bound["path"] == "/a"
    assert bound["extra"] == ("/b", "/c")
    assert bound["flag"] is True
    # Every positional value is reachable by the walk.
    values = [av.value for av in iter_argument_values(bound)]
    assert "/a" in values and "/b" in values and "/c" in values
