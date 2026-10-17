"""Property tests for ``UnsafeDeserializationGuard``: every pickle shape is refused.

Pickle protocols 0-5 of a harmless ``__reduce__`` sentinel, raw or base64-wrapped,
top-level or nested in a list / dict / positional argument, and the serializer
marker tokens, must all be refused. The sentinel's ``__reduce__`` only appends a
marker to an in-process list, and nothing here ever unpickles untrusted bytes —
the guard inspects magic bytes and tokens only.
"""

from __future__ import annotations

import base64
import pickle

import pytest
from benchmarks.adaptive_redteam.canaries import ReduceSentinel
from hypothesis import given
from hypothesis import strategies as st

from agent_airlock._arg_walk import bind_arguments, signature_of
from agent_airlock.safe_types import DEFAULT_DESERIALIZATION_MARKERS, UnsafeDeserializationGuard

_GUARD = UnsafeDeserializationGuard(advisory="CVE-2026-25874")
_PROTOCOLS = st.integers(min_value=0, max_value=pickle.HIGHEST_PROTOCOL)


def _pickle(proto: int) -> bytes:
    return pickle.dumps(ReduceSentinel("sentinel"), protocol=proto)


@given(proto=_PROTOCOLS)
def test_raw_pickle_bytes_refused(proto: int) -> None:
    decision = _GUARD.evaluate({"blob": _pickle(proto)})
    assert not decision.allowed, f"admitted raw pickle at protocol {proto}"


@given(proto=_PROTOCOLS)
def test_base64_pickle_refused(proto: int) -> None:
    encoded = base64.b64encode(_pickle(proto)).decode("ascii")
    decision = _GUARD.evaluate({"blob": encoded})
    # Base64 of a 0x80-magic pickle (protocols 2+) is the documented vector.
    if proto >= 2:
        assert not decision.allowed, f"admitted base64 pickle at protocol {proto}"


@given(proto=_PROTOCOLS)
def test_nested_pickle_in_list_refused(proto: int) -> None:
    decision = _GUARD.evaluate({"items": ["ok", _pickle(proto), 3]})
    assert not decision.allowed, f"admitted pickle nested in a list at protocol {proto}"


@given(proto=_PROTOCOLS)
def test_nested_pickle_in_dict_refused(proto: int) -> None:
    decision = _GUARD.evaluate({"payload": {"inner": _pickle(proto)}})
    assert not decision.allowed, f"admitted pickle nested in a dict at protocol {proto}"


@given(proto=_PROTOCOLS)
def test_positional_pickle_refused(proto: int) -> None:
    def tool(blob: bytes) -> None: ...

    bound = bind_arguments(signature_of(tool), (_pickle(proto),), {})
    decision = _GUARD.evaluate(bound)
    assert not decision.allowed, f"admitted pickle as a positional arg at protocol {proto}"


@pytest.mark.parametrize("marker", sorted(DEFAULT_DESERIALIZATION_MARKERS))
def test_serializer_marker_tokens_refused(marker: str) -> None:
    decision = _GUARD.evaluate({"code": f"result = {marker}(data)"})
    assert not decision.allowed, f"admitted serializer marker {marker!r}"


def test_plain_json_string_admitted() -> None:
    decision = _GUARD.evaluate({"blob": '{"a": 1, "b": [2, 3]}'})
    assert decision.allowed
