"""Property tests: Pydantic strict validation never coerces a wrong-typed arg.

Strict mode is a deny-by-default contract on argument *type*: ``"5"`` is not an
``int``, ``1`` is not a ``bool``, ``True`` is not an ``int``. The validator must
raise rather than silently coerce. Correct types must pass unchanged.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from agent_airlock.validator import create_strict_validator


def _int_tool(n: int) -> int:
    return n


def _bool_tool(flag: bool) -> bool:
    return flag


def _str_tool(s: str) -> str:
    return s


# Values that LOOK coercible to int but must be refused in strict mode.
_wrong_for_int = st.one_of(
    st.text(alphabet="0123456789", min_size=1, max_size=4),  # "5"
    st.booleans(),  # True/False are not ints in strict mode
    st.floats(allow_nan=False, allow_infinity=False, min_value=-1e6, max_value=1e6),
)


@given(value=_wrong_for_int)
def test_strict_int_never_coerces(value: object) -> None:
    validate = create_strict_validator(_int_tool)
    with pytest.raises(ValidationError):
        validate(n=value)


# Values that LOOK coercible to bool but must be refused.
_wrong_for_bool = st.one_of(
    st.integers(min_value=0, max_value=1),  # 0 / 1
    st.sampled_from(["true", "false", "yes", "no", "1", "0"]),
)


@given(value=_wrong_for_bool)
def test_strict_bool_never_coerces(value: object) -> None:
    validate = create_strict_validator(_bool_tool)
    with pytest.raises(ValidationError):
        validate(flag=value)


_wrong_for_str = st.one_of(st.integers(), st.booleans(), st.floats(allow_nan=False))


@given(value=_wrong_for_str)
def test_strict_str_never_coerces(value: object) -> None:
    validate = create_strict_validator(_str_tool)
    with pytest.raises(ValidationError):
        validate(s=value)


@given(n=st.integers(min_value=-10_000, max_value=10_000))
def test_strict_int_accepts_int(n: int) -> None:
    assert create_strict_validator(_int_tool)(n=n) == n


@given(flag=st.booleans())
def test_strict_bool_accepts_bool(flag: bool) -> None:
    assert create_strict_validator(_bool_tool)(flag=flag) is flag
