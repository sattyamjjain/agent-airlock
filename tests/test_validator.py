"""Tests for the validator module."""

import pytest
from pydantic import ValidationError

from agent_airlock.validator import (
    GhostArgumentError,
    create_strict_validator,
    detect_ghost_arguments,
    format_validation_error,
    get_valid_parameters,
    strip_ghost_arguments,
)


class TestGetValidParameters:
    """Tests for get_valid_parameters function."""

    def test_simple_function(self) -> None:
        def func(a: int, b: str) -> None:
            pass

        params, accepts_kwargs = get_valid_parameters(func)
        assert params == {"a", "b"}
        assert accepts_kwargs is False

    def test_function_with_defaults(self) -> None:
        def func(a: int, b: str = "default") -> None:
            pass

        params, accepts_kwargs = get_valid_parameters(func)
        assert params == {"a", "b"}
        assert accepts_kwargs is False

    def test_function_with_kwargs(self) -> None:
        def func(a: int, **kwargs: str) -> None:
            pass

        params, accepts_kwargs = get_valid_parameters(func)
        assert params == {"a"}
        assert accepts_kwargs is True

    def test_function_with_args_and_kwargs(self) -> None:
        def func(*args: int, **kwargs: str) -> None:
            pass

        params, accepts_kwargs = get_valid_parameters(func)
        assert params == set()
        assert accepts_kwargs is True


class TestDetectGhostArguments:
    """Tests for detect_ghost_arguments function."""

    def test_no_ghost_arguments(self) -> None:
        def func(a: int, b: str) -> None:
            pass

        ghost = detect_ghost_arguments(func, {"a": 1, "b": "test"})
        assert ghost == set()

    def test_with_ghost_arguments(self) -> None:
        def func(a: int) -> None:
            pass

        ghost = detect_ghost_arguments(func, {"a": 1, "force": True, "extra": "value"})
        assert ghost == {"force", "extra"}

    def test_function_with_kwargs_no_ghosts(self) -> None:
        def func(a: int, **kwargs: str) -> None:
            pass

        ghost = detect_ghost_arguments(func, {"a": 1, "force": True, "extra": "value"})
        assert ghost == set()  # **kwargs accepts everything


class TestStripGhostArguments:
    """Tests for strip_ghost_arguments function."""

    def test_strip_ghost_args(self) -> None:
        def func(filename: str) -> None:
            pass

        cleaned, stripped = strip_ghost_arguments(
            func,
            {"filename": "test.txt", "force": True, "mode": "rb"},
        )

        assert cleaned == {"filename": "test.txt"}
        assert stripped == {"force", "mode"}

    def test_no_stripping_needed(self) -> None:
        def func(a: int, b: str) -> None:
            pass

        cleaned, stripped = strip_ghost_arguments(func, {"a": 1, "b": "test"})

        assert cleaned == {"a": 1, "b": "test"}
        assert stripped == set()

    def test_strict_mode_raises(self) -> None:
        def func(a: int) -> None:
            pass

        with pytest.raises(GhostArgumentError) as exc_info:
            strip_ghost_arguments(func, {"a": 1, "force": True}, strict=True)

        assert exc_info.value.func_name == "func"
        assert exc_info.value.ghost_args == {"force"}


class TestCreateStrictValidator:
    """Tests for create_strict_validator function."""

    def test_validates_correct_types(self) -> None:
        def func(x: int, y: str) -> str:
            return f"{x}-{y}"

        validated = create_strict_validator(func)
        result = validated(x=42, y="hello")
        assert result == "42-hello"

    def test_rejects_wrong_types(self) -> None:
        def func(x: int) -> int:
            return x * 2

        validated = create_strict_validator(func)

        with pytest.raises(ValidationError):
            validated(x="42")  # String instead of int

    def test_rejects_string_to_int_coercion(self) -> None:
        def func(age: int) -> int:
            return age

        validated = create_strict_validator(func)

        # In strict mode, "25" should NOT be coerced to 25
        with pytest.raises(ValidationError):
            validated(age="25")

    def test_rejects_float_to_int(self) -> None:
        def func(count: int) -> int:
            return count

        validated = create_strict_validator(func)

        with pytest.raises(ValidationError):
            validated(count=3.14)


class TestFormatValidationError:
    """Tests for format_validation_error function."""

    def test_formats_single_error(self) -> None:
        def func(x: int) -> int:
            return x

        validated = create_strict_validator(func)

        try:
            validated(x="not an int")
        except ValidationError as e:
            result = format_validation_error(e)

        assert result["error_count"] == 1
        assert len(result["errors"]) == 1
        assert result["errors"][0]["field"] == "x"
        assert "fix_hint" in result["errors"][0]

    def test_formats_multiple_errors(self) -> None:
        def func(x: int, y: str, z: bool) -> None:
            pass

        validated = create_strict_validator(func)

        try:
            validated(x="wrong", y=123, z="not bool")
        except ValidationError as e:
            result = format_validation_error(e)

        assert result["error_count"] == 3
        assert len(result["errors"]) == 3
