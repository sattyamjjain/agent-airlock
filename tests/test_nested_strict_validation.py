"""Strict validation reaches inside a Pydantic model or TypedDict argument.

`validate_call(config=ConfigDict(strict=True))` makes the function's own parameters strict,
but a model is validated with its own config, which is lax by default. Until 0.10.16 a tool
taking `user: User` with `age: int` accepted `{"age": "30"}`: the string was coerced and the
call ran, although "no type coercion" is the contract. Strictness given at call level does
reach nested types, so those arguments are now checked once more with it.
"""

from __future__ import annotations

import asyncio
from typing import Any

from pydantic import BaseModel, ValidationError
from typing_extensions import TypedDict

from agent_airlock import Airlock
from agent_airlock.validator import _nested_strict_check, create_argument_validator


class User(BaseModel):
    name: str
    age: int


class UserDict(TypedDict):
    name: str
    age: int


def _refused(result: Any) -> bool:
    return isinstance(result, dict) and result.get("status") == "blocked"


class TestModelArguments:
    def test_a_coerced_field_is_refused_with_its_path(self) -> None:
        @Airlock()
        def create_user(user: User) -> str:
            return user.name

        result = create_user(user={"name": "a", "age": "30"})

        assert _refused(result)
        assert result["fix_hints"] == ["'user.age' must be an integer, not str"]

    def test_a_correct_dict_and_an_instance_still_run(self) -> None:
        @Airlock()
        def create_user(user: User) -> int:
            return user.age

        assert create_user(user={"name": "a", "age": 30}) == 30
        assert create_user(user=User(name="a", age=31)) == 31

    def test_an_element_of_a_list_of_models(self) -> None:
        @Airlock()
        def add_users(users: list[User]) -> int:
            return len(users)

        result = add_users(users=[{"name": "a", "age": 1}, {"name": "b", "age": "2"}])

        assert result["fix_hints"] == ["'users.1.age' must be an integer, not str"]

    def test_an_optional_model_left_as_none(self) -> None:
        @Airlock()
        def maybe(user: User | None = None) -> str:
            return "none" if user is None else user.name

        assert maybe() == "none"
        assert maybe(user=None) == "none"

    def test_an_async_tool(self) -> None:
        @Airlock()
        async def create_user(user: User) -> int:
            return user.age

        assert asyncio.run(create_user(user={"name": "a", "age": 30})) == 30
        assert _refused(asyncio.run(create_user(user={"name": "a", "age": "30"})))


class TestTypedDictArguments:
    def test_a_coerced_field_is_refused(self) -> None:
        @Airlock()
        def create_user(user: UserDict) -> int:
            return user["age"]

        assert create_user(user={"name": "a", "age": 30}) == 30
        assert _refused(create_user(user={"name": "a", "age": "30"}))


class TestTheSandboxPathChecksTheSame:
    def test_the_argument_validator_refuses_a_coerced_field(self) -> None:
        def create_user(user: User) -> str:
            return user.name

        validate = create_argument_validator(create_user)

        try:
            validate((), {"user": {"name": "a", "age": "30"}})
        except ValidationError as exc:
            assert exc.errors()[0]["loc"] == ("user", "age")
        else:
            raise AssertionError("the sandbox path accepted a coerced nested field")


class TestOrdinaryToolsPayNothing:
    def test_no_extra_check_without_a_nested_type(self) -> None:
        def search(query: str, limit: int = 10) -> list[str]:
            return []

        assert _nested_strict_check(search) is None
