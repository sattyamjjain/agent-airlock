"""Regressions for 0.10.25: refusal hints a model can act on, and none that map a deny list.

A blocked call returns ``AirlockResponse.to_dict()`` so the model can retry against its
``fix_hints``. Until 0.10.25:

- A missing argument was told to "check the type and format": Pydantic reports it as
  ``missing_argument`` (or its keyword-only / positional-only variant), which had no hint.
- A constraint was named without its value ("must be greater than the minimum value"), and
  a ``Literal``, a length or a pattern got the generic hint.
- A capability refusal carried no ``fix_hints`` and no ``AIRLOCK_BLOCK`` prefix.
- Every path refusal was told to "use paths within the allowed directory roots" without
  naming them, a deny-pattern match inside those roots included, and the metadata handed
  the model the deny pattern that matched and where a refused symlink sits.
- A ``tool_denied`` policy refusal quoted the ``denied_tools`` glob that matched.
- A ``SafePath`` deny-list match quoted the pattern in its validation message.

The rule the last three follow: a refusal reaches a model whose context may be
attacker-influenced. It discloses the space the model may use (allowed roots, allowed
endpoints, argument names, the tool's own schema constraints) and withholds the space it
may not (deny patterns, deny globs, symlink locations). A deny list is incomplete by
nature, and publishing its coverage helps a search for the entries it lacks. The operator
keeps all of it, through ``on_blocked`` and the log.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Annotated, Any, Literal

import pytest
from pydantic import BaseModel, Field

from agent_airlock import (
    Airlock,
    AirlockConfig,
    AirlockContext,
    AmplificationBudget,
    Capability,
    CapabilityPolicy,
    CostTracker,
    EndpointPolicy,
    FilesystemPolicy,
    HandleField,
    NetworkPolicy,
    SafePath,
    SecurityPolicy,
    UnknownArgsMode,
    handle_run,
    issue_handle,
    requires,
)
from agent_airlock import core as core_module
from agent_airlock import sandbox as sandbox_module
from agent_airlock._arg_walk import MAX_DEPTH
from agent_airlock.cost_tracking import _reset_tracker, set_global_tracker
from agent_airlock.oversight import OversightRequest, OversightResponse, OversightVerdict
from agent_airlock.policy_presets import strict_tier_budget_policy
from agent_airlock.self_heal import (
    BlockReason,
    handle_capability_denied,
    handle_path_violation,
    handle_policy_violation,
)
from agent_airlock.validator import _generate_fix_hint

ISSUER = "fixhints.mint"
SCOPE = "workspace"


def _refused(result: Any) -> dict[str, Any]:
    """``result`` as a refusal dict, failing the test if the call was not refused."""
    assert isinstance(result, dict), f"the call ran: {result!r}"
    assert result.get("success") is False, f"the call was not refused: {result!r}"
    return result


class User(BaseModel):
    name: str
    age: Annotated[int, Field(ge=0)]


class TestMissingArguments:
    def test_a_required_positional_argument_is_named(self) -> None:
        @Airlock()
        def send(to: str, body: str) -> str:
            return "sent"

        result = _refused(send("a@example.com"))  # type: ignore[call-arg]

        assert result["block_reason"] == "validation_error"
        assert result["fix_hints"] == ["'body' is required but was not provided; add it"]
        assert result["metadata"]["errors"][0]["fix_hint"] == result["fix_hints"][0]

    def test_a_required_keyword_only_argument_is_named(self) -> None:
        @Airlock()
        def send(to: str, *, body: str) -> str:
            return "sent"

        result = _refused(send(to="a@example.com"))  # type: ignore[call-arg]

        assert result["fix_hints"] == ["'body' is required but was not provided; add it"]

    def test_an_async_tool_names_it_too(self) -> None:
        @Airlock()
        async def send(to: str, body: str) -> str:
            return "sent"

        result = _refused(asyncio.run(send(to="a@example.com")))  # type: ignore[call-arg]

        assert result["fix_hints"] == ["'body' is required but was not provided; add it"]

    def test_a_missing_field_of_a_nested_model_is_named_by_its_path(self) -> None:
        @Airlock()
        def create(user: User) -> str:
            return user.name

        result = _refused(create(user={"name": "a"}))  # type: ignore[arg-type]

        assert result["fix_hints"] == ["'user.age' is required but was not provided; add it"]

    def test_a_positional_only_argument_is_named_by_its_index(self) -> None:
        @Airlock()
        def double(value: int, /) -> int:
            return value * 2

        result = _refused(double())  # type: ignore[call-arg]

        assert result["fix_hints"] == [
            "The positional argument at index 0 is required but was not provided; add it"
        ]

    def test_surplus_positional_arguments_get_one_hint_and_one_error_each(self) -> None:
        @Airlock()
        def send(to: str, body: str) -> str:
            return "sent"

        result = _refused(send("a", "b", "c", "d"))  # type: ignore[call-arg]

        assert result["fix_hints"] == ["Too many positional arguments; pass arguments by name"]
        errors = result["metadata"]["errors"]
        assert len(errors) == 2
        assert {error["fix_hint"] for error in errors} == set(result["fix_hints"])

    def test_an_argument_given_twice(self) -> None:
        @Airlock()
        def send(to: str, body: str) -> str:
            return "sent"

        result = _refused(send("a", "b", to="c"))  # type: ignore[misc]

        assert "'to' was given twice; pass it only once" in result["fix_hints"]

    @pytest.mark.parametrize(
        ("error_type", "expected"),
        [
            ("unexpected_keyword_argument", "'cc' is not a parameter of this tool; remove it"),
            ("extra_forbidden", "'cc' is not a field this tool accepts; remove it"),
        ],
    )
    def test_an_argument_the_tool_does_not_take(self, error_type: str, expected: str) -> None:
        # @Airlock strips or refuses these as ghost arguments before validation, so the
        # validation hint is reached through a direct validator or a nested model.
        assert _generate_fix_hint(error_type, "cc", 1) == expected


class TestConstraintHints:
    def test_a_lower_bound_is_named(self) -> None:
        @Airlock()
        def page(size: Annotated[int, Field(gt=0)]) -> int:
            return size

        assert _refused(page(size=0))["fix_hints"] == ["'size' must be greater than 0"]

    def test_an_upper_bound_is_named(self) -> None:
        @Airlock()
        def page(size: Annotated[int, Field(le=100)]) -> int:
            return size

        result = _refused(page(size=101))

        assert result["fix_hints"] == ["'size' must be less than or equal to 100"]

    def test_a_nested_bound_is_named_by_its_path(self) -> None:
        @Airlock()
        def create(user: User) -> str:
            return user.name

        result = _refused(create(user={"name": "a", "age": -1}))  # type: ignore[arg-type]

        assert result["fix_hints"] == ["'user.age' must be greater than or equal to 0"]

    def test_the_allowed_literal_values_are_listed(self) -> None:
        @Airlock()
        def sort(order: Literal["asc", "desc"]) -> str:
            return order

        result = _refused(sort(order="up"))  # type: ignore[arg-type]

        assert result["fix_hints"] == ["'order' must be 'asc' or 'desc'"]

    def test_a_string_length_is_named(self) -> None:
        @Airlock()
        def rename(name: Annotated[str, Field(min_length=3, max_length=8)]) -> str:
            return name

        assert _refused(rename(name="ab"))["fix_hints"] == [
            "'name' must have at least 3 characters"
        ]
        assert _refused(rename(name="abcdefghi"))["fix_hints"] == [
            "'name' must have at most 8 characters"
        ]

    def test_a_list_length_is_named_with_the_count_given(self) -> None:
        @Airlock()
        def tag(tags: Annotated[list[str], Field(max_length=2)]) -> int:
            return len(tags)

        result = _refused(tag(tags=["a", "b", "c"]))

        assert result["fix_hints"] == ["'tags' must have at most 2 items (it has 3)"]

    def test_a_pattern_is_named(self) -> None:
        @Airlock()
        def lookup(sku: Annotated[str, Field(pattern=r"^[A-Z]{3}-\d{4}$")]) -> str:
            return sku

        result = _refused(lookup(sku="abc-12"))

        assert result["fix_hints"] == [r"'sku' must match the pattern '^[A-Z]{3}-\d{4}$'"]

    @pytest.mark.parametrize(
        ("error_type", "ctx", "expected"),
        [
            ("greater_than_equal", {"ge": 1.5}, "'x' must be greater than or equal to 1.5"),
            ("less_than", {"lt": 5}, "'x' must be less than 5"),
            ("multiple_of", {"multiple_of": 3}, "'x' must be a multiple of 3"),
            ("enum", {"expected": "'red' or 'blue'"}, "'x' must be 'red' or 'blue'"),
            ("too_short", {"min_length": 1}, "'x' must have at least 1 item"),
        ],
    )
    def test_each_constraint_names_its_value(
        self, error_type: str, ctx: dict[str, Any], expected: str
    ) -> None:
        assert _generate_fix_hint(error_type, "x", None, ctx) == expected

    @pytest.mark.parametrize(
        ("error_type", "value", "expected"),
        [
            ("string_type", 1, "'x' must be a string, not int"),
            ("int_type", "1", "'x' must be an integer, not str"),
            ("float_type", "1.0", "'x' must be a number, not str"),
            ("bool_type", "yes", "'x' must be a boolean (true/false), not str"),
            ("list_type", "a", "'x' must be a list/array, not str"),
            ("dict_type", [], "'x' must be an object/dict, not list"),
        ],
    )
    def test_the_type_error_hints_are_unchanged(
        self, error_type: str, value: Any, expected: str
    ) -> None:
        # Byte-identical to 0.10.24 on purpose: model recovery measured against these
        # hints before and after 0.10.25 compares like for like.
        assert _generate_fix_hint(error_type, "x", value) == expected

    def test_an_error_with_no_wording_of_its_own_names_its_type(self) -> None:
        assert _generate_fix_hint("date_type", "when", "2026-10-12") == (
            "'when' failed validation (date_type): check the type and format"
        )

    def test_a_constraint_without_its_value_falls_back_to_naming_the_type(self) -> None:
        assert _generate_fix_hint("greater_than", "x", 0) == (
            "'x' failed validation (greater_than): check the type and format"
        )


class TestCapabilityDenied:
    def test_a_denied_capability_is_named_and_retrying_is_ruled_out(self) -> None:
        ran: list[str] = []
        config = AirlockConfig(capability_policy=CapabilityPolicy(denied=Capability.PROCESS_SHELL))

        @Airlock(config=config)
        @requires(Capability.PROCESS_SHELL)
        def run_shell(cmd: str) -> str:
            ran.append(cmd)
            return "ran"

        result = _refused(run_shell(cmd="ls"))

        assert ran == []
        assert result["block_reason"] == "capability_denied"
        assert result["error"] == (
            "AIRLOCK_BLOCK: Tool 'run_shell' requires capabilities the policy denies: PROCESS_SHELL"
        )
        hints = result["fix_hints"]
        assert hints, "a capability refusal must say what to do"
        assert "PROCESS_SHELL" in hints[0]
        assert any("will not help" in hint for hint in hints)
        assert any("tell the user" in hint for hint in hints)
        assert result["metadata"]["denied_capabilities"] == ["PROCESS_SHELL"]

    def test_a_capability_not_granted_is_named(self) -> None:
        config = AirlockConfig(
            capability_policy=CapabilityPolicy(granted=Capability.FILESYSTEM_READ)
        )

        @Airlock(config=config)
        @requires(Capability.NETWORK_ARBITRARY)
        def fetch(url: str) -> str:
            return "ran"

        result = _refused(fetch(url="https://example.com"))

        assert "does not grant: NETWORK_ARBITRARY" in result["error"]
        assert "NETWORK_ARBITRARY" in result["fix_hints"][0]
        assert result["metadata"]["missing_capabilities"] == ["NETWORK_ARBITRARY"]

    def test_a_policy_level_capability_policy_refuses_the_same_way(self) -> None:
        policy = SecurityPolicy(capability_policy=CapabilityPolicy(denied=Capability.DATA_SECRETS))

        @Airlock(policy=policy)
        @requires(Capability.DATA_SECRETS)
        def read_vault(key: str) -> str:
            return "ran"

        result = _refused(read_vault(key="db"))

        assert result["block_reason"] == "capability_denied"
        assert "DATA_SECRETS" in result["fix_hints"][0]

    def test_on_blocked_still_gets_the_original_message(self) -> None:
        seen: list[tuple[str, str, dict[str, Any]]] = []
        config = AirlockConfig(
            capability_policy=CapabilityPolicy(denied=Capability.PROCESS_SHELL),
            on_blocked=lambda name, message, info: seen.append((name, message, info)),
        )

        @Airlock(config=config)
        @requires(Capability.PROCESS_SHELL)
        def run_shell(cmd: str) -> str:
            return "ran"

        _refused(run_shell(cmd="ls"))

        assert len(seen) == 1
        assert "requires denied capabilities" in seen[0][1]

    def test_the_helper_names_both_kinds(self) -> None:
        response = handle_capability_denied(
            "t", missing=["NETWORK_ARBITRARY"], denied=["PROCESS_SHELL"]
        )

        assert response.block_reason is BlockReason.CAPABILITY_DENIED
        assert "denies: PROCESS_SHELL" in response.error
        assert "does not grant: NETWORK_ARBITRARY" in response.error


@pytest.fixture
def roots(tmp_path: Path) -> tuple[Path, Path]:
    """An allowed root holding a file, and a file outside it."""
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    (allowed / "ok.txt").write_text("fine")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret")
    return allowed, outside / "secret.txt"


class TestPathHints:
    def test_a_path_outside_the_roots_is_told_the_roots(self, roots: tuple[Path, Path]) -> None:
        allowed, secret = roots

        @Airlock(config=AirlockConfig(filesystem_policy=FilesystemPolicy([allowed])))
        def read(path: str) -> str:
            return Path(path).read_text()

        result = _refused(read(path=str(secret)))

        assert result["block_reason"] == "path_violation"
        assert result["metadata"]["violation_type"] == "outside_allowed_roots"
        assert f"Use a path inside one of: {allowed}" in result["fix_hints"]

    def test_a_deny_pattern_match_is_not_quoted_back(self, roots: tuple[Path, Path]) -> None:
        allowed, _ = roots
        (allowed / "notes.sekret").write_text("x")
        policy = FilesystemPolicy([allowed], deny_patterns=["*.sekret"])

        @Airlock(config=AirlockConfig(filesystem_policy=policy))
        def read(path: str) -> str:
            return Path(path).read_text()

        result = _refused(read(path=str(allowed / "notes.sekret")))

        assert result["metadata"]["violation_type"] == "denied_pattern"
        assert "*.sekret" not in json.dumps(result)
        assert "pattern" not in result["metadata"]
        assert any("protected location" in hint for hint in result["fix_hints"])
        # The path is inside the roots; sending the model back to them was wrong.
        assert not any("allowed directory roots" in hint for hint in result["fix_hints"])

    def test_the_operator_still_sees_the_pattern(self, roots: tuple[Path, Path]) -> None:
        allowed, _ = roots
        seen: list[str] = []
        config = AirlockConfig(
            filesystem_policy=FilesystemPolicy([allowed], deny_patterns=["**/private/**"]),
            on_blocked=lambda name, message, info: seen.append(message),
        )

        @Airlock(config=config)
        def read(path: str) -> str:
            return "ran"

        result = _refused(read(path=str(allowed / "private" / "a.txt")))

        assert "**/private/**" not in json.dumps(result)
        assert seen and "**/private/**" in seen[0]

    def test_a_symlink_refusal_withholds_where_the_link_is(self, tmp_path: Path) -> None:
        real = tmp_path / "real"
        real.mkdir()
        (real / "a.txt").write_text("x")
        link = tmp_path / "linked"
        try:
            os.symlink(real, link)
        except (OSError, NotImplementedError):
            pytest.skip("this platform cannot create a symlink")

        @Airlock(config=AirlockConfig(filesystem_policy=FilesystemPolicy([tmp_path])))
        def read(path: str) -> str:
            return "ran"

        result = _refused(read(path=str(link / "a.txt")))

        assert result["metadata"]["violation_type"] == "symlink_detected"
        assert "symlink_location" not in result["metadata"]
        assert any("symbolic link" in hint for hint in result["fix_hints"])

    def test_a_path_too_deep_is_told_the_limit(self, roots: tuple[Path, Path]) -> None:
        allowed, _ = roots
        policy = FilesystemPolicy([allowed], max_path_depth=3)

        @Airlock(config=AirlockConfig(filesystem_policy=policy))
        def read(path: str) -> str:
            return "ran"

        result = _refused(read(path=str(allowed / "ok.txt")))

        assert result["metadata"]["violation_type"] == "max_depth_exceeded"
        assert result["fix_hints"] == [
            "This path is nested more than 3 levels deep; use a shorter path"
        ]

    def test_a_nul_byte_is_named(self, roots: tuple[Path, Path]) -> None:
        allowed, _ = roots

        @Airlock(config=AirlockConfig(filesystem_policy=FilesystemPolicy([allowed])))
        def read(path: str) -> str:
            return "ran"

        result = _refused(read(path=str(allowed / "ok.txt") + "\x00.png"))

        assert result["metadata"]["violation_type"] == "invalid_path"
        assert any("NUL byte" in hint for hint in result["fix_hints"])

    def test_an_argument_too_deep_to_inspect_is_named_as_an_argument(
        self, roots: tuple[Path, Path]
    ) -> None:
        allowed, secret = roots
        nested: Any = str(secret)
        for _ in range(MAX_DEPTH + 2):
            nested = [nested]

        @Airlock(config=AirlockConfig(filesystem_policy=FilesystemPolicy([allowed])))
        def read_any(paths: list[Any]) -> str:
            return "ran"

        result = _refused(read_any(paths=nested))

        assert result["metadata"]["violation_type"] == "uninspectable_argument"
        assert result["error"].startswith("AIRLOCK_BLOCK: Argument 'paths")
        assert "could not be inspected" in result["error"]
        assert any("could not be inspected" in hint for hint in result["fix_hints"])

    def test_resolution_failure_and_unknown_kinds_still_get_hints(self) -> None:
        failed = handle_path_violation("t", "/x", "resolution_failed", {"error": "loop"})
        unknown = handle_path_violation("t", "/x", "something_new", {"allowed_roots": ["/srv"]})

        assert failed.fix_hints == [
            "This path could not be resolved (loop); check that it is a well-formed path"
        ]
        assert "Use a path inside one of: /srv" in unknown.fix_hints

    def test_withheld_details_are_dropped_and_the_rest_kept(self) -> None:
        response = handle_path_violation(
            "t",
            "/srv/.env",
            "denied_pattern",
            {"pattern": "*.env", "resolved_path": "/srv/.env", "symlink_location": "/srv"},
        )

        assert "pattern" not in response.metadata
        assert "symlink_location" not in response.metadata
        assert response.metadata["resolved_path"] == "/srv/.env"


class TestPolicyDenialHidesGlob:
    def test_the_denied_tools_glob_is_not_quoted_back(self) -> None:
        @Airlock(policy=SecurityPolicy(denied_tools=["rm_*"]))
        def rm_rf(target: str) -> str:
            return "ran"

        result = _refused(rm_rf(target="/"))

        assert "rm_*" not in json.dumps(result)
        assert "Tool 'rm_rf' is denied by policy" in result["error"]
        assert result["metadata"]["violation_type"] == "tool_denied"
        hints = " ".join(result["fix_hints"])
        assert "whatever the arguments" in hints
        assert "do not retry" in hints

    def test_the_operator_still_gets_the_glob(self) -> None:
        seen: list[tuple[str, dict[str, Any]]] = []

        @Airlock(
            policy=SecurityPolicy(denied_tools=["rm_*"]),
            config=AirlockConfig(
                on_blocked=lambda name, message, info: seen.append((message, info))
            ),
        )
        def rm_rf(target: str) -> str:
            return "ran"

        _refused(rm_rf(target="/"))

        assert len(seen) == 1
        message, info = seen[0]
        assert message == "Tool 'rm_rf' is denied by policy (matches 'rm_*')"
        assert info["violation_type"] == "tool_denied"
        assert info["pattern"] == "rm_*"

    def test_a_tool_outside_the_allowlist_is_told_not_to_retry(self) -> None:
        @Airlock(policy=SecurityPolicy(allowed_tools=["read_*"]))
        def write_file(path: str) -> str:
            return "ran"

        result = _refused(write_file(path="a"))

        assert result["metadata"]["violation_type"] == "tool_not_allowed"
        assert "whatever the arguments" in " ".join(result["fix_hints"])

    def test_a_time_restriction_says_retrying_now_will_not_help(self) -> None:
        start = datetime.now() + timedelta(hours=12)
        window = f"{start:%H:%M}-{start + timedelta(minutes=1):%H:%M}"

        @Airlock(policy=SecurityPolicy(time_restrictions={"dep*": window}))
        def deploy(target: str) -> str:
            return "ran"

        result = _refused(deploy(target="prod"))

        assert result["metadata"]["violation_type"] == "time_restricted"
        assert "dep*" not in json.dumps(result)
        assert any("retrying now will not help" in hint for hint in result["fix_hints"])

    @pytest.mark.parametrize(
        ("policy", "violation_type"),
        [
            (SecurityPolicy(require_agent_id=True), "agent_required"),
            (SecurityPolicy(allowed_roles=["admin"]), "role_required"),
        ],
    )
    def test_an_identity_refusal_says_the_arguments_are_not_the_problem(
        self, policy: SecurityPolicy, violation_type: str
    ) -> None:
        @Airlock(policy=policy)
        def deploy(target: str) -> str:
            return "ran"

        result = _refused(deploy(target="prod"))

        assert result["metadata"]["violation_type"] == violation_type
        assert any("changing the arguments will not help" in hint for hint in result["fix_hints"])

    def test_without_a_violation_type_the_hints_stay_generic(self) -> None:
        response = handle_policy_violation("t", policy_name="SequenceGuard", reason="r")

        assert response.fix_hints == [
            "This operation is not permitted by the current security policy",
            "Contact the administrator if you believe this is an error",
        ]
        assert "violation_type" not in response.metadata


class TestOtherRefusalsWithholdDenyLists:
    def test_a_safepath_deny_list_match_is_not_quoted_back(self) -> None:
        @Airlock()
        def read(path: SafePath) -> str:
            return "ran"

        # Strict mode admits only a Path instance here; a host that converts the model's
        # string to one reaches the deny-list check.
        result = _refused(read(path=Path("/srv/app/.env")))

        assert result["block_reason"] == "validation_error"
        assert "denied pattern" not in json.dumps(result)
        assert result["metadata"]["errors"][0]["message"] == (
            "Value error, this path matches a protected location"
        )
        assert result["fix_hints"] == [
            "'path' points to a protected location; choose a different path"
        ]

    def test_a_safepath_structural_rule_is_still_named(self) -> None:
        @Airlock()
        def read(path: SafePath) -> str:
            return "ran"

        result = _refused(read(path=Path("../etc/passwd")))

        assert "parent traversal" in result["error"]

    def test_an_endpoint_refusal_does_not_quote_the_blocked_pattern(self) -> None:
        policy = EndpointPolicy(
            allowed_endpoints=["api.example.com"], blocked_patterns=["*.exfil-host.test"]
        )

        @Airlock(config=AirlockConfig(endpoint_policies={"fetch": policy}))
        def fetch(url: str) -> str:
            return "ran"

        result = _refused(fetch(url="https://drop.exfil-host.test/x"))

        assert result["block_reason"] == "endpoint_blocked"
        assert "*.exfil-host.test" not in json.dumps(result)
        assert any("api.example.com" in hint for hint in result["fix_hints"])


@dataclass
class _Env:
    tmp_path: Path
    monkeypatch: pytest.MonkeyPatch


def _type_error(env: _Env) -> Any:
    @Airlock()
    def tool(count: int) -> int:
        return count

    return tool(count="5")  # type: ignore[arg-type]


def _missing_argument(env: _Env) -> Any:
    @Airlock()
    def tool(count: int) -> int:
        return count

    return tool()  # type: ignore[call-arg]


def _ghost_argument(env: _Env) -> Any:
    @Airlock(config=AirlockConfig(unknown_args=UnknownArgsMode.BLOCK))
    def tool(count: int) -> int:
        return count

    return tool(count=1, force=True)  # type: ignore[call-arg]


def _tool_denied(env: _Env) -> Any:
    @Airlock(policy=SecurityPolicy(denied_tools=["tool"]))
    def tool() -> str:
        return "ran"

    return tool()


def _tool_not_allowed(env: _Env) -> Any:
    @Airlock(policy=SecurityPolicy(allowed_tools=["other"]))
    def tool() -> str:
        return "ran"

    return tool()


def _rate_limited(env: _Env) -> Any:
    @Airlock(policy=SecurityPolicy(rate_limits={"tool": "1/hour"}))
    def tool() -> str:
        return "ran"

    tool()
    return tool()


def _sandbox_unavailable(env: _Env) -> Any:
    env.monkeypatch.setattr(sandbox_module, "_check_e2b_available", lambda: False)

    @Airlock(sandbox=True)
    def tool(count: int) -> int:
        return count

    return tool(count=1)


def _outside_roots(env: _Env) -> Any:
    allowed = env.tmp_path / "allowed"
    allowed.mkdir()

    @Airlock(config=AirlockConfig(filesystem_policy=FilesystemPolicy([allowed])))
    def tool(path: str) -> str:
        return "ran"

    return tool(path=str(env.tmp_path / "elsewhere.txt"))


def _denied_pattern(env: _Env) -> Any:
    policy = FilesystemPolicy([env.tmp_path], deny_patterns=["*.key"])

    @Airlock(config=AirlockConfig(filesystem_policy=policy))
    def tool(path: str) -> str:
        return "ran"

    return tool(path=str(env.tmp_path / "id.key"))


def _network_blocked(env: _Env) -> Any:
    @Airlock(config=AirlockConfig(network_policy=NetworkPolicy(allow_egress=False)))
    def tool() -> str:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect(("127.0.0.1", 9))
        finally:
            sock.close()
        return "ran"

    return tool()


def _capability_denied(env: _Env) -> Any:
    config = AirlockConfig(capability_policy=CapabilityPolicy(denied=Capability.PROCESS_EXEC))

    @Airlock(config=config)
    @requires(Capability.PROCESS_EXEC)
    def tool() -> str:
        return "ran"

    return tool()


def _endpoint_blocked(env: _Env) -> Any:
    policy = EndpointPolicy(allowed_endpoints=["api.example.com"])

    @Airlock(config=AirlockConfig(endpoint_policies={"tool": policy}))
    def tool(url: str) -> str:
        return "ran"

    return tool(url="https://elsewhere.example.org/")


def _budget_exceeded(env: _Env) -> Any:
    pricing = {"default": {"input": Decimal("0.003"), "output": Decimal("0.015")}}
    set_global_tracker(CostTracker(model="default", pricing=pricing))
    try:

        @Airlock(policy=strict_tier_budget_policy())
        def tool(prompt: str) -> str:
            return "ran"

        with AirlockContext[None](metadata={"airlock_tier": "frontier", "input_tokens": 200_000}):
            return tool(prompt="hi")
    finally:
        _reset_tracker()


def _escalation(verdict: OversightVerdict | None) -> Callable[[_Env], Any]:
    def approver(request: OversightRequest) -> OversightResponse:
        assert verdict is not None
        return OversightResponse(request_id=request.request_id, verdict=verdict)

    def make(env: _Env) -> Any:
        policy = SecurityPolicy(
            escalate_tools={"tool": "needs a human"},
            approver=approver if verdict is not None else None,
        )

        @Airlock(policy=policy)
        def tool() -> str:
            return "ran"

        return tool()

    return make


def _kill_switch(env: _Env) -> Any:
    env.monkeypatch.setattr(core_module, "_kill_switch_frozen", lambda: True)
    env.monkeypatch.setattr(core_module, "_kill_switch_get", lambda: None)

    @Airlock()
    def tool() -> str:
        return "ran"

    return tool()


def _token_audience(env: _Env) -> Any:
    @Airlock(
        config=AirlockConfig(
            expected_token_audience="https://mcp.example.test", token_audience_mode="deny"
        )
    )
    def tool() -> str:
        return "ran"

    with AirlockContext(metadata={"access_token_claims": {"aud": "https://other-app.example"}}):
        return tool()


def _output_unreadable(env: _Env) -> Any:
    @Airlock()
    def tool() -> list[Any]:
        nested: list[Any] = ["leaf"]
        for _ in range(5000):  # deeper than the output walk can rebuild
            nested = [nested]
        return nested

    return tool()


def _startup_hook(env: _Env) -> Any:
    from agent_airlock.runtime import startup_hooks

    hook = startup_hooks.StartupHookFinding(
        path=str(env.tmp_path / "x.pth"), kind=startup_hooks.StartupHookKind.PTH, sha256="0" * 64
    )
    # The walk this process already did, standing in for one that found a hook.
    env.monkeypatch.setattr(startup_hooks, "_process_walk", ((hook,), (str(env.tmp_path),)))
    env.monkeypatch.setattr(startup_hooks, "_announced", set())

    @Airlock(config=AirlockConfig(startup_hook_check="deny"))
    def tool() -> str:
        return "ran"

    return tool()


def _amplification_unconfigured(env: _Env) -> Any:
    @Airlock(policy=SecurityPolicy(amplification_budget=AmplificationBudget()))
    def tool() -> str:
        return "ran"

    return tool()


def _handle_tool() -> Callable[..., Any]:
    @Airlock()
    def tool(session: HandleField(issuer=ISSUER, scope=SCOPE)) -> str:  # type: ignore[valid-type]
        return "ran"

    return tool


def _handle_not_issued(env: _Env) -> Any:
    with handle_run("run-1"):
        return _handle_tool()(session="ah_forged")


def _handle_wrong_issuer(env: _Env) -> Any:
    with handle_run("run-1"):
        return _handle_tool()(session=issue_handle(issuer="someone.else", scope=SCOPE))


def _handle_wrong_scope(env: _Env) -> Any:
    with handle_run("run-1"):
        return _handle_tool()(session=issue_handle(issuer=ISSUER, scope="elsewhere"))


def _handle_expired(env: _Env) -> Any:
    with handle_run("run-1"):
        handle = issue_handle(issuer=ISSUER, scope=SCOPE, ttl_seconds=0.01)
        time.sleep(0.05)
        return _handle_tool()(session=handle)


#: Every refusal the @Airlock call path can return, by the block reason it carries.
_REFUSALS: list[tuple[str, Callable[[_Env], Any], BlockReason]] = [
    ("type-error", _type_error, BlockReason.VALIDATION_ERROR),
    ("missing-argument", _missing_argument, BlockReason.VALIDATION_ERROR),
    ("ghost-argument", _ghost_argument, BlockReason.GHOST_ARGUMENTS),
    ("tool-denied", _tool_denied, BlockReason.POLICY_VIOLATION),
    ("tool-not-allowed", _tool_not_allowed, BlockReason.POLICY_VIOLATION),
    ("rate-limited", _rate_limited, BlockReason.RATE_LIMIT),
    ("sandbox-unavailable", _sandbox_unavailable, BlockReason.SANDBOX_ERROR),
    ("outside-roots", _outside_roots, BlockReason.PATH_VIOLATION),
    ("denied-pattern", _denied_pattern, BlockReason.PATH_VIOLATION),
    ("network-blocked", _network_blocked, BlockReason.NETWORK_BLOCKED),
    ("capability-denied", _capability_denied, BlockReason.CAPABILITY_DENIED),
    ("endpoint-blocked", _endpoint_blocked, BlockReason.ENDPOINT_BLOCKED),
    ("budget-exceeded", _budget_exceeded, BlockReason.BUDGET_EXCEEDED),
    ("escalation-no-approver", _escalation(None), BlockReason.ESCALATION_REQUIRED),
    ("escalation-denied", _escalation(OversightVerdict.DENY), BlockReason.ESCALATION_DENIED),
    (
        "escalation-timeout",
        _escalation(OversightVerdict.TIMEOUT),
        BlockReason.ESCALATION_TIMEOUT,
    ),
    ("kill-switch", _kill_switch, BlockReason.KILL_SWITCH),
    ("token-audience", _token_audience, BlockReason.TOKEN_AUDIENCE),
    ("startup-hook", _startup_hook, BlockReason.STARTUP_HOOK),
    ("output-unreadable", _output_unreadable, BlockReason.OUTPUT_UNREADABLE),
    ("amplification", _amplification_unconfigured, BlockReason.AMPLIFICATION_EXCEEDED),
    ("handle-not-issued", _handle_not_issued, BlockReason.HANDLE_NOT_ISSUED),
    ("handle-wrong-issuer", _handle_wrong_issuer, BlockReason.HANDLE_WRONG_ISSUER),
    ("handle-wrong-scope", _handle_wrong_scope, BlockReason.HANDLE_WRONG_SCOPE),
    ("handle-expired", _handle_expired, BlockReason.HANDLE_EXPIRED),
]

#: Block reasons the @Airlock call path never returns: OUTPUT_SANITIZED names no refusal,
#: and ANOMALY_DETECTED comes from the anomaly detector's own handler.
_NOT_ON_THE_CALL_PATH = {BlockReason.OUTPUT_SANITIZED, BlockReason.ANOMALY_DETECTED}


class TestEveryRefusalCarriesHints:
    @pytest.mark.parametrize(
        ("make_refusal", "block_reason"),
        [pytest.param(make, reason, id=name) for name, make, reason in _REFUSALS],
    )
    def test_the_refusal_says_what_to_do(
        self,
        make_refusal: Callable[[_Env], Any],
        block_reason: BlockReason,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        result = _refused(make_refusal(_Env(tmp_path, monkeypatch)))

        assert result["status"] == "blocked"
        assert result["block_reason"] == block_reason.value
        assert result["error"].startswith("AIRLOCK_BLOCK")
        hints = result.get("fix_hints")
        assert isinstance(hints, list) and hints, "a refusal must say what to do"
        assert all(isinstance(hint, str) and hint.strip() for hint in hints)

    def test_every_block_reason_is_covered(self) -> None:
        # A new BlockReason must join _REFUSALS (or _NOT_ON_THE_CALL_PATH, with a reason).
        covered = {reason for _, _, reason in _REFUSALS}
        assert covered | _NOT_ON_THE_CALL_PATH == set(BlockReason)
