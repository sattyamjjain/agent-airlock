"""Regressions for 0.10.24: six MCP guards let through shapes they could not read.

The rule 0.10.21 wrote into ``mcp_spec`` (read every shape a field can take, or refuse it)
had not reached these:

- ``ConfigPathGuard`` read ``command`` only as a string, ``args`` only as a list, ``env`` only
  as a ``dict`` and skipped every other shape, so ``{"command": ["../../etc/evil"]}``, a
  string ``args``, a list ``env`` and a ``MappingProxyType`` ``env`` were all allowed.
- ``McpConfigPinSet`` resolved an ``env`` that was not a mapping to *no keys*, so a pin with
  no env admitted ``{"env": ["LD_PRELOAD=/tmp/x.so"]}`` and ``{"env": "LD_PRELOAD=..."}``.
- ``EvalRCEGuard`` and ``FilterEvalRCEGuard`` scanned top-level strings only, so a payload in
  a list or a nested mapping (``{"payload": {"code": "eval(...)"}}``) was allowed.
- ``StdioCommandInjectionGuard`` skipped any element of ``command`` / ``args`` that was not a
  string, and a ``command`` or ``args`` of any other type.
- ``MCPServerEnvInterpolationGuard`` skipped ``bytes``, sets and other objects, and could not
  read a config that was not a mapping.

Every guard now reads the shape or refuses it. Nesting deeper than a guard walks, and a
container that contains itself, are refused too.
"""

from __future__ import annotations

from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest

from agent_airlock.mcp_spec.config_path_guard import ConfigPathGuard, ConfigPathTraversalError
from agent_airlock.mcp_spec.env_interpolation_guard import (
    MCPEnvInterpolationVerdict,
    MCPServerEnvInterpolationGuard,
)
from agent_airlock.mcp_spec.eval_rce_guard import EvalRCEGuard, EvalRCEVerdict
from agent_airlock.mcp_spec.filter_eval_rce_guard import (
    FilterEvalRCEGuard,
    FilterEvalRCEVerdict,
)
from agent_airlock.mcp_spec.stdio_command_injection_guard import (
    StdioCommandInjectionGuard,
    StdioCommandInjectionVerdict,
)
from agent_airlock.mcp_spec.zero_click_config_guard import (
    McpConfigPinSet,
    McpConfigPinViolation,
)


def _nested(value: object, levels: int) -> object:
    for _ in range(levels):
        value = [value]
    return value


def _self_containing() -> list[object]:
    loop: list[object] = []
    loop.append(loop)
    return loop


class TestTheConfigPathGuardReadsEveryShape:
    @pytest.fixture
    def guard(self, tmp_path: Path) -> ConfigPathGuard:
        return ConfigPathGuard(host_root=tmp_path, platform="posix")

    @pytest.mark.parametrize(
        ("config", "field"),
        [
            ({"command": ["../../etc/evil"]}, "command[0]"),
            ({"command": "uvx", "args": "-y ../../etc/passwd"}, "args[1]"),
            ({"command": "uvx", "env": ["P=../../etc/x"]}, "env[P]"),
            ({"command": "uvx", "env": MappingProxyType({"P": "../../etc/x"})}, "env[P]"),
        ],
        ids=["list command", "string args", "list env", "MappingProxyType env"],
    )
    def test_a_traversal_in_every_readable_shape_is_refused(
        self, guard: ConfigPathGuard, config: dict[str, Any], field: str
    ) -> None:
        inspection = guard.evaluate(config)

        assert inspection.verdict == "block"
        assert [(f.field_name, f.rule) for f in inspection.findings] == [
            (field, "posix_dot_dot_traversal")
        ]

    @pytest.mark.parametrize(
        ("config", "field"),
        [
            ({"command": "uvx", "args": [b"../.."]}, "args[0]"),
            ({"command": ["uvx", ["../.."]]}, "command[1]"),
            ({"command": {"path": "sh"}}, "command"),
            ({"command": "uvx", "args": 0}, "args"),
            ({"command": "uvx", "env": "P=../x"}, "env"),
            ({"command": "uvx", "env": {"P=../x"}}, "env"),
            ({"command": "uvx", "env": [b"P=../x"]}, "env[0]"),
            ({"command": "uvx", "env": {"P": ["../x"]}}, "env[P]"),
            ({"command": "uvx", "workingDirectory": b"/tmp"}, "workingDirectory"),
        ],
        ids=[
            "bytes args item",
            "nested list in command",
            "mapping command",
            "number args",
            "string env",
            "set env",
            "bytes env item",
            "list env value",
            "bytes workingDirectory",
        ],
    )
    def test_a_shape_it_cannot_read_is_refused(
        self, guard: ConfigPathGuard, config: dict[str, Any], field: str
    ) -> None:
        inspection = guard.evaluate(config)

        assert inspection.verdict == "block"
        assert [(f.field_name, f.rule) for f in inspection.findings] == [
            (field, "unreadable_shape")
        ]

    @pytest.mark.parametrize(
        "config",
        [
            {"command": ["uvx", "mcp-server-fetch"]},
            {"command": "uvx", "args": "-y mcp-server-fetch"},
            {"command": "uvx", "env": ["LOG_LEVEL=info", "HOME_ONLY"]},
            {"command": "uvx", "env": {"PORT": 8080, "DEBUG": True, "UNSET": None}},
        ],
        ids=["list command", "string args", "list env", "non-string scalar env values"],
    )
    def test_benign_shapes_still_pass(self, guard: ConfigPathGuard, config: dict[str, Any]) -> None:
        assert guard.evaluate(config).verdict == "allow"

    def test_evaluate_or_raise_raises_on_a_list_command(self, guard: ConfigPathGuard) -> None:
        with pytest.raises(ConfigPathTraversalError) as exc:
            guard.evaluate_or_raise({"command": ["../../etc/evil"]})
        assert exc.value.rule == "posix_dot_dot_traversal"


class TestThePinSetReadsEveryEnvShape:
    BASE: dict[str, Any] = {"name": "fs", "command": "npx", "args": ["-y", "@mcp/fs"]}

    @pytest.fixture
    def pins(self) -> McpConfigPinSet:
        return McpConfigPinSet.from_manifest([self.BASE])

    @pytest.mark.parametrize(
        "env",
        [{"LD_PRELOAD": "/tmp/x.so"}, ["LD_PRELOAD=/tmp/x.so"], ["LD_PRELOAD"]],
        ids=["mapping", "list of KEY=VALUE", "list of bare keys"],
    )
    def test_an_injected_env_key_is_refused_in_every_readable_shape(
        self, pins: McpConfigPinSet, env: object
    ) -> None:
        with pytest.raises(McpConfigPinViolation) as exc:
            pins.check({**self.BASE, "env": env})
        assert exc.value.reason == "mutated"

    @pytest.mark.parametrize(
        "config",
        [
            {"env": "LD_PRELOAD=/tmp/x.so"},
            {"env": b"LD_PRELOAD=/tmp/x.so"},
            {"env": 1},
            {"env": [1]},
            {"env_keys": "LD_PRELOAD"},
            {"args": ["-y", b"@mcp/fs"]},
            {"args": 7},
        ],
        ids=[
            "string env",
            "bytes env",
            "number env",
            "non-string env item",
            "string env_keys",
            "bytes args item",
            "number args",
        ],
    )
    def test_a_shape_it_cannot_read_is_refused_not_read_as_no_keys(
        self, pins: McpConfigPinSet, config: dict[str, Any]
    ) -> None:
        with pytest.raises(McpConfigPinViolation) as exc:
            pins.check({**self.BASE, **config})
        assert exc.value.reason == "unreadable"
        assert exc.value.actual_fingerprint == ""
        assert exc.value.detail

    def test_a_list_env_pin_matches_the_same_keys_as_a_mapping(self) -> None:
        pins = McpConfigPinSet.from_manifest([{**self.BASE, "env": ["MCP_MODE=ro"]}])

        pins.check({**self.BASE, "env": {"MCP_MODE": "rotated-value"}})

    def test_an_empty_env_still_matches_a_pin_with_none(self, pins: McpConfigPinSet) -> None:
        pins.check({**self.BASE, "env": []})
        pins.check({**self.BASE, "env": {}})

    def test_a_manifest_it_cannot_read_fails_loudly(self) -> None:
        with pytest.raises(ValueError, match="env must be"):
            McpConfigPinSet.from_manifest([{**self.BASE, "env": "MCP_MODE=ro"}])


class TestTheEvalGuardsWalkNestedValues:
    EVAL = "eval(input())"
    LAMBDA = "lambda u: exec('rce')"

    @pytest.mark.parametrize(
        "args",
        [
            {"code": [EVAL]},
            {"payload": {"code": EVAL}},
            {"code": (EVAL,)},
            {"code": {EVAL}},
            {"code": EVAL.encode()},
        ],
        ids=["list", "nested mapping", "tuple", "set", "bytes"],
    )
    def test_the_eval_guard_finds_a_nested_sink(self, args: dict[str, Any]) -> None:
        decision = EvalRCEGuard().evaluate(args)

        assert decision.verdict is EvalRCEVerdict.DENY_EVAL_SINK
        assert decision.matched_sink == "eval"

    @pytest.mark.parametrize(
        ("args", "field"),
        [
            ({"condition": [LAMBDA]}, "condition[0]"),
            ({"payload": {"condition": LAMBDA}}, "payload.condition"),
            ({"filter": {"clauses": [{"left": LAMBDA}]}}, "filter.clauses[0].left"),
        ],
        ids=["list under a suspect key", "suspect key nested", "under a suspect ancestor"],
    )
    def test_the_filter_guard_finds_a_nested_expression(
        self, args: dict[str, Any], field: str
    ) -> None:
        decision = FilterEvalRCEGuard().evaluate(args)

        assert decision.verdict is FilterEvalRCEVerdict.DENY_PYTHON_LAMBDA
        assert decision.matched_field == field

    def test_the_filter_guard_still_leaves_non_suspect_fields_to_scan_all(self) -> None:
        args = {"notes": {"text": "lambda x: x"}}

        assert FilterEvalRCEGuard().evaluate(args).allowed is True
        refused = FilterEvalRCEGuard(scan_all_fields=True).evaluate(args)
        assert refused.verdict is FilterEvalRCEVerdict.DENY_PYTHON_LAMBDA
        assert refused.matched_field == "notes.text"

    @pytest.mark.parametrize(
        "value",
        [_nested("x", 40), _self_containing()],
        ids=["deeper than the walk", "contains itself"],
    )
    def test_input_it_cannot_walk_is_refused(self, value: object) -> None:
        eval_decision = EvalRCEGuard().evaluate({"code": value})
        filter_decision = FilterEvalRCEGuard().evaluate({"condition": value})

        assert eval_decision.verdict is EvalRCEVerdict.DENY_UNINSPECTABLE
        assert filter_decision.verdict is FilterEvalRCEVerdict.DENY_UNINSPECTABLE

    def test_benign_nested_values_still_pass(self) -> None:
        args = {"payload": {"code": "x + 1", "condition": "x > 1", "items": [1, 2, "ok"]}}

        assert EvalRCEGuard().evaluate(args).allowed is True
        assert FilterEvalRCEGuard().evaluate(args).allowed is True


class TestTheMetacharGuardRefusesArgvItCannotRead:
    @pytest.mark.parametrize(
        "config",
        [
            {"command": "sh", "args": [["; id"]]},
            {"command": "sh", "args": [b"; id"]},
            {"command": {"path": "sh"}},
            {"command": b"sh -c id"},
            {"command": "sh", "args": 7},
        ],
        ids=["nested list item", "bytes item", "mapping command", "bytes command", "number args"],
    )
    def test_it_is_refused(self, config: dict[str, Any]) -> None:
        decision = StdioCommandInjectionGuard().evaluate(config)

        assert decision.allowed is False
        assert decision.verdict is StdioCommandInjectionVerdict.DENY_UNINSPECTABLE

    def test_a_config_with_no_argv_is_still_none_of_its_business(self) -> None:
        assert StdioCommandInjectionGuard().evaluate({"query": "SELECT 1"}).allowed is True


class TestTheEnvInterpolationGuardReadsEveryValue:
    @pytest.mark.parametrize(
        ("config", "field"),
        [
            (b"https://x/${JWT_SECRET}", "url"),
            ({"headers": {"Authorization": b"Bearer ${JWT_SECRET}"}}, "headers.Authorization"),
            ({"args": {"--token=${JWT_SECRET}"}}, "args[0]"),
        ],
        ids=["bytes url", "bytes header value", "set args"],
    )
    def test_a_token_in_bytes_or_a_set_is_found(self, config: object, field: str) -> None:
        decision = MCPServerEnvInterpolationGuard().evaluate(config)  # type: ignore[arg-type]

        assert decision.verdict is MCPEnvInterpolationVerdict.DENY_DOLLAR_BRACE
        assert decision.matched_field == field
        assert decision.matched_var == "JWT_SECRET"

    @pytest.mark.parametrize(
        ("config", "field"),
        [
            (["https://x/${JWT_SECRET}"], "config"),
            ({"url": object()}, "url"),
            ({"args": _self_containing()}, "args[0]"),
            ({"args": _nested("x", 40)}, "args" + "[0]" * 31),
        ],
        ids=["list config", "object value", "contains itself", "deeper than the walk"],
    )
    def test_a_value_it_cannot_read_is_refused(self, config: object, field: str) -> None:
        decision = MCPServerEnvInterpolationGuard().evaluate(config)  # type: ignore[arg-type]

        assert decision.verdict is MCPEnvInterpolationVerdict.DENY_UNINSPECTABLE
        assert decision.matched_field == field
        assert decision.fix_hints

    def test_json_scalars_and_unscanned_keys_still_pass(self) -> None:
        guard = MCPServerEnvInterpolationGuard()

        assert guard.evaluate({"headers": {"X-Retry": 3, "X-Debug": False}}).allowed is True
        assert guard.evaluate({"url": "https://api.example.com/mcp", "timeout": object()}).allowed
