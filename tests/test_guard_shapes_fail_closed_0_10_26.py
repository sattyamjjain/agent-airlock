"""0.10.26 (security): spawn, argv and config guards read every shape or refuse it.

The ``/init`` drift audit held ``mcp_spec/CLAUDE.md``'s rule ("read every shape a field can
take, or refuse it") against each guard and found these gaps, each reproduced first:

- ``enforce_argv_array`` skipped a slot that was not a string (``bytes``, a nested list, a
  number) with a comment calling it the caller's bug. Nothing below the skip read it,
  ``subprocess`` spawns a ``bytes`` element as written, and the opt-in
  ``reject_option_values`` check never saw such a slot either.
- ``McpSubprocessArgInjectionGuard.evaluate`` allowed any config that was not a mapping (a
  list, a string, ``bytes``, a number) as "no spawn config to inspect".
- ``StdioMetaGuard.evaluate`` raised ``TypeError`` on a non-string argv element and on an
  ``args`` that was not a sequence, ``AttributeError`` on a spec that was not a mapping, and
  dropped a ``command`` of any type other than ``str`` / ``list``, so argv[0] was never the
  program.
- ``StdioCommandInjectionGuard.evaluate`` and ``ConfigPathGuard.evaluate`` raised
  ``AttributeError`` on a payload that was not a mapping; ``LoopbackSessionSpawnGuard
  .check_spawn`` raised ``TypeError`` on a number and ``str()``-coerced a non-string
  element; ``McpConfigPinSet.check`` raised ``ValueError`` on an ``args`` that contained
  itself and ``TypeError`` on a config that was not a mapping.

A crash is not a verdict: a caller of ``evaluate_or_raise`` expects the guard's own error,
and a guard chained behind ``allowed`` never sees an exception at all.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from agent_airlock.mcp_spec.argv_guard import (
    ArgvNonStringSlotError,
    ArgvOptionInjectionError,
    ArgvStringConcatenationError,
    enforce_argv_array,
)
from agent_airlock.mcp_spec.config_path_guard import ConfigPathGuard
from agent_airlock.mcp_spec.loopback_spawn_guard import (
    LoopbackSessionSpawnGuard,
    LoopbackSpawnVerdict,
)
from agent_airlock.mcp_spec.stdio_command_injection_guard import (
    StdioCommandInjectionGuard,
    StdioCommandInjectionVerdict,
)
from agent_airlock.mcp_spec.stdio_meta_guard import StdioMetaGuard
from agent_airlock.mcp_spec.subprocess_arg_guard import (
    McpSubprocessArgInjectionGuard,
    McpSubprocessArgVerdict,
)
from agent_airlock.mcp_spec.zero_click_config_guard import (
    McpConfigPinSet,
    McpConfigPinViolation,
)
from agent_airlock.policy_presets import stdio_guard_ox_defaults


class TestArgvGuardRefusesNonStringSlots:
    @pytest.mark.parametrize(
        "argv",
        [
            ["kubectl", b"get; id"],
            ["kubectl", ["get", "pods; id"]],
            ["kubectl", 7],
            ["kubectl", None],
        ],
        ids=["bytes", "nested list", "int", "None"],
    )
    def test_a_non_string_slot_is_refused(self, argv: list[Any]) -> None:
        with pytest.raises(ArgvNonStringSlotError) as exc:
            enforce_argv_array(argv)

        assert exc.value.argv_index == 1
        assert exc.value.offending_type == type(argv[1]).__name__
        assert "not a string" in str(exc.value)

    def test_the_refusal_is_a_concatenation_error_so_existing_handlers_catch_it(self) -> None:
        with pytest.raises(ArgvStringConcatenationError):
            enforce_argv_array(["kubectl", b"get"])

    def test_the_field_name_is_cited(self) -> None:
        with pytest.raises(ArgvNonStringSlotError) as exc:
            enforce_argv_array(["pod/foo", b"8080:80"], field_names=["pod", "ports"])

        assert exc.value.field_name == "ports"
        assert "'ports'" in str(exc.value)

    def test_the_option_check_cannot_be_dodged_with_bytes(self) -> None:
        """Until 0.10.26 ``reject_option_values`` skipped the slot too (wave-2 F16)."""
        with pytest.raises(ArgvNonStringSlotError):
            enforce_argv_array([b"--kubeconfig=/etc/shadow"], reject_option_values=True)
        with pytest.raises(ArgvOptionInjectionError):
            enforce_argv_array(["--kubeconfig=/etc/shadow"], reject_option_values=True)

    def test_controls(self) -> None:
        enforce_argv_array(["kubectl", "get", "pods"])
        enforce_argv_array(["port-forward", "pod/foo", "8080:80"], reject_option_values=True)
        with pytest.raises(ArgvStringConcatenationError):
            enforce_argv_array(["kubectl", "get pods; id"])


class TestSubprocessArgGuardRefusesNonMappingConfigs:
    @pytest.fixture
    def guard(self) -> McpSubprocessArgInjectionGuard:
        return McpSubprocessArgInjectionGuard(allowed_commands={"python"})

    @pytest.mark.parametrize(
        "config",
        [["bash", "-c", "id"], "bash -c id", b"bash -c id", 7, [], ""],
        ids=["list", "str", "bytes", "int", "empty list", "empty str"],
    )
    def test_a_config_that_is_not_a_mapping_is_refused(
        self, guard: McpSubprocessArgInjectionGuard, config: Any
    ) -> None:
        decision = guard.evaluate(config)

        assert decision.allowed is False
        assert decision.verdict is McpSubprocessArgVerdict.DENY_UNINSPECTABLE
        assert type(config).__name__ in decision.detail
        assert decision.fix_hints

    def test_controls(self, guard: McpSubprocessArgInjectionGuard) -> None:
        assert guard.evaluate(None).allowed is True
        assert guard.evaluate({}).allowed is True
        assert guard.evaluate({"command": "python"}).allowed is True
        assert (
            guard.evaluate({"command": "bash"}).verdict
            is McpSubprocessArgVerdict.DENY_UNTRUSTED_COMMAND
        )
        assert (
            guard.evaluate({"command": "python", "env": {"LD_PRELOAD": "/tmp/x.so"}}).verdict
            is McpSubprocessArgVerdict.DENY_UNTRUSTED_ENV
        )


def _meta() -> StdioMetaGuard:
    return StdioMetaGuard(stdio_config=stdio_guard_ox_defaults())


def _rules(verdict: Any) -> list[str]:
    return [f.rule for f in verdict.findings]


class TestStdioMetaGuardRefusesUnreadableSpecs:
    @pytest.mark.parametrize(
        "spec",
        [
            {"command": "python", "args": ["--version", 7]},
            {"command": "python", "args": [b"--version"]},
            {"command": [b"python"]},
            {"command": ["python", None]},
        ],
        ids=["int arg", "bytes arg", "bytes command element", "None command element"],
    )
    def test_a_non_string_argv_element_is_a_verdict_not_a_type_error(
        self, spec: dict[str, Any]
    ) -> None:
        verdict = _meta().evaluate(spec)

        assert verdict.verdict == "block"
        assert "non_string_argv" in _rules(verdict)

    @pytest.mark.parametrize(
        ("spec", "field"),
        [
            ({"command": "python", "args": 7}, "args"),
            ({"command": "python", "args": {"a": 1}}, "args"),
            ({"command": b"python"}, "command"),
            ({"command": 7, "args": ["--version"]}, "command"),
        ],
        ids=["int args", "mapping args", "bytes command", "int command"],
    )
    def test_an_unreadable_field_is_refused_not_dropped(
        self, spec: dict[str, Any], field: str
    ) -> None:
        verdict = _meta().evaluate(spec)

        assert verdict.verdict == "block"
        finding = next(f for f in verdict.findings if f.rule == "unreadable_shape")
        assert finding.finding_id == f"{field}_unreadable"
        assert finding.details["field"] == field

    @pytest.mark.parametrize("spec", [["python"], "python", 7], ids=["list", "str", "int"])
    def test_a_spec_that_is_not_a_mapping_is_refused(self, spec: Any) -> None:
        verdict = _meta().evaluate(spec)  # type: ignore[arg-type]

        assert verdict.verdict == "block"
        assert [f.finding_id for f in verdict.findings] == ["server_spec_unreadable"]

    def test_a_string_args_is_split_like_the_sibling_guards_split_it(self) -> None:
        as_list = _meta().evaluate({"command": "python", "args": ["--version", "--help"]})
        as_string = _meta().evaluate({"command": "python", "args": "--version --help"})

        assert as_string.verdict == as_list.verdict
        assert _rules(as_string) == _rules(as_list)

    def test_controls_raise_nothing_and_read_every_slot(self) -> None:
        for spec in (
            {"command": "python", "args": ["--version"]},
            {"command": ["python", "--version"]},
            {"command": ("python", "--version")},
            {"args": ["python", "--version"]},
        ):
            verdict = _meta().evaluate(spec)
            assert verdict.verdict in {"allow", "block"}
            assert not {"unreadable_shape", "non_string_argv"} & set(_rules(verdict))


class TestStdioCommandInjectionGuardRefusesNonMappingArgs:
    @pytest.mark.parametrize(
        "args", [["ls"], "ls; id", 7, b"ls"], ids=["list", "str", "int", "bytes"]
    )
    def test_refused(self, args: Any) -> None:
        decision = StdioCommandInjectionGuard().evaluate(args)

        assert decision.allowed is False
        assert decision.verdict is StdioCommandInjectionVerdict.DENY_UNINSPECTABLE
        assert type(args).__name__ in decision.detail

    def test_controls(self) -> None:
        guard = StdioCommandInjectionGuard()
        assert guard.evaluate(None).allowed is True
        assert guard.evaluate({"command": "ls"}).allowed is True
        assert guard.evaluate({"command": "ls; id"}).allowed is False


class TestConfigPathGuardRefusesNonMappingConfigs:
    @pytest.mark.parametrize("config", ["x", ["x"], 7, None], ids=["str", "list", "int", "None"])
    def test_refused(self, tmp_path: Path, config: Any) -> None:
        inspection = ConfigPathGuard(host_root=tmp_path, platform="posix").evaluate(config)

        assert inspection.verdict == "block"
        assert [f.rule for f in inspection.findings] == ["unreadable_shape"]
        assert inspection.findings[0].field_name == "server_config"

    def test_control(self, tmp_path: Path) -> None:
        assert ConfigPathGuard(host_root=tmp_path, platform="posix").evaluate({}).verdict == "allow"


class TestLoopbackSpawnGuardRefusesUnreadableCommands:
    @pytest.mark.parametrize(
        "command",
        [7, b"python3", ["python3", 7], ["python3", b"-V"], None, {"command": "python3"}],
        ids=["int", "bytes", "int element", "bytes element", "None", "mapping"],
    )
    def test_refused(self, command: Any) -> None:
        decision = LoopbackSessionSpawnGuard(allowed_commands=["python3"]).check_spawn(command)

        assert decision.allowed is False
        assert decision.verdict is LoopbackSpawnVerdict.DENY_UNINSPECTABLE
        assert decision.fix_hints

    def test_controls(self) -> None:
        guard = LoopbackSessionSpawnGuard(allowed_commands=["python3"])
        assert guard.check_spawn("python3 -V").allowed is True
        assert guard.check_spawn(["python3", "-V"]).allowed is True
        assert guard.check_spawn("bash").verdict is LoopbackSpawnVerdict.DENY_RESOLVED_DENIED
        assert guard.check_spawn("").verdict is LoopbackSpawnVerdict.DENY_EMPTY_COMMAND


class TestConfigPinSetRefusesUnreadableConfigs:
    @pytest.fixture
    def pins(self) -> McpConfigPinSet:
        return McpConfigPinSet.from_manifest(
            [{"name": "srv", "command": "python", "args": ["-m", "srv"]}]
        )

    def test_an_args_that_contains_itself_is_unreadable_not_a_value_error(
        self, pins: McpConfigPinSet
    ) -> None:
        args: list[Any] = ["-m"]
        args.append(args)

        with pytest.raises(McpConfigPinViolation) as exc:
            pins.check({"name": "srv", "command": "python", "args": args})

        assert exc.value.reason == "unreadable"
        assert exc.value.server_name == "srv"

    @pytest.mark.parametrize(
        "config", [["srv"], "srv", b"srv", 7], ids=["list", "str", "bytes", "int"]
    )
    def test_a_config_that_is_not_a_mapping_is_refused(
        self, pins: McpConfigPinSet, config: Any
    ) -> None:
        with pytest.raises(McpConfigPinViolation) as exc:
            pins.check(config)

        assert exc.value.reason == "unreadable"
        assert "mapping" in exc.value.detail

    def test_controls(self, pins: McpConfigPinSet) -> None:
        pins.check({"name": "srv", "command": "python", "args": ["-m", "srv"]})
        with pytest.raises(McpConfigPinViolation) as exc:
            pins.check({"name": "srv", "command": "python", "args": ["-m", "evil"]})
        assert exc.value.reason == "mutated"
