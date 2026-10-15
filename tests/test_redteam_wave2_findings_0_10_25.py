"""Regressions for genuine guard fail-opens found by adaptive red-team wave 2.

Wave 2 drove 11 SSRF / eval-RCE / path / spawn / stdio guards. Most of its mode-C
adapters score an admitted attack probe as a "bypass" without an independent reference
detector, so the raw counts over-report and were triaged by hand. The two findings below
are the **oracle-anchored** ones — the harness confirmed each with its own stdlib-backed
reference detector (``ipaddress`` for SSRF, a ``\\b``-boundary sink regex for eval-RCE) —
and are fixed in 0.10.25. Further hand-triaged wave-2 findings land in their own commits.

F3 ``SSRFEgressGuard`` admitted IETF-reserved IPv6 (``200::/7`` … ``fe00::/9``): its
``_blocked_reason`` enumerated loopback/link-local/metadata/unspecified/ULA/RFC1918 but had
no ``is_reserved`` catch, so reserved/unallocated space — not globally routable — was
returned as public. Now denied ``DENY_RESERVED``.

F4 ``EvalRCEGuard`` admitted an eval-family call behind a ``.`` on a non-identifier
receiver (``get_evaluator().eval(…)``, ``cfg["x"].eval(…)``, a leading ``.eval(``): the
sink regex excluded ``.`` from its left boundary. Aligned to a ``\\b`` word boundary, which
also catches the bare ``.getattr(`` miss while still rejecting ``xeval(`` and
``parse_expression(``.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from agent_airlock.mcp_spec.config_path_guard import ConfigPathGuard
from agent_airlock.mcp_spec.eval_rce_guard import EvalRCEGuard
from agent_airlock.mcp_spec.loopback_spawn_guard import LoopbackSessionSpawnGuard
from agent_airlock.mcp_spec.stdio_command_injection_guard import StdioCommandInjectionGuard
from agent_airlock.mcp_spec.stdio_guard import StdioInjectionError, validate_stdio_command
from agent_airlock.mcp_spec.stdio_meta_guard import StdioMetaGuard
from agent_airlock.mcp_spec.subprocess_arg_guard import (
    McpSubprocessArgInjectionGuard,
    McpSubprocessArgVerdict,
)
from agent_airlock.policy import StdioGuardConfig
from agent_airlock.policy_presets import stdio_guard_ox_defaults
from agent_airlock.ssrf_egress_guard import SSRFEgressGuard, SSRFEgressVerdict


class TestSSRFReservedIPv6:
    """F3: reserved / unallocated IP space must be refused as not globally routable."""

    @pytest.fixture
    def guard(self) -> SSRFEgressGuard:
        # Resolver only matters for hostnames; these cases use IP literals.
        return SSRFEgressGuard()

    @pytest.mark.parametrize(
        "ip",
        ["200::1", "400::1", "800::1", "1000::1", "4000::1", "fe00::1", "fc00:1::1"],
    )
    def test_reserved_ipv6_is_refused(self, guard: SSRFEgressGuard, ip: str) -> None:
        decision = guard.check_url(f"http://[{ip}]/")
        assert decision.allowed is False

    def test_reserved_verdict_is_specific(self, guard: SSRFEgressGuard) -> None:
        # 200::/7 is reserved but matches none of the pre-existing specific rules.
        assert guard.check_url("http://[200::1]/").verdict is SSRFEgressVerdict.DENY_RESERVED

    def test_reserved_ipv4_240_4_is_refused(self, guard: SSRFEgressGuard) -> None:
        assert guard.check_url("http://240.0.0.1/").allowed is False

    def test_public_ipv6_still_admitted(self) -> None:
        guard = SSRFEgressGuard(resolver=lambda _h: ["2606:4700:4700::1111"])
        assert guard.check_url("http://[2606:4700:4700::1111]/").allowed is True

    def test_public_hostname_still_admitted(self) -> None:
        guard = SSRFEgressGuard(resolver=lambda _h: ["93.184.216.34"])
        assert guard.check_url("https://example.com/").allowed is True


class TestEvalRCELoneDotSink:
    """F4: an eval-family call on a non-identifier receiver must be refused."""

    @pytest.fixture
    def guard(self) -> EvalRCEGuard:
        return EvalRCEGuard()

    @pytest.mark.parametrize(
        "snippet",
        [
            ".eval(user_input)",
            "get_evaluator().eval(payload)",
            'cfg["engine"].eval(x)',
            "(obj).exec(src)",
            "handlers[0].compile(code)",
            ".getattr(o, 'x')",  # getattr is a guard sink the old boundary also dropped
        ],
    )
    def test_lone_dot_receiver_is_refused(self, guard: EvalRCEGuard, snippet: str) -> None:
        assert guard.evaluate({"expr": snippet}).allowed is False

    def test_namespaced_sink_still_refused(self, guard: EvalRCEGuard) -> None:
        assert guard.evaluate({"expr": "sympy.eval(s)"}).allowed is False

    @pytest.mark.parametrize(
        "benign",
        [
            "xeval(y)",  # word-prefixed: not a boundary
            "parse_expression(z)",  # longer identifier, not parse_expr
            ".EVAL(q)",  # case-sensitive; EVAL is not eval
            "total = a + b * 2",
        ],
    )
    def test_benign_values_still_admitted(self, guard: EvalRCEGuard, benign: str) -> None:
        assert guard.evaluate({"expr": benign}).allowed is True

    def test_parse_expr_pinned_dict_still_exempt(self, guard: EvalRCEGuard) -> None:
        # The CVE-2026-44717 safe form (local_dict pinned) stays allowed.
        assert guard.evaluate({"expr": "parse_expr(s, local_dict={})"}).allowed is True


class TestConfigPathTilde:
    """F5: a ``~`` home reference in command/args/env must be refused, not only in
    workingDirectory; and a bare ``..``/``~`` env value must reach the inspector."""

    @pytest.fixture
    def guard(self, tmp_path: Path) -> ConfigPathGuard:
        root = Path(os.path.realpath(str(tmp_path)))
        return ConfigPathGuard(host_root=root, platform="posix")

    @staticmethod
    def _rules(guard: ConfigPathGuard, cfg: dict[str, Any]) -> list[str]:
        return [f.rule for f in guard.evaluate(cfg).findings]

    def test_tilde_command_is_refused(self, guard: ConfigPathGuard) -> None:
        assert self._rules(guard, {"command": "~/evil/launcher"}) == ["home_dir_escape"]

    def test_tilde_arg_is_refused(self, guard: ConfigPathGuard) -> None:
        rules = self._rules(guard, {"command": "python", "args": ["~/.ssh/id_rsa"]})
        assert "home_dir_escape" in rules

    def test_tilde_env_value_is_refused(self, guard: ConfigPathGuard) -> None:
        rules = self._rules(guard, {"command": "python", "env": {"KEYFILE": "~/.ssh/id_rsa"}})
        assert "home_dir_escape" in rules

    def test_bare_dotdot_env_value_reaches_inspector(self, guard: ConfigPathGuard) -> None:
        # Previously skipped by the ``"/" in value`` prefilter.
        assert self._rules(guard, {"command": "python", "env": {"X": ".."}}) == [
            "posix_dot_dot_traversal"
        ]

    def test_bare_tilde_env_value_is_refused(self, guard: ConfigPathGuard) -> None:
        assert self._rules(guard, {"command": "python", "env": {"X": "~"}}) == ["home_dir_escape"]

    def test_tilde_user_is_refused(self, guard: ConfigPathGuard) -> None:
        # ``~root`` resolves to a real home outside host_root (or is unresolvable); either way
        # the config is refused.
        rules = self._rules(guard, {"command": "python", "args": ["~root/.ssh/authorized_keys"]})
        assert rules and rules[0] in {"home_dir_escape", "unresolvable_home"}

    def test_benign_config_still_admitted(self, guard: ConfigPathGuard) -> None:
        cfg = {"command": "python", "args": ["app.py"], "env": {"DEBUG": "1", "NAME": "prod"}}
        assert guard.evaluate(cfg).verdict == "allow"


class TestSubprocessArgNestedAndEnv:
    """F7/F8: recurse into nested server configs; broaden the dangerous-env denylist."""

    @pytest.fixture
    def guard(self) -> McpSubprocessArgInjectionGuard:
        return McpSubprocessArgInjectionGuard(allowed_commands=["python"])

    @pytest.mark.parametrize(
        "cfg",
        [
            {"mcpServers": {"evil": {"command": "bash", "args": ["-c", "id"]}}},
            {"servers": {"evil": {"command": "sh", "args": ["-c", "id"]}}},
            {"transport": {"type": "stdio", "command": "ncat", "args": ["-e", "/bin/sh"]}},
            {"mcp": {"servers": [{"command": "bash", "args": ["-c", "id"]}]}},
            {"stdio": {"command": "ncat"}},
            {"config": {"command": "bash"}},
        ],
    )
    def test_nested_untrusted_command_is_refused(
        self, guard: McpSubprocessArgInjectionGuard, cfg: dict[str, Any]
    ) -> None:
        assert guard.evaluate(cfg).allowed is False

    def test_nested_allowlisted_command_is_admitted(
        self, guard: McpSubprocessArgInjectionGuard
    ) -> None:
        cfg = {"mcpServers": {"ok": {"command": "python", "args": ["s.py"]}}}
        assert guard.evaluate(cfg).allowed is True

    def test_stray_args_data_key_is_not_a_spawn(
        self, guard: McpSubprocessArgInjectionGuard
    ) -> None:
        # A nested mapping without command/cmd is not mistaken for a spawn config.
        cfg = {"tools": {"args": ["--help"]}, "meta": {"env": {"X": "1"}}}
        assert guard.evaluate(cfg).allowed is True

    def test_plain_data_config_admitted(self, guard: McpSubprocessArgInjectionGuard) -> None:
        assert guard.evaluate({"query": "select 1", "limit": 10}).allowed is True

    def test_deeply_nested_config_refused(self, guard: McpSubprocessArgInjectionGuard) -> None:
        node: dict[str, Any] = {}
        cur = node
        for _ in range(40):
            cur["n"] = {}
            cur = cur["n"]
        cur["command"] = "bash"
        decision = guard.evaluate(node)
        assert decision.allowed is False
        assert decision.verdict is McpSubprocessArgVerdict.DENY_UNINSPECTABLE

    @pytest.mark.parametrize(
        "var",
        [
            "LD_AUDIT",
            "GCONV_PATH",
            "LD_PROFILE",
            "DYLD_FALLBACK_LIBRARY_PATH",
            "DYLD_FRAMEWORK_PATH",
            "PYTHONHOME",
            "RUBYLIB",
            "PERL5OPT",
            "CLASSPATH",
            "JAVA_TOOL_OPTIONS",
            "_JAVA_OPTIONS",
            "GIT_SSH_COMMAND",
        ],
    )
    def test_dangerous_env_var_is_refused(
        self, guard: McpSubprocessArgInjectionGuard, var: str
    ) -> None:
        decision = guard.evaluate({"command": "python", "env": {var: "/tmp/x"}})
        assert decision.allowed is False
        assert decision.verdict is McpSubprocessArgVerdict.DENY_UNTRUSTED_ENV

    def test_benign_env_still_admitted(self, guard: McpSubprocessArgInjectionGuard) -> None:
        cfg = {"command": "python", "env": {"NODE_ENV": "prod", "DEBUG": "1"}}
        assert guard.evaluate(cfg).allowed is True


class TestStdioMetaEnv:
    """F6: StdioMetaGuard must inspect env for code-loading variables."""

    @pytest.fixture
    def guard(self) -> StdioMetaGuard:
        return StdioMetaGuard(stdio_config=StdioGuardConfig(allowed_binaries={"python"}))

    @pytest.mark.parametrize(
        "var",
        ["LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "NODE_OPTIONS", "PYTHONPATH", "GIT_SSH_COMMAND"],
    )
    def test_dangerous_env_blocks(self, guard: StdioMetaGuard, var: str) -> None:
        result = guard.evaluate({"command": "python", "args": ["s.py"], "env": {var: "/tmp/x"}})
        assert result.verdict == "block"
        assert any(f.finding_id == "env_code_loading_var" for f in result.findings)

    def test_env_list_form_blocks(self, guard: StdioMetaGuard) -> None:
        result = guard.evaluate(
            {"command": "python", "args": ["s.py"], "env": ["LD_PRELOAD=/tmp/x.so"]}
        )
        assert result.verdict == "block"

    def test_unreadable_env_is_refused(self, guard: StdioMetaGuard) -> None:
        result = guard.evaluate({"command": "python", "args": ["s.py"], "env": "LD_PRELOAD=/x"})
        assert result.verdict == "block"
        assert any(f.finding_id == "env_unreadable" for f in result.findings)

    def test_clean_env_allowed(self, guard: StdioMetaGuard) -> None:
        spec = {"command": "python", "args": ["s.py"], "env": {"NODE_ENV": "prod"}}
        assert guard.evaluate(spec).verdict == "allow"

    def test_variant_declared(self) -> None:
        assert "env_code_loading_var" in StdioMetaGuard.__variants__


class TestStdioGuardHardening:
    """F9/F10/F11: stdio_guard relative-binary, unicode, and -c/-m deny-pattern gaps."""

    @pytest.fixture
    def bare(self) -> StdioGuardConfig:
        return StdioGuardConfig(allowed_binaries={"python"})

    @pytest.mark.parametrize("binary", ["../python", "evil/python", "./python", "a/b/python"])
    def test_relative_binary_is_refused(self, bare: StdioGuardConfig, binary: str) -> None:
        with pytest.raises(StdioInjectionError) as exc:
            validate_stdio_command([binary, "app.py"], bare)
        assert exc.value.rule == "relative_path_binary"

    def test_bare_allowlisted_binary_admitted(self, bare: StdioGuardConfig) -> None:
        validate_stdio_command(["python", "app.py"], bare)  # no raise

    @pytest.mark.parametrize(
        "ch",
        [" ", " ", "‎", "‏", "؜", "​", "﻿", "­"],
    )
    def test_banned_unicode_in_arg_is_refused(self, bare: StdioGuardConfig, ch: str) -> None:
        with pytest.raises(StdioInjectionError) as exc:
            validate_stdio_command(["python", f"arg{ch}x"], bare)
        assert exc.value.rule == "banned_unicode"

    @pytest.mark.parametrize(
        "cmd",
        [
            ["python", "-cprint(1)"],
            ["python", "-Ic", "print(1)"],
            ["python", "-m", "http.server"],
            ["python", "-mhttp.server"],
        ],
    )
    def test_inline_and_module_exec_refused_under_ox_preset(self, cmd: list[str]) -> None:
        with pytest.raises(StdioInjectionError) as exc:
            validate_stdio_command(cmd, stdio_guard_ox_defaults())
        assert exc.value.rule == "deny_pattern"

    @pytest.mark.parametrize(
        "cmd",
        [
            ["python", "server.py"],
            ["python", "-v"],
            ["python", "server.py", "--config", "x"],  # double-dash long option
        ],
    )
    def test_benign_argv_admitted_under_ox_preset(self, cmd: list[str]) -> None:
        validate_stdio_command(cmd, stdio_guard_ox_defaults())  # no raise


class TestStdioCommandInjectionMetachars:
    """F12: single ``&`` and process substitution ``<(`` / ``>(`` must be refused; the
    longest-matching metachar is reported deterministically."""

    @pytest.fixture
    def guard(self) -> StdioCommandInjectionGuard:
        return StdioCommandInjectionGuard()

    @pytest.mark.parametrize(
        ("payload", "expected"),
        [
            ("app.py & id", "&"),
            ("app.py&id", "&"),
            ("cat <(id)", "<("),
            (">(sh)", ">("),
            ("a && b", "&&"),  # longest-first: reports && not &
        ],
    )
    def test_metachar_refused_with_label(
        self, guard: StdioCommandInjectionGuard, payload: str, expected: str
    ) -> None:
        decision = guard.evaluate({"command": "sh", "args": ["-c", payload]})
        assert decision.allowed is False
        assert decision.matched_metachar == expected

    def test_standalone_ampersand_element_refused(self, guard: StdioCommandInjectionGuard) -> None:
        assert guard.evaluate({"command": "sh", "args": ["-c", "app", "&", "id"]}).allowed is False

    @pytest.mark.parametrize("arg", ["pkg>=1.0", "a<b", "--port=8080", "server.py"])
    def test_benign_args_admitted(self, guard: StdioCommandInjectionGuard, arg: str) -> None:
        # Bare < / > are intentionally not default metachars (benign version constraints).
        assert guard.evaluate({"command": "python", "args": [arg]}).allowed is True


class TestLoopbackWrapperOptionConsumption:
    """F13: a value-taking wrapper option consumes its argument; the guard must not read
    that argument as the downstream program (CVE-2026-53820 surface-vs-effective)."""

    @pytest.fixture
    def guard(self) -> LoopbackSessionSpawnGuard:
        return LoopbackSessionSpawnGuard(allowed_commands=["python"])

    @pytest.mark.parametrize(
        "cmd",
        [
            ["env", "-u", "python", "bash"],
            ["env", "--unset", "python", "bash"],
            ["env", "-u", "python", "bash", "-c", "id"],
            ["sudo", "-u", "root", "bash"],
            ["doas", "-u", "root", "sh"],
            ["env", "--unset=python", "bash"],  # attached form also blocked
        ],
    )
    def test_wrapper_option_value_not_mistaken_for_program(
        self, guard: LoopbackSessionSpawnGuard, cmd: list[str]
    ) -> None:
        decision = guard.check_spawn(cmd)
        assert decision.allowed is False
        assert decision.effective_command in {"bash", "sh"}

    @pytest.mark.parametrize(
        "cmd",
        [
            ["env", "-u", "FOO", "python"],
            ["sudo", "-u", "root", "python"],
            ["env", "-i", "python"],
            ["env", "HOME=/x", "python"],
            ["python", "s.py"],
        ],
    )
    def test_legitimate_wrapped_program_admitted(
        self, guard: LoopbackSessionSpawnGuard, cmd: list[str]
    ) -> None:
        decision = guard.check_spawn(cmd)
        assert decision.allowed is True
        assert decision.effective_command == "python"
