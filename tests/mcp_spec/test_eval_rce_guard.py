"""Tests for the v0.8.0 EvalRCEGuard (CVE-2026-44717).

NVD 2026-05-15: "MCP Calculate Server is a mathematical calculation
service based on MCP protocol and SymPy library. Prior to 0.1.1, the
use of eval() to evaluate mathematical expressions without proper
input sanitization leads to remote code execution. This vulnerability
is fixed in 0.1.1."

This guard is complementary to v0.7.5 FilterEvalRCEGuard:

- FilterEvalRCEGuard targets ``lambda`` / ``Expression.Lambda<>`` /
  Mustache-template-eval syntax shapes inside known filter fields.
- EvalRCEGuard targets the **bare-eval class** — any string value
  containing ``eval(`` / ``exec(`` / ``compile(`` / ``__import__(`` /
  ``getattr(`` / ``sympy.parsing.sympy_parser.parse_expr(`` reaching
  any tool. Plus a denylist for known-vulnerable MCP server packages.

Primary source
--------------
https://nvd.nist.gov/vuln/detail/CVE-2026-44717
"""

from __future__ import annotations

import time

import pytest

from agent_airlock.mcp_spec.eval_rce_guard import (
    DEFAULT_EVAL_SINKS,
    DEFAULT_VULNERABLE_PACKAGES,
    EvalRCEDecision,
    EvalRCEGuard,
    EvalRCEVerdict,
)


class TestCVE_2026_44717_PrimaryAnchor:
    """The MCP Calculate Server eval() RCE payload class."""

    def test_eval_call_in_expression_arg_denied(self) -> None:
        """The CVE payload: tool arg containing ``eval(...)`` is denied."""
        guard = EvalRCEGuard()
        decision = guard.evaluate({"expression": 'eval(\'__import__("os").system("id")\')'})
        assert isinstance(decision, EvalRCEDecision)
        assert decision.allowed is False
        assert decision.verdict == EvalRCEVerdict.DENY_EVAL_SINK
        assert decision.matched_sink == "eval"

    def test_parse_expr_without_pinned_local_dict_denied(self) -> None:
        """``parse_expr(...)`` without ``local_dict=`` is the MCP Calculate Server pattern."""
        guard = EvalRCEGuard()
        decision = guard.evaluate({"expression": 'parse_expr(\'__import__("os").system("id")\')'})
        assert decision.allowed is False
        assert decision.verdict == EvalRCEVerdict.DENY_EVAL_SINK
        assert decision.matched_sink == "parse_expr"


class TestOtherEvalSinks:
    """exec/compile/__import__/getattr are caught with the same shape."""

    @pytest.mark.parametrize(
        "payload,expected_sink",
        [
            ("exec('rce')", "exec"),
            ("compile('print(1)', 'x', 'eval')", "compile"),
            ("__import__('os').system('id')", "__import__"),
            ("getattr(__builtins__, 'eval')('rce')", "getattr"),
        ],
    )
    def test_sink_caught(self, payload: str, expected_sink: str) -> None:
        guard = EvalRCEGuard()
        decision = guard.evaluate({"expression": payload})
        assert decision.allowed is False
        assert decision.verdict == EvalRCEVerdict.DENY_EVAL_SINK
        assert decision.matched_sink == expected_sink


class TestBenignAllowed:
    """Math-only / clean expressions are not denied."""

    def test_simple_arithmetic_allowed(self) -> None:
        guard = EvalRCEGuard()
        decision = guard.evaluate({"expression": "2 + 2 * 3"})
        assert decision.allowed is True
        assert decision.verdict == EvalRCEVerdict.ALLOW

    def test_string_containing_word_eval_in_user_value_allowed(self) -> None:
        """``user.name == 'Eval Industries'`` is NOT a sink — word boundary matters."""
        guard = EvalRCEGuard()
        decision = guard.evaluate({"filter": "user.name == 'Eval Industries'"})
        assert decision.allowed is True

    def test_none_args_allowed(self) -> None:
        guard = EvalRCEGuard()
        decision = guard.evaluate(None)
        assert decision.allowed is True


class TestParseExprWithPinnedLocalDictAllowed:
    """``parse_expr(s, local_dict={})`` is the safe form — must not deny."""

    def test_pinned_empty_local_dict_allowed(self) -> None:
        """The fix from CVE-2026-44717 patch (0.1.1) — local_dict pinned to ``{}``."""
        guard = EvalRCEGuard()
        decision = guard.evaluate({"expression": "parse_expr(user_input, local_dict={})"})
        assert decision.allowed is True

    def test_pinned_global_dict_allowed(self) -> None:
        """Pinning ``global_dict={}`` is also a safe form."""
        guard = EvalRCEGuard()
        decision = guard.evaluate({"expression": "parse_expr(user_input, global_dict={})"})
        assert decision.allowed is True


class TestEachParseExprCallNeedsItsOwnPin:
    """Until 0.10.34 one pinned call anywhere exempted the whole string."""

    @pytest.mark.parametrize(
        "text",
        [
            "parse_expr(user_input); parse_expr('1', local_dict={})",
            "parse_expr('1', local_dict={}); parse_expr(user_input)",
            "parse_expr(a, local_dict={})\nx = 1\nsympy.parse_expr(b)",
            # A pin in a string literal pins nothing.
            "parse_expr('x local_dict=1')",
            'parse_expr("global_dict = 1")',
            # Past the end of the call's own argument list.
            "parse_expr(x) or y(local_dict={})",
            "parse_expr(f(x), local_dict={})",
            # Too long to read as one call.
            "parse_expr(" + "a" * 2000 + ", local_dict={})",
        ],
    )
    def test_an_unpinned_call_is_refused(self, text: str) -> None:
        decision = EvalRCEGuard().evaluate({"expression": text})
        assert decision.allowed is False, text
        assert decision.matched_sink == "parse_expr"

    @pytest.mark.parametrize(
        "text",
        [
            "parse_expr(a, local_dict={}); parse_expr(b, global_dict={})",
            'parse_expr("a + b", local_dict={})',
            "parse_expr('a + b', global_dict=safe)",
            "parse_expr(\n    source,\n    local_dict={},\n)",
            "sympy.parsing.sympy_parser.parse_expr(s, local_dict={})",
            "parse_expr (s, local_dict = {})",
        ],
    )
    def test_every_call_pinned_is_allowed(self, text: str) -> None:
        assert EvalRCEGuard().evaluate({"expression": text}).allowed is True, text

    @pytest.mark.parametrize(
        "text",
        [
            pytest.param("parse_expr(" * 90_000, id="unpinned-calls"),
            pytest.param("parse_expr(" + "'a' " * 240_000, id="one-long-call"),
            pytest.param(
                ("parse_expr(" + "a" * 1000 + ", local_dict={}) ") * 1000, id="pinned-calls"
            ),
        ],
    )
    def test_a_long_argument_does_not_stall_the_guard(self, text: str) -> None:
        """1 MB of ``parse_expr(`` took about six minutes on 0.10.31."""
        started = time.perf_counter()
        EvalRCEGuard().evaluate({"expression": text})
        assert time.perf_counter() - started < 20


class TestVulnerablePackageDenylist:
    """A registered vulnerable package import path is denied at evaluation."""

    def test_vulnerable_package_import_denied(self) -> None:
        """``mcp-calculate-server < 0.1.1`` is on the curated denylist."""
        guard = EvalRCEGuard()
        decision = guard.evaluate(
            {"server_package": "mcp-calculate-server", "server_version": "0.1.0"}
        )
        assert decision.allowed is False
        assert decision.verdict == EvalRCEVerdict.DENY_VULNERABLE_PACKAGE
        assert decision.matched_package == "mcp-calculate-server"

    def test_patched_version_allowed(self) -> None:
        """The patched version (0.1.1+) is allowed."""
        guard = EvalRCEGuard()
        decision = guard.evaluate(
            {"server_package": "mcp-calculate-server", "server_version": "0.1.1"}
        )
        assert decision.allowed is True

    def test_unknown_package_allowed(self) -> None:
        guard = EvalRCEGuard()
        decision = guard.evaluate(
            {"server_package": "some-unrelated-server", "server_version": "1.0.0"}
        )
        assert decision.allowed is True


class TestCustomSinksAndPackages:
    """Operators can extend the sink set and denylist."""

    def test_custom_sink_caught(self) -> None:
        guard = EvalRCEGuard(extra_sinks=frozenset({"runpy.run_path"}))
        decision = guard.evaluate({"expression": "runpy.run_path('/tmp/x.py')"})
        assert decision.allowed is False
        assert decision.matched_sink == "runpy.run_path"

    def test_custom_vulnerable_package(self) -> None:
        guard = EvalRCEGuard(
            extra_vulnerable_packages=(
                ("my-mcp-server", "1.0.0"),
                ("my-mcp-server", "1.0.1"),
            )
        )
        decision = guard.evaluate({"server_package": "my-mcp-server", "server_version": "1.0.0"})
        assert decision.allowed is False
        assert decision.matched_package == "my-mcp-server"


class TestFactoryShape:
    """`policy_presets.stdio_guard_eval_defaults_2026_05_15` factory."""

    def test_factory_returns_expected_config_shape(self) -> None:
        from agent_airlock.policy_presets import stdio_guard_eval_defaults_2026_05_15

        config = stdio_guard_eval_defaults_2026_05_15()
        assert config["preset_id"] == "stdio_guard_eval_defaults_2026_05_15"
        assert config["severity"] == "critical"
        assert config["default_action"] == "deny"
        assert "CVE-2026-44717" in config["cves"]
        assert "nvd.nist.gov" in config["advisory_url"]
        assert isinstance(config["sinks"], frozenset)
        assert "eval" in config["sinks"]
        assert "parse_expr" in config["sinks"]

    def test_factory_overrides_propagate(self) -> None:
        from agent_airlock.policy_presets import stdio_guard_eval_defaults_2026_05_15

        config = stdio_guard_eval_defaults_2026_05_15(extra_sinks=frozenset({"runpy.run_path"}))
        assert "runpy.run_path" in config["extra_sinks"]


class TestCodeObjectScreen:
    """CVE-2026-123783's class: a string that builds or fetches a Python code object."""

    @pytest.mark.parametrize(
        "text",
        [
            # The dunder, anywhere, quoted included.
            "f.__code__",
            'vars(f)["__code__"]',
            "'__code__'",
            "f.__code__ = g",
            # Attribute access, with whatever may follow the dot.
            "c.co_code",
            "g.gi_code",
            "c.cr_code",
            "a.ag_code",
            "frame.f_code",
            "dis.Bytecode(f).codeobj",
            "g . gi_code",
            "g  .gi_code",
            "(g.\n    gi_code)",
            "g.\\\n    gi_code",
            "(g. # the attribute follows\n    gi_code)",
            # The types, called or not.
            "types.CodeType(0, 0)",
            "CT = types.CodeType",
            "from types import CodeType",
            "types.FunctionType(c, {})",
            "F = FunctionType",
            "types.LambdaType(c, {})",
            "L = LambdaType",
            # code.replace.
            "c.replace(co_code=b'')",
            "c.replace( co_consts = (42,) )",
            'c.replace(**{"co_code": b""})',
            # marshal, by name or by alias.
            'marshal.loads(b"")',
            "marshal.load(handle)",
            "marshal . loads (b'')",
            "L = marshal.loads",
            "from marshal import loads",
            "import marshal as m",
            "import os, marshal",
            "x = 1; import marshal",
            'importlib.import_module("marshal")',
            "sys.modules['marshal']",
            'pkgutil.resolve_name("marshal:loads")',
            # Compilers not spelled compile(.
            "codeop.Compile()",
            'code.compile_command("42")',
            'InspectLoader.source_to_code("42")',
            "importlib._bootstrap_external._compile_bytecode(b'')",
            "dis._get_code_object(f)",
            # Walkers that hand one over unnamed.
            "gc.get_referents(f)",
            "from gc import get_referents as r",
            "g.get_referents(f)",
            "inspect.getmembers(f)",
            "inspect . getmembers(f)",
            "getmembers_static(f)",
            "from inspect import getmembers",
            "import inspect as i",
            "inspect.iscode(v)",
            "sys.monitoring.register_callback(1, 1, print)",
            "from sys import monitoring",
            "s.monitoring.register_callback(1, 1, print)",
        ],
    )
    def test_each_spelling_is_refused(self, text: str) -> None:
        decision = EvalRCEGuard().evaluate({"code": text})
        assert decision.allowed is False, text
        assert decision.verdict == EvalRCEVerdict.DENY_EVAL_SINK
        assert decision.matched_sink == "code_object"
        assert "builds or fetches a Python code object (CVE-2026-123783 class)" in decision.detail
        assert decision.matched_package is None

    @pytest.mark.parametrize(
        "text",
        [
            # Word boundaries, as in _compile_sink_pattern.
            "decode__",
            "x__code__",
            "__code__x",
            "MyCodeTypeHelper",
            "CodeTypes are documented in the data model",
            "CodeType_x",
            "MyFunctionTypes",
            "LambdaTypeX",
            # The bare words an attribute needs a dot for.
            "the f code is 7",
            "status_code = 200",
            "print(response.status_code)",
            "self.ref_code",
            "co_code = 'ACME'",
            "f_code = 7",
            # Common names matched only with their module.
            "names = tar.getmembers()",
            "gc.collect()",
            "import gc",
            "import gc as g",
            "from gc import collect",
            "gc.get_objects()",
            "gc.get_referrers(x)",
            "import inspect",
            "bucket.get_objects()",
            "api.get_referrers()",
            "monitoring.enabled = True",
            # Other uses of the same words.
            "the fire marshal signed it",
            "we marshal the arguments first",
            "json.Marshal(v)",
            'text.replace("a", "b")',
            "text.replace(old, new)",
            "dataclasses.replace(obj, co_code=1)",
            "row._replace(co_code=1)",
            "compile_commands.json",
            "code = loader.get_code()",
            "codeops = 1",
        ],
    )
    def test_ordinary_text_passes(self, text: str) -> None:
        assert EvalRCEGuard().evaluate({"code": text}).allowed is True, text

    def test_extra_sinks_cannot_turn_it_off(self) -> None:
        guard = EvalRCEGuard(extra_sinks=frozenset({"runpy.run_path"}))
        assert guard.evaluate({"code": "CT = types.CodeType"}).matched_sink == "code_object"

    def test_a_sink_is_reported_first(self) -> None:
        """The screen runs after the sink loop, so the existing reports do not change."""
        decision = EvalRCEGuard().evaluate({"code": "exec(f.__code__)"})
        assert decision.matched_sink == "exec"

    def test_a_pinned_parse_expr_does_not_hide_a_code_object(self) -> None:
        decision = EvalRCEGuard().evaluate({"code": "parse_expr(s, local_dict={}); f.__code__"})
        assert decision.matched_sink == "code_object"

    def test_the_refusal_names_the_route(self) -> None:
        decision = EvalRCEGuard().evaluate({"code": "CT = types.CodeType"})
        assert "CodeType, FunctionType or LambdaType" in decision.detail

    def test_the_names_stay_out_of_the_sink_set(self) -> None:
        """The presets copy that set, and its call-shape regex would miss an alias."""
        assert not {"CodeType", "FunctionType", "LambdaType", "code_object"} & DEFAULT_EVAL_SINKS


class TestIdentifiersPythonFoldsToAscii:
    """PEP 3131: Python reads an identifier in NFKC, so fullwidth letters spell the same name."""

    @pytest.mark.parametrize(
        ("text", "sink"),
        [
            ("ｅｘｅｃ('x = 1')", "exec"),
            ("ｅｖａｌ('1')", "eval"),
            ("𝐞𝐯𝐚𝐥('1')", "eval"),
            ("__ｉｍｐｏｒｔ__('os')", "__import__"),
            ("ｇｅｔａｔｔｒ(f, 'x')", "getattr"),
            ("ｐａｒｓｅ＿ｅｘｐｒ(s)", "parse_expr"),
            ("f.__ｃｏｄｅ__", "code_object"),
            ("g.ｇｉ＿ｃｏｄｅ", "code_object"),
            ("types.ＣｏｄｅＴｙｐｅ", "code_object"),
            ("ｍａｒｓｈａｌ.ｌｏａｄｓ(b'')", "code_object"),
        ],
    )
    def test_the_guard_reads_them_the_way_python_does(self, text: str, sink: str) -> None:
        decision = EvalRCEGuard().evaluate({"code": text})
        assert decision.allowed is False, text
        assert decision.matched_sink == sink

    def test_a_pinned_parse_expr_in_fullwidth_stays_exempt(self) -> None:
        assert (
            EvalRCEGuard()
            .evaluate({"code": "ｐａｒｓｅ_ｅｘｐｒ(s, ｌｏｃａｌ_ｄｉｃｔ={})"})
            .allowed
            is True
        )

    def test_non_ascii_text_with_no_such_name_passes(self) -> None:
        assert EvalRCEGuard().evaluate({"code": "résumé 日本語 ｅｘａｍｐｌｅ"}).allowed is True


class TestBadConstruction:
    """Construction-time validation rejects nonsense inputs."""

    def test_non_frozenset_extra_sinks_rejected(self) -> None:
        with pytest.raises(TypeError, match="frozenset"):
            EvalRCEGuard(extra_sinks=["runpy.run_path"])  # type: ignore[arg-type]


class TestDefaultExports:
    """Module-level constants are exposed for operator introspection."""

    def test_default_eval_sinks_includes_known_class(self) -> None:
        assert "eval" in DEFAULT_EVAL_SINKS
        assert "exec" in DEFAULT_EVAL_SINKS
        assert "parse_expr" in DEFAULT_EVAL_SINKS
        assert "__import__" in DEFAULT_EVAL_SINKS

    def test_default_vulnerable_packages_includes_mcp_calculate_server(self) -> None:
        pkg_names = {p for p, _ in DEFAULT_VULNERABLE_PACKAGES}
        assert "mcp-calculate-server" in pkg_names
