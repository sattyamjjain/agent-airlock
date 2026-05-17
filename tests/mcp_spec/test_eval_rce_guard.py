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
