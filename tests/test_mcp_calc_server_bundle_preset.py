"""Tests for the v0.8.1 ``mcp_calc_server_bundle_defaults_2026_05_15`` factory.

Honest reframing of the operator's 2026-05-17 "Suggestion 2" — the
proposal-as-written would have duplicated v0.8.0's
:class:`EvalRCEGuard` (CVE-2026-44717 anchor) and v0.7.6's
:class:`StdioCommandInjectionGuard` (shell metachar detection). To
honour the operator's "do all" decision without introducing a
redundant detector module, this preset is a **composition factory**:
it returns a config dict that names the two existing guards plus the
calc-server class tool-name patterns.

What this preset gives you that the individual factories don't
---------------------------------------------------------------

- A single ``preset_id`` namespace (``mcp_calc_server_bundle_2026_05_15``)
  for security teams cataloguing CVE-2026-44717 coverage.
- A curated tool-name pattern set (``calc``, ``calculate``,
  ``evaluate``, ``sympy_eval``, ``math_eval``) that the two
  underlying guards can be scoped to at the policy layer.
- A ``composes`` field that auditors can use to enumerate every
  guard the bundle wires together.

This factory does NOT introduce a new runtime guard. It does NOT
re-implement eval-sink detection. Operators wanting bare-eval
detection at any tool name should keep using
:class:`EvalRCEGuard` / :func:`stdio_guard_eval_defaults_2026_05_15`.

Primary source
--------------
https://nvd.nist.gov/vuln/detail/CVE-2026-44717
"""

from __future__ import annotations

import pytest


class TestBundleFactoryShape:
    """The factory returns a composition config dict."""

    def test_factory_is_importable(self) -> None:
        from agent_airlock.policy_presets import mcp_calc_server_bundle_defaults_2026_05_15

        assert callable(mcp_calc_server_bundle_defaults_2026_05_15)

    def test_factory_returns_expected_config_shape(self) -> None:
        from agent_airlock.policy_presets import mcp_calc_server_bundle_defaults_2026_05_15

        config = mcp_calc_server_bundle_defaults_2026_05_15()
        assert config["preset_id"] == "mcp_calc_server_bundle_2026_05_15"
        assert config["severity"] == "critical"
        assert config["default_action"] == "deny"
        assert "CVE-2026-44717" in config["cves"]
        assert "nvd.nist.gov" in config["advisory_url"]

    def test_factory_lists_default_tool_name_patterns(self) -> None:
        from agent_airlock.policy_presets import mcp_calc_server_bundle_defaults_2026_05_15

        config = mcp_calc_server_bundle_defaults_2026_05_15()
        patterns = config["tool_name_patterns"]
        # The calc-server class is identified by tool names that look
        # like a math-evaluation entry point.
        assert "calculate" in patterns
        assert "calc" in patterns
        assert "evaluate" in patterns
        assert "sympy_eval" in patterns
        assert "math_eval" in patterns

    def test_factory_lists_composed_presets(self) -> None:
        """The ``composes`` field enumerates the underlying guards."""
        from agent_airlock.policy_presets import mcp_calc_server_bundle_defaults_2026_05_15

        config = mcp_calc_server_bundle_defaults_2026_05_15()
        composes = config["composes"]
        # Both anchor presets are named so auditors can trace coverage.
        assert "stdio_guard_eval_defaults_2026_05_15" in composes
        assert "mcp_stdio_command_injection_preset_defaults" in composes

    def test_factory_carries_eval_sink_set(self) -> None:
        """The composed eval-sink frozenset is exposed for policy wiring."""
        from agent_airlock.mcp_spec.eval_rce_guard import DEFAULT_EVAL_SINKS
        from agent_airlock.policy_presets import mcp_calc_server_bundle_defaults_2026_05_15

        config = mcp_calc_server_bundle_defaults_2026_05_15()
        # Equality (not just superset) — the bundle re-exports the
        # v0.8.0 default sink set verbatim by default.
        assert config["eval_sinks"] == DEFAULT_EVAL_SINKS

    def test_factory_carries_vulnerable_package_tuple(self) -> None:
        """The bundle re-exports the calc-server vulnerable package tuple."""
        from agent_airlock.mcp_spec.eval_rce_guard import DEFAULT_VULNERABLE_PACKAGES
        from agent_airlock.policy_presets import mcp_calc_server_bundle_defaults_2026_05_15

        config = mcp_calc_server_bundle_defaults_2026_05_15()
        assert config["vulnerable_packages"] == DEFAULT_VULNERABLE_PACKAGES


class TestBundleFactoryOverrides:
    """Operator-supplied overrides extend (not replace) the defaults."""

    def test_extra_sinks_propagate(self) -> None:
        from agent_airlock.policy_presets import mcp_calc_server_bundle_defaults_2026_05_15

        config = mcp_calc_server_bundle_defaults_2026_05_15(
            extra_sinks=frozenset({"runpy.run_path"})
        )
        assert "runpy.run_path" in config["eval_sinks"]
        # Defaults still present.
        assert "eval" in config["eval_sinks"]
        assert "parse_expr" in config["eval_sinks"]

    def test_extra_metachars_propagate(self) -> None:
        from agent_airlock.policy_presets import mcp_calc_server_bundle_defaults_2026_05_15

        config = mcp_calc_server_bundle_defaults_2026_05_15(extra_metachars=frozenset({"\x00"}))
        assert "\x00" in config["extra_metachars"]

    def test_extra_tool_name_patterns_propagate(self) -> None:
        from agent_airlock.policy_presets import mcp_calc_server_bundle_defaults_2026_05_15

        config = mcp_calc_server_bundle_defaults_2026_05_15(
            extra_tool_name_patterns=("solve", "wolfram_eval")
        )
        assert "solve" in config["tool_name_patterns"]
        assert "wolfram_eval" in config["tool_name_patterns"]
        # Defaults still present.
        assert "calculate" in config["tool_name_patterns"]


class TestBundleFactoryConfigValidation:
    """Bad operator inputs are rejected up front."""

    def test_extra_sinks_must_be_frozenset(self) -> None:
        from agent_airlock.policy_presets import mcp_calc_server_bundle_defaults_2026_05_15

        with pytest.raises(TypeError, match="frozenset"):
            mcp_calc_server_bundle_defaults_2026_05_15(
                extra_sinks=["runpy.run_path"]  # type: ignore[arg-type]
            )

    def test_extra_metachars_must_be_frozenset(self) -> None:
        from agent_airlock.policy_presets import mcp_calc_server_bundle_defaults_2026_05_15

        with pytest.raises(TypeError, match="frozenset"):
            mcp_calc_server_bundle_defaults_2026_05_15(
                extra_metachars=["\x00"]  # type: ignore[arg-type]
            )

    def test_extra_tool_name_patterns_must_be_tuple(self) -> None:
        from agent_airlock.policy_presets import mcp_calc_server_bundle_defaults_2026_05_15

        with pytest.raises(TypeError, match="tuple"):
            mcp_calc_server_bundle_defaults_2026_05_15(
                extra_tool_name_patterns=["solve"]  # type: ignore[arg-type]
            )
