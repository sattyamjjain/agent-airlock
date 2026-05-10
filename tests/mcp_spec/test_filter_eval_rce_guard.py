"""Tests for the v0.7.5 Filter-Eval RCE guard (CVE-2026-25592 + CVE-2026-26030).

Microsoft's 2026-05-07 MSRC blog post "When prompts become shells: RCE
vulnerabilities in AI agent frameworks" disclosed two CVEs in the
Semantic Kernel filter-evaluation pipeline:

- CVE-2026-25592 — lambda-filter eval RCE: a model-derived filter
  expression containing a Python ``lambda`` reaches a runtime
  ``compile()`` / ``eval()`` sink.
- CVE-2026-26030 — template-expression eval RCE: a model-derived
  template fragment containing a C# ``Expression.Lambda<>`` /
  template-eval token reaches a runtime expression evaluator.

The exploit class is **not Semantic-Kernel-specific** — any agent
framework that compiles user-controlled filter expressions is
vulnerable. The guard is a generic detector that fires on the
filter-eval signature regardless of the surrounding framework.

Primary source
--------------
https://www.microsoft.com/en-us/security/blog/2026/05/07/prompts-become-shells-rce-vulnerabilities-ai-agent-frameworks/
"""

from __future__ import annotations

import pytest

from agent_airlock.mcp_spec.filter_eval_rce_guard import (
    FilterEvalRCEDecision,
    FilterEvalRCEGuard,
    FilterEvalRCEVerdict,
)


class TestCVE_2026_25592_PythonLambdaFilter:
    """CVE-2026-25592 — lambda-filter eval RCE in Python-shape SDKs."""

    def test_python_lambda_in_filter_field_denied(self) -> None:
        """The original CVE payload — ``filter`` field with a Python lambda."""
        guard = FilterEvalRCEGuard()
        decision = guard.evaluate(
            {
                "tool": "search_users",
                "filter": "lambda x: __import__('os').system('id')",
            }
        )
        assert isinstance(decision, FilterEvalRCEDecision)
        assert decision.allowed is False
        assert decision.verdict == FilterEvalRCEVerdict.DENY_PYTHON_LAMBDA
        assert decision.matched_field == "filter"
        assert decision.matched_pattern is not None

    def test_lambda_in_condition_field_denied(self) -> None:
        """``condition`` is also a known filter-eval entrypoint."""
        guard = FilterEvalRCEGuard()
        decision = guard.evaluate({"condition": "lambda u: u.role == 'admin' or exec('rce')"})
        assert decision.allowed is False
        assert decision.verdict == FilterEvalRCEVerdict.DENY_PYTHON_LAMBDA
        assert decision.matched_field == "condition"


class TestCVE_2026_26030_TemplateExpression:
    """CVE-2026-26030 — template-expression eval RCE in C#-shape SDKs."""

    def test_csharp_expression_lambda_in_template_denied(self) -> None:
        """The original CVE payload — ``template`` field with C# Expression.Lambda."""
        guard = FilterEvalRCEGuard()
        decision = guard.evaluate(
            {
                "tool": "build_query",
                "template": "Expression.Lambda<Func<User, bool>>(...)",
            }
        )
        assert decision.allowed is False
        assert decision.verdict == FilterEvalRCEVerdict.DENY_CSHARP_EXPRESSION
        assert decision.matched_field == "template"

    def test_template_eval_token_denied(self) -> None:
        """Mustache-style template-eval injection (`{{ eval(...) }}`)."""
        guard = FilterEvalRCEGuard()
        decision = guard.evaluate({"expression": '{{ eval(\'__import__("os").system("id")\') }}'})
        assert decision.allowed is False
        assert decision.verdict == FilterEvalRCEVerdict.DENY_TEMPLATE_EVAL


class TestBenignFilterAllowed:
    """Benign filter expressions must NOT be denied — no false-positives."""

    def test_benign_equality_filter_allowed(self) -> None:
        guard = FilterEvalRCEGuard()
        decision = guard.evaluate({"filter": "status == 'active' AND created_at >= '2026-01-01'"})
        assert decision.allowed is True
        assert decision.verdict == FilterEvalRCEVerdict.ALLOW
        assert decision.matched_field is None

    def test_benign_field_with_word_lambda_in_string_value_allowed(self) -> None:
        """A user record name that happens to contain the word 'lambda' is allowed.

        The guard fires on the **lambda-expression syntax** (``lambda x:``),
        not on the substring ``lambda``. A ``user.name == "Lambda Inc"``
        equality filter must not trigger a DENY.
        """
        guard = FilterEvalRCEGuard()
        decision = guard.evaluate({"filter": "user.name == 'Lambda Inc'"})
        assert decision.allowed is True
        assert decision.verdict == FilterEvalRCEVerdict.ALLOW

    def test_no_filter_fields_allowed(self) -> None:
        guard = FilterEvalRCEGuard()
        decision = guard.evaluate({"tool": "delete_user", "user_id": "abc-42"})
        assert decision.allowed is True
        assert decision.verdict == FilterEvalRCEVerdict.ALLOW

    def test_none_args_allowed(self) -> None:
        """``None`` args = no payload to inspect = allow."""
        guard = FilterEvalRCEGuard()
        decision = guard.evaluate(None)
        assert decision.allowed is True


class TestMultilineLambdaInjectionVariant:
    """Multi-line lambda injection — the exploit hides the lambda across newlines."""

    def test_multiline_python_lambda_denied(self) -> None:
        """Newlines + indentation should not bypass detection."""
        payload = "lambda x:\n    __import__('subprocess').check_output(['id'])"
        guard = FilterEvalRCEGuard()
        decision = guard.evaluate({"filter": payload})
        assert decision.allowed is False
        assert decision.verdict == FilterEvalRCEVerdict.DENY_PYTHON_LAMBDA

    def test_multiline_with_leading_whitespace_denied(self) -> None:
        """Leading whitespace before ``lambda`` should not bypass detection."""
        payload = "   \t lambda u, v: exec('rce')"
        guard = FilterEvalRCEGuard()
        decision = guard.evaluate({"filter": payload})
        assert decision.allowed is False
        assert decision.verdict == FilterEvalRCEVerdict.DENY_PYTHON_LAMBDA


class TestScanAllFieldsMode:
    """Operator-defensive ``scan_all_fields=True`` checks every value."""

    def test_lambda_in_unknown_field_caught_when_scan_all(self) -> None:
        """A lambda in a non-default field name is caught when scan_all_fields=True."""
        guard = FilterEvalRCEGuard(scan_all_fields=True)
        decision = guard.evaluate({"some_random_field": "lambda x: exec('rce')"})
        assert decision.allowed is False
        assert decision.verdict == FilterEvalRCEVerdict.DENY_PYTHON_LAMBDA
        assert decision.matched_field == "some_random_field"

    def test_lambda_in_unknown_field_passes_default_mode(self) -> None:
        """Default mode only scans the suspect_fields set."""
        guard = FilterEvalRCEGuard()  # scan_all_fields=False
        decision = guard.evaluate({"some_random_field": "lambda x: exec('rce')"})
        assert decision.allowed is True


class TestCustomSuspectFields:
    """Operators on a non-default vocabulary can override suspect_fields."""

    def test_custom_suspect_field_set(self) -> None:
        guard = FilterEvalRCEGuard(suspect_fields=frozenset({"my_filter"}))
        decision = guard.evaluate({"my_filter": "lambda x: exec('rce')"})
        assert decision.allowed is False
        assert decision.matched_field == "my_filter"

    def test_default_field_no_longer_consulted_when_overridden(self) -> None:
        """Overriding suspect_fields means the default vocabulary is replaced."""
        guard = FilterEvalRCEGuard(suspect_fields=frozenset({"my_filter"}))
        decision = guard.evaluate({"filter": "lambda x: exec('rce')"})
        assert decision.allowed is True


class TestBadConstruction:
    """Construction-time validation rejects nonsense inputs."""

    def test_non_frozenset_suspect_fields_rejected(self) -> None:
        with pytest.raises(TypeError, match="frozenset"):
            FilterEvalRCEGuard(suspect_fields=["filter"])  # type: ignore[arg-type]

    def test_non_string_member_rejected(self) -> None:
        with pytest.raises(TypeError, match="str"):
            FilterEvalRCEGuard(suspect_fields=frozenset({42}))  # type: ignore[arg-type]


class TestFactoryShape:
    """`policy_presets.semantic_kernel_filter_eval_rce_2026_25592_26030_defaults` factory."""

    def test_factory_returns_expected_config_shape(self) -> None:
        from agent_airlock.policy_presets import (
            semantic_kernel_filter_eval_rce_2026_25592_26030_defaults,
        )

        config = semantic_kernel_filter_eval_rce_2026_25592_26030_defaults()
        assert config["preset_id"] == "semantic_kernel_filter_eval_rce_2026_25592_26030"
        assert config["severity"] == "critical"
        assert config["default_action"] == "deny"
        assert "microsoft.com" in config["advisory_url"]
        assert config["scan_all_fields"] is False
        assert isinstance(config["suspect_fields"], frozenset)
        # Spec-required defaults
        assert "filter" in config["suspect_fields"]
        assert "condition" in config["suspect_fields"]
        assert "template" in config["suspect_fields"]

    def test_factory_scan_all_fields_overridable(self) -> None:
        from agent_airlock.policy_presets import (
            semantic_kernel_filter_eval_rce_2026_25592_26030_defaults,
        )

        config = semantic_kernel_filter_eval_rce_2026_25592_26030_defaults(scan_all_fields=True)
        assert config["scan_all_fields"] is True

    def test_factory_suspect_fields_overridable(self) -> None:
        from agent_airlock.policy_presets import (
            semantic_kernel_filter_eval_rce_2026_25592_26030_defaults,
        )

        custom = frozenset({"my_filter", "my_template"})
        config = semantic_kernel_filter_eval_rce_2026_25592_26030_defaults(suspect_fields=custom)
        assert config["suspect_fields"] == custom
