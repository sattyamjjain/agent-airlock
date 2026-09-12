"""CVE-2026-75062 — Google langfun lf.query evaluates model-generated Python unsandboxed.

Vulnerability (NVD 2026-08-26):
    "Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval
    Injection') in the default ``lf.query`` Python protocol in Google langfun
    versions prior to 0.1.2 allows remote unauthenticated attackers to execute
    arbitrary Python code in the context of the host application via crafted
    prompt inputs that cause the model to generate executable Python expressions
    evaluated without a sandbox."

Advisory: https://github.com/google/langfun/issues/725
NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-75062
CVSS:     9.2 (CRITICAL) — CWE-95, CWE-1188

Airlock fit: partial.
    This is the exploitation class ``EvalRCEGuard``'s own docstring names — "a
    model-derived string reaches a Python runtime evaluator" — and the guard
    refuses the disclosed payload shapes while admitting the arithmetic the
    protocol exists to evaluate.

    It is ``partial`` for a reason worth stating rather than burying. The defect
    is that langfun calls an evaluator on model output **at all**; the sandbox is
    missing inside langfun, not at a tool-call boundary. agent-airlock only sees
    this if the generated expression passes through an airlocked tool argument.
    Where it does, the guard refuses it. Where langfun evaluates internally,
    nothing in this library is on the path, and no arrangement of presets changes
    that — upgrade to langfun 0.1.2.

    So this fixture pins the primitive, not the patch: **if a model-generated
    expression carrying an eval sink reaches a guarded argument, it is refused.**
"""

from __future__ import annotations

import pytest

from agent_airlock.mcp_spec.eval_rce_guard import EvalRCEGuard

#: Expression shapes a prompt-injected model would emit for this CVE. Each is a
#: bare-eval primitive, which is what the guard detects.
_MALICIOUS: tuple[tuple[str, dict[str, str]], ...] = (
    ("import_os_system", {"expression": "__import__('os').system('id')"}),
    ("nested_eval", {"code": 'eval("1+1")'}),
    ("compile_exec", {"query": "compile('print(1)','<s>','exec')"}),
    ("getattr_builtins", {"expression": "getattr(__builtins__, 'exec')('x')"}),
)

#: What ``lf.query``'s Python protocol is actually for.
_BENIGN: tuple[tuple[str, dict[str, str]], ...] = (
    ("arithmetic", {"expression": "2 + 2 * 3"}),
    ("comparison", {"expression": "len('abcd') > 3"}),
)


class TestEvalSinksInModelOutputAreRefused:
    @pytest.mark.parametrize(("name", "args"), _MALICIOUS)
    def test_blocked(self, name: str, args: dict[str, str]) -> None:
        decision = EvalRCEGuard().evaluate(args)
        assert decision.verdict != "allow", f"{name} must not be admitted: {decision}"

    @pytest.mark.parametrize(("name", "args"), _BENIGN)
    def test_the_protocol_still_works(self, name: str, args: dict[str, str]) -> None:
        """Blocking every expression would not be a fix, it would be a removal."""
        assert EvalRCEGuard().evaluate(args).verdict == "allow", name


class TestScopeBoundary:
    """What this guard does not reach, asserted so the `partial` label is earned."""

    def test_an_expression_with_no_eval_primitive_is_admitted(self) -> None:
        """The guard is a syntax-shape detector, not a Python semantics analyser.

        A payload that reaches dangerous behaviour without naming ``eval``,
        ``exec``, ``compile``, ``__import__`` or ``getattr`` is not detected
        here. That is the documented limit of ``EvalRCEGuard``, restated at this
        CVE because langfun's threat is *arbitrary* model-generated Python, which
        is a strictly larger set than the sink list.
        """
        decision = EvalRCEGuard().evaluate({"expression": "[x for x in range(10**9)]"})
        assert decision.verdict == "allow", (
            "if the guard gained resource-exhaustion or broader AST analysis this now "
            "blocks — update the 'Airlock fit' note rather than deleting the assertion"
        )

    def test_the_guard_never_sees_a_purely_internal_evaluation(self) -> None:
        """No tool argument, no guard.

        langfun's own ``lf.query`` path evaluates inside the library. This is a
        statement about topology rather than about detection quality, and it is
        why the fit is partial and why the remediation is an upgrade.
        """
        assert EvalRCEGuard().evaluate(None).verdict == "allow"
        assert EvalRCEGuard().evaluate({}).verdict == "allow"
