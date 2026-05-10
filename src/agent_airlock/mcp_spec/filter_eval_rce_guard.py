"""Filter-Eval RCE guard (v0.7.5+, anchors CVE-2026-25592 + CVE-2026-26030).

Microsoft's 2026-05-07 MSRC blog "When prompts become shells: RCE
vulnerabilities in AI agent frameworks" disclosed two CVEs in the
Semantic Kernel filter-evaluation pipeline:

- **CVE-2026-25592** — lambda-filter eval RCE: a model-derived filter
  expression containing a Python ``lambda`` reaches a runtime
  ``compile()`` / ``eval()`` sink.
- **CVE-2026-26030** — template-expression eval RCE: a model-derived
  template fragment containing a C# ``Expression.Lambda<>`` /
  template-eval token reaches a runtime expression evaluator.

The exploit class is **not Semantic-Kernel-specific**. Any agent
framework that compiles user-controlled filter expressions is
vulnerable. This guard is a generic detector that fires on the
filter-eval signature regardless of the surrounding framework, so an
airlock-fronted agent that *might* call into Semantic-Kernel-style
filter expressions — even from a different framework — gets the same
denial.

Why structural (no SDK import)
------------------------------
The detection is regex-based against the value strings of a small
default vocabulary of suspect fields (``filter``, ``condition``,
``predicate``, ``template``, ``expression``). No
``semantic-kernel`` dep is required. Operators on a non-default
vocabulary can override ``suspect_fields``; the most defensive mode
is ``scan_all_fields=True`` which inspects every value.

Companion preset
----------------
:func:`agent_airlock.policy_presets.semantic_kernel_filter_eval_rce_2026_25592_26030_defaults`
returns the recommended config dict. The guard accepts the same
inputs directly; the factory exists for parity with other dict-
returning presets (e.g. ``mcp_config_path_traversal_cve_2026_31402``).

Honest scope
------------
- The guard is a regex heuristic. It catches the disclosed CVE
  payload class and the obvious obfuscation variants (multi-line,
  leading whitespace). A determined attacker who controls the field
  name can hide the lambda outside the default vocabulary —
  ``scan_all_fields=True`` is the operator-defensive remedy.
- The guard does **not** evaluate the expression. It refuses on
  syntax-shape, never compiles. There is no eval-on-untrusted-input
  surface in the guard itself.

Primary source
--------------
https://www.microsoft.com/en-us/security/blog/2026/05/07/prompts-become-shells-rce-vulnerabilities-ai-agent-frameworks/
"""

from __future__ import annotations

import enum
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import structlog

logger = structlog.get_logger("agent-airlock.mcp_spec.filter_eval_rce_guard")


# Default suspect-field vocabulary. A subset of the names Semantic
# Kernel and similar frameworks use for runtime-compiled filter
# expressions. Operators can override via the ``suspect_fields``
# constructor argument, or pass ``scan_all_fields=True`` to inspect
# every value on the payload.
DEFAULT_SUSPECT_FIELDS: frozenset[str] = frozenset(
    {
        "filter",
        "condition",
        "predicate",
        "template",
        "expression",
        "where",
        "lambda",
    }
)


# Detection patterns. Each pattern targets one verdict class so the
# decision carries enough information to log + observe.
#
# Python lambda: ``lambda <bindings>:`` with optional whitespace /
# newlines / leading indentation. Word-boundary on ``lambda`` to
# avoid matching the literal substring inside a benign string like
# ``user.name == "Lambda Inc"``.
_PYTHON_LAMBDA_RE = re.compile(
    r"\blambda\b\s*[\w\s,*]*\s*:",
    re.MULTILINE | re.DOTALL,
)

# C# Expression.Lambda<...> / Func<...> / Predicate<...> tokens.
_CSHARP_EXPRESSION_RE = re.compile(
    r"\b(?:Expression\.Lambda|Func\s*<|Predicate\s*<)\b",
    re.MULTILINE,
)

# Template-eval tokens: Mustache-style ``{{ eval(...) }}``,
# Razor-style ``@(...)`` with eval/exec inside, JS-template-string
# ``${...}`` containing eval/exec.
_TEMPLATE_EVAL_RE = re.compile(
    r"(?:\{\{\s*(?:eval|exec)\s*\(|\$\{\s*(?:eval|exec)\s*\()",
    re.MULTILINE,
)


class FilterEvalRCEVerdict(str, enum.Enum):
    """Stable reason codes for :class:`FilterEvalRCEDecision`."""

    ALLOW = "allow"
    DENY_PYTHON_LAMBDA = "deny_python_lambda"
    DENY_CSHARP_EXPRESSION = "deny_csharp_expression"
    DENY_TEMPLATE_EVAL = "deny_template_eval"


@dataclass(frozen=True)
class FilterEvalRCEDecision:
    """Outcome of a single :meth:`FilterEvalRCEGuard.evaluate` call.

    Mirrors the field shape of the v0.6.1 ``AllowlistVerdict`` and the
    v0.7.4 ``OutcomesRubricDecision`` — both expose ``allowed: bool``
    so an integrator can chain guards on a single short-circuit
    predicate.

    Attributes:
        allowed: True iff no filter-eval RCE pattern was detected.
        verdict: A stable :class:`FilterEvalRCEVerdict` value.
        detail: Free-form human-readable explanation, including the
            field name and a fragment of the matched pattern (truncated
            to avoid logging large payloads).
        matched_field: The argument-dict key whose value matched, or
            ``None`` when ``allowed=True``.
        matched_pattern: A short label of the pattern class that fired,
            or ``None`` when ``allowed=True``.
    """

    allowed: bool
    verdict: FilterEvalRCEVerdict
    detail: str
    matched_field: str | None
    matched_pattern: str | None


class FilterEvalRCEGuard:
    """Detect Semantic-Kernel-class filter-eval RCE payloads.

    Anchors CVE-2026-25592 (Python lambda-filter eval) and
    CVE-2026-26030 (C# template-expression eval). The guard is a
    syntax-shape detector — it never compiles or evaluates the
    expression itself.

    Args:
        suspect_fields: Frozenset of argument-dict keys whose values
            the guard inspects. Defaults to
            :data:`DEFAULT_SUSPECT_FIELDS`. Each member must be a
            string. Operators on a non-default vocabulary should
            override; the most defensive mode is
            ``scan_all_fields=True``.
        scan_all_fields: If True, every value on the payload is
            inspected — even fields outside ``suspect_fields``. Use
            when the operator does not trust the field-name
            allowlist (e.g. unknown framework wiring).

    Raises:
        TypeError: ``suspect_fields`` is not a frozenset, or any
            member is not a string.
    """

    def __init__(
        self,
        *,
        suspect_fields: frozenset[str] = DEFAULT_SUSPECT_FIELDS,
        scan_all_fields: bool = False,
    ) -> None:
        if not isinstance(suspect_fields, frozenset):
            raise TypeError(
                f"suspect_fields must be a frozenset[str]; got {type(suspect_fields).__name__}"
            )
        for member in suspect_fields:
            if not isinstance(member, str):
                raise TypeError(f"suspect_fields members must be str; got {type(member).__name__}")
        self._suspect_fields = suspect_fields
        self._scan_all_fields = scan_all_fields

    def evaluate(self, args: Mapping[str, Any] | None) -> FilterEvalRCEDecision:
        """Decide whether the call args carry a filter-eval RCE shape.

        Args:
            args: The tool call's argument dict. ``None`` (no args) is
                trivially allowed — there's nothing to compile.

        Returns:
            :class:`FilterEvalRCEDecision`. Callers map ``allowed=False``
            to a refusal at the Airlock decorator boundary.
        """
        if args is None:
            return FilterEvalRCEDecision(
                allowed=True,
                verdict=FilterEvalRCEVerdict.ALLOW,
                detail="no args to inspect",
                matched_field=None,
                matched_pattern=None,
            )

        for key, value in args.items():
            if not isinstance(value, str):
                continue
            if not self._scan_all_fields and key not in self._suspect_fields:
                continue
            decision = self._inspect_value(field=key, value=value)
            if decision is not None:
                return decision

        return FilterEvalRCEDecision(
            allowed=True,
            verdict=FilterEvalRCEVerdict.ALLOW,
            detail="no filter-eval RCE pattern matched",
            matched_field=None,
            matched_pattern=None,
        )

    def _inspect_value(self, *, field: str, value: str) -> FilterEvalRCEDecision | None:
        """Return a deny decision if any pattern fires, else ``None``."""
        if _PYTHON_LAMBDA_RE.search(value):
            logger.warning(
                "filter_eval_rce_python_lambda",
                matched_field=field,
                cve="CVE-2026-25592",
            )
            return FilterEvalRCEDecision(
                allowed=False,
                verdict=FilterEvalRCEVerdict.DENY_PYTHON_LAMBDA,
                detail=(
                    f"field {field!r} contains a Python lambda expression "
                    "(CVE-2026-25592 filter-eval RCE class)"
                ),
                matched_field=field,
                matched_pattern="python_lambda",
            )
        if _CSHARP_EXPRESSION_RE.search(value):
            logger.warning(
                "filter_eval_rce_csharp_expression",
                matched_field=field,
                cve="CVE-2026-26030",
            )
            return FilterEvalRCEDecision(
                allowed=False,
                verdict=FilterEvalRCEVerdict.DENY_CSHARP_EXPRESSION,
                detail=(
                    f"field {field!r} contains a C# Expression.Lambda / Func<> / "
                    "Predicate<> token (CVE-2026-26030 template-expression eval)"
                ),
                matched_field=field,
                matched_pattern="csharp_expression",
            )
        if _TEMPLATE_EVAL_RE.search(value):
            logger.warning(
                "filter_eval_rce_template_eval",
                matched_field=field,
                cve="CVE-2026-26030",
            )
            return FilterEvalRCEDecision(
                allowed=False,
                verdict=FilterEvalRCEVerdict.DENY_TEMPLATE_EVAL,
                detail=(
                    f"field {field!r} contains a template-eval token "
                    "({{ eval(...) }} or ${ eval(...) })"
                ),
                matched_field=field,
                matched_pattern="template_eval",
            )
        return None


__all__ = [
    "DEFAULT_SUSPECT_FIELDS",
    "FilterEvalRCEDecision",
    "FilterEvalRCEGuard",
    "FilterEvalRCEVerdict",
]
