"""Codegen string-delimiter-injection guard (v0.8.21+, CVE-2026-11393 anchor).

CVE-2026-11393 (AWS AgentCore CLI < 0.14.2, CVSS 9, CWE-94, published
2026-06-08): the CLI generates Python source by interpolating a
model-/user-controlled ``collaborationInstruction`` into a code string
**without neutralising triple-quote characters**. A crafted instruction
containing ``\"\"\"`` (or ``'''``) closes the generated string literal and
appends attacker-controlled statements; the payload executes when another
user in the same AWS account imports the agent — RCE on the AgentCore
Runtime (inheriting the agent's IAM role) and on the importer's machine.
Patched in 0.14.2.

The exploit class is **not** AgentCore-specific: any agent/tool that
splices model-controlled text into a generated code string, a template
render, or an ``exec`` / ``eval`` sink is exposed to the same
string-delimiter break-out. This guard is the reusable, CVE-agnostic
primitive.

What it detects
---------------
In any string argument that flows toward a codegen / template / exec
sink:

- **Triple-quote tokens** — ``\"\"\"`` or ``'''`` (the CVE-2026-11393
  primitive: closes a Python triple-quoted string literal).
- **Quote break-out tokens** — a string-closing quote immediately
  followed by a statement separator / continuation (``");``, ``')``,
  ``" +``, ``']`` ...) that would terminate the literal and start code.
- **Newline-into-code** — a raw newline (``\n`` / ``\r``) embedded in a
  value bound for a single-line code string, which lets the attacker
  append a statement on the next line.

Deny-by-default posture
-----------------------
Any detected token denies, **unless** the argument's field name is on an
operator-declared ``allowed_literal_fields`` allowlist — the explicit
"this field is a safe literal context" escape hatch (e.g. a value that is
JSON-escaped or rendered through a sandboxed templating layer downstream).
An empty allowlist (the default) scans every field.

Why structural (no codegen)
---------------------------
The guard never generates or executes code — it matches the break-out
*tokens* in the candidate string and refuses. It therefore carries no
execution risk itself.

Primary sources (retrieved 2026-06-09):
  https://www.thehackerwire.com/agentcore-cli-rce-via-triple-quote-neutralization-bypass-cve-2026-11393/
  https://cwe.mitre.org/data/definitions/94.html
"""

from __future__ import annotations

import enum
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

import structlog

from ..exceptions import AirlockError

logger = structlog.get_logger("agent-airlock.mcp_spec.codegen_delimiter_guard")


# Triple-quoted string-literal delimiters (the CVE-2026-11393 primitive).
_TRIPLE_QUOTE_RE = re.compile(r'"""|\'\'\'')
# A string-closing quote followed by a statement separator / continuation
# that would break out of a single- or double-quoted literal and run code:
#   ");  ')  " +  ']  "}  ',
_QUOTE_BREAKOUT_RE = re.compile(r"""["'][ \t]*[);,\]}+]""")
# Raw newline embedded in a value bound for a single-line code string.
_NEWLINE_RE = re.compile(r"[\r\n]")

# Connection/codegen arg keys are not assumed — every string value is
# scanned by default. Operators narrow via ``allowed_literal_fields``.


class CodegenDelimiterVerdict(str, enum.Enum):
    """Stable reason codes for :class:`CodegenDelimiterDecision`."""

    ALLOW = "allow"
    DENY_TRIPLE_QUOTE = "deny_triple_quote"  # \"\"\" or '''
    DENY_QUOTE_BREAKOUT = "deny_quote_breakout"  # "); ') " + ...
    DENY_NEWLINE_INTO_CODE = "deny_newline_into_code"  # raw \n / \r


@dataclass(frozen=True)
class CodegenDelimiterDecision:
    """Outcome of a single :meth:`CodegenDelimiterInjectionGuard.evaluate` call.

    Mirrors the v0.7.x / v0.8.x guard decision family — every guard
    exposes ``allowed: bool`` so integrators can chain on one
    short-circuit predicate.

    Attributes:
        allowed: True iff no break-out delimiter token was found.
        verdict: A stable :class:`CodegenDelimiterVerdict` value.
        detail: Free-form human-readable explanation.
        matched_field: The argument name (e.g. ``"instruction"`` or
            ``"context.body"``) that tripped the guard, or ``None`` when
            allowed.
        matched_token: The literal offending token (e.g. ``'\"\"\"'``),
            or ``None`` when allowed.
        fix_hints: LLM-actionable remediation hints. Carries the advisory
            / CVE reference when the guard was constructed with one.
    """

    allowed: bool
    verdict: CodegenDelimiterVerdict
    detail: str
    matched_field: str | None = None
    matched_token: str | None = None
    fix_hints: list[str] = field(default_factory=list)


class CodegenDelimiterInjectionError(AirlockError):
    """Raised on a denied codegen-bound argument (fail-closed).

    Carries the :class:`CodegenDelimiterDecision` and exposes
    ``fix_hints`` so an upstream airlock layer can route the refusal into
    self-healing retry semantics.

    Attributes:
        decision: The decision that triggered the refusal.
        fix_hints: LLM-actionable remediation hints.
    """

    def __init__(self, decision: CodegenDelimiterDecision) -> None:
        self.decision = decision
        self.fix_hints = decision.fix_hints
        super().__init__(decision.detail)


class CodegenDelimiterInjectionGuard:
    """Deny-by-default gate on string-delimiter break-out tokens in codegen args.

    Refuses any argument value (flowing toward a code-generation /
    template-render / ``exec`` / ``eval`` sink) that contains a
    triple-quote, a quote break-out token, or a raw newline — unless the
    argument's field name is on an operator-declared allowlist of safe
    literal contexts. Blocks the CVE-2026-11393 class, where a
    model-controlled string is spliced into generated source without
    delimiter neutralisation and executes.

    Args:
        allowed_literal_fields: Field names whose values are an
            explicitly-declared safe literal context and are therefore
            NOT scanned (e.g. a value JSON-escaped or rendered through a
            sandboxed templating layer downstream). Empty (default)
            scans every field.
        check_newline: When True (default), a raw newline in a scanned
            value is a break-out token (``DENY_NEWLINE_INTO_CODE``). Set
            False for sinks where multi-line literals are safely escaped
            downstream but quote break-out must still be blocked.
        advisory: Optional advisory / CVE id (e.g. ``"CVE-2026-11393"``)
            surfaced in every deny ``fix_hints``.
        advisory_url: Optional primary-source URL surfaced alongside.

    Raises:
        TypeError: ``allowed_literal_fields`` is a bare ``str`` (a footgun
            that would be iterated character-by-character).
    """

    def __init__(
        self,
        *,
        allowed_literal_fields: Iterable[str] | None = None,
        check_newline: bool = True,
        advisory: str | None = None,
        advisory_url: str | None = None,
    ) -> None:
        if isinstance(allowed_literal_fields, str):
            raise TypeError(
                "allowed_literal_fields must be an iterable of str, not a bare str: "
                f"{allowed_literal_fields!r}"
            )
        self._allowed_fields: frozenset[str] = frozenset(allowed_literal_fields or ())
        self._check_newline = check_newline
        self._advisory = advisory
        self._advisory_url = advisory_url

    def evaluate(self, args: Mapping[str, Any] | str | None) -> CodegenDelimiterDecision:
        """Decide whether a codegen-bound argument carries a break-out token.

        Args:
            args: A single candidate string, or a mapping of argument
                name → value (values may nest dicts / lists). ``None`` =
                nothing to inspect = allow.

        Returns:
            :class:`CodegenDelimiterDecision`. ``allowed=False`` maps to a
            refusal at the codegen / tool boundary.
        """
        if args is None:
            return self._allow()
        if isinstance(args, str):
            return self._scan_field("arg", args)
        for key, value in args.items():
            if key in self._allowed_fields:
                continue
            decision = self._scan_value(str(key), value)
            if not decision.allowed:
                return decision
        return self._allow()

    # -- internal helpers --------------------------------------------------

    def _scan_value(self, field_name: str, value: Any) -> CodegenDelimiterDecision:
        """Recursively scan a value (str / list / dict) for break-out tokens."""
        if isinstance(value, str):
            return self._scan_field(field_name, value)
        if isinstance(value, Mapping):
            for sub_key, sub_val in value.items():
                if sub_key in self._allowed_fields:
                    continue
                decision = self._scan_value(f"{field_name}.{sub_key}", sub_val)
                if not decision.allowed:
                    return decision
            return self._allow()
        if isinstance(value, (list, tuple)):
            for idx, item in enumerate(value):
                decision = self._scan_value(f"{field_name}[{idx}]", item)
                if not decision.allowed:
                    return decision
            return self._allow()
        return self._allow()

    def _scan_field(self, field_name: str, text: str) -> CodegenDelimiterDecision:
        """Scan a single string for the three break-out forms (most-severe first)."""
        triple = _TRIPLE_QUOTE_RE.search(text)
        if triple is not None:
            return self._deny(
                CodegenDelimiterVerdict.DENY_TRIPLE_QUOTE,
                field_name,
                triple.group(0),
                f"argument {field_name!r} contains a triple-quote delimiter "
                f"{triple.group(0)!r} that would close a generated string literal "
                f"and inject code",
            )
        breakout = _QUOTE_BREAKOUT_RE.search(text)
        if breakout is not None:
            return self._deny(
                CodegenDelimiterVerdict.DENY_QUOTE_BREAKOUT,
                field_name,
                breakout.group(0),
                f"argument {field_name!r} contains a quote break-out token "
                f"{breakout.group(0)!r} (closing quote + statement separator)",
            )
        if self._check_newline and _NEWLINE_RE.search(text):
            return self._deny(
                CodegenDelimiterVerdict.DENY_NEWLINE_INTO_CODE,
                field_name,
                "\\n",
                f"argument {field_name!r} contains a raw newline that could append "
                f"a statement after a generated single-line code string",
            )
        return self._allow()

    def _allow(self) -> CodegenDelimiterDecision:
        return CodegenDelimiterDecision(
            allowed=True,
            verdict=CodegenDelimiterVerdict.ALLOW,
            detail="no codegen delimiter break-out token found",
        )

    def _deny(
        self,
        verdict: CodegenDelimiterVerdict,
        field_name: str,
        token: str,
        detail: str,
    ) -> CodegenDelimiterDecision:
        logger.warning(
            "codegen_delimiter_blocked",
            verdict=verdict.value,
            field=field_name,
            token=token,
            advisory=self._advisory,
        )
        prefix = f"({self._advisory}) " if self._advisory else ""
        hints: list[str] = [
            f"{prefix}Argument {field_name!r} contains the string-delimiter break-out "
            f"token {token!r}, which could close a generated code string and execute "
            f"injected statements.",
            "Do not splice model-controlled text into generated source / templates / "
            "exec sinks. Pass values through a parameterised API, or escape + render "
            "them in a sandboxed layer, instead of string interpolation.",
        ]
        if self._allowed_fields:
            hints.append(
                "Fields declared as safe literal contexts (not scanned): "
                + ", ".join(sorted(self._allowed_fields))
            )
        if self._advisory_url:
            hints.append(f"See: {self._advisory_url}")
        return CodegenDelimiterDecision(
            allowed=False,
            verdict=verdict,
            detail=detail,
            matched_field=field_name,
            matched_token=token,
            fix_hints=hints,
        )


__all__ = [
    "CodegenDelimiterDecision",
    "CodegenDelimiterInjectionError",
    "CodegenDelimiterInjectionGuard",
    "CodegenDelimiterVerdict",
]
