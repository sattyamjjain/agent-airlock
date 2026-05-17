"""Eval-RCE guard (v0.8.0+, CVE-2026-44717 anchor).

NVD 2026-05-15: "MCP Calculate Server is a mathematical calculation
service based on MCP protocol and SymPy library. Prior to 0.1.1, the
use of ``eval()`` to evaluate mathematical expressions without proper
input sanitization leads to remote code execution. This vulnerability
is fixed in 0.1.1."

Complement to v0.7.5 :class:`FilterEvalRCEGuard`. The two guards target
the same exploitation class (model-derived string reaches a Python
runtime evaluator) but **different syntax shapes**:

- :class:`FilterEvalRCEGuard` catches ``lambda``,
  ``Expression.Lambda<>``, and ``{{ eval(...) }}`` template tokens
  inside the known filter-field vocabulary.
- :class:`EvalRCEGuard` (this module) catches **bare-eval primitives**
  — ``eval(``, ``exec(``, ``compile(``, ``__import__(``, ``getattr(``,
  and ``sympy.parsing.sympy_parser.parse_expr(`` (without a pinned
  ``local_dict=`` / ``global_dict=`` kwarg) — anywhere in any string
  argument. Plus a versioned denylist of known-vulnerable MCP server
  packages.

Why structural (no SDK import)
------------------------------
Regex pass over string values + tuple membership for the package
denylist. No ``sympy`` / ``mcp-calculate-server`` dep loaded.

Honest scope
------------
- The guard is a **syntax-shape detector**. It catches the disclosed
  CVE class and the obvious obfuscation variants (whitespace before
  the open-paren, namespace prefix on ``parse_expr``). A determined
  attacker who controls the surrounding context can sometimes hide
  the sink behind an indirection (``locals()["eval"](...)``). That
  variant is named explicitly via ``extra_sinks``.
- ``parse_expr`` is allowed when a pinned ``local_dict=`` /
  ``global_dict=`` kwarg appears in the same string — that's the
  upstream-patched safe form per CVE-2026-44717.

Primary source
--------------
https://nvd.nist.gov/vuln/detail/CVE-2026-44717
"""

from __future__ import annotations

import enum
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import structlog

logger = structlog.get_logger("agent-airlock.mcp_spec.eval_rce_guard")


# Default sink set. Each entry is a label that maps to a compiled
# pattern below. Operators can extend via ``extra_sinks``.
DEFAULT_EVAL_SINKS: frozenset[str] = frozenset(
    {
        "eval",
        "exec",
        "compile",
        "__import__",
        "getattr",
        "parse_expr",
    }
)


# Known-vulnerable MCP server package + version pairs from public
# advisories. Tuples are ``(package_name, version)``. Operators can
# extend via ``extra_vulnerable_packages``.
DEFAULT_VULNERABLE_PACKAGES: tuple[tuple[str, str], ...] = (
    ("mcp-calculate-server", "0.1.0"),
    ("mcp-calculate-server", "0.0.9"),
    ("mcp-calculate-server", "0.0.8"),
)


# Compiled patterns. Word-boundary on the sink name so a substring
# like ``"Eval Industries"`` doesn't fire. We allow optional
# namespace prefix (``sympy.parse_expr`` → matches ``parse_expr``).
def _compile_sink_pattern(sink: str) -> re.Pattern[str]:
    """Compile a regex that matches ``[<namespace>.]<sink>(`` boundary.

    The sink is matched as a callable invocation: word-boundary, an
    optional namespace prefix joined with ``.``, the sink identifier,
    optional whitespace, and an open paren. This avoids matching
    substrings of larger identifiers (``parse_expression`` doesn't
    match ``parse_expr``) and avoids matching the sink name in
    quoted string values.
    """
    # Escape dunders for regex; ``__import__`` would otherwise be
    # interpreted literally which is fine, but ``__`` triggers no
    # special regex semantics so escape is a no-op here.
    return re.compile(
        rf"(?:^|[^\w.])(?:[\w.]+\.)?{re.escape(sink)}\s*\(",
        re.MULTILINE,
    )


# ``parse_expr`` is the special case: caller may pin ``local_dict=``
# or ``global_dict=`` in the same call to mitigate, per the
# CVE-2026-44717 patch. We detect both and exempt the call when the
# pin appears within the same parenthesised argument list.
_PARSE_EXPR_PINNED_RE = re.compile(
    r"parse_expr\s*\([^)]*\b(?:local_dict|global_dict)\s*=",
    re.MULTILINE | re.DOTALL,
)


class EvalRCEVerdict(str, enum.Enum):
    """Stable reason codes for :class:`EvalRCEDecision`."""

    ALLOW = "allow"
    DENY_EVAL_SINK = "deny_eval_sink"
    DENY_VULNERABLE_PACKAGE = "deny_vulnerable_package"


@dataclass(frozen=True)
class EvalRCEDecision:
    """Outcome of a single :meth:`EvalRCEGuard.evaluate` call.

    Mirrors the v0.6.1 :class:`AllowlistVerdict` / v0.7.x decision
    family — all expose ``allowed: bool`` for chain-friendly
    composition.

    Attributes:
        allowed: True iff no eval-sink or vulnerable-package match.
        verdict: Stable :class:`EvalRCEVerdict` value.
        detail: Free-form explanation.
        matched_sink: Sink label (``eval`` / ``parse_expr`` / etc.)
            that fired, or ``None`` if the deny was a package match.
        matched_package: Package name from the vulnerable-package
            denylist, or ``None`` if the deny was a sink match.
    """

    allowed: bool
    verdict: EvalRCEVerdict
    detail: str
    matched_sink: str | None
    matched_package: str | None


class EvalRCEGuard:
    """Fail-closed gate on bare-eval sinks and known-vulnerable packages.

    Args:
        extra_sinks: Frozenset of additional sink labels to detect on
            top of :data:`DEFAULT_EVAL_SINKS`. Each label must be a
            valid Python identifier (the regex looks for
            ``[<ns>.]<label>(`` shape).
        extra_vulnerable_packages: Additional ``(package, version)``
            pairs to deny on top of :data:`DEFAULT_VULNERABLE_PACKAGES`.

    Raises:
        TypeError: ``extra_sinks`` is not a frozenset, or
            ``extra_vulnerable_packages`` is not a tuple of tuples.
    """

    def __init__(
        self,
        *,
        extra_sinks: frozenset[str] = frozenset(),
        extra_vulnerable_packages: tuple[tuple[str, str], ...] = (),
    ) -> None:
        if not isinstance(extra_sinks, frozenset):
            raise TypeError(
                f"extra_sinks must be a frozenset[str]; got {type(extra_sinks).__name__}"
            )
        if not isinstance(extra_vulnerable_packages, tuple):
            raise TypeError("extra_vulnerable_packages must be a tuple of (name, version) tuples")
        self._sinks = DEFAULT_EVAL_SINKS | extra_sinks
        # Deterministic priority order: most-specific sinks first so a
        # payload containing both ``parse_expr(...)`` and
        # ``__import__(...)`` matches as ``parse_expr`` (the CVE-2026-44717
        # primary anchor). Within the default set the priority is fixed;
        # operator-added sinks are appended in sorted order.
        _default_priority = (
            "parse_expr",
            "eval",
            "exec",
            "compile",
            "__import__",
            "getattr",
        )
        ordered: list[str] = [s for s in _default_priority if s in self._sinks]
        ordered.extend(sorted(self._sinks - set(_default_priority)))
        self._patterns: dict[str, re.Pattern[str]] = {
            sink: _compile_sink_pattern(sink) for sink in ordered
        }
        self._vulnerable_packages: frozenset[tuple[str, str]] = frozenset(
            DEFAULT_VULNERABLE_PACKAGES + extra_vulnerable_packages
        )

    def evaluate(self, args: Mapping[str, Any] | None) -> EvalRCEDecision:
        """Decide whether the call args carry an eval-RCE shape.

        Args:
            args: Tool call argument dict. ``None`` = allow.

        Returns:
            :class:`EvalRCEDecision`. ``allowed=False`` maps to a
            refusal at the Airlock decorator boundary.
        """
        if args is None:
            return self._allow("no args to inspect")

        # 1) Known-vulnerable package check (cheap dict-lookup).
        pkg = args.get("server_package")
        ver = args.get("server_version")
        if isinstance(pkg, str) and isinstance(ver, str):
            if (pkg, ver) in self._vulnerable_packages:
                logger.warning(
                    "eval_rce_vulnerable_package",
                    package=pkg,
                    version=ver,
                )
                return EvalRCEDecision(
                    allowed=False,
                    verdict=EvalRCEVerdict.DENY_VULNERABLE_PACKAGE,
                    detail=(
                        f"server package {pkg!r} version {ver!r} is on the "
                        "known-vulnerable denylist (CVE-2026-44717 class)"
                    ),
                    matched_sink=None,
                    matched_package=pkg,
                )

        # 2) Sink-pattern scan over every string-valued field.
        for key, value in args.items():
            if not isinstance(value, str):
                continue
            decision = self._inspect_value(field=key, value=value)
            if decision is not None:
                return decision

        return self._allow("no eval-RCE pattern matched")

    def _allow(self, reason: str) -> EvalRCEDecision:
        return EvalRCEDecision(
            allowed=True,
            verdict=EvalRCEVerdict.ALLOW,
            detail=reason,
            matched_sink=None,
            matched_package=None,
        )

    def _inspect_value(self, *, field: str, value: str) -> EvalRCEDecision | None:
        """Return a deny decision if any sink fires on ``value``."""
        for sink, pattern in self._patterns.items():
            if not pattern.search(value):
                continue
            # ``parse_expr`` exemption: pinned local_dict / global_dict
            # is the CVE-2026-44717 patch shape — safe.
            if sink == "parse_expr" and _PARSE_EXPR_PINNED_RE.search(value):
                continue
            logger.warning(
                "eval_rce_sink_match",
                sink=sink,
                field=field,
                snippet=value[:64],
            )
            return EvalRCEDecision(
                allowed=False,
                verdict=EvalRCEVerdict.DENY_EVAL_SINK,
                detail=(
                    f"field {field!r} contains a bare-eval sink {sink!r} (CVE-2026-44717 class)"
                ),
                matched_sink=sink,
                matched_package=None,
            )
        return None


__all__ = [
    "DEFAULT_EVAL_SINKS",
    "DEFAULT_VULNERABLE_PACKAGES",
    "EvalRCEDecision",
    "EvalRCEGuard",
    "EvalRCEVerdict",
]
