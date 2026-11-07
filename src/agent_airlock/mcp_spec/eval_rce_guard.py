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

Since 0.10.34 it also refuses a string that builds or fetches a Python code object
(CVE-2026-123783 class). A payload that calls none of the sinks above can take a function's
code object, swap its bytecode with ``.replace(co_code=...)`` or build one with
``types.CodeType(...)``, and call the result.

Why structural (no SDK import)
------------------------------
Regex pass over string values + tuple membership for the package
denylist. No ``sympy`` / ``mcp-calculate-server`` dep loaded.

Honest scope
------------
- The guard is a **syntax-shape detector**: it reads a string and never runs it. It catches
  the disclosed CVE classes and the obvious obfuscation variants: whitespace before the
  open-paren, a namespace prefix on ``parse_expr``, an alias at the line that takes it, a line
  break or comment after a dot, and identifiers in characters Python folds to ASCII when it
  parses them (NFKC, PEP 3131).
- **Code objects are covered where a name can be read.** ``__code__`` anywhere; attribute
  access to ``co_code``, ``gi_code``, ``cr_code``, ``ag_code``, ``f_code`` and ``codeobj``;
  ``CodeType``, ``FunctionType`` and ``LambdaType`` as whole words, called or not;
  ``.replace(co_...=)``; ``marshal``'s loaders; the compilers that are not spelled
  ``compile(`` (``codeop``, ``compile_command``, ``source_to_code``); and the walkers that
  hand one over unnamed (``gc.get_referents``, ``inspect.getmembers``, ``iscode``,
  ``sys.monitoring``). The screen is on by default and ``extra_sinks``, which only
  adds, cannot turn it off.
- **What still passes.** A string that assembles a name at runtime through something other
  than ``getattr(``: ``f.__getattribute__("__co" + "de__")``, or a sink behind an indirection
  such as ``locals()["eval"](...)``. A module that runs source text without naming a sink
  (``timeit``, ``runpy``, ``pdb``, ``code.InteractiveInterpreter``), and ``loader.get_code``,
  too generic a name to refuse. ``ctypes``, which reaches the C API. ``extra_sinks`` can name
  an indirection or a runner you know of, but no list of names closes this. **Isolation is the
  defence for all of it**: run the code in a ``sandbox.py`` backend, and treat this guard as
  the check at the argument, not as a sandbox.
- ``parse_expr`` is allowed when a pinned ``local_dict=`` /
  ``global_dict=`` kwarg appears in the same call — that's the
  upstream-patched safe form per CVE-2026-44717. Every call in the
  string needs its own.

Primary source
--------------
https://nvd.nist.gov/vuln/detail/CVE-2026-44717
https://nvd.nist.gov/vuln/detail/CVE-2026-123783
"""

from __future__ import annotations

import enum
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._log import structlog

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


# What may sit between a dot and the attribute it selects: whitespace, a line continuation, or
# a comment inside brackets. Bounded, like every gap below, so a long argument cannot make a
# pattern quadratic.
_AFTER_DOT = r"\.(?:\s|\\\n|#[^\n]{0,200}\n)*"

# The rest of one import statement.
_IN_IMPORT = r"[^\n;#]{0,200}"


#: Every spelling that builds or fetches a Python code object (CVE-2026-123783 class), each with
#: the words a refusal names it by. Not in :data:`DEFAULT_EVAL_SINKS`: that set's call-shape
#: regex would miss an alias or an attribute. Whole words only, so ``decode__`` and
#: ``MyCodeTypeHelper`` pass. A module-level name that is common elsewhere is matched only with
#: its module: ``tar.getmembers()`` is ordinary code. ``gc`` has one route, ``get_referents``: code
#: objects are not tracked by the collector, so ``gc.get_objects()`` holds none.
_CODE_OBJECT_ROUTES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("__code__", re.compile(r"\b__code__\b")),
    (
        "an attribute holding a code object",
        re.compile(rf"{_AFTER_DOT}(?:co_code|gi_code|cr_code|ag_code|f_code|codeobj)\b"),
    ),
    (
        "CodeType, FunctionType or LambdaType",
        re.compile(r"\b(?:CodeType|FunctionType|LambdaType)\b"),
    ),
    (
        "a code object's replace()",
        re.compile(r"\breplace\s*\(\s*(?:\*\*\s*\{\s*['\"])?co_[a-z]+\b"),
    ),
    (
        "marshal",
        re.compile(
            r"\bmarshal\s*[.:]\s*loads?\b"
            r"|\bfrom\s+marshal\s+import\b"
            rf"|\bimport\b{_IN_IMPORT}\bmarshal\b"
            r"|['\"]marshal['\"]"
        ),
    ),
    (
        "a compiler not spelled compile(",
        re.compile(
            r"\b(?:codeop|compile_command|source_to_code|_compile_bytecode|_get_code_object)\b"
        ),
    ),
    (
        "a walker that hands over a code object unnamed",
        re.compile(
            r"\bget_referents\b"
            r"|\binspect\s*\.\s*getmembers\b"
            rf"|\bfrom\s+inspect\s+import\b{_IN_IMPORT}\bgetmembers\b"
            r"|\bimport\s+inspect\s+as\b"
            r"|\bgetmembers_static\b"
            r"|\biscode\b"
            r"|\bsys\s*\.\s*monitoring\b"
            rf"|\bfrom\s+sys\s+import\b{_IN_IMPORT}\bmonitoring\b"
            r"|\bmonitoring\s*\.\s*register_callback\b"
        ),
    ),
)

#: The ``matched_sink`` of a refusal from :data:`_CODE_OBJECT_ROUTES`.
_CODE_OBJECT_SINK = "code_object"


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
    #
    # A leading word boundary (``\b``) is the sink boundary, not ``(?:^|[^\w.])`` with an
    # optional ``[\w.]+\.`` namespace: the latter excluded ``.`` from the boundary class, so
    # a ``.`` before the sink that was not itself preceded by a word/dot char — a method call
    # on a non-identifier receiver (``get_evaluator().eval(``, ``cfg["x"].eval(``), a leading
    # ``.eval(``, or a lone dot after ``)``/``]``/space — slipped past while real Python (and
    # the ``\b``-based reference detector) see an eval-family call. ``\b`` still rejects a
    # word-prefixed name (``xeval(``) and a longer identifier (``parse_expression(``), and the
    # namespaced form (``sympy.eval(``) still matches on the sink's own boundary.
    # Adaptive red-team wave 2 (v0.10.25).
    return re.compile(
        rf"\b{re.escape(sink)}\s*\(",
        re.MULTILINE,
    )


# ``parse_expr`` is the special case: caller may pin ``local_dict=``
# or ``global_dict=`` in the same call to mitigate, per the
# CVE-2026-44717 patch. We detect both and exempt the call when the
# pin appears within the same parenthesised argument list, outside a
# string literal. Matched at each call by ``_sink_fires``: until 0.10.34
# it was searched for, so one pinned call exempted the whole string,
# ``parse_expr(x); parse_expr("1", local_dict={})`` included, a pin
# inside a string counted, and the unbounded gap made a long argument
# quadratic (1 MB of ``parse_expr(`` took minutes). An argument list too
# long for the bounds is refused.
_PARSE_EXPR_PINNED_RE = re.compile(
    r"""parse_expr\s*\((?:[^)'"]|'[^'\n]{0,1024}'|"[^"\n]{0,1024}"){0,1024}?"""
    r"""\b(?:local_dict|global_dict)\s*=""",
    re.MULTILINE | re.DOTALL,
)


def _sink_fires(sink: str, pattern: re.Pattern[str], text: str) -> bool:
    """Whether ``text`` calls ``sink``. A ``parse_expr`` call counts unless it pins its own dict."""
    if sink != "parse_expr":
        return pattern.search(text) is not None
    return any(
        _PARSE_EXPR_PINNED_RE.match(text, call.start()) is None for call in pattern.finditer(text)
    )


#: Nesting deeper than this is refused rather than walked. A guard that stopped looking at
#: some depth would fail open on the payload placed one level below it.
_MAX_DEPTH = 32


class EvalRCEVerdict(str, enum.Enum):
    """Stable reason codes for :class:`EvalRCEDecision`."""

    ALLOW = "allow"
    DENY_EVAL_SINK = "deny_eval_sink"
    DENY_VULNERABLE_PACKAGE = "deny_vulnerable_package"
    DENY_UNINSPECTABLE = "deny_uninspectable"


@dataclass(frozen=True)
class EvalRCEDecision:
    """Outcome of a single :meth:`EvalRCEGuard.evaluate` call.

    Mirrors the v0.6.1 :class:`AllowlistVerdict` / v0.7.x decision
    family — all expose ``allowed: bool`` for chain-friendly
    composition.

    Attributes:
        allowed: True iff no eval-sink, code-object or vulnerable-package match.
        verdict: Stable :class:`EvalRCEVerdict` value. A code-object refusal is
            ``DENY_EVAL_SINK``, so a caller that handles that verdict refuses it too.
        detail: Free-form explanation.
        matched_sink: Sink label (``eval`` / ``parse_expr`` / etc.)
            that fired, ``code_object`` for the code-object screen, or
            ``None`` for a package or uninspectable deny.
        matched_package: Package name from the vulnerable-package
            denylist, or ``None`` for a sink or uninspectable deny.
    """

    allowed: bool
    verdict: EvalRCEVerdict
    detail: str
    matched_sink: str | None
    matched_package: str | None


class EvalRCEGuard:
    """Fail-closed gate on bare-eval sinks, code objects and known-vulnerable packages.

    Args:
        extra_sinks: Frozenset of additional sink labels to detect on
            top of :data:`DEFAULT_EVAL_SINKS`. Each label must be a
            valid Python identifier (the regex looks for
            ``[<ns>.]<label>(`` shape). It only adds: the code-object screen
            always runs.
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

        Every string is scanned at any depth: inside mappings, lists, tuples and sets,
        with ``bytes`` decoded (``eval`` and ``exec`` accept bytes source). Until v0.10.24
        only top-level string values were scanned, so ``{"code": ["eval(input())"]}`` and
        ``{"payload": {"code": "eval(...)"}}`` passed. Nesting deeper than the guard walks,
        a container that contains itself, and bytes that are not UTF-8 (v0.10.28: they were
        decoded with replacement characters, which hid a sink split by an invalid byte) are
        refused (``DENY_UNINSPECTABLE``).

        Args:
            args: Tool call argument dict. ``None`` = allow.

        Returns:
            :class:`EvalRCEDecision`. ``allowed=False`` maps to a
            refusal at the Airlock decorator boundary.
        """
        if args is None:
            return self._allow("no args to inspect")
        if not isinstance(args, Mapping):
            decision = self._scan_value("args", args, depth=0, ancestors=frozenset())
            return decision or self._allow("no eval-RCE pattern matched")

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

        # 2) Sink-pattern scan over every string, at any depth.
        top = frozenset({id(args)})
        for key, value in args.items():
            decision = self._scan_value(str(key), value, depth=1, ancestors=top)
            if decision is not None:
                return decision

        return self._allow("no eval-RCE pattern matched")

    def _scan_value(
        self, field: str, value: Any, *, depth: int, ancestors: frozenset[int]
    ) -> EvalRCEDecision | None:
        """Scan a str or bytes value, or walk a container; ``None`` when nothing fires.

        Bytes are decoded strictly (v0.10.28). Until then they were decoded with
        ``errors="replace"``, so ``b"ev\\xffal("`` read as ``ev\\ufffdal(`` and passed,
        while a consumer that drops the undecodable byte reads ``eval(``; bytes that are
        not UTF-8 are now refused as ``DENY_UNINSPECTABLE``.
        """
        if isinstance(value, str):
            return self._inspect_value(field=field, value=value)
        if isinstance(value, (bytes, bytearray, memoryview)):
            try:
                text = bytes(value).decode("utf-8")
            except UnicodeDecodeError:
                return self._deny_uninspectable(field, "is bytes that are not valid UTF-8")
            return self._inspect_value(field=field, value=text)
        children: list[tuple[str, Any]]
        if isinstance(value, Mapping):
            children = [(f"{field}.{key}", item) for key, item in value.items()]
        elif isinstance(value, (list, tuple, set, frozenset)):
            children = [(f"{field}[{idx}]", item) for idx, item in enumerate(value)]
        else:
            return None  # numbers, booleans, None and other objects carry no source text
        if depth >= _MAX_DEPTH:
            return self._deny_uninspectable(field, f"nests deeper than {_MAX_DEPTH} levels")
        if id(value) in ancestors:
            return self._deny_uninspectable(field, "contains itself")
        inner = ancestors | {id(value)}
        for child_field, child in children:
            decision = self._scan_value(child_field, child, depth=depth + 1, ancestors=inner)
            if decision is not None:
                return decision
        return None

    def _deny_uninspectable(self, field: str, why: str) -> EvalRCEDecision:
        logger.warning("eval_rce_uninspectable", field=field, reason=why)
        return EvalRCEDecision(
            allowed=False,
            verdict=EvalRCEVerdict.DENY_UNINSPECTABLE,
            detail=(
                f"field {field!r} {why}, so the guard cannot inspect all of it; refused "
                "rather than skipped"
            ),
            matched_sink=None,
            matched_package=None,
        )

    def _allow(self, reason: str) -> EvalRCEDecision:
        return EvalRCEDecision(
            allowed=True,
            verdict=EvalRCEVerdict.ALLOW,
            detail=reason,
            matched_sink=None,
            matched_package=None,
        )

    def _inspect_value(self, *, field: str, value: str) -> EvalRCEDecision | None:
        """Return a deny decision if a sink or a code-object route fires on ``value``.

        Both read the NFKC form, which is how Python reads an identifier (PEP 3131). Until
        0.10.34 ``ｅｘｅｃ('x')`` in fullwidth letters ran ``exec`` and matched no sink.
        """
        text = unicodedata.normalize("NFKC", value)
        for sink, pattern in self._patterns.items():
            # ``parse_expr`` exemption: pinned local_dict / global_dict
            # is the CVE-2026-44717 patch shape — safe.
            if not _sink_fires(sink, pattern, text):
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
        return self._screen_code_objects(field=field, text=text, value=value)

    def _screen_code_objects(self, *, field: str, text: str, value: str) -> EvalRCEDecision | None:
        """Return a deny decision if ``text`` builds or fetches a Python code object."""
        for route, pattern in _CODE_OBJECT_ROUTES:
            if not pattern.search(text):
                continue
            logger.warning(
                "eval_rce_code_object",
                route=route,
                field=field,
                snippet=value[:64],
            )
            return EvalRCEDecision(
                allowed=False,
                verdict=EvalRCEVerdict.DENY_EVAL_SINK,
                detail=(
                    f"field {field!r} names {route}, so it builds or fetches a Python code "
                    "object (CVE-2026-123783 class)"
                ),
                matched_sink=_CODE_OBJECT_SINK,
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
