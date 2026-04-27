#!/usr/bin/env python3
"""STDIO-taint static-analysis CI gate (v0.5.7+).

Flags any code path where remote/network/user-input data flows into
``StdioServerParameters(command=...)``, ``subprocess.Popen(args=...)``
without ``shell=False`` asserted, or
``mcp.client.stdio.stdio_client(...)``.

This is a *static* gate — distinct from the v0.5.1 runtime
``stdio_guard.validate_stdio_command``. The runtime guard catches a
malicious value at the moment of ``execve``; this gate catches the
*flow shape* at PR time, before the value is ever constructed.

Motivation
----------
OX Security's 2026-04-15 deep-dive established that arbitrary strings
reaching ``StdioServerParameters.command`` is "the" agent-supply-chain
class of bug. Anthropic confirmed the behavior is "by design" and
declined to patch. CVE-2026-6980 (GitPilot-MCP, 2026-04-25) and
CVE-2026-30615 (Windsurf zero-click) are the same flow shape:
remote input reaches an STDIO command construction site.

This scanner is the leverage point Anthropic explicitly punted to
"developer responsibility": catch the flow shape at PR review time.

Usage
-----
::

    python tools/scan_stdio_remote_input_flow.py src/ tests/ examples/

Exit codes:

* ``0`` — no findings (or all findings carry the
  ``# noqa: AIRLOCK-TAINT-OK <reason>`` pragma)
* ``1`` — at least one unsuppressed finding; ``.airlock-stdio-taint.json``
  written with the full finding list

The pragma must include a one-line reason; empty pragmas fail.

Sources
-------
* OX Security (2026-04-15):
  https://www.ox.security/blog/mother-of-all-ai-supply-chains-2026-04-20
* The Hacker News (2026-04-16):
  https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html
* SecurityWeek (2026-04-16):
  https://www.securityweek.com/by-design-flaw-in-mcp/
"""

from __future__ import annotations

import ast
import json
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

# -----------------------------------------------------------------------------
# Default taint sources / sinks
# -----------------------------------------------------------------------------

# Modules whose return values are treated as remote/network input. Any
# attribute access on these modules is a source.
DEFAULT_TAINT_MODULE_ROOTS: frozenset[str] = frozenset(
    {
        "requests",
        "httpx",
        "aiohttp",
        "urllib.request",
    }
)

# Specific dotted-call expressions whose return value is tainted.
DEFAULT_TAINT_CALL_PREFIXES: frozenset[str] = frozenset(
    {
        # FastAPI / Flask request bodies — any json.loads(<request>.body)
        # is downstream-tainted via the body attribute below; we also
        # accept the direct call shape.
        "request.body",
        "request.get_json",
        "request.form",
        "request.args",
        # MCP tool-call inputs flow through the tool handler signature;
        # the function-parameter taint is handled separately via the
        # decorator pattern.
    }
)

# Sinks: dotted-call expressions whose argument(s) must NOT carry tainted data.
DEFAULT_SINK_DOTTED_CALLS: frozenset[str] = frozenset(
    {
        "subprocess.Popen",
        "subprocess.run",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.call",
        "StdioServerParameters",
        "mcp.client.stdio.stdio_client",
        "stdio_client",  # bare-name import form
    }
)

# Tools / decorators that mark a function parameter as taint-source.
# A function decorated with one of these names (or ``something.name``)
# has every parameter treated as remote/user input. We match on the
# trailing token so ``app.post`` / ``router.post`` / ``v1.post`` all
# reach the same rule.
DEFAULT_USER_INPUT_DECORATORS: frozenset[str] = frozenset(
    {
        "post",
        "get",
        "put",
        "patch",
        "delete",
        "route",
        "tool",
        "secure_tool",
    }
)


# -----------------------------------------------------------------------------
# Data classes
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    """A single taint-flow finding."""

    file: str
    line: int
    col: int
    sink: str
    source_kind: str
    reason: str
    suppressed_by_pragma: bool = False
    pragma_reason: str = ""


@dataclass
class ScanResult:
    """Aggregate result of a repository scan."""

    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0

    @property
    def unsuppressed(self) -> list[Finding]:
        return [f for f in self.findings if not f.suppressed_by_pragma]


# -----------------------------------------------------------------------------
# Pragma handling
# -----------------------------------------------------------------------------

PRAGMA_TOKEN = "AIRLOCK-TAINT-OK"


def _line_pragma(file_lines: list[str], lineno: int) -> tuple[bool, str]:
    """Return (suppressed, reason) for a 1-indexed line number.

    A line is suppressed iff it contains ``# noqa: AIRLOCK-TAINT-OK <reason>``
    where ``<reason>`` is at least one non-whitespace character. Empty
    pragmas (``# noqa: AIRLOCK-TAINT-OK``) are NOT suppressed.
    """
    if lineno - 1 >= len(file_lines):
        return False, ""
    line = file_lines[lineno - 1]
    marker = f"noqa: {PRAGMA_TOKEN}"
    idx = line.find(marker)
    if idx < 0:
        return False, ""
    tail = line[idx + len(marker) :].strip()
    if not tail:
        return False, ""
    # First word becomes the reason (rest is allowed).
    return True, tail


# -----------------------------------------------------------------------------
# AST helpers
# -----------------------------------------------------------------------------


def _dotted_name(node: ast.AST) -> str:
    """Best-effort dotted-name extraction.

    ``foo.bar.baz()`` → ``"foo.bar.baz"``. Returns ``""`` for shapes
    we can't statically resolve.
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted_name(node.value)
        if prefix:
            return f"{prefix}.{node.attr}"
        return node.attr
    if isinstance(node, ast.Call):
        return _dotted_name(node.func)
    return ""


def _matches_any_prefix(dotted: str, prefixes: frozenset[str]) -> bool:
    """True iff ``dotted`` starts with any of ``prefixes`` at a segment boundary."""
    if dotted in prefixes:
        return True
    return any(dotted.startswith(f"{p}.") for p in prefixes)


def _name_is_taint_source(node: ast.AST) -> str:
    """If ``node`` represents a known taint source, return its kind label.

    Returns the empty string if not a recognised source.
    """
    if isinstance(node, ast.Call):
        callee = _dotted_name(node.func)
        if _matches_any_prefix(callee, DEFAULT_TAINT_MODULE_ROOTS):
            return f"network_call:{callee}"
        if callee in DEFAULT_TAINT_CALL_PREFIXES or _matches_any_prefix(
            callee, DEFAULT_TAINT_CALL_PREFIXES
        ):
            return f"request_body:{callee}"
    if isinstance(node, ast.Attribute):
        dotted = _dotted_name(node)
        if _matches_any_prefix(dotted, DEFAULT_TAINT_CALL_PREFIXES):
            return f"request_attr:{dotted}"
        # ``requests.get(...).text`` and similar chained access on a
        # network module are tainted too. ``_dotted_name`` returns the
        # full path including the call: ``requests.get.text``.
        if _matches_any_prefix(dotted, DEFAULT_TAINT_MODULE_ROOTS):
            return f"network_attr:{dotted}"
    return ""


# -----------------------------------------------------------------------------
# Per-function taint walker
# -----------------------------------------------------------------------------


class _FuncTaintScanner(ast.NodeVisitor):
    """Walks one function body, tracking which local names hold tainted data
    and emitting findings when tainted data reaches a sink."""

    def __init__(
        self,
        *,
        file_path: Path,
        file_lines: list[str],
        params_are_tainted: bool,
        param_names: list[str],
    ) -> None:
        self.file_path = file_path
        self.file_lines = file_lines
        # name -> source-kind label; presence ⇒ tainted
        self.tainted: dict[str, str] = {}
        if params_are_tainted:
            for name in param_names:
                self.tainted[name] = f"decorated_user_input:{name}"
        self.findings: list[Finding] = []

    def _expr_taint_kind(self, node: ast.AST) -> str:
        """Return the source-kind label for a tainted expression, or ``""``."""
        # Direct source call.
        kind = _name_is_taint_source(node)
        if kind:
            return kind
        # Tainted local name.
        if isinstance(node, ast.Name) and node.id in self.tainted:
            return self.tainted[node.id]
        # Attribute access on tainted root: ``req.body`` is tainted iff ``req`` is.
        if isinstance(node, ast.Attribute):
            root = node
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name) and root.id in self.tainted:
                return self.tainted[root.id]
        # Subscript on tainted root: ``data["x"]`` is tainted iff ``data`` is.
        if isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Name) and node.value.id in self.tainted:
                return self.tainted[node.value.id]
        # Call on tainted attribute: ``payload.json()`` etc.
        if isinstance(node, ast.Call):
            callee = _dotted_name(node.func)
            head = callee.split(".", 1)[0]
            if head in self.tainted:
                return self.tainted[head]
            # Also check args — wrapping a tainted value transmits taint.
            for arg in node.args:
                inner = self._expr_taint_kind(arg)
                if inner:
                    return inner
        # List / tuple / dict containing a tainted element propagates.
        if isinstance(node, ast.List | ast.Tuple):
            for elt in node.elts:
                inner = self._expr_taint_kind(elt)
                if inner:
                    return inner
        if isinstance(node, ast.Dict):
            for v in node.values:
                if v is None:
                    continue
                inner = self._expr_taint_kind(v)
                if inner:
                    return inner
        return ""

    # ---- statement visitors ----

    def visit_Assign(self, node: ast.Assign) -> None:
        kind = self._expr_taint_kind(node.value)
        for tgt in node.targets:
            if isinstance(tgt, ast.Name):
                if kind:
                    self.tainted[tgt.id] = kind
                elif tgt.id in self.tainted:
                    # Reassignment to a clean value clears the taint
                    # (best-effort; conservative would keep it, but
                    # over-flagging the codebase's own assignments is
                    # the bigger usability problem).
                    del self.tainted[tgt.id]
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        kind = self._expr_taint_kind(node.value)
        if kind and isinstance(node.target, ast.Name):
            self.tainted[node.target.id] = kind
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        sink = _dotted_name(node.func)
        if sink in DEFAULT_SINK_DOTTED_CALLS or any(
            sink.endswith(f".{s}") for s in DEFAULT_SINK_DOTTED_CALLS
        ):
            # Inspect every positional + keyword argument.
            sources_seen: list[str] = []
            for arg in node.args:
                k = self._expr_taint_kind(arg)
                if k:
                    sources_seen.append(k)
            for kw in node.keywords:
                # ``shell=True`` on subprocess raises severity, but the
                # taint check is the same — we always flag tainted data
                # reaching the sink, regardless of ``shell``.
                if kw.value is None:
                    continue
                k = self._expr_taint_kind(kw.value)
                if k:
                    sources_seen.append(f"kw:{kw.arg}={k}")
            if sources_seen:
                suppressed, reason = _line_pragma(self.file_lines, node.lineno)
                self.findings.append(
                    Finding(
                        file=str(self.file_path),
                        line=node.lineno,
                        col=node.col_offset,
                        sink=sink,
                        source_kind=", ".join(sources_seen),
                        reason=(
                            f"tainted data reaches {sink}() — "
                            "remote/user input must not flow into a STDIO command "
                            "construction site (CVE-2026-6980 / CVE-2026-30615 class)"
                        ),
                        suppressed_by_pragma=suppressed,
                        pragma_reason=reason,
                    )
                )
        self.generic_visit(node)


# -----------------------------------------------------------------------------
# Module-level walker
# -----------------------------------------------------------------------------


def _decorator_marks_user_input(
    decorators: list[ast.expr],
    user_input_decorators: frozenset[str],
) -> bool:
    """True iff any decorator's trailing token is in the user-input set.

    Examples that match (trailing token in braces):
    - ``@{post}``
    - ``@app.{post}("/x")``
    - ``@router.{tool}``
    - ``@v1.api.{get}("/y")``
    """
    for dec in decorators:
        name = _dotted_name(dec)
        if not name:
            continue
        last = name.rsplit(".", 1)[-1] if "." in name else name
        if last in user_input_decorators:
            return True
    return False


def _scan_file(
    path: Path,
    *,
    user_input_decorators: frozenset[str] = DEFAULT_USER_INPUT_DECORATORS,
) -> list[Finding]:
    try:
        source = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return []
    file_lines = source.splitlines()
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            params_are_tainted = _decorator_marks_user_input(
                node.decorator_list, user_input_decorators
            )
            param_names = [a.arg for a in node.args.args]
            walker = _FuncTaintScanner(
                file_path=path,
                file_lines=file_lines,
                params_are_tainted=params_are_tainted,
                param_names=param_names,
            )
            for stmt in node.body:
                walker.visit(stmt)
            findings.extend(walker.findings)
    return findings


def scan_repo(
    roots: list[Path] | tuple[Path, ...],
    *,
    user_input_decorators: frozenset[str] = DEFAULT_USER_INPUT_DECORATORS,
) -> ScanResult:
    """Walk every ``.py`` file under each root and return the combined result."""
    result = ScanResult()
    for root in roots:
        if not root.exists():
            continue
        files = [root] if root.is_file() and root.suffix == ".py" else sorted(root.rglob("*.py"))
        for path in files:
            result.files_scanned += 1
            result.findings.extend(_scan_file(path, user_input_decorators=user_input_decorators))
    return result


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------


def _emit_summary(result: ScanResult) -> str:
    if not result.findings:
        return f"clean — {result.files_scanned} files scanned, 0 findings"
    lines = [
        f"scanned {result.files_scanned} files; "
        f"{len(result.findings)} findings "
        f"({len(result.unsuppressed)} unsuppressed)"
    ]
    for f in result.findings:
        flag = "(noqa)" if f.suppressed_by_pragma else "(NEW)"
        lines.append(f"  {flag} {f.file}:{f.line}:{f.col} {f.sink}() ← {f.source_kind}")
    return "\n".join(lines)


def _write_json_summary(path: Path, result: ScanResult) -> None:
    payload = {
        "files_scanned": result.files_scanned,
        "finding_count": len(result.findings),
        "unsuppressed_count": len(result.unsuppressed),
        "findings": [asdict(f) for f in result.findings],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    args = list(argv) if argv is not None else sys.argv[1:]
    if not args:
        print("usage: scan_stdio_remote_input_flow.py <root> [<root> ...]", file=sys.stderr)
        return 2
    roots = [Path(a) for a in args]
    result = scan_repo(roots)
    print(_emit_summary(result))
    if result.unsuppressed:
        _write_json_summary(Path(".airlock-stdio-taint.json"), result)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
