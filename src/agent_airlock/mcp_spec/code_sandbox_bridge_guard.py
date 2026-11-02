"""Code-sandbox host-bridge guard (v0.10.31+, CVE-2026-120338 anchor).

NVD 2026-11-01 (CVE-2026-120338, CNA JFrog, CVSS 3.1 10.0): a generative-UI
tool runs caller-supplied Python inside a Pyodide (CPython-on-WASM) runtime
hosted in a Deno subprocess. The subprocess was started with read, write and
network permission, and the runner left the Deno API reachable on the
JavaScript global object, so sandboxed Python could reach the host through
Pyodide's ``js`` proxy (``from js import Deno`` / ``js.Deno.<call>``) and read
or write files as the server user. The usual remote path is an MCP tool
(``generate_prefab_ui``) that forwards its ``code`` argument into the sandbox,
reachable by any client on an unauthenticated server. Fixed upstream by
revoking the host permissions before accepting code.

This guard is the **second defence at the argument seam**: it refuses a
tool-call argument that carries a sandbox-escape host bridge, before the string
ever reaches the runtime. It targets the exploitation *class* — model-derived
code that reaches out of its sandbox to the host runtime — not one product;
version detection of the vulnerable package is not this library's job.

What it matches (any string argument, at any depth)
---------------------------------------------------
- **Pyodide-to-JS bridge**: ``from js import``, ``import js``, ``pyodide.ffi``,
  ``pyodide.code``, ``js.Deno`` — the proxy a Pyodide program uses to reach the
  host JS runtime.
- **Deno host API**: ``Deno.`` followed by a filesystem, process or network
  call (``writeTextFile``, ``writeFile``, ``readTextFile``, ``readFile``,
  ``open``, ``remove``, ``mkdir``, ``Command``, ``run``, ``env``, ``connect``,
  ``listen``).
- **Node bridge**: ``process.binding(``, ``require("child_process")``,
  ``import("child_process")``, ``node:child_process`` — the equivalent escape
  on a Node-hosted sandbox.
- Operator-supplied ``extra_bridges`` (each matched as a literal substring).

Honest scope
------------
A **syntax-shape screen**, like :class:`EvalRCEGuard`. It catches the disclosed
class and the obvious spellings. It does not catch a bridge assembled at run
time *inside* the sandbox (``getattr(__import__(chr(106)+'s'), 'Deno')``,
a name built from pieces, a base64 blob decoded and exec'd): a string the guard
cannot see through is not a string it can screen. The real fix is to upgrade the
sandbox runtime so the host API is not reachable and its permissions are
revoked before untrusted code runs (CVE-2026-120338 was fixed that way). Pair
this guard with ``AirlockConfig(startup_hook_check="warn")`` so a persistence
file written through some other path is caught at the next process start, and
with the default :class:`SafePath` deny list, which now refuses ``.pth`` writes
into site directories.

Why structural (no SDK import)
------------------------------
Compiled-regex pass over string values. No Pyodide, Deno or FastMCP dependency
is imported.

Primary source
--------------
https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-120338
https://github.com/PrefectHQ/prefab/security/advisories/GHSA-595q-jv4r-q7j9
"""

from __future__ import annotations

import enum
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .._log import structlog

logger = structlog.get_logger("agent-airlock.mcp_spec.code_sandbox_bridge_guard")


class BridgeGroup(str, enum.Enum):
    """Which family a matched bridge primitive belongs to."""

    PYODIDE_JS = "pyodide_js"
    DENO_API = "deno_api"
    NODE_BRIDGE = "node_bridge"
    EXTRA = "extra"


#: Deno host-API members that read/write the filesystem, spawn a process, read
#: the environment, or open the network. ``Deno.<member>`` of one of these is a
#: host reach-out from inside the sandbox.
_DENO_MEMBERS: tuple[str, ...] = (
    "writeTextFile",
    "writeFile",
    "readTextFile",
    "readFile",
    "open",
    "remove",
    "mkdir",
    "Command",
    "run",
    "env",
    "connect",
    "listen",
)


def _deno_member_pattern() -> re.Pattern[str]:
    """``Deno.<member>`` with a word boundary and optional whitespace before ``(``.

    The member list is alternated; the trailing ``\\b`` rejects a longer
    identifier (``Deno.runner`` does not match ``run``), and the optional
    ``\\s*`` before ``(`` is tolerated but not required so a bare
    ``Deno.env`` property access still matches.
    """
    members = "|".join(re.escape(m) for m in _DENO_MEMBERS)
    return re.compile(rf"\bDeno\.(?:{members})\b\s*\(?")


#: Ordered (label, group, pattern). Priority runs top to bottom so the most
#: specific primitive is the one reported: ``js.Deno`` before ``import js`` for
#: a string that contains both, and the Pyodide-JS proxy before the bare
#: ``Deno.*`` call it leads into.
def _build_primitives() -> tuple[tuple[str, BridgeGroup, re.Pattern[str]], ...]:
    return (
        ("js.Deno", BridgeGroup.PYODIDE_JS, re.compile(r"\bjs\.Deno\b")),
        ("from js import", BridgeGroup.PYODIDE_JS, re.compile(r"\bfrom\s+js\s+import\b")),
        ("import js", BridgeGroup.PYODIDE_JS, re.compile(r"\bimport\s+js\b")),
        ("pyodide.ffi", BridgeGroup.PYODIDE_JS, re.compile(r"\bpyodide\.ffi\b")),
        ("pyodide.code", BridgeGroup.PYODIDE_JS, re.compile(r"\bpyodide\.code\b")),
        ("Deno host API", BridgeGroup.DENO_API, _deno_member_pattern()),
        ("process.binding", BridgeGroup.NODE_BRIDGE, re.compile(r"\bprocess\.binding\s*\(")),
        (
            "require(child_process)",
            BridgeGroup.NODE_BRIDGE,
            re.compile(r"""\brequire\s*\(\s*['"]child_process['"]"""),
        ),
        (
            "import(child_process)",
            BridgeGroup.NODE_BRIDGE,
            re.compile(r"""\bimport\s*\(\s*['"]child_process['"]"""),
        ),
        ("node:child_process", BridgeGroup.NODE_BRIDGE, re.compile(r"node:child_process")),
    )


#: Nesting deeper than this is refused rather than walked. A guard that stopped
#: looking at some depth would fail open on the payload one level below it.
_MAX_DEPTH = 32


class CodeSandboxBridgeVerdict(str, enum.Enum):
    """Stable reason codes for :class:`CodeSandboxBridgeDecision`."""

    ALLOW = "allow"
    DENY_BRIDGE = "deny_bridge"
    DENY_UNINSPECTABLE = "deny_uninspectable"


@dataclass(frozen=True)
class CodeSandboxBridgeDecision:
    """Outcome of a single :meth:`CodeSandboxBridgeGuard.evaluate` call.

    Mirrors the :class:`~agent_airlock.mcp_spec.eval_rce_guard.EvalRCEDecision`
    shape — all expose ``allowed: bool`` for chain-friendly composition.

    Attributes:
        allowed: True iff no host-bridge primitive matched.
        verdict: Stable :class:`CodeSandboxBridgeVerdict` value.
        detail: Free-form explanation.
        field: The argument (or nested ``field.key`` / ``field[i]`` path) the
            match sits in, or ``None`` on allow.
        matched_primitive: The bridge primitive label that fired
            (``"js.Deno"`` / ``"Deno host API"`` / ...), or ``None`` on allow
            or an uninspectable refusal.
        group: The :class:`BridgeGroup` the primitive belongs to, or ``None``.
    """

    allowed: bool
    verdict: CodeSandboxBridgeVerdict
    detail: str
    field: str | None
    matched_primitive: str | None
    group: BridgeGroup | None


class CodeSandboxBridgeGuard:
    """Fail-closed gate on sandbox-escape host-bridge calls in string arguments.

    Args:
        extra_bridges: Additional bridge spellings to refuse, each matched as a
            literal substring (``frozenset`` of ``str``). Use for a host API
            this guard does not ship, e.g. a vendor-specific escape.

    Raises:
        TypeError: ``extra_bridges`` is not a frozenset of str.
    """

    def __init__(self, *, extra_bridges: frozenset[str] = frozenset()) -> None:
        if not isinstance(extra_bridges, frozenset):
            raise TypeError(
                f"extra_bridges must be a frozenset[str]; got {type(extra_bridges).__name__}"
            )
        if not all(isinstance(b, str) for b in extra_bridges):
            raise TypeError("extra_bridges entries must be str")
        self._primitives: tuple[tuple[str, BridgeGroup, re.Pattern[str]], ...] = _build_primitives()
        # Operator-supplied bridges are matched as literal substrings, appended
        # in sorted order so a refusal is deterministic.
        self._extra: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
            (b, re.compile(re.escape(b))) for b in sorted(extra_bridges)
        )

    def evaluate(self, args: Mapping[str, Any] | None) -> CodeSandboxBridgeDecision:
        """Decide whether the call args carry a sandbox-escape host bridge.

        Every string is scanned at any depth: inside mappings, lists, tuples and
        sets, with ``bytes`` decoded strictly. ``None`` and a non-mapping are
        both handled. Nesting deeper than the guard walks, a container that
        contains itself, and bytes that are not UTF-8 are refused
        (``DENY_UNINSPECTABLE``) rather than skipped.

        Args:
            args: Tool-call argument mapping. ``None`` = allow.

        Returns:
            :class:`CodeSandboxBridgeDecision`. ``allowed=False`` maps to a
            refusal at the Airlock decorator boundary.
        """
        if args is None:
            return self._allow("no args to inspect")
        if not isinstance(args, Mapping):
            decision = self._scan_value("args", args, depth=0, ancestors=frozenset())
            return decision or self._allow("no sandbox host-bridge pattern matched")

        top = frozenset({id(args)})
        for key, value in args.items():
            decision = self._scan_value(str(key), value, depth=1, ancestors=top)
            if decision is not None:
                return decision
        return self._allow("no sandbox host-bridge pattern matched")

    def _scan_value(
        self, field: str, value: Any, *, depth: int, ancestors: frozenset[int]
    ) -> CodeSandboxBridgeDecision | None:
        """Scan a str/bytes value or walk a container; ``None`` when nothing fires."""
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

    def _inspect_value(self, *, field: str, value: str) -> CodeSandboxBridgeDecision | None:
        """Return a deny decision if any bridge primitive fires on ``value``."""
        for label, group, pattern in self._primitives:
            if pattern.search(value):
                return self._deny_bridge(field, label, group)
        for label, pattern in self._extra:
            if pattern.search(value):
                return self._deny_bridge(field, label, BridgeGroup.EXTRA)
        return None

    def _deny_bridge(
        self, field: str, primitive: str, group: BridgeGroup
    ) -> CodeSandboxBridgeDecision:
        logger.warning(
            "code_sandbox_bridge_match",
            field=field,
            primitive=primitive,
            group=group.value,
        )
        return CodeSandboxBridgeDecision(
            allowed=False,
            verdict=CodeSandboxBridgeVerdict.DENY_BRIDGE,
            detail=(
                f"field {field!r} reaches the sandbox host via {primitive!r} "
                f"({group.value}); refused (CVE-2026-120338 class)"
            ),
            field=field,
            matched_primitive=primitive,
            group=group,
        )

    def _deny_uninspectable(self, field: str, why: str) -> CodeSandboxBridgeDecision:
        logger.warning("code_sandbox_bridge_uninspectable", field=field, reason=why)
        return CodeSandboxBridgeDecision(
            allowed=False,
            verdict=CodeSandboxBridgeVerdict.DENY_UNINSPECTABLE,
            detail=(
                f"field {field!r} {why}, so the guard cannot inspect all of it; refused "
                "rather than skipped"
            ),
            field=field,
            matched_primitive=None,
            group=None,
        )

    def _allow(self, reason: str) -> CodeSandboxBridgeDecision:
        return CodeSandboxBridgeDecision(
            allowed=True,
            verdict=CodeSandboxBridgeVerdict.ALLOW,
            detail=reason,
            field=None,
            matched_primitive=None,
            group=None,
        )


__all__ = [
    "BridgeGroup",
    "CodeSandboxBridgeDecision",
    "CodeSandboxBridgeGuard",
    "CodeSandboxBridgeVerdict",
]
