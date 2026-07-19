"""Static contract / type-checker for MCP tool declarations (``airlock scan-tools``).

This is a **static** check, distinct from the runtime ``@Airlock`` decorator and
distinct from content-signature *tool-poisoning* scanners (MCP-Scan, eSentire
MCP-Scanner). It answers one question per tool:

    Does this tool's *declared contract* fit inside a least-privilege
    :class:`~agent_airlock.policy.SecurityPolicy` envelope?

It reuses shipped airlock primitives rather than adding a new mechanism:

* :meth:`SecurityPolicy.check_tool_allowed` — least-privilege allow/deny.
* :class:`~agent_airlock.capabilities.CapabilityPolicy` — capability caps.
* :func:`~agent_airlock.policy_presets.is_destructive_tool` — destructive-verb classifier.
* the ``mcp_spec_2026_07`` Server-Card / SEP-2468 preset — trust-boundary check on
  each tool description (the same ``ToolOutputTrustGuard`` used at runtime).

The output is a graded report: each tool is ``pass`` / ``warn`` / ``fail`` with the
specific contract violation, and the run carries a CI-friendly exit code.
"""

from __future__ import annotations

import enum
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ..capabilities import Capability, CapabilityPolicy
from ..policy import PolicyViolation, SecurityPolicy
from ..policy_presets import is_destructive_tool
from .schema import SurfaceState, analyze_schema, iter_property_schemas

__all__ = [
    "Grade",
    "ContractViolation",
    "ToolScanResult",
    "ScanReport",
    "scan_tool",
    "scan_tools",
    "infer_required_capability",
]


class Grade(str, enum.Enum):
    """Per-tool contract grade (str-Enum for JSON serialization)."""

    PASS = "pass"  # nosec B105 - enum value name, not actual password
    WARN = "warn"
    FAIL = "fail"


# Ordering so a run can take the worst grade across checks / tools.
_GRADE_RANK: dict[Grade, int] = {Grade.PASS: 0, Grade.WARN: 1, Grade.FAIL: 2}


def _worst(grades: Sequence[Grade]) -> Grade:
    """Return the most severe grade in ``grades`` (PASS if empty)."""
    return max(grades, key=lambda g: _GRADE_RANK[g], default=Grade.PASS)


# Property-name tokens that denote a security-sensitive argument whose type the
# contract should constrain (airlock's SafePath / SafeURL do this at runtime).
_SENSITIVE_ARG_TOKENS: tuple[str, ...] = (
    "path",
    "file",
    "dir",
    "directory",
    "url",
    "uri",
    "command",
    "cmd",
    "query",
    "sql",
    "host",
    "hostname",
    "endpoint",
    "script",
    "code",
)

# Coarse name → capability heuristic, used ONLY when a tool declares no explicit
# capabilities and no MCP annotations. Documented as a heuristic in the report.
_NAME_CAPABILITY_RULES: tuple[tuple[tuple[str, ...], Capability], ...] = (
    (
        ("exec", "shell", "spawn", "subprocess", "run_command", "bash", "sh_"),
        Capability.PROCESS_SHELL,
    ),
    (("eval", "compile", "sandbox"), Capability.PROCESS_EXEC),
    (
        ("delete", "remove", "rm_", "drop", "purge", "destroy", "unlink"),
        Capability.FILESYSTEM_DELETE,
    ),
    (
        ("write", "create", "update", "put_", "save", "edit", "patch", "append", "upload"),
        Capability.FILESYSTEM_WRITE,
    ),
    (("read", "get_", "list", "fetch_file", "cat_", "open_", "load"), Capability.FILESYSTEM_READ),
    (("http", "url", "request", "curl", "download", "webhook"), Capability.NETWORK_HTTPS),
    (("socket", "connect", "tcp", "udp"), Capability.NETWORK_ARBITRARY),
)


@dataclass(frozen=True)
class ContractViolation:
    """A single contract violation found on a tool declaration."""

    code: str  # e.g. "SCAN001"
    grade: Grade  # WARN or FAIL (never PASS)
    message: str
    arg: str | None = None
    suggestion: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "grade": self.grade.value,
            "message": self.message,
            "arg": self.arg,
            "suggestion": self.suggestion,
        }


@dataclass
class ToolScanResult:
    """Graded contract-check result for one tool."""

    tool_name: str
    grade: Grade
    violations: list[ContractViolation] = field(default_factory=list)
    inferred_capability: str = "NONE"

    @property
    def passed(self) -> bool:
        return self.grade is Grade.PASS

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool_name,
            "grade": self.grade.value,
            "inferred_capability": self.inferred_capability,
            "violations": [v.to_dict() for v in self.violations],
        }


@dataclass
class ScanReport:
    """Aggregate report over a set of tool declarations."""

    results: list[ToolScanResult] = field(default_factory=list)
    policy_name: str = "permissive"

    @property
    def tools_scanned(self) -> int:
        return len(self.results)

    @property
    def failed(self) -> list[ToolScanResult]:
        return [r for r in self.results if r.grade is Grade.FAIL]

    @property
    def warned(self) -> list[ToolScanResult]:
        return [r for r in self.results if r.grade is Grade.WARN]

    @property
    def passed(self) -> list[ToolScanResult]:
        return [r for r in self.results if r.grade is Grade.PASS]

    @property
    def worst_grade(self) -> Grade:
        return _worst([r.grade for r in self.results])

    @property
    def exit_code(self) -> int:
        """0 = all pass, 1 = warnings only, 2 = at least one fail."""
        worst = self.worst_grade
        if worst is Grade.FAIL:
            return 2
        if worst is Grade.WARN:
            return 1
        return 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy": self.policy_name,
            "tools_scanned": self.tools_scanned,
            "passed": len(self.passed),
            "warned": len(self.warned),
            "failed": len(self.failed),
            "worst_grade": self.worst_grade.value,
            "exit_code": self.exit_code,
            "results": [r.to_dict() for r in self.results],
        }


# --------------------------------------------------------------------------- #
# Capability inference
# --------------------------------------------------------------------------- #


def infer_required_capability(tool: Mapping[str, Any]) -> Capability:
    """Infer the capability a tool requires from its declared contract.

    Precedence (most authoritative first):

    1. An explicit ``capabilities`` list of :class:`Capability` member names.
    2. MCP tool ``annotations`` (``destructiveHint`` / ``readOnlyHint`` /
       ``openWorldHint``) — real MCP-spec fields.
    3. A coarse tool-name heuristic (documented as such).

    Returns ``Capability.NONE`` when nothing can be inferred.
    """
    explicit = _capability_from_explicit(tool)
    if explicit is not Capability.NONE:
        return explicit
    annotated = _capability_from_annotations(tool)
    if annotated is not Capability.NONE:
        return annotated
    return _capability_from_name(str(tool.get("name", "")))


def _capability_from_explicit(tool: Mapping[str, Any]) -> Capability:
    caps = tool.get("capabilities")
    if not isinstance(caps, (list, tuple)):
        return Capability.NONE
    combined = Capability.NONE
    for name in caps:
        member = getattr(Capability, str(name).upper(), None)
        if isinstance(member, Capability):
            combined |= member
    return combined


def _capability_from_annotations(tool: Mapping[str, Any]) -> Capability:
    ann = tool.get("annotations")
    if not isinstance(ann, Mapping):
        return Capability.NONE
    combined = Capability.NONE
    if ann.get("destructiveHint") is True:
        combined = combined | Capability.FILESYSTEM_DELETE
    if ann.get("openWorldHint") is True:
        combined = combined | Capability.NETWORK_HTTPS
    # ``not combined`` uses Flag truthiness (Capability(0) is falsy) rather than an
    # ``is NONE`` identity check, which would narrow ``combined`` to a Literal and
    # break the subsequent ``|`` under mypy's Flag handling.
    if ann.get("readOnlyHint") is True and not combined:
        combined = combined | Capability.FILESYSTEM_READ
    return combined


def _capability_from_name(name: str) -> Capability:
    lowered = name.lower()
    for tokens, cap in _NAME_CAPABILITY_RULES:
        if any(tok in lowered for tok in tokens):
            return cap
    return Capability.NONE


# --------------------------------------------------------------------------- #
# Per-check helpers (each appends 0..n violations)
# --------------------------------------------------------------------------- #


def _check_policy_allowed(
    tool_name: str, policy: SecurityPolicy, out: list[ContractViolation]
) -> None:
    """SCAN001 — the tool is denied / not allow-listed by the least-privilege policy."""
    try:
        policy.check_tool_allowed(tool_name)
    except PolicyViolation as exc:
        out.append(
            ContractViolation(
                code="SCAN001",
                grade=Grade.FAIL,
                message=str(exc),
                suggestion=(
                    "Add the tool to the policy's allowed_tools, or drop it from the "
                    "agent's tool set — under a least-privilege policy every tool must "
                    "be opted in by name."
                ),
            )
        )


def _check_server_card_trust(
    tool: Mapping[str, Any], card_guard: Any, out: list[ContractViolation]
) -> None:
    """SCAN002 — the tool description widens the trust boundary (Server-Card / Agentjacking).

    Reuses the shipped ``ToolOutputTrustGuard`` behind the ``mcp_spec_2026_07``
    Server-Card / SEP-2468 preset. A poisoned (injection-shaped) description is
    a FAIL.
    """
    from ..tool_output_trust_guard import ToolOutputTrustError

    desc = tool.get("description")
    if not isinstance(desc, str) or not desc:
        return
    try:
        card_guard.process(desc, raise_on_flag=True)
    except ToolOutputTrustError as exc:
        verdicts = ", ".join(sorted({s.verdict.value for s in exc.decision.signals}))
        out.append(
            ContractViolation(
                code="SCAN002",
                grade=Grade.FAIL,
                message=(
                    "Tool description carries injected instructions "
                    f"(server-card trust boundary; signals: {verdicts}). Treated as "
                    "untrusted content, not trusted configuration."
                ),
                suggestion=(
                    "Reject this server card / tool. A tool description must not contain "
                    "imperative instructions to the agent (Agentjacking-class injection)."
                ),
            )
        )


def _input_schema(tool: Mapping[str, Any]) -> Mapping[str, Any] | None:
    schema = tool.get("inputSchema", tool.get("input_schema", tool.get("parameters")))
    return schema if isinstance(schema, Mapping) else None


def _emit_open_surface(destructive: bool, reason: str, out: list[ContractViolation]) -> None:
    """SCAN003 (fail) / SCAN004 (warn) — over-broad argument surface (ghost-arg vector)."""
    if destructive:
        out.append(
            ContractViolation(
                code="SCAN003",
                grade=Grade.FAIL,
                message=(
                    "Destructive/mutating tool declares an open argument surface "
                    f"({reason}). Ghost/hallucinated arguments would be accepted into a "
                    "high-blast-radius operation."
                ),
                suggestion='Set "additionalProperties": false and declare every parameter explicitly.',
            )
        )
    else:
        out.append(
            ContractViolation(
                code="SCAN004",
                grade=Grade.WARN,
                message=(
                    f"Tool declares an open argument surface ({reason}); hallucinated "
                    "arguments would be accepted."
                ),
                suggestion='Set "additionalProperties": false to reject ghost arguments.',
            )
        )


def _check_schema_contract(
    tool: Mapping[str, Any],
    destructive: bool,
    ref_guard: Any,
    out: list[ContractViolation],
) -> None:
    """Composition-aware schema contract checks (JSON Schema 2020-12).

    Emits, deny-by-default:

    * SCAN009 (fail) — an external ``$ref`` (attacker-controlled contract; SEP-2106).
    * SCAN010 (fail) — a composition ambiguity (a ``oneOf``/``anyOf`` branch permits
      an argument shape a sibling forbids, or an ``allOf`` footgun). Deny on ambiguity.
    * SCAN011 (fail) — an unsupported schema keyword that cannot be soundly bounded
      (denied rather than silently passed).
    * SCAN003/SCAN004 — an open argument surface, now determined across composition
      branches rather than only the top level.
    """
    schema = _input_schema(tool)
    if schema is None:
        # No declared schema → accepts anything (open surface), as before.
        _emit_open_surface(destructive, "no inputSchema declared", out)
        return

    analysis = analyze_schema(schema)

    # SCAN009 — external $ref anywhere in the schema tree (the ref guard walks the
    # whole document, catching refs nested inside property / items subschemas too).
    for decision in ref_guard.scan_schema(schema):
        if decision.allowed:
            continue
        out.append(
            ContractViolation(
                code="SCAN009",
                grade=Grade.FAIL,
                message=(
                    "Tool schema dereferences an external $ref "
                    f"({decision.verdict.value}): {decision.detail}. A fetched schema is "
                    "untrusted input that redefines the contract at call time."
                ),
                suggestion=(
                    "Inline the subschema or use a within-document '#/$defs/...' pointer; "
                    "external schema sources are not dereferenced (SEP-2106)."
                ),
            )
        )

    # SCAN011 — unsupported construct (cannot bound the surface): deny.
    if analysis.unsupported:
        out.append(
            ContractViolation(
                code="SCAN011",
                grade=Grade.FAIL,
                message=(
                    "Tool schema uses a construct the contract checker cannot soundly "
                    f"bound: {'; '.join(analysis.unsupported)}. Denied rather than "
                    "silently partially-validated."
                ),
                suggestion=(
                    "Express the contract with modelled keywords (properties / "
                    "additionalProperties / oneOf / anyOf / allOf / $defs), or validate "
                    "at runtime with @Airlock."
                ),
            )
        )

    # SCAN010 — composition ambiguity (deny-by-default). External-$ref-caused
    # ambiguity is already reported as SCAN009, so it is filtered out here.
    structural = [a for a in analysis.ambiguities if not a.startswith("external $ref")]
    if structural:
        out.append(
            ContractViolation(
                code="SCAN010",
                grade=Grade.FAIL,
                message=(
                    "Tool schema is ambiguous under composition — the argument surface is "
                    f"not consistent across branches: {'; '.join(structural)}. Deny-by-"
                    "default: an ambiguous contract cannot be least-privilege."
                ),
                suggestion=(
                    "Make every oneOf/anyOf branch declare the same closed property set "
                    '(each with "additionalProperties": false), or split the tool.'
                ),
            )
        )

    # SCAN003/SCAN004 — open surface, only when unambiguously OPEN (an AMBIGUOUS
    # surface is already the stronger SCAN010 signal; CLOSED is clean).
    if analysis.surface is SurfaceState.OPEN:
        _emit_open_surface(destructive, "additionalProperties is not false", out)


def _check_type_constraints(tool: Mapping[str, Any], out: list[ContractViolation]) -> None:
    """SCAN005 (warn) — under-specified types on declared properties (composition-aware)."""
    schema = _input_schema(tool)
    if schema is None:
        return
    warned: set[str] = set()
    # A non-Mapping top-level property value still gets the "no schema object" warn.
    props = schema.get("properties")
    if isinstance(props, Mapping):
        for prop_name, prop_schema in props.items():
            if not isinstance(prop_schema, Mapping):
                out.append(
                    ContractViolation(
                        code="SCAN005",
                        grade=Grade.WARN,
                        message=f"Property '{prop_name}' has no schema object.",
                        arg=str(prop_name),
                        suggestion="Declare a JSON-Schema type for every property.",
                    )
                )
                warned.add(str(prop_name))
    # Type-constraint checks over every property reachable through composition
    # (oneOf / anyOf / allOf / if-then-else / local $ref), deduped by name.
    for prop_name, prop_schema in iter_property_schemas(schema):
        if prop_name in warned:
            continue
        warned.add(prop_name)
        _check_one_property(prop_name, prop_schema, out)


def _check_one_property(
    prop_name: str, prop_schema: Mapping[str, Any], out: list[ContractViolation]
) -> None:
    ptype = prop_schema.get("type")
    if ptype is None and "enum" not in prop_schema and "const" not in prop_schema:
        out.append(
            ContractViolation(
                code="SCAN005",
                grade=Grade.WARN,
                message=f"Property '{prop_name}' declares no type constraint.",
                arg=prop_name,
                suggestion="Add a JSON-Schema 'type' (and enum/pattern where applicable).",
            )
        )
        return
    # A sensitive string with no value constraint is an under-specified contract.
    lowered = prop_name.lower()
    is_sensitive = any(tok in lowered for tok in _SENSITIVE_ARG_TOKENS)
    constrained = any(k in prop_schema for k in ("enum", "const", "pattern", "format", "maxLength"))
    if is_sensitive and ptype == "string" and not constrained:
        out.append(
            ContractViolation(
                code="SCAN005",
                grade=Grade.WARN,
                message=(
                    f"Sensitive argument '{prop_name}' is an unconstrained string "
                    "(no enum/pattern/format/maxLength)."
                ),
                arg=prop_name,
                suggestion=(
                    "Constrain the value (pattern/format/maxLength), or validate it at "
                    "runtime with SafePath/SafeURL."
                ),
            )
        )


def _check_capability_caps(
    tool_name: str,
    required: Capability,
    capability_policy: CapabilityPolicy | None,
    out: list[ContractViolation],
) -> None:
    """SCAN006 (fail) / SCAN007 (warn) — declared capability exceeds the policy caps."""
    if capability_policy is None or required is Capability.NONE:
        return
    from ..capabilities import CapabilityDeniedError

    try:
        capability_policy.check(required, tool_name)
    except CapabilityDeniedError as exc:
        out.append(
            ContractViolation(
                code="SCAN006",
                grade=Grade.FAIL,
                message=str(exc),
                suggestion=(
                    "The tool needs a capability the policy does not grant (or explicitly "
                    "denies). Right-size the tool or the policy's capability_policy."
                ),
            )
        )
        return
    if capability_policy.requires_sandbox(required):
        out.append(
            ContractViolation(
                code="SCAN007",
                grade=Grade.WARN,
                message=(
                    f"Tool requires a sandbox-gated capability ({_cap_names(required)}); "
                    "the policy allows it only under sandbox execution."
                ),
                suggestion="Run this tool with @Airlock(sandbox_required=True).",
            )
        )


def _check_issuer_shape(tool: Mapping[str, Any], out: list[ContractViolation]) -> None:
    """SCAN008 (warn) — a declared OAuth issuer is malformed (SEP-2468 companion).

    scan-tools is static, so it cannot validate a live authorization *response*
    ``iss`` (that is the runtime job of the ``mcp_spec_2026_07`` preset). What it
    *can* do statically is flag a declared issuer identifier that is malformed —
    a signal that SEP-2468 / RFC 9207 issuer binding will be brittle at runtime.
    """
    issuer = tool.get("issuer")
    if issuer is None:
        oauth = tool.get("oauth")
        if isinstance(oauth, Mapping):
            issuer = oauth.get("issuer")
    if issuer is None:
        return
    if not isinstance(issuer, str) or not issuer.strip() or issuer != issuer.strip():
        out.append(
            ContractViolation(
                code="SCAN008",
                grade=Grade.WARN,
                message=(
                    "Declared OAuth issuer is malformed (empty or padded). SEP-2468 / "
                    "RFC 9207 issuer binding requires a clean issuer identifier."
                ),
                suggestion="Declare the issuer as a bare https URL with no surrounding whitespace.",
            )
        )


def _cap_names(caps: Capability) -> str:
    from ..capabilities import capabilities_to_list

    names = capabilities_to_list(caps)
    return " | ".join(names) if names else "NONE"


# --------------------------------------------------------------------------- #
# Public entry points
# --------------------------------------------------------------------------- #


def _default_card_guard() -> Any:
    """Reuse the shipped Server-Card / SEP-2468 preset's trust guard."""
    from ..policy_presets import mcp_spec_2026_07_defaults

    return mcp_spec_2026_07_defaults()["card_guard"]


def _default_ref_guard() -> Any:
    """Reuse the shipped SEP-2106 external-``$ref`` guard."""
    from ..mcp_spec.schema_ref_guard import SchemaRefGuard

    return SchemaRefGuard()


def scan_tool(
    tool: Mapping[str, Any],
    policy: SecurityPolicy,
    *,
    card_guard: Any | None = None,
    ref_guard: Any | None = None,
) -> ToolScanResult:
    """Statically check one tool declaration against a least-privilege policy.

    Args:
        tool: A single MCP tool definition (``name`` / ``description`` /
            ``inputSchema`` / optional ``annotations`` / ``capabilities``).
        policy: The least-privilege :class:`SecurityPolicy` to check against.
        card_guard: The Server-Card trust guard to reuse. Defaults to the
            ``mcp_spec_2026_07`` preset's guard.
        ref_guard: The SEP-2106 external-``$ref`` guard to reuse. Defaults to a
            :class:`~agent_airlock.mcp_spec.schema_ref_guard.SchemaRefGuard`.

    Returns:
        A graded :class:`ToolScanResult`.
    """
    if card_guard is None:
        card_guard = _default_card_guard()
    if ref_guard is None:
        ref_guard = _default_ref_guard()
    tool_name = str(tool.get("name", "")).strip() or "<unnamed>"
    required = infer_required_capability(tool)
    destructive = (
        is_destructive_tool(tool_name)
        or bool(
            required
            & (
                Capability.FILESYSTEM_DELETE
                | Capability.PROCESS_SHELL
                | Capability.FILESYSTEM_WRITE
            )
        )
        or _has_destructive_annotation(tool)
    )

    violations: list[ContractViolation] = []
    _check_policy_allowed(tool_name, policy, violations)
    _check_server_card_trust(tool, card_guard, violations)
    _check_schema_contract(tool, destructive, ref_guard, violations)
    _check_type_constraints(tool, violations)
    _check_capability_caps(tool_name, required, policy.capability_policy, violations)
    _check_issuer_shape(tool, violations)

    grade = _worst([v.grade for v in violations])
    return ToolScanResult(
        tool_name=tool_name,
        grade=grade,
        violations=violations,
        inferred_capability=_cap_names(required),
    )


def _has_destructive_annotation(tool: Mapping[str, Any]) -> bool:
    ann = tool.get("annotations")
    return isinstance(ann, Mapping) and ann.get("destructiveHint") is True


def scan_tools(
    tools: Sequence[Mapping[str, Any]],
    policy: SecurityPolicy,
    *,
    policy_name: str = "permissive",
) -> ScanReport:
    """Statically check a set of tool declarations against a policy.

    A single guard instance is reused across all tools (one preset construction).
    """
    card_guard = _default_card_guard()
    ref_guard = _default_ref_guard()
    results = [
        scan_tool(tool, policy, card_guard=card_guard, ref_guard=ref_guard) for tool in tools
    ]
    return ScanReport(results=results, policy_name=policy_name)
