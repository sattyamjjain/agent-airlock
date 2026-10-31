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
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel

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

# Coarse name → capability heuristic. It only adds to what the annotations (or their
# spec defaults) imply, and is not read when a tool declares explicit capabilities.
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
    #: The ``mcpServers`` entry the tool was listed under, when the loader saw one.
    server: str | None = None
    #: Risk-lowering hints the tool carries that were not used: its server is not trusted.
    untrusted_hints: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.grade is Grade.PASS

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool_name,
            "grade": self.grade.value,
            "inferred_capability": self.inferred_capability,
            "server": self.server,
            "untrusted_hints": list(self.untrusted_hints),
            "violations": [v.to_dict() for v in self.violations],
        }


@dataclass
class ScanReport:
    """Aggregate report over a set of tool declarations."""

    results: list[ToolScanResult] = field(default_factory=list)
    policy_name: str = "permissive"
    #: The servers whose risk-lowering hints were used, sorted.
    trusted_servers: list[str] = field(default_factory=list)

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
            "trusted_servers": list(self.trusted_servers),
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


def infer_required_capability(tool: Mapping[str, Any], *, trusted: bool = False) -> Capability:
    """Infer the capability a tool requires from its declared contract.

    Precedence (most authoritative first):

    1. An explicit ``capabilities`` list of :class:`Capability` member names, returned
       as declared.
    2. MCP tool ``annotations`` (``readOnlyHint`` / ``destructiveHint`` /
       ``openWorldHint``), each absent hint read at its MCP spec default: not
       read-only, destructive, open-world. So a tool with no annotations is read as
       destructive and open-world. A hint that lowers the risk (``readOnlyHint: true``,
       ``destructiveHint: false``, ``openWorldHint: false``) counts only when
       ``trusted``: the spec says not to decide anything from an untrusted server's
       annotations.
    3. A coarse tool-name heuristic, which only adds to step 2 and never removes from
       it.

    Args:
        tool: One MCP tool definition. ``annotations`` may be a mapping or a pydantic
            model such as ``mcp.types.ToolAnnotations``.
        trusted: Whether the tool's server is one the caller trusts.

    Returns:
        The capability the tool needs; never ``Capability.NONE`` without explicit
        capabilities, since the spec defaults always need some.
    """
    explicit = _capability_from_explicit(tool)
    if explicit is not Capability.NONE:
        return explicit
    annotated = _capability_from_annotations(_read_annotations(tool), trusted=trusted)
    return annotated | _capability_from_name(str(tool.get("name", "")))


#: The hints that lower a tool's inferred risk, with the value that lowers it.
_RISK_LOWERING_HINTS: tuple[tuple[str, bool], ...] = (
    ("readOnlyHint", True),
    ("destructiveHint", False),
    ("openWorldHint", False),
)


def _read_annotations(tool: Mapping[str, Any]) -> dict[str, Any]:
    """A tool's ``annotations`` as a plain dict keyed by the MCP spec's camelCase names.

    A pydantic model (``mcp.types.ToolAnnotations``, whose fields are snake_case in
    mcp 2.x) is read through ``model_dump(by_alias=True, exclude_none=True)``, so an
    unset hint stays absent and gets its spec default. Anything else that is not a
    mapping, or a model that cannot be dumped, reads as no annotations: the spec
    defaults, which are the worst case.
    """
    ann = tool.get("annotations")
    if isinstance(ann, BaseModel):
        try:
            ann = ann.model_dump(by_alias=True, exclude_none=True)
        except Exception:  # noqa: BLE001 - an unreadable model reads as absent (worst case)
            return {}
    return dict(ann) if isinstance(ann, Mapping) else {}


def _untrusted_hints(tool: Mapping[str, Any], *, trusted: bool) -> list[str]:
    """The risk-lowering hints a tool carries that were not used, as ``"name: value"``.

    Empty when the server is trusted, or when explicit capabilities decide anyway.
    """
    if trusted or _capability_from_explicit(tool) is not Capability.NONE:
        return []
    ann = _read_annotations(tool)
    return [
        f"{name}: {str(value).lower()}"
        for name, value in _RISK_LOWERING_HINTS
        if ann.get(name) is value
    ]


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


def _capability_from_annotations(ann: Mapping[str, Any], *, trusted: bool) -> Capability:
    """The capability the hints imply, an absent or untrusted lowering hint at its default.

    One effect capability (read, write or delete), plus ``NETWORK_HTTPS`` for an
    open-world tool. ``destructiveHint`` counts only on a tool that is not read-only,
    as the spec says.
    """
    read_only = trusted and ann.get("readOnlyHint") is True
    destructive = not (trusted and ann.get("destructiveHint") is False)
    open_world = not (trusted and ann.get("openWorldHint") is False)
    combined: Capability
    if read_only:
        combined = Capability.FILESYSTEM_READ
    elif destructive:
        combined = Capability.FILESYSTEM_DELETE
    else:
        combined = Capability.FILESYSTEM_WRITE
    if open_world:
        combined = combined | Capability.NETWORK_HTTPS
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
    server: str | None = None,
    trusted_servers: Collection[str] = (),
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
        server: The server the tool came from, as the caller knows it (never read
            from the tool definition, which the server writes).
        trusted_servers: Servers whose risk-lowering hints may be used. A tool with no
            ``server``, or one not listed, is read at the spec defaults.

    Returns:
        A graded :class:`ToolScanResult`.
    """
    if card_guard is None:
        card_guard = _default_card_guard()
    if ref_guard is None:
        ref_guard = _default_ref_guard()
    tool_name = str(tool.get("name", "")).strip() or "<unnamed>"
    trusted = server is not None and server in trusted_servers
    required = infer_required_capability(tool, trusted=trusted)

    violations: list[ContractViolation] = []
    _check_policy_allowed(tool_name, policy, violations)
    _check_server_card_trust(tool, card_guard, violations)
    _check_schema_contract(tool, _is_destructive(tool, tool_name, required), ref_guard, violations)
    _check_type_constraints(tool, violations)
    _check_capability_caps(tool_name, required, policy.capability_policy, violations)
    _check_issuer_shape(tool, violations)

    return ToolScanResult(
        tool_name=tool_name,
        grade=_worst([v.grade for v in violations]),
        violations=violations,
        inferred_capability=_cap_names(required),
        server=server,
        untrusted_hints=_untrusted_hints(tool, trusted=trusted),
    )


def _is_destructive(tool: Mapping[str, Any], tool_name: str, required: Capability) -> bool:
    """Whether an open argument surface on this tool is a FAIL (SCAN003), not a WARN."""
    mutating = Capability.FILESYSTEM_DELETE | Capability.PROCESS_SHELL | Capability.FILESYSTEM_WRITE
    return (
        is_destructive_tool(tool_name)
        or bool(required & mutating)
        or _read_annotations(tool).get("destructiveHint") is True
    )


def scan_tools(
    tools: Sequence[Mapping[str, Any]],
    policy: SecurityPolicy,
    *,
    policy_name: str = "permissive",
    servers: Sequence[str | None] | None = None,
    trusted_servers: Collection[str] = (),
) -> ScanReport:
    """Statically check a set of tool declarations against a policy.

    A single guard instance is reused across all tools (one preset construction).

    Args:
        tools: The tool definitions.
        policy: The least-privilege policy to check against.
        policy_name: The name the report carries.
        servers: The server each tool came from, in the same order
            (:attr:`~agent_airlock.scan.loaders.LoadedTools.servers`); None when the
            caller knows none, so no tool's risk-lowering hints are used.
        trusted_servers: Servers whose risk-lowering hints may be used.

    Raises:
        ValueError: ``servers`` is not the same length as ``tools``.
    """
    if servers is None:
        servers = [None] * len(tools)
    if len(servers) != len(tools):
        raise ValueError(f"servers names {len(servers)} servers for {len(tools)} tools")
    card_guard = _default_card_guard()
    ref_guard = _default_ref_guard()
    results = [
        scan_tool(
            tool,
            policy,
            card_guard=card_guard,
            ref_guard=ref_guard,
            server=server,
            trusted_servers=trusted_servers,
        )
        for tool, server in zip(tools, servers, strict=True)
    ]
    return ScanReport(
        results=results, policy_name=policy_name, trusted_servers=sorted(trusted_servers)
    )
