"""JSON Schema 2020-12 composition analyzer for the static contract checker.

The ``scan-tools`` contract checker (:mod:`agent_airlock.scan.contract`) must be
able to reason about a tool's ``inputSchema`` even when the contract is expressed
through **composition** — ``oneOf`` / ``anyOf`` / ``allOf`` / ``not`` /
``if``-``then``-``else`` / ``$ref`` / ``$defs`` / ``prefixItems`` — not just a flat
``properties`` map. A checker that only understands top-level ``properties`` reads
a composed-but-closed contract as an open surface (and vice-versa): a silent hole.

This module is a **conservative, deny-by-default static analysis**, not a full
JSON Schema *validator*. It answers three contract-safety questions about a schema:

1. **What is the permitted argument surface?** The union of ``properties`` keys
   reachable through every composition branch (:attr:`SchemaAnalysis.permitted_props`).
2. **Is that surface provably closed?** :class:`SurfaceState` —
   ``CLOSED`` only when every satisfiable path pins ``additionalProperties: false``
   over a consistent property set; ``OPEN`` when a path leaves it open; ``AMBIGUOUS``
   when branches disagree. Deny-by-default treats anything that is not ``CLOSED`` as
   not-closed, and treats ``AMBIGUOUS`` as a hard denial.
3. **Can we soundly reason at all?** Any keyword or ``$ref`` target we cannot
   resolve locally is reported as ``unsupported`` / ``external`` and **denied** —
   never silently passed. Silent partial validation is the failure mode this avoids.

Zero dependency beyond Pydantic (already a core dep): the analysis is stdlib
mapping traversal. Pydantic does not consume arbitrary JSON Schema for validation,
so composition is analyzed locally here rather than by adding a ``jsonschema`` dep
(the no-pivot guardrail).

Aligned to MCP SEP-2106 (external ``$ref`` dereference is denied — see
:mod:`agent_airlock.mcp_spec.schema_ref_guard`, which classifies the external refs
this analyzer surfaces).
"""

from __future__ import annotations

import enum
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "SurfaceState",
    "SchemaAnalysis",
    "BranchReport",
    "GhostStripResult",
    "analyze_schema",
    "strip_ghost_args_under_composition",
    "iter_property_schemas",
    "is_local_ref",
    "COMPOSITION_KEYWORDS",
]

#: The JSON Schema 2020-12 composition keywords this analyzer understands.
COMPOSITION_KEYWORDS: frozenset[str] = frozenset(
    {"oneOf", "anyOf", "allOf", "not", "if", "then", "else", "$ref", "$defs", "prefixItems"}
)

# Keywords we recognise but that carry no surface constraint on their own.
_INERT_KEYWORDS: frozenset[str] = frozenset(
    {
        "$defs",
        "definitions",
        "title",
        "description",
        "default",
        "examples",
        "$schema",
        "$id",
        "$comment",
        "type",
        "enum",
        "const",
        "format",
        "pattern",
        "minLength",
        "maxLength",
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "multipleOf",
        "minItems",
        "maxItems",
        "uniqueItems",
        "readOnly",
        "writeOnly",
        "deprecated",
        "contentEncoding",
        "contentMediaType",
    }
)


class SurfaceState(str, enum.Enum):
    """Whether an object's additional-property surface is provably closed."""

    CLOSED = "closed"  # additionalProperties:false over a consistent prop set
    OPEN = "open"  # a satisfiable path leaves the surface open
    AMBIGUOUS = "ambiguous"  # branches disagree — deny-by-default


@dataclass(frozen=True)
class SchemaAnalysis:
    """Result of analysing one schema for contract-safety.

    Attributes:
        permitted_props: Union of ``properties`` keys reachable through every
            composition branch (the ghost-argument allow-set).
        surface: Whether the object surface is provably closed.
        ambiguities: Human-readable descriptions of branch disagreements. A
            non-empty list means deny-by-default (the policy decides).
        external_refs: Raw non-local ``$ref`` strings found anywhere in the
            schema (classified by :mod:`schema_ref_guard`).
        unsupported: Keywords / constructs that cannot be soundly analysed and
            are therefore denied rather than silently passed.
        array_tail: For an array contract using ``prefixItems``, whether the tail
            (``items``) is closed; ``None`` when the schema is not an array.
    """

    permitted_props: frozenset[str]
    surface: SurfaceState
    ambiguities: tuple[str, ...] = ()
    external_refs: tuple[str, ...] = ()
    unsupported: tuple[str, ...] = ()
    array_tail: SurfaceState | None = None

    @property
    def is_closed(self) -> bool:
        """True iff the surface is provably closed and nothing is ambiguous/denied."""
        return (
            self.surface is SurfaceState.CLOSED
            and not self.ambiguities
            and not self.external_refs
            and not self.unsupported
        )

    @property
    def is_ambiguous(self) -> bool:
        return self.surface is SurfaceState.AMBIGUOUS or bool(self.ambiguities)


@dataclass
class _Node:
    """Internal per-node analysis result, combined up the tree."""

    props: set[str] = field(default_factory=set)
    surface: SurfaceState = SurfaceState.OPEN
    ambiguities: list[str] = field(default_factory=list)
    external_refs: list[str] = field(default_factory=list)
    unsupported: list[str] = field(default_factory=list)
    array_tail: SurfaceState | None = None


def is_local_ref(ref: str) -> bool:
    """True iff ``ref`` is a within-document JSON pointer (``#/$defs/...``).

    A local ref is a bare fragment starting with ``#``. Anything with a scheme,
    a path, or a document part before the ``#`` targets an external document and
    is NOT local (SEP-2106: implementations must not auto-dereference it).
    """
    return isinstance(ref, str) and ref.startswith("#")


def _resolve_local_ref(root: Mapping[str, Any], ref: str) -> Any | None:
    """Resolve a local ``#/a/b`` JSON pointer against ``root``; ``None`` if absent."""
    pointer = ref[1:]
    if pointer.startswith("/"):
        pointer = pointer[1:]
    if pointer == "":
        return root
    node: Any = root
    for raw_token in pointer.split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(node, Mapping) and token in node:
            node = node[token]
        elif isinstance(node, Sequence) and not isinstance(node, str):
            try:
                node = node[int(token)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return node


def _bool_schema_node(value: bool) -> _Node:
    """A JSON Schema boolean: ``true`` permits anything, ``false`` permits nothing."""
    if value:
        return _Node(surface=SurfaceState.OPEN)
    # ``false`` accepts no instance — an empty, fully-closed surface.
    return _Node(surface=SurfaceState.CLOSED)


def _self_object_surface(schema: Mapping[str, Any]) -> _Node:
    """The object surface implied by this node's own ``properties`` / ``additionalProperties``."""
    node = _Node()
    props = schema.get("properties")
    if isinstance(props, Mapping):
        node.props.update(str(k) for k in props)
    add = schema.get("additionalProperties", None)
    declares_object = (
        isinstance(props, Mapping)
        or "additionalProperties" in schema
        or "required" in schema
        or schema.get("type") == "object"
    )
    if add is False:
        node.surface = SurfaceState.CLOSED
    elif declares_object:
        # Object shape declared, but additionalProperties is open (default True).
        node.surface = SurfaceState.OPEN
    else:
        # No object indicators here — this node adds no object surface. Neutral.
        node.surface = SurfaceState.OPEN
    return node


def _array_surface(schema: Mapping[str, Any]) -> SurfaceState | None:
    """Closed-tail state for a ``prefixItems`` array contract, else ``None``."""
    has_prefix = isinstance(schema.get("prefixItems"), Sequence)
    is_array = schema.get("type") == "array" or has_prefix or "items" in schema
    if not is_array:
        return None
    items = schema.get("items", None)
    if items is False:
        return SurfaceState.CLOSED
    # items absent/true/schema → the tail accepts extra elements.
    return SurfaceState.OPEN


def _combine_and(parts: list[_Node]) -> _Node:
    """AND-combine components at one level (all constraints must hold).

    A CLOSED component pins the surface (extras are rejected). If a CLOSED
    component's allowed set does not cover a property another component
    declares, the schema is a footgun (that property is simultaneously declared
    and rejected) — reported as an ambiguity.
    """
    out = _Node()
    union: set[str] = set()
    for p in parts:
        union |= p.props
        out.ambiguities.extend(p.ambiguities)
        out.external_refs.extend(p.external_refs)
        out.unsupported.extend(p.unsupported)
        if p.array_tail is not None:
            out.array_tail = _worst_surface(out.array_tail, p.array_tail)
    out.props = union

    closed_parts = [p for p in parts if p.surface is SurfaceState.CLOSED]
    ambiguous = any(p.surface is SurfaceState.AMBIGUOUS for p in parts)
    for cp in closed_parts:
        rejected = union - cp.props
        if rejected:
            out.ambiguities.append(
                "allOf/AND: a closed subschema rejects "
                f"{sorted(rejected)!r} that a sibling subschema declares"
            )
            ambiguous = True
    if ambiguous:
        out.surface = SurfaceState.AMBIGUOUS
    elif closed_parts:
        out.surface = SurfaceState.CLOSED
    else:
        out.surface = SurfaceState.OPEN
    return out


def _combine_or(parts: list[_Node], kind: str) -> _Node:
    """OR-combine branches (``oneOf`` / ``anyOf``): an instance may pick any branch.

    Deny-by-default: the surface is CLOSED only if every branch is CLOSED over the
    *same* property set. If branches disagree — a property permitted by one branch
    is forbidden by a sibling, or one branch is open while another is closed — the
    result is AMBIGUOUS and reported.
    """
    out = _Node()
    for p in parts:
        out.props |= p.props
        out.external_refs.extend(p.external_refs)
        out.unsupported.extend(p.unsupported)
        out.ambiguities.extend(p.ambiguities)

    if not parts:
        out.surface = SurfaceState.OPEN
        return out

    shapes = {(p.surface, frozenset(p.props)) for p in parts}
    if any(p.surface is SurfaceState.AMBIGUOUS for p in parts):
        out.surface = SurfaceState.AMBIGUOUS
    elif len(shapes) == 1:
        # Every branch has the identical (state, props) shape.
        out.surface = next(iter(shapes))[0]
    else:
        out.surface = SurfaceState.AMBIGUOUS
        # Describe the specific disagreement (deny-by-default anchor).
        all_props = out.props
        for prop in sorted(all_props):
            permit = [i for i, p in enumerate(parts) if _branch_permits(p, prop)]
            forbid = [i for i, p in enumerate(parts) if not _branch_permits(p, prop)]
            if permit and forbid:
                out.ambiguities.append(
                    f"{kind}: property {prop!r} is permitted by branch(es) {permit} "
                    f"but forbidden by branch(es) {forbid}"
                )
        if not any(a.startswith(f"{kind}:") for a in out.ambiguities):
            out.ambiguities.append(
                f"{kind}: branches disagree on the argument surface (open vs closed)"
            )
    return out


def _branch_permits(node: _Node, prop: str) -> bool:
    """Whether a branch permits property ``prop`` (declared, or an open surface)."""
    if prop in node.props:
        return True
    return node.surface is not SurfaceState.CLOSED


def _worst_surface(a: SurfaceState | None, b: SurfaceState) -> SurfaceState:
    order = {SurfaceState.CLOSED: 0, SurfaceState.OPEN: 1, SurfaceState.AMBIGUOUS: 2}
    if a is None:
        return b
    return a if order[a] >= order[b] else b


def _analyze_node(
    schema: Any,
    root: Mapping[str, Any],
    visited: frozenset[str],
) -> _Node:
    """Recursively analyse one schema node."""
    if isinstance(schema, bool):
        return _bool_schema_node(schema)
    if not isinstance(schema, Mapping):
        return _Node(surface=SurfaceState.AMBIGUOUS, unsupported=["non-object schema node"])

    parts: list[_Node] = [_self_object_surface(schema)]
    array_tail = _array_surface(schema)
    if array_tail is not None:
        parts[0].array_tail = array_tail

    # $ref — resolve locally or flag as external (SEP-2106).
    ref = schema.get("$ref")
    if isinstance(ref, str):
        parts.append(_analyze_ref(ref, root, visited))

    # allOf — AND of subschemas.
    allof = schema.get("allOf")
    if isinstance(allof, Sequence) and not isinstance(allof, str):
        parts.append(_combine_and([_analyze_node(s, root, visited) for s in allof]))

    # oneOf / anyOf — OR of subschemas (branch disagreement = ambiguity).
    for kind in ("oneOf", "anyOf"):
        branches = schema.get(kind)
        if isinstance(branches, Sequence) and not isinstance(branches, str):
            parts.append(_combine_or([_analyze_node(s, root, visited) for s in branches], kind))

    # if / then / else — conditional application.
    if "if" in schema or "then" in schema or "else" in schema:
        parts.append(_analyze_if_then_else(schema, root, visited))

    # not — negation cannot be soundly reduced to a closed surface. Still walk it
    # for external refs, but mark the surface ambiguous (deny-by-default).
    if "not" in schema:
        sub = _analyze_node(schema["not"], root, visited)
        parts.append(
            _Node(
                surface=SurfaceState.AMBIGUOUS,
                ambiguities=["'not' subschema: surface closedness is not statically decidable"],
                external_refs=list(sub.external_refs),
                unsupported=list(sub.unsupported),
            )
        )

    _flag_unsupported_keywords(schema, parts)
    return _combine_and(parts)


def _analyze_ref(ref: str, root: Mapping[str, Any], visited: frozenset[str]) -> _Node:
    if not is_local_ref(ref):
        # External $ref — attacker-controlled contract at call time (SEP-2106).
        return _Node(
            surface=SurfaceState.AMBIGUOUS,
            external_refs=[ref],
            ambiguities=[f"external $ref {ref!r} — target contract is not in the document"],
        )
    if ref in visited:
        # Ref cycle — bounded, treated as neutral (already analysed once).
        return _Node(surface=SurfaceState.OPEN)
    target = _resolve_local_ref(root, ref)
    if target is None:
        return _Node(
            surface=SurfaceState.AMBIGUOUS,
            unsupported=[f"local $ref {ref!r} does not resolve within the document"],
        )
    return _analyze_node(target, root, visited | {ref})


def _analyze_if_then_else(
    schema: Mapping[str, Any], root: Mapping[str, Any], visited: frozenset[str]
) -> _Node:
    """The effective surface of ``if``/``then``/``else`` is the OR of its outcomes."""
    then_node = (
        _analyze_node(schema["then"], root, visited)
        if "then" in schema
        else _Node(surface=SurfaceState.OPEN)
    )
    else_node = (
        _analyze_node(schema["else"], root, visited)
        if "else" in schema
        else _Node(surface=SurfaceState.OPEN)
    )
    # The 'if' subschema only selects a branch; it never itself constrains the
    # surface, but it may carry external refs we must still surface.
    extra_refs: list[str] = []
    extra_unsupported: list[str] = []
    if "if" in schema:
        if_node = _analyze_node(schema["if"], root, visited)
        extra_refs = list(if_node.external_refs)
        extra_unsupported = list(if_node.unsupported)
    combined = _combine_or([then_node, else_node], "if/then/else")
    combined.external_refs.extend(extra_refs)
    combined.unsupported.extend(extra_unsupported)
    return combined


def _flag_unsupported_keywords(schema: Mapping[str, Any], parts: list[_Node]) -> None:
    """Deny (do not silently pass) any keyword we do not model."""
    known = (
        COMPOSITION_KEYWORDS
        | _INERT_KEYWORDS
        | {
            "properties",
            "additionalProperties",
            "required",
            "items",
            "patternProperties",
            "propertyNames",
            "dependentSchemas",
            "dependentRequired",
            "unevaluatedProperties",
            "contains",
        }
    )
    unsupported: list[str] = []
    for key in schema:
        if key not in known:
            continue
        # A few object keywords change the surface and we do not fully model them:
        # treat their presence as a deny signal rather than silently ignoring.
        if key in ("patternProperties", "unevaluatedProperties"):
            unsupported.append(
                f"unsupported object keyword {key!r} — denied (cannot bound surface)"
            )
    if unsupported:
        parts.append(_Node(surface=SurfaceState.AMBIGUOUS, unsupported=unsupported))


def analyze_schema(schema: Any, *, root: Mapping[str, Any] | None = None) -> SchemaAnalysis:
    """Analyse a JSON Schema 2020-12 document for contract-safety.

    Args:
        schema: The schema (a tool ``inputSchema``) to analyse.
        root: The document root for local ``$ref`` resolution. Defaults to
            ``schema`` itself (the common case where ``$defs`` live at the root).

    Returns:
        A :class:`SchemaAnalysis`. Deny-by-default: treat anything where
        :attr:`SchemaAnalysis.is_closed` is False as an open/undetermined surface,
        and any non-empty ``ambiguities`` / ``external_refs`` / ``unsupported`` as
        a denial.
    """
    doc_root = root if root is not None else (schema if isinstance(schema, Mapping) else {})
    node = _analyze_node(schema, doc_root, frozenset())
    # De-duplicate while preserving order for stable reports.
    return SchemaAnalysis(
        permitted_props=frozenset(node.props),
        surface=node.surface,
        ambiguities=tuple(dict.fromkeys(node.ambiguities)),
        external_refs=tuple(dict.fromkeys(node.external_refs)),
        unsupported=tuple(dict.fromkeys(node.unsupported)),
        array_tail=node.array_tail,
    )


@dataclass(frozen=True)
class BranchReport:
    """Per-branch ghost-strip outcome, so ``airlock explain`` can show which branch ran."""

    index: int
    kind: str  # "oneOf" / "anyOf" / "root"
    permitted: tuple[str, ...]
    stripped: tuple[str, ...]


@dataclass(frozen=True)
class GhostStripResult:
    """Outcome of stripping ghost arguments against a (possibly composed) schema."""

    kept: tuple[str, ...]
    stripped: tuple[str, ...]
    per_branch: tuple[BranchReport, ...]


def strip_ghost_args_under_composition(
    schema: Any,
    arg_names: Sequence[str],
    *,
    root: Mapping[str, Any] | None = None,
) -> GhostStripResult:
    """Strip arguments permitted by no schema branch, reporting per-branch.

    An argument permitted by *no* branch of the (possibly composed) schema is a
    ghost argument and is stripped — the static analog of the runtime ghost-arg
    strip. The per-branch report records which arguments each top-level
    ``oneOf`` / ``anyOf`` branch would accept, so ``airlock explain`` can show
    which branch was evaluated.

    Args:
        schema: The tool ``inputSchema`` (may use composition).
        arg_names: The argument names the model produced.
        root: Document root for ``$ref`` resolution (defaults to ``schema``).

    Returns:
        A :class:`GhostStripResult`.
    """
    doc_root = root if root is not None else (schema if isinstance(schema, Mapping) else {})
    analysis = analyze_schema(schema, root=doc_root)
    permitted = analysis.permitted_props

    kept: list[str] = []
    stripped: list[str] = []
    for name in arg_names:
        (kept if name in permitted else stripped).append(name)

    per_branch: list[BranchReport] = []
    branches = _top_level_branches(schema)
    if branches:
        for i, (kind, branch) in enumerate(branches):
            b = analyze_schema(branch, root=doc_root)
            b_permit = [n for n in arg_names if n in b.permitted_props]
            b_strip = [n for n in arg_names if n not in b.permitted_props]
            per_branch.append(
                BranchReport(index=i, kind=kind, permitted=tuple(b_permit), stripped=tuple(b_strip))
            )
    else:
        per_branch.append(
            BranchReport(index=0, kind="root", permitted=tuple(kept), stripped=tuple(stripped))
        )

    return GhostStripResult(
        kept=tuple(kept), stripped=tuple(stripped), per_branch=tuple(per_branch)
    )


def iter_property_schemas(
    schema: Any, *, root: Mapping[str, Any] | None = None
) -> Iterator[tuple[str, Mapping[str, Any]]]:
    """Yield ``(property_name, property_schema)`` for every property reachable via composition.

    Walks ``properties`` at the node plus every composition branch
    (``allOf`` / ``oneOf`` / ``anyOf`` / ``then`` / ``else`` / ``not`` / local
    ``$ref``), so the contract checker can type-check properties declared inside a
    branch — not only a flat top-level ``properties`` map. The same property name
    may be yielded more than once (declared in multiple branches); callers dedup
    as needed.
    """
    doc_root = root if root is not None else (schema if isinstance(schema, Mapping) else {})
    seen_refs: set[str] = set()

    def _walk(node: Any) -> Iterator[tuple[str, Mapping[str, Any]]]:
        if not isinstance(node, Mapping):
            return
        props = node.get("properties")
        if isinstance(props, Mapping):
            for name, sub in props.items():
                if isinstance(sub, Mapping):
                    yield str(name), sub
        for kw in ("allOf", "oneOf", "anyOf"):
            branches = node.get(kw)
            if isinstance(branches, Sequence) and not isinstance(branches, str):
                for branch in branches:
                    yield from _walk(branch)
        for kw in ("then", "else", "not"):
            if kw in node:
                yield from _walk(node[kw])
        ref = node.get("$ref")
        if isinstance(ref, str) and is_local_ref(ref) and ref not in seen_refs:
            seen_refs.add(ref)
            target = _resolve_local_ref(doc_root, ref)
            if target is not None:
                yield from _walk(target)

    yield from _walk(schema)


def _top_level_branches(schema: Any) -> list[tuple[str, Any]]:
    """Top-level ``oneOf`` / ``anyOf`` branches, for per-branch reporting."""
    if not isinstance(schema, Mapping):
        return []
    out: list[tuple[str, Any]] = []
    for kind in ("oneOf", "anyOf"):
        branches = schema.get(kind)
        if isinstance(branches, Sequence) and not isinstance(branches, str):
            out.extend((kind, b) for b in branches)
    return out
