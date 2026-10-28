"""MCP SEP-2106 external ``$ref`` dereference guard (v0.8.49+).

MCP SEP-2106 tightens how a tool's JSON Schema ``$ref`` is resolved: an
implementation **MUST NOT auto-dereference an external ``$ref`` URI**. The reason
is a contract-integrity one, not merely SSRF: a tool schema is the *contract* the
agent validates its arguments against. If that schema can pull in a subschema from
an attacker-influenceable URL at registration / call time, the contract itself is
attacker-controlled — the fetched document can widen types, open the argument
surface, or redefine ``additionalProperties`` after the tool was reviewed. A
fetched external schema is untrusted input, so it must not silently redefine the
contract.

This guard is the reusable primitive. It classifies every ``$ref`` in a tool
schema and **denies by default** any ref whose target is not a local
``#/$defs/...`` (within-document) JSON pointer:

- ``http`` / ``https`` external document → deny (``DENY_EXTERNAL_HTTP``). The ref
  URL is additionally run through the shipped
  :class:`~agent_airlock.ssrf_egress_guard.SSRFEgressGuard` so the deny carries the
  egress classification (an external ref that points at loopback / cloud-metadata
  is both a contract *and* an SSRF problem). This **reuses** the SSRF egress logic
  rather than duplicating host classification.
- ``file://`` path → deny (``DENY_EXTERNAL_FILE``).
- a relative / absolute document path (``other.json``, ``../x.json#/y``) that would
  resolve *outside* the document → deny (``DENY_RELATIVE_ESCAPE``).
- any other non-local scheme → deny (``DENY_NON_LOCAL``).
- a within-document pointer (``#/$defs/Foo``) → allow (``ALLOW_LOCAL``).

Every reference keyword is read, not only ``$ref``: JSON Schema 2020-12's
``$dynamicRef`` and 2019-09's ``$recursiveRef`` dereference a URI the same
way and get the same classification (v0.10.28; until then an external
``$dynamicRef`` passed unseen). A reference keyword whose value is not text
(other than a mapping or boolean, which is a property *named* ``$ref`` and is
walked as a subschema), and a schema nested deeper than 32 levels or
containing itself, are refused (``DENY_UNINSPECTABLE``) — until v0.10.28 a
schema that contained itself raised ``RecursionError``.

Composition note
----------------
:mod:`agent_airlock.mcp_spec.mcp_origin_host_guard` validates *inbound* Origin /
Host headers (DNS-rebinding on a listening transport) — it is the wrong tool for
an *outbound* ref URL, so this guard composes with the outbound
:class:`SSRFEgressGuard` instead. Both are deny-by-default and share the
decision-emission shape (``allowed`` + ``verdict`` + ``fix_hints``).

References:
    - MCP SEP-2106 — external ``$ref`` dereference restriction.
    - MCP 2026-07-28 specification (final).
"""

from __future__ import annotations

import enum
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .._log import structlog
from ..exceptions import AirlockError
from ..scan.schema import is_local_ref
from ..ssrf_egress_guard import SSRFEgressDecision, SSRFEgressGuard

logger = structlog.get_logger("agent-airlock.mcp_spec.schema_ref_guard")

__all__ = [
    "SchemaRefVerdict",
    "SchemaRefDecision",
    "SchemaRefError",
    "SchemaRefGuard",
]


class SchemaRefVerdict(str, enum.Enum):
    """Stable reason codes for :class:`SchemaRefDecision`."""

    ALLOW_LOCAL = "allow_local"
    DENY_EXTERNAL_HTTP = "deny_external_http"
    DENY_EXTERNAL_FILE = "deny_external_file"
    DENY_RELATIVE_ESCAPE = "deny_relative_escape"
    DENY_NON_LOCAL = "deny_non_local"
    # A ref value or schema the guard cannot read: a ref keyword whose value is not text,
    # or a schema deeper than 32 levels or containing itself (0.10.28).
    DENY_UNINSPECTABLE = "deny_uninspectable"


@dataclass(frozen=True)
class SchemaRefDecision:
    """Outcome of classifying a single ``$ref``.

    Mirrors the v0.7.x / v0.8.x guard decision family — exposes ``allowed: bool``
    so integrators can chain on one short-circuit predicate.

    Attributes:
        allowed: True iff the ref is a within-document pointer. False =
            fail-closed (an external, attacker-controllable contract source).
        verdict: A stable :class:`SchemaRefVerdict` value.
        ref: The raw ``$ref`` string evaluated.
        detail: Free-form human-readable explanation.
        ssrf: The :class:`SSRFEgressGuard` classification of an ``http(s)`` ref's
            host, when applicable (``None`` otherwise).
        fix_hints: Operator/LLM-actionable remediation hints.
    """

    allowed: bool
    verdict: SchemaRefVerdict
    ref: str
    detail: str
    ssrf: SSRFEgressDecision | None = None
    fix_hints: list[str] = field(default_factory=list)


class SchemaRefError(AirlockError):
    """Raised when a tool schema carries an external ``$ref`` (fail-closed).

    Carries the offending :class:`SchemaRefDecision` and exposes ``fix_hints`` so
    an upstream airlock layer can surface the refusal.

    Attributes:
        decision: The decision that triggered the refusal.
        fix_hints: Operator/LLM-actionable remediation hints.
    """

    def __init__(self, decision: SchemaRefDecision) -> None:
        self.decision = decision
        self.fix_hints = decision.fix_hints
        super().__init__(decision.detail)


class SchemaRefGuard:
    """Deny-by-default external-``$ref`` gate for MCP tool schemas (SEP-2106).

    Args:
        ssrf_guard: The egress guard used to classify an ``http(s)`` ref's host.
            Defaults to a :class:`SSRFEgressGuard` that does not resolve DNS
            (``deny_on_resolution_failure=False``) — the ref is denied regardless
            of where it points, and the SSRF classification is enrichment, not the
            gate. Inject a resolver-backed guard to fail even harder on
            internal-pointing refs.
        advisory: Advisory / spec id surfaced in deny ``fix_hints``.
        advisory_url: Optional primary-source URL surfaced alongside.
    """

    def __init__(
        self,
        *,
        ssrf_guard: SSRFEgressGuard | None = None,
        advisory: str | None = "SEP-2106",
        advisory_url: str | None = "https://modelcontextprotocol.io/specification/2026-07-28",
    ) -> None:
        # Default: do not fail closed on an unresolvable host — the ref is denied
        # anyway; the SSRF classification is only enrichment on http(s) refs.
        self._ssrf = ssrf_guard or SSRFEgressGuard(deny_on_resolution_failure=False)
        self._advisory = advisory
        self._advisory_url = advisory_url

    def check_ref(self, ref: object) -> SchemaRefDecision:
        """Classify one ``$ref`` / ``$dynamicRef`` / ``$recursiveRef`` value.

        Args:
            ref: The reference value from a tool schema, normally a string.
                ``bytes`` are decoded as UTF-8; any other value (or bytes that are
                not UTF-8) is refused as ``DENY_UNINSPECTABLE`` (v0.10.28; a list
                raised ``AttributeError`` before).

        Returns:
            A :class:`SchemaRefDecision`. ``allowed=False`` maps to a refusal of
            the tool registration.
        """
        if isinstance(ref, (bytes, bytearray)):
            try:
                ref = bytes(ref).decode("utf-8")
            except UnicodeDecodeError:
                return self._deny_uninspectable(None, "a reference is bytes that are not UTF-8")
        if not isinstance(ref, str):
            return self._deny_uninspectable(
                None, f"a reference is a {type(ref).__name__}, not a string"
            )
        if is_local_ref(ref):
            return SchemaRefDecision(
                allowed=True,
                verdict=SchemaRefVerdict.ALLOW_LOCAL,
                ref=ref,
                detail=f"local within-document pointer {ref!r}",
            )

        parts = urlsplit(ref)
        scheme = parts.scheme.lower()
        if scheme in ("http", "https"):
            ssrf = self._ssrf.check_url(ref)
            return self._deny(
                SchemaRefVerdict.DENY_EXTERNAL_HTTP,
                ref,
                f"external {scheme} $ref {ref!r} — a fetched schema is attacker-controlled "
                "input that would redefine the tool contract at call time (SEP-2106)",
                ssrf=ssrf,
            )
        if scheme == "file":
            return self._deny(
                SchemaRefVerdict.DENY_EXTERNAL_FILE,
                ref,
                f"file:// $ref {ref!r} — the tool contract must not be loaded from the "
                "local filesystem at call time (SEP-2106)",
            )
        if scheme:
            return self._deny(
                SchemaRefVerdict.DENY_NON_LOCAL,
                ref,
                f"non-local {scheme} $ref {ref!r} — only within-document '#/$defs/...' "
                "pointers are permitted (SEP-2106)",
            )
        # No scheme and not a '#' fragment → a relative/absolute document path
        # ('other.json', '../x.json#/y', '/abs.json') that resolves outside this
        # document.
        return self._deny(
            SchemaRefVerdict.DENY_RELATIVE_ESCAPE,
            ref,
            f"$ref {ref!r} resolves to another document — only within-document "
            "'#/$defs/...' pointers are permitted (SEP-2106)",
        )

    def scan_schema(self, schema: Mapping[str, object]) -> list[SchemaRefDecision]:
        """Return a decision for every reference found anywhere in ``schema``.

        Walks the whole schema (including nested composition subschemas and
        ``$defs``) so a ref buried inside a ``oneOf`` branch is caught. Each
        ``$ref``, ``$dynamicRef`` and ``$recursiveRef`` value gets a
        :meth:`check_ref` decision; a part of the schema the walk cannot read
        (deeper than 32 levels, or containing itself) gets a
        ``DENY_UNINSPECTABLE`` decision in its place.
        """
        decisions: list[SchemaRefDecision] = []
        for found in _iter_refs(schema):
            if isinstance(found, _Unwalkable):
                decisions.append(self._deny_uninspectable(found.location, found.why))
            else:
                decisions.append(self.check_ref(found))
        return decisions

    def validate(self, schema: Mapping[str, object]) -> None:
        """Raise :class:`SchemaRefError` on the first refused reference in ``schema``."""
        for decision in self.scan_schema(schema):
            if not decision.allowed:
                raise SchemaRefError(decision)

    # -- internals --------------------------------------------------------

    def _deny(
        self,
        verdict: SchemaRefVerdict,
        ref: str,
        detail: str,
        *,
        ssrf: SSRFEgressDecision | None = None,
    ) -> SchemaRefDecision:
        logger.warning(
            "schema_external_ref_blocked",
            verdict=verdict.value,
            ref=ref,
            ssrf_verdict=(ssrf.verdict.value if ssrf is not None else None),
            advisory=self._advisory,
        )
        return SchemaRefDecision(
            allowed=False,
            verdict=verdict,
            ref=ref,
            detail=detail,
            ssrf=ssrf,
            fix_hints=self._hints(
                f"Replace the external $ref {ref!r} with an inline schema or a "
                "within-document '#/$defs/...' pointer. External schema sources are "
                "not dereferenced (SEP-2106).",
            ),
        )

    def _hints(self, *extra: str) -> list[str]:
        prefix = f"({self._advisory}) " if self._advisory else ""
        hints = [f"{prefix}{extra[0]}", *extra[1:]] if extra else []
        if self._advisory_url:
            hints.append(f"See: {self._advisory_url}")
        return hints

    def _deny_uninspectable(self, where: str | None, why: str) -> SchemaRefDecision:
        logger.warning(
            "schema_external_ref_blocked",
            verdict=SchemaRefVerdict.DENY_UNINSPECTABLE.value,
            ref=None,
            location=where,
            reason=why,
            advisory=self._advisory,
        )
        at = f" (at {where})" if where else ""
        return SchemaRefDecision(
            allowed=False,
            verdict=SchemaRefVerdict.DENY_UNINSPECTABLE,
            ref="",
            detail=(
                f"{why}{at}, so the guard cannot classify every reference in the schema; "
                "refused rather than skipped"
            ),
            fix_hints=self._hints(
                "Send a tool schema whose $ref / $dynamicRef / $recursiveRef values are "
                f"strings, nested no deeper than {_MAX_DEPTH} levels and with no part that "
                "contains itself, so every reference can be checked (SEP-2106).",
            ),
        )


#: Keywords that dereference a URI: ``$ref`` everywhere, JSON Schema 2020-12's
#: ``$dynamicRef`` and 2019-09's ``$recursiveRef`` (collected since v0.10.28).
_REF_KEYWORDS: tuple[str, ...] = ("$ref", "$dynamicRef", "$recursiveRef")

#: Nesting deeper than this is refused rather than walked.
_MAX_DEPTH = 32


@dataclass(frozen=True)
class _Unwalkable:
    """A part of the schema the walk cannot read, and why."""

    location: str
    why: str


def _iter_refs(node: object) -> list[object]:
    """Collect every reference value anywhere in a schema tree.

    A ``$ref`` / ``$dynamicRef`` / ``$recursiveRef`` value that is a mapping or a
    boolean is a *property* or subschema of that name, not a reference, and is walked
    like any other subschema; every other value is collected for :meth:`check_ref`,
    which refuses one that is not text. A container nested deeper than
    :data:`_MAX_DEPTH`, or one that contains itself, is collected as an
    :class:`_Unwalkable` instead of being walked.
    """
    out: list[object] = []

    def _walk(n: object, where: str, depth: int, ancestors: frozenset[int]) -> None:
        refs: list[object] = []
        if isinstance(n, Mapping):
            refs = [
                n[keyword]
                for keyword in _REF_KEYWORDS
                if keyword in n and not isinstance(n[keyword], (Mapping, bool))
            ]
            children = [(f"{where}/{key}", value) for key, value in n.items()]
        elif isinstance(n, Sequence) and not isinstance(n, (str, bytes, bytearray)):
            children = [(f"{where}/{idx}", item) for idx, item in enumerate(n)]
        else:
            return
        if depth >= _MAX_DEPTH:
            out.append(
                _Unwalkable(where or "/", f"the schema nests deeper than {_MAX_DEPTH} levels")
            )
            return
        if id(n) in ancestors:
            out.append(_Unwalkable(where or "/", "the schema contains itself"))
            return
        out.extend(refs)
        inner = ancestors | {id(n)}
        for child_where, child in children:
            _walk(child, child_where, depth + 1, inner)

    _walk(node, "", 0, frozenset())
    return out
