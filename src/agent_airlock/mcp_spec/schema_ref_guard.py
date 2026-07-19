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

import structlog

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

    def check_ref(self, ref: str) -> SchemaRefDecision:
        """Classify one ``$ref`` string.

        Args:
            ref: The ``$ref`` value from a tool schema.

        Returns:
            A :class:`SchemaRefDecision`. ``allowed=False`` maps to a refusal of
            the tool registration.
        """
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
        """Return a decision for every ``$ref`` found anywhere in ``schema``.

        Walks the whole schema (including nested composition subschemas and
        ``$defs``) so a ref buried inside a ``oneOf`` branch is caught.
        """
        return [self.check_ref(ref) for ref in _iter_refs(schema)]

    def validate(self, schema: Mapping[str, object]) -> None:
        """Raise :class:`SchemaRefError` on the first external ``$ref`` in ``schema``."""
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


def _iter_refs(node: object) -> list[str]:
    """Collect every ``$ref`` string value anywhere in a schema tree."""
    out: list[str] = []

    def _walk(n: object) -> None:
        if isinstance(n, Mapping):
            ref = n.get("$ref")
            if isinstance(ref, str):
                out.append(ref)
            for value in n.values():
                _walk(value)
        elif isinstance(n, Sequence) and not isinstance(n, (str, bytes)):
            for item in n:
                _walk(item)

    _walk(node)
    return out
