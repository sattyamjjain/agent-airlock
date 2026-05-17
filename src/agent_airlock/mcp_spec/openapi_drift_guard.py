"""OpenAPI drift guard (v0.8.1+, Hermes 2026-05-13 paper anchor).

The Hermes paper (arXiv:2605.14312, 2026-05-13) measured production
OpenAPI-driven agent failures and found that the dominant failure mode
is **payload-shape drift**: the model emits a tool-call body that
violates the published OpenAPI schema — a required field absent, an
invented field, or a value of the wrong JSON type. The downstream
service either errors back to the agent (an infinite-retry loop) or,
worse, dispatches on the malformed payload as if it were valid (the
spec is advisory, not enforced).

agent-airlock's v0.7.x / v0.8.0 guards catch *exploit shapes* (eval
sinks, shell metachars, vulnerable packages). This guard catches the
**drift** class one layer earlier — the malformed payload never gets
to the eval guard because it never gets to the tool.

Drift modes
-----------
- ``strict`` (default): any drift → deny.
- ``warn``: drift → allow, structured warning logged, divergences
  surfaced on the decision so the operator can audit.
- ``shadow``: drift → allow, divergences recorded on the decision
  without a warning log (use this when you're calibrating the spec
  against real production traffic before flipping to strict).

Spec source format
------------------
Per the 2026-05-17 operator decision: **caller supplies a dict**. The
core has no PyYAML / json-load dependency. Operators load their spec
from disk, from the running server's ``/openapi.json`` endpoint, or
from any other source themselves and hand the parsed dict to the
guard's constructor.

Honest scope
------------
- Body-schema only. Query / path / header parameters are NOT yet
  inspected. The Hermes paper finding is dominantly request-body
  drift; the parameter surface is a deliberate follow-up.
- ``application/json`` content type only. Other body types
  (``multipart/form-data``, ``application/x-www-form-urlencoded``,
  ``application/xml``) are not in scope for this cut.
- ``additionalProperties: false`` is REQUIRED to detect unknown
  fields. A permissive schema (no ``additionalProperties`` key, or
  set to ``true``) means the operator has opted in to extra fields
  and we honour that.
- ``$ref`` resolution is shallow — only direct ``properties`` and
  direct ``required`` keys on the body schema are inspected. Nested
  ``$ref`` chains are deferred (operators with deep refs should
  resolve them at load time before passing the dict).

Primary source
--------------
https://arxiv.org/abs/2605.14312
"""

from __future__ import annotations

import enum
import functools
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, TypeVar

import structlog

logger = structlog.get_logger("agent-airlock.mcp_spec.openapi_drift_guard")


_VALID_DRIFT_MODES: frozenset[str] = frozenset({"strict", "warn", "shadow"})
_JSON_CONTENT_TYPE = "application/json"

F = TypeVar("F", bound=Callable[..., Any])


class OpenAPIDriftVerdict(str, enum.Enum):
    """Stable reason codes for :class:`OpenAPIDriftDecision`."""

    ALLOW = "allow"
    ALLOW_WARN = "allow_warn"
    ALLOW_SHADOW = "allow_shadow"
    DENY_DRIFT = "deny_drift"
    DENY_UNKNOWN_OPERATION = "deny_unknown_operation"


class OpenAPIDivergenceKind(str, enum.Enum):
    """The three drift categories detected by the guard."""

    MISSING_REQUIRED = "missing_required"
    UNKNOWN_FIELD = "unknown_field"
    TYPE_MISMATCH = "type_mismatch"


@dataclass(frozen=True)
class OpenAPIDivergence:
    """A single drift finding.

    Attributes:
        kind: The category of drift detected.
        field: The argument key the divergence applies to.
        expected: For ``TYPE_MISMATCH``, the JSON-Schema type the
            spec declared (``"string"`` / ``"integer"`` / etc.).
            ``None`` for ``MISSING_REQUIRED`` and ``UNKNOWN_FIELD``.
        observed: For ``TYPE_MISMATCH``, the JSON-Schema type label
            of the actual value (e.g. ``"boolean"`` for a Python
            ``bool``). ``None`` for the other categories.
    """

    kind: OpenAPIDivergenceKind
    field: str
    expected: str | None
    observed: str | None


@dataclass(frozen=True)
class OpenAPIDriftDecision:
    """Outcome of a single :meth:`OpenAPIDriftGuard.evaluate` call.

    Mirrors the v0.7.x / v0.8.0 decision family — every guard in the
    chain exposes ``allowed: bool`` for composable predicate use.

    Attributes:
        allowed: True iff the call should proceed. Drift in
            ``warn`` / ``shadow`` mode still produces ``True``.
        verdict: Stable :class:`OpenAPIDriftVerdict` value.
        detail: Free-form explanation suitable for logs.
        operation_id: Echo of the operation_id the guard was asked
            about, or ``None`` for early failures.
        divergences: Tuple of every drift finding. Empty tuple when
            no drift detected.
    """

    allowed: bool
    verdict: OpenAPIDriftVerdict
    detail: str
    operation_id: str | None
    divergences: tuple[OpenAPIDivergence, ...]


class OpenAPIDriftViolation(Exception):
    """Raised by :func:`vaccinate_openapi`-wrapped tools on a deny decision.

    Attributes:
        decision: The :class:`OpenAPIDriftDecision` that triggered
            the refusal. Carries the divergences so the operator
            (or an upstream airlock layer) can audit the failure.
    """

    def __init__(self, decision: OpenAPIDriftDecision) -> None:
        self.decision = decision
        super().__init__(decision.detail)


class OpenAPIDriftGuard:
    """Validates tool-call args against an operator-supplied OpenAPI spec.

    Args:
        spec: Parsed OpenAPI 3.x document as a dict. Must contain a
            top-level ``paths`` key.
        drift_mode: One of ``"strict"`` (default) / ``"warn"`` /
            ``"shadow"``. Controls whether drift denies.

    Raises:
        TypeError: ``spec`` is not a mapping.
        ValueError: ``drift_mode`` is unknown, or ``spec`` has no
            ``paths`` key.
    """

    def __init__(
        self,
        *,
        spec: Mapping[str, Any],
        drift_mode: str = "strict",
    ) -> None:
        if not isinstance(spec, Mapping):
            raise TypeError(f"spec must be a dict-like mapping; got {type(spec).__name__}")
        if drift_mode not in _VALID_DRIFT_MODES:
            raise ValueError(
                f"drift_mode must be one of {sorted(_VALID_DRIFT_MODES)!r}; got {drift_mode!r}"
            )
        if "paths" not in spec:
            raise ValueError("spec is missing top-level 'paths' key")
        self._spec = spec
        self._drift_mode = drift_mode
        # Pre-index operations by operationId for O(1) lookup.
        self._operations: dict[str, dict[str, Any]] = self._index_operations(spec)

    @staticmethod
    def _index_operations(spec: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
        """Walk ``spec.paths`` and collect ``{operationId: operation}``."""
        out: dict[str, dict[str, Any]] = {}
        paths = spec.get("paths") or {}
        if not isinstance(paths, Mapping):
            return out
        for _path, methods in paths.items():
            if not isinstance(methods, Mapping):
                continue
            for _method, op in methods.items():
                if not isinstance(op, Mapping):
                    continue
                op_id = op.get("operationId")
                if isinstance(op_id, str):
                    out[op_id] = dict(op)
        return out

    def evaluate(
        self,
        *,
        operation_id: str,
        args: Mapping[str, Any] | None,
    ) -> OpenAPIDriftDecision:
        """Compare ``args`` against the spec for ``operation_id``.

        Args:
            operation_id: The ``operationId`` from the spec.
            args: The proposed tool-call body. ``None`` is treated
                as an empty mapping (and will trip required-field
                detection if any are declared).

        Returns:
            :class:`OpenAPIDriftDecision`. ``allowed=False`` maps
            to a refusal at the Airlock decorator boundary.
        """
        body = dict(args) if args is not None else {}

        op = self._operations.get(operation_id)
        if op is None:
            return self._unknown_operation(operation_id)

        schema = self._extract_body_schema(op)
        if schema is None:
            # No JSON body schema declared → nothing to drift-check.
            return OpenAPIDriftDecision(
                allowed=True,
                verdict=OpenAPIDriftVerdict.ALLOW,
                detail="operation has no application/json body schema",
                operation_id=operation_id,
                divergences=(),
            )

        divergences = self._compare(body=body, schema=schema)
        return self._wrap_verdict(
            operation_id=operation_id,
            divergences=divergences,
        )

    def _unknown_operation(self, operation_id: str) -> OpenAPIDriftDecision:
        detail = f"operation_id {operation_id!r} not found in spec"
        if self._drift_mode == "strict":
            logger.warning(
                "openapi_drift_unknown_operation",
                operation_id=operation_id,
            )
            return OpenAPIDriftDecision(
                allowed=False,
                verdict=OpenAPIDriftVerdict.DENY_UNKNOWN_OPERATION,
                detail=detail,
                operation_id=operation_id,
                divergences=(),
            )
        verdict = (
            OpenAPIDriftVerdict.ALLOW_WARN
            if self._drift_mode == "warn"
            else OpenAPIDriftVerdict.ALLOW_SHADOW
        )
        if self._drift_mode == "warn":
            logger.warning(
                "openapi_drift_unknown_operation_warn",
                operation_id=operation_id,
            )
        return OpenAPIDriftDecision(
            allowed=True,
            verdict=verdict,
            detail=detail,
            operation_id=operation_id,
            divergences=(),
        )

    @staticmethod
    def _extract_body_schema(op: Mapping[str, Any]) -> Mapping[str, Any] | None:
        """Pull ``requestBody.content[application/json].schema`` (or ``None``)."""
        body = op.get("requestBody")
        if not isinstance(body, Mapping):
            return None
        content = body.get("content")
        if not isinstance(content, Mapping):
            return None
        media = content.get(_JSON_CONTENT_TYPE)
        if not isinstance(media, Mapping):
            return None
        schema = media.get("schema")
        if not isinstance(schema, Mapping):
            return None
        return schema

    @staticmethod
    def _compare(
        *,
        body: Mapping[str, Any],
        schema: Mapping[str, Any],
    ) -> tuple[OpenAPIDivergence, ...]:
        """Compute the divergence tuple for ``body`` against ``schema``."""
        divergences: list[OpenAPIDivergence] = []
        properties = schema.get("properties")
        properties_map: Mapping[str, Any] = properties if isinstance(properties, Mapping) else {}

        # 1) missing required
        required = schema.get("required") or ()
        if isinstance(required, (list, tuple)):
            for field in required:
                if isinstance(field, str) and field not in body:
                    divergences.append(
                        OpenAPIDivergence(
                            kind=OpenAPIDivergenceKind.MISSING_REQUIRED,
                            field=field,
                            expected=None,
                            observed=None,
                        )
                    )

        # 2) unknown fields — only when additionalProperties is explicit false
        additional = schema.get("additionalProperties", True)
        if additional is False:
            for field in body:
                if field not in properties_map:
                    divergences.append(
                        OpenAPIDivergence(
                            kind=OpenAPIDivergenceKind.UNKNOWN_FIELD,
                            field=field,
                            expected=None,
                            observed=None,
                        )
                    )

        # 3) type mismatch for fields present in both body and properties
        for field, value in body.items():
            prop = properties_map.get(field)
            if not isinstance(prop, Mapping):
                continue
            expected = prop.get("type")
            if not isinstance(expected, str):
                continue
            observed = _json_type_of(value)
            if not _types_compatible(expected=expected, observed=observed):
                divergences.append(
                    OpenAPIDivergence(
                        kind=OpenAPIDivergenceKind.TYPE_MISMATCH,
                        field=field,
                        expected=expected,
                        observed=observed,
                    )
                )

        return tuple(divergences)

    def _wrap_verdict(
        self,
        *,
        operation_id: str,
        divergences: tuple[OpenAPIDivergence, ...],
    ) -> OpenAPIDriftDecision:
        if not divergences:
            return OpenAPIDriftDecision(
                allowed=True,
                verdict=OpenAPIDriftVerdict.ALLOW,
                detail="payload matches OpenAPI body schema",
                operation_id=operation_id,
                divergences=(),
            )
        detail = (
            f"{len(divergences)} divergence(s) vs spec for "
            f"operation_id={operation_id!r}: "
            + ", ".join(f"{d.kind.value}:{d.field}" for d in divergences)
        )
        if self._drift_mode == "strict":
            logger.warning(
                "openapi_drift_strict_deny",
                operation_id=operation_id,
                count=len(divergences),
            )
            return OpenAPIDriftDecision(
                allowed=False,
                verdict=OpenAPIDriftVerdict.DENY_DRIFT,
                detail=detail,
                operation_id=operation_id,
                divergences=divergences,
            )
        if self._drift_mode == "warn":
            logger.warning(
                "openapi_drift_warn_allow",
                operation_id=operation_id,
                count=len(divergences),
            )
            return OpenAPIDriftDecision(
                allowed=True,
                verdict=OpenAPIDriftVerdict.ALLOW_WARN,
                detail=detail,
                operation_id=operation_id,
                divergences=divergences,
            )
        # shadow
        return OpenAPIDriftDecision(
            allowed=True,
            verdict=OpenAPIDriftVerdict.ALLOW_SHADOW,
            detail=detail,
            operation_id=operation_id,
            divergences=divergences,
        )


def _json_type_of(value: Any) -> str:
    """Map a Python value to its JSON-Schema type label.

    Order matters: ``bool`` must be checked before ``int`` because
    Python's ``bool`` subclasses ``int``.
    """
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, (list, tuple)):
        return "array"
    if isinstance(value, Mapping):
        return "object"
    if value is None:
        return "null"
    return type(value).__name__


def _types_compatible(*, expected: str, observed: str) -> bool:
    """Compatibility table per OpenAPI 3.x JSON-Schema semantics.

    - ``number`` accepts ``integer`` (every integer is a number).
    - All other types match exactly.
    """
    if expected == observed:
        return True
    if expected == "number" and observed == "integer":
        return True
    return False


def vaccinate_openapi(
    spec: Mapping[str, Any],
    *,
    drift_mode: str = "strict",
) -> Callable[[str], Callable[[F], F]]:
    """Return a decorator factory that drift-checks tool calls.

    Wires an :class:`OpenAPIDriftGuard` to the supplied spec / mode
    once, then returns a callable that takes an ``operation_id`` and
    decorates a tool function. The wrapped function calls
    :meth:`OpenAPIDriftGuard.evaluate` on its kwargs and raises
    :class:`OpenAPIDriftViolation` when the decision is a deny.

    Example::

        spec = json.loads(Path("openapi.json").read_text())
        vaccine = vaccinate_openapi(spec, drift_mode="strict")

        @vaccine("createUser")
        def create_user(*, email: str, age: int) -> dict:
            ...

    Args:
        spec: Parsed OpenAPI 3.x document.
        drift_mode: ``strict`` / ``warn`` / ``shadow``.

    Returns:
        ``(operation_id) -> decorator`` factory.
    """
    guard = OpenAPIDriftGuard(spec=spec, drift_mode=drift_mode)

    def make_decorator(operation_id: str) -> Callable[[F], F]:
        def decorator(fn: F) -> F:
            @functools.wraps(fn)
            def wrapped(*args: Any, **kwargs: Any) -> Any:
                decision = guard.evaluate(
                    operation_id=operation_id,
                    args=kwargs,
                )
                if not decision.allowed:
                    raise OpenAPIDriftViolation(decision)
                return fn(*args, **kwargs)

            return wrapped  # type: ignore[return-value]

        return decorator

    return make_decorator


__all__ = [
    "OpenAPIDivergence",
    "OpenAPIDivergenceKind",
    "OpenAPIDriftDecision",
    "OpenAPIDriftGuard",
    "OpenAPIDriftViolation",
    "OpenAPIDriftVerdict",
    "vaccinate_openapi",
]
