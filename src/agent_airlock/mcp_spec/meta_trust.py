"""MCP 2026-07-28 ``_meta`` trust-boundary guard — treat ``_meta`` as untrusted input.

The MCP 2026-07-28 final spec makes every request **self-describing**: the client's
protocol version, client info, and capabilities now travel in a ``_meta`` object on
each call, so any stateless server instance can answer any request. Those fields are
**unsigned**. A server that keys an authorization or routing decision off them is
trusting attacker-controlled data. Akamai's 2026-06-25 review ("The New MCP
Specification: What Security Teams Must Prepare For",
https://www.akamai.com/blog/security-research/new-mcp-specification-security-teams-must-prepare)
put it plainly:

    "Because these fields lack cryptographic signing, if a server thoughtlessly
    trusts this metadata for routing or authorization decisions, a single malicious
    request can instantly lead to privilege escalation or cross-tenant data access."

This module provides the single contract check that closes that class, built **only**
on stdlib mapping traversal (no new detection engine, Pydantic-only core). It is a
**trust-boundary reading of the 2026-07-28 spec — not a SEP id and not a CVE.**

* :func:`validate_meta_trust` — deny-by-default. With a :class:`MetaPin` (the
  server-side, out-of-band declaration of the identity / protocol version /
  capabilities the caller is ENTITLED to — an OAuth claim, an mTLS identity, a
  deployment config), any ``_meta`` value that DISAGREES with the pin fails closed.
  With no pin, any ``_meta`` key that asserts a capability / role / scope / permission
  that would BROADEN what the call may do is refused (the operator opts into a
  narrower set). Type + shape discipline runs regardless: ``_meta`` must be a mapping,
  identity/role values must be scalar, keys that collide under case / unicode
  normalisation are refused (a confused-deputy vector), and total ``_meta`` size is
  capped.

  On any violation it raises :class:`MetaTrustError`, which carries a structured
  ``audit_event`` mapping in the same shape
  :class:`~agent_airlock.mcp_spec.header_integrity.HeaderBodyMismatchError` uses
  (``event`` / ``reason`` / the specific keys involved).

References:
    - MCP 2026-07-28 specification (final) — ``_meta`` on every request.
    - Akamai (2026-06-25): client-controlled metadata manipulation.
"""

from __future__ import annotations

import json
import re
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "DEFAULT_ESCALATION_TOKENS",
    "DEFAULT_MAX_META_BYTES",
    "MetaPin",
    "MetaTrustConfig",
    "MetaTrustError",
    "validate_meta_trust",
]

#: Word-tokens in a ``_meta`` key that mark it as identity / privilege-shaped —
#: asserting one is an authorization-broadening claim the server did not grant.
#: The operator can narrow this via :class:`MetaTrustConfig`.
DEFAULT_ESCALATION_TOKENS: frozenset[str] = frozenset(
    {
        "capability",
        "capabilities",
        "role",
        "roles",
        "scope",
        "scopes",
        "permission",
        "permissions",
        "admin",
        "tenant",
        "privilege",
        "privileges",
        "grant",
        "grants",
        "entitlement",
        "entitlements",
        "acl",
        "elevated",
        "sudo",
        "superuser",
    }
)

#: Tokens whose value is legitimately structured (a capabilities object / list) and
#: is validated by set-subset against the pin rather than by scalar discipline.
_CAPABILITY_TOKENS: frozenset[str] = frozenset({"capability", "capabilities"})

#: Default cap on the serialized size of a ``_meta`` block (bytes). Generous enough
#: that ordinary metadata (traceparent, progressToken, small annotations) passes.
DEFAULT_MAX_META_BYTES = 16384

_SCALAR_TYPES = (str, int, float, bool, type(None))
_CAMEL_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|[0-9]+")


@dataclass(frozen=True)
class MetaPin:
    """Server-side declaration of what a caller is ENTITLED to (established out of band).

    A pin is the authoritative record — an OAuth claim, an mTLS identity, deployment
    config — that ``_meta`` is checked *against*. Any field the pin sets that ``_meta``
    contradicts is a fail-closed denial. Fields left ``None`` are not pinned (``_meta``
    may carry them, but they are still subject to the no-pin escalation sweep unless a
    matching ``fields`` entry whitelists them).

    Attributes:
        protocol_version: The protocol version the caller may declare.
        client_name: The client name the caller may declare (``clientInfo.name``).
        client_version: The client version the caller may declare.
        capabilities: The entitled capability set. A ``_meta`` capability outside this
            set is an escalation and is denied.
        fields: Arbitrary ``_meta`` key → expected value. A present-but-different value
            is a denial; an entry here also whitelists that key from the escalation sweep.
    """

    protocol_version: str | None = None
    client_name: str | None = None
    client_version: str | None = None
    capabilities: frozenset[str] | None = None
    fields: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class MetaTrustConfig:
    """Tunables for :func:`validate_meta_trust` (deny-by-default; operator narrows)."""

    escalation_tokens: frozenset[str] = DEFAULT_ESCALATION_TOKENS
    max_meta_bytes: int = DEFAULT_MAX_META_BYTES
    #: Keys under which the ``_meta`` block may live (top level or under ``params``).
    meta_keys: tuple[str, ...] = ("_meta", "meta")


class MetaTrustError(ValueError):
    """Raised when ``_meta`` is untrustworthy for an authorization / routing decision.

    Carries a structured, machine-readable :attr:`audit_event` in the same shape
    :class:`~agent_airlock.mcp_spec.header_integrity.HeaderBodyMismatchError` uses, so
    the ``@Airlock`` seam can log a record of the rejected request.
    """

    def __init__(self, message: str, audit_event: Mapping[str, Any]) -> None:
        super().__init__(message)
        #: Structured, machine-readable description of the rejection.
        self.audit_event: dict[str, Any] = dict(audit_event)


def _reject(reason: str, message: str, **specifics: Any) -> MetaTrustError:
    """Build the structured-audit-carrying rejection error (mirrors HeaderBodyMismatchError)."""
    audit_event: dict[str, Any] = {"event": "mcp.meta_trust.reject", "reason": reason}
    audit_event.update(specifics)
    return MetaTrustError(message, audit_event)


def _extract_meta(request: Mapping[str, Any], meta_keys: tuple[str, ...]) -> Any:
    """Find the ``_meta`` block at the top level or under ``params``; ``None`` if absent."""
    params = request.get("params")
    containers: list[Mapping[str, Any]] = [request]
    if isinstance(params, Mapping):
        containers.append(params)
    for container in containers:
        for key in meta_keys:
            if key in container:
                return container[key]
    return None


def _key_tokens(key: str) -> set[str]:
    """Split a ``_meta`` key into casefolded word tokens (camelCase + separators)."""
    tokens: set[str] = set()
    for part in re.split(r"[^0-9A-Za-z]+", key):
        for match in _CAMEL_RE.findall(part):
            tokens.add(match.casefold())
    return tokens


def _normalized_key(key: str) -> str:
    """NFKC + casefold — the form two keys collide on in a confused-deputy attack."""
    return unicodedata.normalize("NFKC", key).casefold()


def _is_scalar(value: Any) -> bool:
    return isinstance(value, _SCALAR_TYPES)


def _is_scalar_or_flat_scalar_list(value: Any) -> bool:
    if _is_scalar(value):
        return True
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return all(_is_scalar(item) for item in value)
    return False


def _is_broadening(value: Any) -> bool:
    """Whether an asserted value actually widens privilege (non-empty / truthy)."""
    return bool(value)


def _meta_capabilities(value: Any) -> set[str]:
    """Normalize a ``_meta`` capabilities value to the set of asserted capability names."""
    if isinstance(value, Mapping):
        return {str(k) for k, v in value.items() if v}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return {str(item) for item in value}
    if value:
        return {str(value)}
    return set()


def _check_size(meta: Mapping[str, Any], config: MetaTrustConfig) -> None:
    try:
        size = len(json.dumps(meta, default=str).encode("utf-8"))
    except (TypeError, ValueError):
        # Unserializable content is itself a shape violation → fail closed.
        raise _reject(
            "meta_unserializable",
            "_meta could not be serialized for size accounting — refusing untrusted shape",
        ) from None
    if size > config.max_meta_bytes:
        raise _reject(
            "meta_too_large",
            f"_meta is {size} bytes, over the {config.max_meta_bytes}-byte cap",
            size_bytes=size,
            limit_bytes=config.max_meta_bytes,
        )


def _check_duplicate_keys(meta: Mapping[str, Any]) -> None:
    seen: dict[str, str] = {}
    for key in meta:
        norm = _normalized_key(str(key))
        if norm in seen and seen[norm] != str(key):
            raise _reject(
                "meta_ambiguous_key",
                f"_meta keys {seen[norm]!r} and {key!r} collide under case/unicode "
                "normalization — a confused-deputy vector",
                key=str(key),
                collides_with=seen[norm],
                normalized_key=norm,
            )
        seen[norm] = str(key)


def _check_pin(meta: Mapping[str, Any], pinned: MetaPin) -> None:
    """Deny any ``_meta`` value that disagrees with the entitled pin (fail-closed)."""
    checks: list[tuple[str, str | None, Any]] = [
        (
            "protocolVersion",
            pinned.protocol_version,
            _first(meta, "protocolVersion", "protocol_version"),
        ),
        ("clientInfo.name", pinned.client_name, _client_field(meta, "name", "client_name")),
        (
            "clientInfo.version",
            pinned.client_version,
            _client_field(meta, "version", "client_version"),
        ),
    ]
    for field_name, pin_value, meta_value in checks:
        if pin_value is not None and meta_value is not None and meta_value != pin_value:
            raise _reject(
                "meta_pin_disagreement",
                f"_meta {field_name}={meta_value!r} disagrees with the pinned {pin_value!r}",
                field=field_name,
                meta_value=meta_value,
                pin_value=pin_value,
            )
    if pinned.capabilities is not None:
        asserted = _collect_capabilities(meta)
        extra = asserted - pinned.capabilities
        if extra:
            raise _reject(
                "meta_capability_escalation",
                f"_meta asserts capabilities {sorted(extra)!r} outside the entitled set",
                offending_capabilities=sorted(extra),
                entitled=sorted(pinned.capabilities),
            )
    for key, expected in pinned.fields.items():
        if key in meta and meta[key] != expected:
            raise _reject(
                "meta_pin_disagreement",
                f"_meta {key!r}={meta[key]!r} disagrees with the pinned {expected!r}",
                field=key,
                meta_value=meta[key],
                pin_value=expected,
            )


def _collect_capabilities(meta: Mapping[str, Any]) -> set[str]:
    caps: set[str] = set()
    for key, value in meta.items():
        if _key_tokens(str(key)) & _CAPABILITY_TOKENS:
            caps |= _meta_capabilities(value)
    return caps


def _first(meta: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in meta:
            return meta[key]
    return None


def _client_field(meta: Mapping[str, Any], nested: str, flat: str) -> Any:
    info = meta.get("clientInfo")
    if isinstance(info, Mapping) and nested in info:
        return info[nested]
    return meta.get(flat)


def validate_meta_trust(
    request: Mapping[str, Any],
    *,
    pinned: MetaPin | None = None,
    config: MetaTrustConfig | None = None,
) -> None:
    """Reject a request whose ``_meta`` block cannot be trusted for authorization/routing.

    Args:
        request: The request / tool-call mapping. ``_meta`` is looked for at the top
            level and under ``params`` (keys from ``config.meta_keys``).
        pinned: The server-side entitlement declaration to check ``_meta`` against. When
            supplied, any disagreeing ``_meta`` value fails closed. When omitted, any
            ``_meta`` key asserting a capability/role/scope/permission that would broaden
            the call is refused (deny-by-default).
        config: Tunables (escalation token set, size cap, ``_meta`` lookup keys).

    Raises:
        MetaTrustError: On any trust-boundary violation. The error carries a structured
            ``audit_event`` mapping (``event`` / ``reason`` / the specific keys involved).
    """
    config = config or MetaTrustConfig()
    meta = _extract_meta(request, config.meta_keys)
    if meta is None:
        return  # no _meta → nothing to check
    if not isinstance(meta, Mapping):
        raise _reject(
            "meta_not_mapping",
            f"_meta must be a mapping, got {type(meta).__name__} — refusing untrusted shape",
            meta_type=type(meta).__name__,
        )

    # Type + shape discipline (runs regardless of pin).
    _check_size(meta, config)
    _check_duplicate_keys(meta)

    # Identity / privilege-shaped key sweep.
    for key, value in meta.items():
        tokens = _key_tokens(str(key))
        is_capability = bool(tokens & _CAPABILITY_TOKENS)
        is_escalation = bool(tokens & config.escalation_tokens) or str(key).casefold() in (
            config.escalation_tokens
        )
        if not is_escalation:
            continue
        # (c) Non-capability identity/role values must be scalar (a structured value at
        #     a role/tenant position is a classic confused-deputy vector).
        if not is_capability and not _is_scalar_or_flat_scalar_list(value):
            raise _reject(
                "meta_nonscalar_identity",
                f"_meta {key!r} is an identity/role field with a non-scalar value "
                f"{type(value).__name__} — refusing",
                field=str(key),
                value_type=type(value).__name__,
            )
        if not _is_broadening(value):
            continue
        if pinned is None:
            # (b) deny-by-default: the client asserts privilege the server cannot verify.
            raise _reject(
                "meta_capability_escalation" if is_capability else "meta_role_escalation",
                f"_meta {key!r} asserts a capability/role the server did not grant "
                "(no pin supplied) — refusing to trust client-controlled metadata",
                field=str(key),
                asserted=value if _is_scalar(value) else sorted(_meta_capabilities(value)),
            )
        # Pin supplied: capabilities are validated by subset in _check_pin; a pinned
        # ``fields`` entry whitelists its key. Any other broadening escalation key the
        # pin does not address is still an ungranted assertion → deny.
        if is_capability or str(key) in pinned.fields:
            continue
        raise _reject(
            "meta_role_escalation",
            f"_meta {key!r} asserts a role/scope the pin does not grant — refusing",
            field=str(key),
            asserted=value,
        )

    if pinned is not None:
        _check_pin(meta, pinned)
