"""MCP 2026-07-28 request header-integrity conformance (SEP-2243).

The MCP 2026-07-28 Streamable HTTP transport mirrors selected body fields into
HTTP routing headers so operational infrastructure can route on the operation
without inspecting the body, and mandates a server-side integrity rule between
those headers and the body (SEP-2243). Because the edge routes/rate-limits/
authorizes on the headers while the server executes the body, a request whose
headers disagree with its body is a confused-deputy vector: one operation is
routed past the gateway while a different one runs. Verbatim from the ratified
2026-07-28 spec
(https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http):

    Standard request headers — ``Mcp-Method`` (source ``method``) is
    "Required For: All requests"; ``Mcp-Name`` (source ``params.name`` or
    ``params.uri``) is "Required For: ``tools/call``, ``resources/read``,
    ``prompts/get`` requests". "These headers are REQUIRED for compliance."

    Server Validation — "Servers that process the request body MUST reject
    requests where the values specified in the headers do not match the
    corresponding values in the request body."

So ``Mcp-Method`` is required on every request; ``Mcp-Name`` is required only on
the name-bearing methods above (requiring it on, e.g., ``tools/list`` would be a
benign-request false positive, stricter than spec).

This module provides that single contract check, built **only** on stdlib
mapping traversal — it adds no new detection engine:

* :func:`validate_header_body_integrity` — fail closed (deny) when a required
  routing header is absent, or when ``Mcp-Method`` / ``Mcp-Name`` disagree with
  the request body's method / operation name. On any violation it raises
  :class:`HeaderBodyMismatchError`, which carries a structured ``audit_event``
  mapping for the audit log.

Every spelling of a routing header is read, and they must agree. With a ``headers``
mapping (or a list of ``(name, value)`` pairs, the ASGI shape) present, those are the
transport's headers and a top-level key spelled like one is a body member: it can never
stand in for the header, and if its value differs the request is refused. Until 0.10.28
a body key such as ``mcp-name`` was read before the real ``headers`` mapping, so the
check compared the body with itself while the edge routed the real header. The flattened
form (headers merged into the top level, no ``headers`` mapping) still works; two
spellings there that disagree are refused too.

References:
    - MCP 2026-07-28 specification (final).
    - SEP-2243 — ``Mcp-Method`` / ``Mcp-Name`` routing headers + header/body
      integrity ("Servers reject requests where the headers and body disagree").
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

__all__ = [
    "METHOD_HEADER",
    "NAME_BEARING_METHODS",
    "NAME_HEADER",
    "HeaderBodyMismatchError",
    "validate_header_body_integrity",
]

#: Routing header carrying the JSON-RPC method (SEP-2243). Required on all requests.
METHOD_HEADER = "Mcp-Method"

#: Routing header carrying the operation / tool name (SEP-2243).
NAME_HEADER = "Mcp-Name"

#: SEP-2243 scopes the ``Mcp-Name`` requirement to exactly these methods (its
#: source field is ``params.name`` / ``params.uri``). Every other method carries
#: ``Mcp-Method`` but no ``Mcp-Name``, so requiring the name header on them is
#: stricter than spec.
NAME_BEARING_METHODS = frozenset({"tools/call", "resources/read", "prompts/get"})


class HeaderBodyMismatchError(ValueError):
    """Raised when SEP-2243 routing headers are missing or disagree with the body.

    The structured event describing the violation is attached as
    :attr:`audit_event` so the ``@Airlock`` seam can log a machine-readable
    record of the rejected request.
    """

    def __init__(self, message: str, audit_event: Mapping[str, Any]) -> None:
        super().__init__(message)
        #: Structured, machine-readable description of the rejection.
        self.audit_event: dict[str, Any] = dict(audit_event)


class _Refusal(Exception):
    """Internal: a reason and message the validator turns into a structured rejection."""

    def __init__(
        self,
        reason: str,
        message: str,
        *,
        header_value: Any = None,
        conflicting_values: list[Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message
        #: The value the authoritative spelling of the header carries, when known.
        self.header_value = header_value
        #: Every value found under a spelling of the header, when they disagree.
        self.conflicting_values = conflicting_values


def _text(value: Any) -> Any:
    """A ``bytes`` header name or value as text (RFC 9110 field values are Latin-1)."""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("latin-1")
    return value


def _header_pairs(container: Any) -> list[tuple[Any, Any]]:
    """The ``(name, value)`` pairs of a ``headers`` mapping or an ASGI-style pair list.

    Raises:
        _Refusal: ``unreadable_headers`` for any other shape, or a list item that is
            not a two-item pair.
    """
    if isinstance(container, Mapping):
        return list(container.items())
    if isinstance(container, (list, tuple)):
        pairs: list[tuple[Any, Any]] = []
        for item in container:
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                raise _Refusal(
                    "unreadable_headers",
                    f"headers item {item!r} is not a (name, value) pair (SEP-2243)",
                )
            pairs.append((item[0], item[1]))
        return pairs
    raise _Refusal(
        "unreadable_headers",
        f"headers is a {type(container).__name__}, not a mapping or a list of "
        "(name, value) pairs; refusing rather than skipping it (SEP-2243)",
    )


def _spelled(pairs: list[tuple[Any, Any]], wanted: str) -> list[Any]:
    """Every value ``pairs`` hold under a spelling of header ``wanted`` (case-insensitive)."""
    found: list[Any] = []
    for key, value in pairs:
        name = _text(key)
        if isinstance(name, str) and name.lower() == wanted:
            found.append(_text(value))
    return found


def _same(left: Any, right: Any) -> bool:
    """Equality that never raises (an object whose ``==`` raises compares unequal)."""
    try:
        return bool(left == right)
    except Exception:  # noqa: BLE001 - an uncomparable value is a disagreement
        return False


def _header_value(
    top_pairs: list[tuple[Any, Any]],
    header_pairs: list[tuple[Any, Any]] | None,
    name: str,
    reason: str,
) -> Any:
    """The one value header ``name`` carries, refusing a request that spells it two ways.

    With a ``headers`` container present (``header_pairs`` is not None) the header is read
    from it alone: a top-level key with the header's spelling is a body member, so it can
    only agree with the transport's value or be refused, never supply it. Without one (the
    flattened form) the top level is the header set. Either way, every spelling found must
    carry the same value.

    Raises:
        _Refusal: ``reason`` when two spellings disagree.
    """
    wanted = name.lower()
    from_body = _spelled(top_pairs, wanted)
    if header_pairs is None:
        authoritative = from_body
        shadows: list[Any] = []
    else:
        authoritative = _spelled(header_pairs, wanted)
        shadows = from_body
    value = authoritative[0] if authoritative else None
    found = [*authoritative, *shadows]
    for other in authoritative[1:]:
        if not _same(other, value):
            raise _Refusal(
                reason,
                f"{name!r} appears more than once with values that disagree "
                f"({value!r} vs {other!r}); refusing an ambiguous routing header (SEP-2243)",
                header_value=value,
                conflicting_values=found,
            )
    for other in shadows:
        if not _same(other, value):
            raise _Refusal(
                reason,
                f"a body member spelled like the {name!r} header carries {other!r} while "
                f"the transport header carries {value!r}; a body key cannot shadow a "
                "routing header (SEP-2243)",
                header_value=value,
                conflicting_values=found,
            )
    return value


def _body_method(request: Mapping[str, Any]) -> Any:
    """The JSON-RPC method the body actually invokes."""
    return request.get("method")


def _body_name(request: Mapping[str, Any], method: Any) -> Any:
    """The operation/tool name the body actually targets.

    SEP-2243's ``Mcp-Name`` source is ``params.name`` (``tools/call``,
    ``prompts/get``) or ``params.uri`` (``resources/read``); a flattened
    top-level ``name`` is accepted too. For a name-bearing method the method's own
    source is read: a ``resources/read`` server reads ``params.uri``, so a matching
    ``params.name`` beside a different ``uri`` is a decoy and is refused.

    Raises:
        _Refusal: ``ambiguous_body_name`` when a name-bearing method's ``params`` carries
            a ``name`` and a ``uri`` that disagree; ``unreadable_body_name`` when its
            ``params`` is present but not a mapping.
    """
    params = request.get("params")
    name_bearing = isinstance(method, str) and method in NAME_BEARING_METHODS
    if isinstance(params, Mapping):
        if name_bearing:
            source, other = ("uri", "name") if method == "resources/read" else ("name", "uri")
            if source in params and other in params and not _same(params[source], params[other]):
                raise _Refusal(
                    "ambiguous_body_name",
                    f"{method!r} params carry name {params.get('name')!r} and uri "
                    f"{params.get('uri')!r}; the server reads params.{source}, so the "
                    "other is a decoy (SEP-2243)",
                )
            if source in params:
                return params[source]
            if other in params:
                return params[other]
        else:
            if "name" in params:
                return params["name"]
            if "uri" in params:
                return params["uri"]
    elif params is not None and name_bearing:
        raise _Refusal(
            "unreadable_body_name",
            f"{method!r} params is a {type(params).__name__}, not a mapping, so the "
            "operation name cannot be read (SEP-2243)",
        )
    return request.get("name")


def _reject(
    reason: str,
    message: str,
    *,
    header_method: Any,
    body_method: Any,
    header_name: Any,
    body_name: Any,
) -> HeaderBodyMismatchError:
    """Build the structured-audit-carrying rejection error."""
    audit_event = {
        "event": "mcp.header_integrity.reject",
        "spec": "SEP-2243",
        "reason": reason,
        "header_method": header_method,
        "body_method": body_method,
        "header_name": header_name,
        "body_name": body_name,
    }
    return HeaderBodyMismatchError(message, audit_event)


def _read_request(
    request: Any, *, method_header: str, name_header: str
) -> tuple[Any, Any, Any, Any]:
    """``(header_method, body_method, header_name, body_name)`` of ``request``.

    Raises:
        HeaderBodyMismatchError: The request, its ``headers`` or a name-bearing method's
            ``params`` cannot be read, or a routing header is spelled twice (or as a body
            member) with values that disagree.
    """
    if not isinstance(request, Mapping):
        raise _reject(
            "unreadable_request",
            f"request is a {type(request).__name__}, not a mapping; refusing rather than "
            "skipping it (SEP-2243)",
            header_method=None,
            body_method=None,
            header_name=None,
            body_name=None,
        )
    body_method = _body_method(request)
    header_method: Any = None
    header_name: Any = None
    try:
        top_pairs = list(request.items())
        raw_headers = request.get("headers")
        header_pairs = None if raw_headers is None else _header_pairs(raw_headers)
        header_method = _header_value(
            top_pairs, header_pairs, method_header, "conflicting_method_header"
        )
        header_name = _header_value(top_pairs, header_pairs, name_header, "conflicting_name_header")
        return header_method, body_method, header_name, _body_name(request, body_method)
    except _Refusal as refusal:
        if refusal.reason == "conflicting_method_header":
            header_method = refusal.header_value
        elif refusal.reason == "conflicting_name_header":
            header_name = refusal.header_value
        error = _reject(
            refusal.reason,
            refusal.message,
            header_method=header_method,
            body_method=body_method,
            header_name=header_name,
            body_name=None,
        )
        if refusal.conflicting_values is not None:
            error.audit_event["conflicting_values"] = refusal.conflicting_values
        raise error from None


def validate_header_body_integrity(
    request: Mapping[str, Any],
    *,
    method_header: str = METHOD_HEADER,
    name_header: str = NAME_HEADER,
) -> None:
    """Reject a request whose SEP-2243 routing headers are missing or disagree with the body.

    Args:
        request: The request / tool-call mapping. Headers are read from a
            ``headers`` sub-mapping or list of ``(name, value)`` pairs (or, flattened,
            the top level); the body method is ``request['method']`` and the body
            operation name is ``request['params']['name']`` (``params.uri`` for
            ``resources/read``; a top-level ``name`` in the flattened form).
        method_header: Header carrying the JSON-RPC method (default ``Mcp-Method``).
        name_header: Header carrying the operation name (default ``Mcp-Name``).

    Raises:
        HeaderBodyMismatchError: If a required routing header is absent/empty, if a
            header disagrees with the corresponding body field, if a header is spelled
            twice (or as a body member) with values that disagree, or if the request,
            its ``headers`` or a name-bearing method's ``params`` cannot be read. The
            raised error carries a structured ``audit_event`` mapping.
    """
    header_method, body_method, header_name, body_name = _read_request(
        request, method_header=method_header, name_header=name_header
    )

    # (a) SEP-2243: ``Mcp-Method`` is REQUIRED on every request; ``Mcp-Name`` is
    #     REQUIRED only on the name-bearing methods (tools/call, resources/read,
    #     prompts/get). Deny-by-default: a required-but-absent header is a rejected
    #     request. Requiring ``Mcp-Name`` on, e.g., ``tools/list`` would be a
    #     benign-request false positive (stricter than spec), so it is not required
    #     there.
    if header_method is None or (isinstance(header_method, str) and header_method == ""):
        raise _reject(
            "missing_method_header",
            f"required {method_header!r} routing header is absent (SEP-2243)",
            header_method=header_method,
            body_method=body_method,
            header_name=header_name,
            body_name=body_name,
        )
    name_required = isinstance(body_method, str) and body_method in NAME_BEARING_METHODS
    if name_required and (
        header_name is None or (isinstance(header_name, str) and not header_name)
    ):
        raise _reject(
            "missing_name_header",
            f"required {name_header!r} routing header is absent for {body_method!r} "
            "(SEP-2243 name-bearing method)",
            header_method=header_method,
            body_method=body_method,
            header_name=header_name,
            body_name=body_name,
        )

    # (b) "Servers reject requests where the headers and body disagree" (SEP-2243).
    #     Compared whenever the body declares the corresponding field.
    if body_method is not None and not _same(header_method, body_method):
        raise _reject(
            "method_mismatch",
            f"{method_header!r}={header_method!r} disagrees with body method "
            f"{body_method!r} (SEP-2243)",
            header_method=header_method,
            body_method=body_method,
            header_name=header_name,
            body_name=body_name,
        )
    if body_name is not None and not _same(header_name, body_name):
        raise _reject(
            "name_mismatch",
            f"{name_header!r}={header_name!r} disagrees with body name {body_name!r} (SEP-2243)",
            header_method=header_method,
            body_method=body_method,
            header_name=header_name,
            body_name=body_name,
        )
