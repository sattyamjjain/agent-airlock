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

``Mcp-Name`` can arrive encoded. A name a header cannot carry plainly travels as
``=?base64?<payload>?=``, the spec's "Value Encoding" section requires a server to decode it
before comparing it with the body, and a client must also encode a plain value shaped like
that, so any value of that shape is read as encoded. The payload must be base64, canonical
(re-encoding gives the same text) and strict UTF-8, or the request is refused as
``malformed_name_header``. So is a plain value a header cannot carry: anything but visible
ASCII, space and tab, or whitespace at either end (the same section, and "a header value
contains invalid characters" among its validation failures). The audit event keeps the raw
value in ``header_name`` beside the decoded one in ``header_name_decoded``. ``Mcp-Method``
has no encoded form. Until 0.10.32 the raw value was compared, so a valid client was refused
and a malformed one got the wrong reason (``name_mismatch``).

References:
    - MCP 2026-07-28 specification (final).
    - SEP-2243 — ``Mcp-Method`` / ``Mcp-Name`` routing headers + header/body
      integrity ("Servers reject requests where the headers and body disagree").
"""

from __future__ import annotations

import base64
import re
from collections.abc import Mapping
from decimal import Decimal, InvalidOperation
from typing import Any

__all__ = [
    "METHOD_HEADER",
    "NAME_BEARING_METHODS",
    "NAME_HEADER",
    "PARAM_HEADER_PREFIX",
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

#: The markers of an encoded ``Mcp-Name``, exactly as the spec spells them (case-sensitive).
_ENCODED_PREFIX = "=?base64?"
_ENCODED_SUFFIX = "?="

#: A tool parameter annotated ``x-mcp-header: <name>`` is mirrored into ``Mcp-Param-<name>``.
PARAM_HEADER_PREFIX = "Mcp-Param-"
_PARAM_ANNOTATION = "x-mcp-header"
#: RFC 9110 section 5.1 ``1*tchar``: what an ``x-mcp-header`` value must match.
_TCHAR = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
#: ``x-mcp-header`` applies to these JSON Schema types only (``number`` is excluded).
_PARAM_TYPES = frozenset({"integer", "string", "boolean"})
#: The JavaScript safe-integer bound an annotated integer must stay within.
_SAFE_INTEGER = 2**53 - 1
#: How deep a schema is walked looking for annotations before it is refused unread.
_MAX_SCHEMA_DEPTH = 64


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


def _decode_encoded_name(value: str, name: str, reason: str = "malformed_name_header") -> str:
    """The name inside an ``=?base64?<payload>?=`` value.

    Raises:
        _Refusal: ``reason`` (``malformed_name_header`` by default) when the payload is not
            base64, is not canonical or is not strict UTF-8. A value too short to hold both
            markers has no payload.
    """
    form = f"{name!r} is in the =?base64?...?= form, but its payload"
    if len(value) < len(_ENCODED_PREFIX) + len(_ENCODED_SUFFIX):
        raise _Refusal(reason, f"{form} is missing (SEP-2243)")
    payload = value[len(_ENCODED_PREFIX) : -len(_ENCODED_SUFFIX)]
    try:
        # Not only binascii.Error: a non-ASCII str raises plain ValueError (python-sdk #3817).
        decoded = base64.b64decode(payload, validate=True)
    except ValueError:
        raise _Refusal(reason, f"{form} is not base64 (SEP-2243)") from None
    if base64.b64encode(decoded).decode("ascii") != payload:
        raise _Refusal(reason, f"{form} is not canonical base64 (SEP-2243)")
    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError:
        raise _Refusal(reason, f"{form} is not UTF-8 (SEP-2243)") from None


def _decode_name_header(
    value: Any, name: str = NAME_HEADER, reason: str = "malformed_name_header"
) -> Any:
    """The operation name ``Mcp-Name`` carries, for comparing with the body.

    A value in the sentinel form (it starts with ``=?base64?`` and ends with ``?=``) is
    decoded. Any other value is returned as it is, the very object passed in, a value that is
    not a string included: comparing it refuses it.

    Raises:
        _Refusal: ``malformed_name_header`` when the sentinel form does not decode, or when a
            plain value holds a character a header cannot carry or whitespace at either end,
            which a client must have encoded.
    """
    if not isinstance(value, str):
        return value
    if value.startswith(_ENCODED_PREFIX) and value.endswith(_ENCODED_SUFFIX):
        return _decode_encoded_name(value, name, reason)
    if not all(char == "\t" or " " <= char <= "~" for char in value):
        raise _Refusal(
            reason,
            f"{name!r} holds a character a plain header value cannot carry, so it must use "
            "the =?base64?...?= form (SEP-2243)",
        )
    if value != value.strip(" \t"):
        raise _Refusal(
            reason,
            f"{name!r} has whitespace at one end, so it must use the =?base64?...?= form "
            "(SEP-2243)",
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
    header_name_decoded: Any = None,
) -> HeaderBodyMismatchError:
    """Build the structured-audit-carrying rejection error.

    ``header_name`` is the raw value; ``header_name_decoded`` is what it decodes to, the same
    value when it is plain, and None when it is absent, malformed or not reached.
    """
    audit_event = {
        "event": "mcp.header_integrity.reject",
        "spec": "SEP-2243",
        "reason": reason,
        "header_method": header_method,
        "body_method": body_method,
        "header_name": header_name,
        "header_name_decoded": header_name_decoded,
        "body_name": body_name,
    }
    return HeaderBodyMismatchError(message, audit_event)


def _read_request(
    request: Any, *, method_header: str, name_header: str
) -> tuple[Any, Any, Any, Any, Any]:
    """``(header_method, body_method, header_name, header_name_decoded, body_name)``.

    Raises:
        HeaderBodyMismatchError: The request, its ``headers`` or a name-bearing method's
            ``params`` cannot be read, a routing header is spelled twice (or as a body
            member) with values that disagree, or the name header is malformed.
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
    decoded_name: Any = None
    try:
        top_pairs = list(request.items())
        raw_headers = request.get("headers")
        header_pairs = None if raw_headers is None else _header_pairs(raw_headers)
        header_method = _header_value(
            top_pairs, header_pairs, method_header, "conflicting_method_header"
        )
        # Spellings are compared raw above: a client has no reason to send one name two ways.
        header_name = _header_value(top_pairs, header_pairs, name_header, "conflicting_name_header")
        decoded_name = _decode_name_header(header_name, name_header)
        body_name = _body_name(request, body_method)
        return header_method, body_method, header_name, decoded_name, body_name
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
            header_name_decoded=decoded_name,
            body_name=None,
        )
        if refusal.conflicting_values is not None:
            error.audit_event["conflicting_values"] = refusal.conflicting_values
        raise error from None


def _annotation_count(node: Any, depth: int = 0) -> int:
    """How many ``x-mcp-header`` keys ``node`` holds anywhere, however reached.

    Raises:
        _Refusal: ``invalid_param_schema`` for a schema nested past the depth bound.
    """
    if depth > _MAX_SCHEMA_DEPTH:
        raise _Refusal(
            "invalid_param_schema",
            "the tool's inputSchema is nested too deeply to read its x-mcp-header annotations",
        )
    if isinstance(node, Mapping):
        own = 1 if _PARAM_ANNOTATION in node else 0
        return own + sum(_annotation_count(child, depth + 1) for child in node.values())
    if isinstance(node, list):
        return sum(_annotation_count(child, depth + 1) for child in node)
    return 0


def _declared_type(prop: Mapping[str, Any]) -> str | None:
    """The one primitive type an annotated property declares, or None if it is not one."""
    declared = prop.get("type")
    if isinstance(declared, list):
        kinds = [kind for kind in declared if kind != "null"]
        declared = kinds[0] if len(kinds) == 1 else None
    return declared if isinstance(declared, str) and declared in _PARAM_TYPES else None


def _param_annotations(schema: Any) -> dict[str, tuple[str, tuple[str, ...], str]]:
    """``{lowercased header name: (x-mcp-header value, property path, type)}``.

    Only properties reached through a chain of ``properties`` keys count (the spec's
    statically reachable rule); an annotation anywhere else makes the definition invalid.

    Raises:
        _Refusal: ``invalid_param_schema`` for a schema the spec says a client must reject:
            an annotation that is empty, not an RFC 9110 token, repeated (case-insensitive),
            on a type other than integer, string or boolean, or not statically reachable.
    """
    if not isinstance(schema, Mapping):
        raise _Refusal(
            "invalid_param_schema",
            f"the tool's inputSchema is a {type(schema).__name__}, not a mapping",
        )
    found: dict[str, tuple[str, tuple[str, ...], str]] = {}
    stack: list[tuple[Mapping[str, Any], tuple[str, ...]]] = [(schema, ())]
    while stack:
        node, path = stack.pop()
        properties = node.get("properties")
        if not isinstance(properties, Mapping):
            continue
        for key, prop in properties.items():
            if not isinstance(prop, Mapping):
                continue
            here = (*path, str(key))
            if _PARAM_ANNOTATION in prop:
                value = prop[_PARAM_ANNOTATION]
                where = ".".join(here)
                if not isinstance(value, str) or not _TCHAR.fullmatch(value):
                    raise _Refusal(
                        "invalid_param_schema",
                        f"x-mcp-header on {where!r} is not an RFC 9110 token (SEP-2243)",
                    )
                if value.lower() in found:
                    raise _Refusal(
                        "invalid_param_schema",
                        f"x-mcp-header {value!r} is used twice, ignoring case (SEP-2243)",
                    )
                kind = _declared_type(prop)
                if kind is None:
                    raise _Refusal(
                        "invalid_param_schema",
                        f"x-mcp-header on {where!r} needs type integer, string or boolean "
                        "(SEP-2243)",
                    )
                found[value.lower()] = (value, here, kind)
            stack.append((prop, here))
    if _annotation_count(schema) != len(found):
        raise _Refusal(
            "invalid_param_schema",
            "an x-mcp-header annotation is not reachable through properties alone (it sits "
            "under items, a composition or conditional keyword, or $ref), so the tool "
            "definition is invalid (SEP-2243)",
        )
    return found


_ABSENT = object()


def _argument_at(arguments: Any, path: tuple[str, ...]) -> Any:
    """The call's argument at ``path``, or ``_ABSENT`` when there is none (or it is null)."""
    node = arguments
    for key in path:
        if not isinstance(node, Mapping) or key not in node:
            return _ABSENT
        node = node[key]
    return _ABSENT if node is None else node


def _param_matches(decoded: str, body: Any, kind: str) -> bool:
    """Whether a decoded ``Mcp-Param-*`` value carries the body's argument of type ``kind``."""
    if kind == "string":
        return isinstance(body, str) and decoded == body
    if kind == "boolean":
        return isinstance(body, bool) and decoded == ("true" if body else "false")
    if isinstance(body, bool) or not isinstance(body, int) or abs(body) > _SAFE_INTEGER:
        return False
    try:
        number = Decimal(decoded)
    except InvalidOperation:
        return False
    # Compared numerically, as the spec asks: ``42.0`` carries ``42``.
    return number.is_finite() and number == body


def _check_param_headers(request: Mapping[str, Any], schema: Any) -> None:
    """Refuse a ``tools/call`` whose ``Mcp-Param-*`` headers disagree with its arguments.

    Raises:
        _Refusal: ``invalid_param_schema``, ``missing_param_header``,
            ``malformed_param_header``, ``conflicting_param_header`` or ``param_mismatch``,
            carrying the header in ``header_value`` (never the value it holds).
    """
    annotations = _param_annotations(schema)
    if not annotations:
        return
    params = request.get("params")
    arguments = params.get("arguments") if isinstance(params, Mapping) else None
    top_pairs = list(request.items())
    raw_headers = request.get("headers")
    header_pairs = None if raw_headers is None else _header_pairs(raw_headers)
    for spelled, path, kind in annotations.values():
        header = f"{PARAM_HEADER_PREFIX}{spelled}"
        where = ".".join(path)
        try:
            raw = _header_value(top_pairs, header_pairs, header, "conflicting_param_header")
        except _Refusal as refusal:
            raise _Refusal(refusal.reason, refusal.message, header_value=header) from None
        body = _argument_at(arguments, path)
        if body is _ABSENT:
            if raw is not None:
                raise _Refusal(
                    "param_mismatch",
                    f"{header!r} is present but argument {where!r} is absent or null (SEP-2243)",
                    header_value=header,
                )
            continue
        if raw is None:
            raise _Refusal(
                "missing_param_header",
                f"argument {where!r} has a value but its {header!r} header is absent (SEP-2243)",
                header_value=header,
            )
        try:
            decoded = _decode_name_header(_text(raw), header, "malformed_param_header")
        except _Refusal as refusal:
            raise _Refusal(refusal.reason, refusal.message, header_value=header) from None
        if not isinstance(decoded, str) or not _param_matches(decoded, body, kind):
            raise _Refusal(
                "param_mismatch",
                f"{header!r} disagrees with argument {where!r} (SEP-2243)",
                header_value=header,
            )


def validate_header_body_integrity(
    request: Mapping[str, Any],
    *,
    method_header: str = METHOD_HEADER,
    name_header: str = NAME_HEADER,
    input_schema: Mapping[str, Any] | None = None,
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
        input_schema: The called tool's ``inputSchema``, for a ``tools/call``. When given,
            every parameter it annotates with ``x-mcp-header`` is checked too: its
            ``Mcp-Param-{name}`` header must be present exactly when the argument has a
            value, decode, and carry that value (integers compared numerically). An
            unrecognised ``Mcp-Param-*`` header is ignored, as the spec has servers do.
            Since 0.10.33; until then ``Mcp-Param-*`` was not read at all.

    An encoded ``Mcp-Name`` or ``Mcp-Param-*`` value (``=?base64?<payload>?=``) is decoded
    before it is compared.

    Raises:
        HeaderBodyMismatchError: If a required routing header is absent/empty, if a
            header disagrees with the corresponding body field, if a header is spelled
            twice (or as a body member) with values that disagree, if the name header is
            malformed (``malformed_name_header``: an encoded form that does not decode, or
            a plain value a header cannot carry), or if the request, its ``headers`` or a
            name-bearing method's ``params`` cannot be read. The raised error carries a
            structured ``audit_event`` mapping, with the raw name in ``header_name`` and
            the decoded one in ``header_name_decoded``.
    """
    header_method, body_method, header_name, decoded_name, body_name = _read_request(
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
            header_name_decoded=decoded_name,
            body_name=body_name,
        )
    name_required = isinstance(body_method, str) and body_method in NAME_BEARING_METHODS
    # The decoded value: an encoded empty name (``=?base64??=``) names nothing either.
    if name_required and (
        decoded_name is None or (isinstance(decoded_name, str) and not decoded_name)
    ):
        raise _reject(
            "missing_name_header",
            f"required {name_header!r} routing header is absent for {body_method!r} "
            "(SEP-2243 name-bearing method)",
            header_method=header_method,
            body_method=body_method,
            header_name=header_name,
            header_name_decoded=decoded_name,
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
            header_name_decoded=decoded_name,
            body_name=body_name,
        )
    if body_name is not None and not _same(decoded_name, body_name):
        decoded = "" if decoded_name is header_name else f" (decoded {decoded_name!r})"
        raise _reject(
            "name_mismatch",
            f"{name_header!r}={header_name!r}{decoded} disagrees with body name {body_name!r} "
            "(SEP-2243)",
            header_method=header_method,
            body_method=body_method,
            header_name=header_name,
            header_name_decoded=decoded_name,
            body_name=body_name,
        )

    # (c) Mcp-Param-{Name} (x-mcp-header). The schema says which arguments are mirrored.
    if input_schema is not None and body_method == "tools/call":
        try:
            _check_param_headers(request, input_schema)
        except _Refusal as refusal:
            error = _reject(
                refusal.reason,
                refusal.message,
                header_method=header_method,
                body_method=body_method,
                header_name=header_name,
                header_name_decoded=decoded_name,
                body_name=body_name,
            )
            # The header's name, never its value: a mirrored argument can be sensitive.
            error.audit_event["param_header"] = refusal.header_value
            raise error from None
