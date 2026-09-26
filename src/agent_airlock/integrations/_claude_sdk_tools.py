"""Route a Claude Agent SDK tool's handler through ``Airlock``.

``claude_agent_sdk.tool(name, description, input_schema)`` builds an ``SdkMcpTool`` whose
``handler`` takes a single ``args`` dict, and ``create_sdk_mcp_server`` checks that dict
against a JSON schema built from ``input_schema`` before calling it. Handed the handler as
it is, ``Airlock`` would see one positional parameter, and every gate that reads keyword
arguments (ghost arguments, strict per-argument validation, filesystem paths) would see
nothing inside the dict.

So the handler is fronted by a proxy whose keyword-only signature is derived from
``input_schema``, in the three forms the SDK accepts, and the dict is spread into it:

* ``{"name": str}`` — every key is required, as the SDK marks it.
* a ``TypedDict`` — the keys in ``__required_keys__`` are required. It is recognised
  with ``typing_extensions.is_typeddict``, which also knows a
  ``typing_extensions.TypedDict``. From Python 3.11 the SDK checks with the stdlib
  ``is_typeddict``, which does not (checked with typing_extensions 4.16 on 3.11 to 3.13),
  and advertises such a tool with no properties; the model then learns its keys from
  Airlock's fix hints.
* a JSON schema (``type`` plus ``properties``) — the keys in ``required`` are. A key
  outside ``properties`` is admitted only when ``additionalProperties`` is present and not
  ``false``; the JSON Schema default of admitting it is not taken, because an undeclared
  argument is a ghost argument everywhere else in Airlock.

Each argument is checked against the type the SDK advertises to the model and hands the
handler, not against the Python annotation: the SDK sends a type it does not map as a
string, and a ``float`` field receives the JSON number unconverted (``3`` stays ``3``).
Nested structure (list items, object properties, enums) is left to the SDK's own schema
check, which runs first.

A refusal comes back as an SDK error result (``is_error: True``) carrying Airlock's error
and fix hints. Returned as it was, the SDK would have read no ``content`` from it and
reported an empty success.

Every key in the ``args`` dict comes from the model, so none may start with ``_airlock_``:
``Airlock`` pops ``_airlock_tier`` and ``_airlock_input_tokens`` as a router's control values
before it looks for ghost arguments, which would let the model pick the budget tier its call
is checked against. Such a key is refused at call time, and at wrap time in a schema.
"""

from __future__ import annotations

import copy
import inspect
import keyword
import types
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Annotated, Any, Union, get_args, get_origin

# A Pydantic dependency, so it is in the core install. The stdlib is_typeddict does not
# recognise a typing_extensions.TypedDict, which is a separate class on every version.
from typing_extensions import get_type_hints, is_typeddict

from .._log import structlog
from ..core import Airlock
from ..exceptions import AirlockError
from ..policy import SecurityPolicy
from ._tool_proxy import _adopt_identity

logger = structlog.get_logger("agent-airlock.integrations._claude_sdk_tools")

# Typed Any so a union built at runtime is not read by mypy as a type expression.
_UNION: Any = Union

# The prefix of the keyword arguments Airlock reads as a router's control values.
_RESERVED_PREFIX = "_airlock_"

_JSON_TYPES: dict[str, Any] = {
    "string": str,
    "integer": int,
    "number": int | float,
    "boolean": bool,
    "array": list[Any],
    "object": dict[str, Any],
    "null": type(None),
}

_TYPEDDICT_QUALIFIERS = ("NotRequired", "Required", "ReadOnly")


class _Absent:
    """The default of a key the schema does not require, so an omitted key stays omitted."""

    def __repr__(self) -> str:
        return "<absent>"


_ABSENT = _Absent()


@dataclass(frozen=True)
class _Field:
    annotation: Any
    required: bool


def is_sdk_mcp_tool(obj: Any) -> bool:
    """Whether ``obj`` has the shape of a ``claude_agent_sdk.SdkMcpTool``."""
    return (
        isinstance(getattr(obj, "name", None), str)
        and callable(getattr(obj, "handler", None))
        and hasattr(obj, "input_schema")
    )


def guard_sdk_tool(tool: Any, *, policy: SecurityPolicy | None = None) -> Any:
    """Return a copy of ``tool`` whose handler runs through ``Airlock``.

    Args:
        tool: An ``SdkMcpTool``, or an object of that shape.
        policy: Optional :class:`SecurityPolicy`; its tool lists match ``tool.name``, the
            name the model calls the tool by.

    Returns:
        A shallow copy of ``tool`` with ``handler`` replaced. ``tool`` itself is unchanged.

    Raises:
        AirlockError: ``input_schema`` is not a form the SDK accepts, or declares a key
            that cannot be a Python parameter name or that starts with ``_airlock_``, so
            no contract can be derived from it.
    """
    fields, open_ended = _schema_fields(tool.input_schema, name=tool.name)
    proxy = _spread_proxy(tool.handler, name=tool.name, fields=fields, open_ended=open_ended)
    airlocked: Any = (Airlock(policy=policy) if policy is not None else Airlock())(proxy)

    async def handler(args: Mapping[str, Any] | None) -> Any:
        arguments = dict(args or {})
        reserved = sorted(str(key) for key in arguments if str(key).startswith(_RESERVED_PREFIX))
        if reserved:
            logger.warning("sdk_tool_reserved_arguments_refused", tool=tool.name, keys=reserved)
            return _sdk_error_result(
                {
                    "error": f"AIRLOCK_BLOCK: {reserved} are reserved for Airlock, not arguments",
                    "fix_hints": [f"Call '{tool.name}' without {reserved}"],
                }
            )
        result = await airlocked(**arguments)
        return _sdk_error_result(result) if _is_refusal(result) else result

    guarded = copy.copy(tool)
    guarded.handler = handler
    return guarded


def _spread_proxy(
    handler: Callable[..., Any],
    *,
    name: str,
    fields: dict[str, _Field],
    open_ended: bool,
) -> Callable[..., Any]:
    """An async proxy taking the declared keys as keyword arguments and calling ``handler``."""

    async def proxy(**kwargs: Any) -> Any:
        args = {key: value for key, value in kwargs.items() if value is not _ABSENT}
        result = handler(args)
        return await result if inspect.isawaitable(result) else result

    kw_only = inspect.Parameter.KEYWORD_ONLY
    parameters = [
        inspect.Parameter(
            key,
            kw_only,
            annotation=field.annotation,
            default=inspect.Parameter.empty if field.required else _ABSENT,
        )
        for key, field in fields.items()
    ]
    if open_ended:
        extra = "undeclared_keys"
        while extra in fields:
            extra += "_"
        parameters.append(inspect.Parameter(extra, inspect.Parameter.VAR_KEYWORD, annotation=Any))
    annotations = {param.name: param.annotation for param in parameters}
    _adopt_identity(
        proxy,
        handler,
        name=name,
        signature=inspect.Signature(parameters),
        annotations=annotations,
    )
    return proxy


def _schema_fields(schema: Any, *, name: str) -> tuple[dict[str, _Field], bool]:
    """The keys ``schema`` declares, and whether it also admits keys it does not declare."""
    if isinstance(schema, Mapping):
        if _is_json_schema(schema):
            fields, open_ended = _json_schema_fields(schema, name=name)
        else:
            fields = {key: _Field(_wire_annotation(tp), True) for key, tp in schema.items()}
            open_ended = False
    elif is_typeddict(schema):
        fields, open_ended = _typeddict_fields(schema, name=name), False
    else:
        raise AirlockError(
            f"tool {name!r}: input_schema is a {type(schema).__name__}, not a dict, a "
            "TypedDict or a JSON schema, so Airlock cannot derive the tool's arguments"
        )
    reserved = [key for key in fields if str(key).startswith(_RESERVED_PREFIX)]
    if reserved:
        raise AirlockError(
            f"tool {name!r}: input_schema keys {reserved} start with {_RESERVED_PREFIX!r}, "
            "which Airlock reads as its own control values; rename them"
        )
    invalid = [key for key in fields if not _is_parameter_name(key)]
    if invalid:
        raise AirlockError(
            f"tool {name!r}: input_schema keys {invalid} cannot be Python parameter names "
            "(each must be an identifier and not a keyword such as 'from'). Airlock checks "
            "every argument as a keyword parameter, so it cannot guard this tool until "
            "they are renamed"
        )
    return fields, open_ended


def _is_json_schema(schema: Mapping[Any, Any]) -> bool:
    """The test ``create_sdk_mcp_server`` applies to tell a JSON schema from a type map."""
    return "type" in schema and "properties" in schema and isinstance(schema["type"], str)


def _json_schema_fields(schema: Mapping[str, Any], *, name: str) -> tuple[dict[str, _Field], bool]:
    properties = schema["properties"]
    required = schema.get("required") or []
    if not isinstance(properties, Mapping) or not isinstance(required, list | tuple):
        raise AirlockError(
            f"tool {name!r}: input_schema 'properties' must be an object and 'required' an array"
        )
    fields = {
        key: _Field(_json_annotation(sub), key in required) for key, sub in properties.items()
    }
    for key in required:
        # Required but not described: the key is declared, with any type.
        fields.setdefault(key, _Field(Any, True))
    return fields, schema.get("additionalProperties", False) is not False


def _typeddict_fields(schema: Any, *, name: str) -> dict[str, _Field]:
    try:
        hints = get_type_hints(schema, include_extras=True)
    except Exception as exc:  # an unresolvable forward reference
        raise AirlockError(
            f"tool {name!r}: cannot resolve the annotations of input_schema "
            f"{schema.__name__} ({exc})"
        ) from exc
    required = getattr(schema, "__required_keys__", frozenset(hints))
    fields: dict[str, _Field] = {}
    for key, tp in hints.items():
        qualified = _qualified_required(tp)
        fields[key] = _Field(
            _wire_annotation(tp), key in required if qualified is None else qualified
        )
    return fields


def _qualified_required(tp: Any) -> bool | None:
    """Whether ``tp`` is wrapped in ``Required`` (True) or ``NotRequired`` (False).

    Read from the resolved annotation because ``__required_keys__`` cannot see the
    qualifier through a string annotation: under ``from __future__ import annotations``
    it lists every key, so a ``NotRequired`` key would be refused when omitted.
    """
    while True:
        origin = get_origin(tp)
        qualifier = getattr(origin, "_name", None)
        if qualifier == "Required":
            return True
        if qualifier == "NotRequired":
            return False
        if origin is not Annotated and qualifier != "ReadOnly":
            return None
        tp = get_args(tp)[0]


def _is_parameter_name(key: Any) -> bool:
    return isinstance(key, str) and key.isidentifier() and not keyword.iskeyword(key)


def _json_annotation(schema: Any) -> Any:
    """The Python type of a property's top-level JSON ``type``; ``Any`` when it has none."""
    declared = schema.get("type") if isinstance(schema, Mapping) else None
    if isinstance(declared, str):
        return _JSON_TYPES.get(declared, Any)
    if (
        isinstance(declared, list)
        and declared
        and all(isinstance(each, str) and each in _JSON_TYPES for each in declared)
    ):
        return _UNION[tuple(_JSON_TYPES[each] for each in declared)]
    return Any


def _wire_annotation(tp: Any) -> Any:
    """The type the SDK advertises for annotation ``tp`` and hands the handler.

    Mirrors ``claude_agent_sdk._python_type_to_json_schema``, so Airlock checks the value
    the handler will actually receive. ``None`` stays allowed where ``tp`` allows it;
    the SDK's schema drops it, so that only matters for a direct call.
    """
    origin = get_origin(tp)
    if origin is Annotated or getattr(origin, "_name", None) in _TYPEDDICT_QUALIFIERS:
        return _wire_annotation(get_args(tp)[0])
    if tp in (str, int, bool):
        return tp
    if tp is float:
        return int | float
    if origin is Union or isinstance(tp, types.UnionType):
        return _UNION[tuple(_wire_annotation(arg) for arg in get_args(tp))]
    if origin is list or tp is list:
        items = get_args(tp)
        return list[_wire_annotation(items[0])] if items else list[Any]  # type: ignore[misc]
    if origin is dict or tp is dict or is_typeddict(tp):
        return dict[str, Any]
    if tp is type(None):
        return tp
    return str  # the SDK advertises and checks any other type as a string


def _is_refusal(result: Any) -> bool:
    """Whether ``result`` is Airlock's own refusal (``AirlockResponse.to_dict()``)."""
    return (
        isinstance(result, dict)
        and result.get("success") is False
        and result.get("status") == "blocked"
    )


def _sdk_error_result(refusal: dict[str, Any]) -> dict[str, Any]:
    """Airlock's refusal in the shape an SDK handler returns, read by the model as an error."""
    lines = [str(refusal.get("error") or "AIRLOCK_BLOCK: call refused")]
    hints = refusal.get("fix_hints") or []
    if hints:
        lines.append("Fix hints:")
        lines.extend(f"- {hint}" for hint in hints)
    return {"content": [{"type": "text", "text": "\n".join(lines)}], "is_error": True}
