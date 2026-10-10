"""Every value a tool call carries, under the name it was passed by.

Until 0.10.24 the gates that read argument *values* (the deserialization guard, the
filesystem check and the endpoint check) looked only at top-level keyword arguments, and
only at ``str`` values. A positional argument, a list of paths, a nested mapping, a
pydantic model, a ``pathlib.Path`` and a pydantic URL all walked past them. This module
names positional arguments by their parameter and walks what a call's arguments contain,
so each gate sees every value.

It descends into mappings (keys included), sequences, sets and mapping views, and into
pydantic models and dataclasses the tool's author defined: a model-typed parameter is the
model's JSON once a framework has validated it. It does not descend into an object whose
class comes from an agent framework or from agent-airlock itself (a run context carries
the chat history, which no gate should read as tool arguments), into any other object, or
into an iterator, which walking would consume. A value nested deeper than
:data:`MAX_DEPTH`, or a container that contains itself, raises
:class:`ArgumentNestingError`, so the gate refuses the call instead of skipping what it
could not read.
"""

from __future__ import annotations

import dataclasses
import inspect
import os
import urllib.parse
from collections import UserString
from collections.abc import Iterator, Mapping, Sequence, Set, ValuesView
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel

from .exceptions import AirlockError

MAX_DEPTH = 32
"""Deepest container nesting a gate walks; deeper input is refused, not skipped."""

_URL_RESULT_TYPES = (
    urllib.parse.SplitResult,
    urllib.parse.ParseResult,
    urllib.parse.DefragResult,
    urllib.parse.SplitResultBytes,
    urllib.parse.ParseResultBytes,
    urllib.parse.DefragResultBytes,
)

#: Top-level packages whose objects are framework or library state, never the model's
#: JSON: their models and dataclasses (run contexts, messages, SDK responses) are not
#: walked. A tool author's own models and dataclasses are.
FRAMEWORK_PACKAGES = frozenset(
    {
        "agent_airlock",
        "agents",
        "anthropic",
        "autogen",
        "autogen_agentchat",
        "autogen_core",
        "claude_agent_sdk",
        "crewai",
        "fastmcp",
        "google",
        "langchain",
        "langchain_core",
        "langgraph",
        "llama_index",
        "mcp",
        "openai",
        "pydantic",
        "pydantic_ai",
        "smolagents",
    }
)

_TEXT_TYPES = (str, bytes, bytearray, memoryview, UserString)


class ArgumentNestingError(AirlockError):
    """An argument is nested deeper than :data:`MAX_DEPTH` or contains itself.

    Attributes:
        path: Where the walk stopped, e.g. ``"config.items[3]"``.
        reason: Why it stopped.
    """

    def __init__(self, path: str, reason: str) -> None:
        self.path = path
        self.reason = reason
        super().__init__(f"argument {path!r} cannot be inspected: {reason}")


@dataclass(frozen=True)
class ArgumentValue:
    """One leaf value of a call's arguments.

    Attributes:
        key: The nearest name: the parameter, the mapping key or field name, or (for an
            item of a sequence or set, or a mapping key) the name of the container it
            sits in.
        path: Where it sits, e.g. ``"paths[0]"`` or ``"config.output_file"``.
        value: The value itself.
        depth: 0 for a top-level argument, one more for each container it sits in.
        is_key: True when the value is a mapping's key rather than one of its values.
    """

    key: str
    path: str
    value: Any
    depth: int = 0
    is_key: bool = False


def signature_of(func: Any) -> inspect.Signature | None:
    """The signature positional arguments are bound against, or None when there is none."""
    try:
        return inspect.signature(func)
    except (TypeError, ValueError):
        return None


def bind_arguments(
    signature: inspect.Signature | None,
    args: tuple[Any, ...],
    kwargs: Mapping[str, Any],
) -> dict[str, Any]:
    """Name every argument a call passes, positional ones by their parameter.

    ``*args`` items stay together under the parameter's own name, as a tuple, so they are
    walked as a container with that name; ``**kwargs`` items are named by their keys.
    When the call does not bind to the signature, each positional argument is named
    ``arg[i]`` so no value goes unread; the call itself then fails on its own.

    Args:
        signature: The tool's signature, from :func:`signature_of`.
        args: The call's positional arguments.
        kwargs: The call's keyword arguments, after ghost-argument handling.

    Returns:
        A mapping from name to value covering every argument.
    """
    if signature is not None:
        try:
            bound = signature.bind_partial(*args, **kwargs)
        except TypeError:
            pass
        else:
            named: dict[str, Any] = {}
            for name, value in bound.arguments.items():
                kind = signature.parameters[name].kind
                if kind is inspect.Parameter.VAR_POSITIONAL:
                    named[name] = tuple(value)
                elif kind is inspect.Parameter.VAR_KEYWORD:
                    named.update(value)
                else:
                    named[name] = value
            return named
    fallback: dict[str, Any] = {f"arg[{index}]": item for index, item in enumerate(args)}
    fallback.update(kwargs)
    return fallback


def url_text(value: Any) -> str | None:
    """The URL a URL object stands for, or None when ``value`` is not a URL object.

    Recognises the ``urllib.parse`` result types and any object whose class carries both a
    ``scheme`` and a ``host`` attribute (pydantic's ``Url`` / ``AnyUrl``, ``httpx.URL``,
    ``yarl.URL``). The check is on the class, so an object that answers every attribute
    (a mock) is not mistaken for one. Strings and bytes are not URL objects.
    """
    if isinstance(value, _URL_RESULT_TYPES):
        url = value.geturl()
        return url.decode("utf-8", "replace") if isinstance(url, bytes) else url
    if isinstance(value, _TEXT_TYPES):
        return None
    cls = type(value)
    if hasattr(cls, "scheme") and hasattr(cls, "host"):
        return str(value)
    return None


def path_text(value: Any) -> str | None:
    """The filesystem path an ``os.PathLike`` value names, or None for anything else."""
    if isinstance(value, os.PathLike):
        return os.fsdecode(os.fspath(value))
    return None


def is_framework_object(value: Any) -> bool:
    """Whether ``value``'s class comes from an agent framework or library, not the tool."""
    module = getattr(type(value), "__module__", "") or ""
    return module.split(".", 1)[0] in FRAMEWORK_PACKAGES


def iter_argument_values(arguments: Mapping[str, Any]) -> Iterator[ArgumentValue]:
    """Yield every leaf value of ``arguments``, depth first.

    Args:
        arguments: Named arguments, typically from :func:`bind_arguments`.

    Yields:
        One :class:`ArgumentValue` per leaf, mapping keys included.

    Raises:
        ArgumentNestingError: A value is nested deeper than :data:`MAX_DEPTH` or a
            container contains itself.
    """
    for name, value in arguments.items():
        yield from _walk(str(name), str(name), value, 0, ())


def _children(value: Any, key: str, path: str) -> Iterator[tuple[str, str, Any, bool]] | None:
    """``(key, path, child, is_key)`` for each child of a walkable value, else None."""
    if isinstance(value, (*_URL_RESULT_TYPES, *_TEXT_TYPES)):
        return None
    if isinstance(value, Mapping):
        return _mapping_children(value, key, path)
    fields = getattr(value, "_fields", None) if isinstance(value, tuple) else None
    if fields is not None:
        return (
            (str(n), f"{path}.{n}", item, False) for n, item in zip(fields, value, strict=False)
        )
    if isinstance(value, (Sequence, Set, ValuesView)):
        return ((key, f"{path}[{i}]", item, False) for i, item in enumerate(value))
    if is_framework_object(value):
        return None
    if isinstance(value, BaseModel):
        return ((str(n), f"{path}.{n}", item, False) for n, item in value)
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return (
            (f.name, f"{path}.{f.name}", getattr(value, f.name), False)
            for f in dataclasses.fields(value)
        )
    return None


def _mapping_children(
    value: Mapping[Any, Any], key: str, path: str
) -> Iterator[tuple[str, str, Any, bool]]:
    for item_key, item in value.items():
        name = str(item_key)
        if isinstance(item_key, (str, bytes, os.PathLike)):
            # A key can be a path or a URL itself (`files={"/etc/passwd": ...}`); it is
            # read under the mapping's own name.
            yield key, f"{path}[{name!r}]", item_key, True
        yield name, f"{path}.{name}", item, False


def _walk(
    key: str,
    path: str,
    value: Any,
    depth: int,
    ancestors: tuple[int, ...],
    is_key: bool = False,
) -> Iterator[ArgumentValue]:
    children = None if is_key else _children(value, key, path)
    if children is None:
        yield ArgumentValue(key=key, path=path, value=value, depth=depth, is_key=is_key)
        return
    if depth >= MAX_DEPTH:
        raise ArgumentNestingError(path, f"nested deeper than {MAX_DEPTH} levels")
    if id(value) in ancestors:
        raise ArgumentNestingError(path, "the container contains itself")
    inner = (*ancestors, id(value))
    for child_key, child_path, child, child_is_key in children:
        yield from _walk(child_key, child_path, child, depth + 1, inner, child_is_key)
