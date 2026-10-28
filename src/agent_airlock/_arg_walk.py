"""Every value a tool call carries, under the name it was passed by.

Until 0.10.24 the gates that read argument *values* (the deserialization guard, the
filesystem check and the endpoint check) looked only at top-level keyword arguments, and
only at ``str`` values. A positional argument, a list of paths, a nested mapping, a
pydantic model, a ``pathlib.Path`` and a pydantic URL all walked past them. This module
names positional arguments by their parameter and walks what a call's arguments contain,
so each gate sees every value.

It descends into mappings (every key included, as a value of its own), sequences, sets
and mapping views, and into pydantic models and dataclasses the tool's author defined: a
model-typed parameter is the model's JSON once a framework has validated it. It does not
descend into an object an agent framework or agent-airlock itself defines (a run context
carries the chat history, which no gate should read as tool arguments), into any other
object, or into an iterator or generator, which walking would consume (model JSON cannot
produce one). A framework's object is one whose class is defined in a file its installed
distribution lists (:func:`is_framework_object`), not merely one whose module bears the
framework's name. A ``memoryview`` is read as its bytes and a ``UserString`` as its text.
A value nested deeper than :data:`MAX_DEPTH`, or a container that contains itself, raises
:class:`ArgumentNestingError`, so the gate refuses the call instead of skipping what it
could not read.
"""

from __future__ import annotations

import contextlib
import dataclasses
import fnmatch
import importlib.metadata
import inspect
import os
import sys
import threading
import urllib.parse
import weakref
from collections import UserString
from collections.abc import Iterator, Mapping, Sequence, Set, ValuesView
from dataclasses import dataclass
from functools import cache
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

#: The installed distributions each agent framework's top-level package comes from. An
#: object is the framework's only when the file its class is defined in is listed in the
#: RECORD of one of them (:func:`is_framework_object`). A name ending in ``*`` stands for a
#: family of distributions named after the module path (``llama-index-llms-openai`` ships
#: ``llama_index.llms.openai``).
_FRAMEWORK_DISTRIBUTIONS: dict[str, tuple[str, ...]] = {
    "agents": ("openai-agents",),
    "anthropic": ("anthropic",),
    "autogen": ("autogen", "pyautogen", "ag2"),
    "autogen_agentchat": ("autogen-agentchat",),
    "autogen_core": ("autogen-core",),
    "claude_agent_sdk": ("claude-agent-sdk",),
    "crewai": ("crewai",),
    "fastmcp": ("fastmcp",),
    "google": ("google-adk", "google-genai", "google-generativeai", "google-cloud-aiplatform"),
    "langchain": ("langchain",),
    "langchain_core": ("langchain-core",),
    "langgraph": ("langgraph", "langgraph-*"),
    "llama_index": ("llama-index", "llama-index-*"),
    "mcp": ("mcp",),
    "openai": ("openai",),
    "pydantic": ("pydantic",),
    "pydantic_ai": ("pydantic-ai-slim", "pydantic-ai"),
    "smolagents": ("smolagents",),
}

#: Top-level packages whose objects are framework or library state, never the model's
#: JSON: their models and dataclasses (run contexts, messages, SDK responses) are not
#: walked. A tool author's own models and dataclasses are, and so is any class only named
#: as if it came from one of these: since 0.10.28 a class counts only when its installed
#: distribution defines it (:func:`is_framework_object`).
FRAMEWORK_PACKAGES = frozenset({"agent_airlock", *_FRAMEWORK_DISTRIBUTIONS})

#: agent-airlock's own package directory: its classes are verified by location, since an
#: editable install's RECORD lists no module files.
_OWN_PACKAGE = os.path.realpath(os.path.dirname(os.path.abspath(__file__)))

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


class ArgumentName(str):
    """A name an argument is bound under that is not the name the gates classify it by.

    A ``**kwargs`` key that repeats the name of a positional-only parameter or of
    ``*args`` (``f(path, /, **kw)`` called ``f(a, path=b)``) is bound beside the value it
    shares a name with, under ``"kw['path']"``; :attr:`key` keeps ``"path"``, the name the
    path and URL gates read it by (:func:`iter_argument_values`).

    Attributes:
        key: The name the value was passed under.
    """

    key: str

    def __new__(cls, text: str, key: str | None = None) -> ArgumentName:
        name = super().__new__(cls, text)
        name.key = text if key is None else key
        return name


@dataclass(frozen=True)
class ArgumentValue:
    """One leaf value of a call's arguments.

    Attributes:
        key: The nearest name: the parameter, the mapping key or field name, or (for an
            item of a sequence or set, or a mapping key) the name of the container it
            sits in.
        path: Where it sits, e.g. ``"paths[0]"`` or ``"config.output_file"``.
        value: The value itself; a ``memoryview`` as its bytes, a ``UserString`` as its
            text.
        depth: 0 for a top-level argument, one more for each container it sits in.
        is_key: True when the value is a mapping's key, or sits inside one, rather than
            being one of its values.
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
    *,
    skip_first: bool = False,
) -> dict[str, Any]:
    """Name every argument a call passes, positional ones by their parameter.

    ``*args`` items stay together under the parameter's own name, as a tuple, so they are
    walked as a container with that name; ``**kwargs`` items are named by their keys. A
    ``**kwargs`` key that repeats the name of a positional-only parameter or of ``*args``
    is kept beside that value under an :class:`ArgumentName`: until 0.10.28 it replaced
    the value it shared a name with, and no gate read that value. When the call does not
    bind to the signature, each positional argument is named ``arg[i]`` so no value goes
    unread; the call itself then fails on its own.

    Args:
        signature: The tool's signature, from :func:`signature_of`.
        args: The call's positional arguments.
        kwargs: The call's keyword arguments, after ghost-argument handling.
        skip_first: Leave out the first positional argument: the host's run wrapper,
            which model JSON cannot have built (``ContextExtractor.run_wrapper``).

    Returns:
        A mapping from name to value covering every argument.
    """
    if signature is not None:
        try:
            bound = signature.bind_partial(*args, **kwargs)
        except TypeError:
            pass
        else:
            first = _first_positional(signature) if skip_first and args else None
            named: dict[str, Any] = {}
            for name, value in bound.arguments.items():
                kind = signature.parameters[name].kind
                if kind is inspect.Parameter.VAR_POSITIONAL:
                    items = tuple(value)
                    named[name] = items[1:] if name == first else items
                elif kind is inspect.Parameter.VAR_KEYWORD:
                    for item_key, item in value.items():
                        named[_unshadowed(named, str(item_key), name)] = item
                elif name != first:
                    named[name] = value
            return named
    start = 1 if skip_first else 0
    fallback: dict[str, Any] = {
        f"arg[{index}]": item for index, item in enumerate(args) if index >= start
    }
    for item_key, item in kwargs.items():
        fallback[_unshadowed(fallback, str(item_key), "kwargs")] = item
    return fallback


def _first_positional(signature: inspect.Signature) -> str | None:
    """The parameter a call's first positional argument binds to."""
    positional = (
        inspect.Parameter.POSITIONAL_ONLY,
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
        inspect.Parameter.VAR_POSITIONAL,
    )
    for name, parameter in signature.parameters.items():
        if parameter.kind in positional:
            return name
    return None


def _unshadowed(named: Mapping[str, Any], key: str, container: str) -> str:
    """``key``, or an :class:`ArgumentName` beside it when ``named`` already holds it."""
    if key not in named:
        return key
    label = f"{container}[{key!r}]"
    text, suffix = label, 2
    while text in named:
        text, suffix = f"{label}#{suffix}", suffix + 1
    return ArgumentName(text, key)


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


_framework_types: weakref.WeakKeyDictionary[type, bool] = weakref.WeakKeyDictionary()
_framework_types_lock = threading.Lock()


def is_framework_object(value: Any) -> bool:
    """Whether ``value``'s class is defined by an agent framework or library, not the tool.

    True only when the class's module is under a :data:`FRAMEWORK_PACKAGES` name, the
    class is the one its module and qualified name resolve to, and that module's file is
    listed in the installed RECORD of the framework's own distribution (agent-airlock's
    own classes: inside this package). Until 0.10.28 the top-level module name alone
    decided, so a tool author's own package named ``agents``, ``mcp`` or ``google`` was
    skipped by the value gates. A class that cannot be verified, such as one from an
    editable install, is not a framework's, so it is walked. The answer is cached per
    class.
    """
    cls = type(value)
    with _framework_types_lock:
        known = _framework_types.get(cls)
    if known is None:
        known = _defined_by_framework(cls)
        # A class that takes no weak reference is answered, just not cached.
        with _framework_types_lock, contextlib.suppress(TypeError):
            _framework_types[cls] = known
    return known


def _defined_by_framework(cls: type) -> bool:
    """Whether ``cls`` is defined in a file its framework's installed distribution ships."""
    module_name = getattr(cls, "__module__", None)
    qualname = getattr(cls, "__qualname__", None)
    if not isinstance(module_name, str) or not isinstance(qualname, str):
        return False
    top = module_name.partition(".")[0]
    if top not in FRAMEWORK_PACKAGES:
        return False
    module = sys.modules.get(module_name)
    if module is None or not _resolves_to(module, qualname, cls):
        return False
    filename = getattr(module, "__file__", None)
    if not isinstance(filename, str):
        return False
    path = os.path.realpath(filename)
    if top == "agent_airlock":
        return _is_within(path, _OWN_PACKAGE)
    return any(
        path in _distribution_files(name) for name in _candidate_distributions(top, module_name)
    )


def _resolves_to(module: Any, qualname: str, cls: type) -> bool:
    """Whether ``module.<qualname>`` is ``cls``: a class only *named* as a module's is not."""
    target: Any = module
    for part in qualname.split("."):
        try:
            target = getattr(target, part)
        except Exception:  # noqa: BLE001 - a name that does not resolve is not the class
            return False
    return target is cls


def _is_within(path: str, directory: str) -> bool:
    try:
        return os.path.commonpath([path, directory]) == directory
    except ValueError:  # different drives
        return False


def _candidate_distributions(top: str, module_name: str) -> tuple[str, ...]:
    """The distribution names that may ship ``module_name`` for framework ``top``."""
    names = [name for name in _FRAMEWORK_DISTRIBUTIONS.get(top, ()) if "*" not in name]
    families = [name for name in _FRAMEWORK_DISTRIBUTIONS.get(top, ()) if "*" in name]
    if families:
        parts = module_name.split(".")
        for end in range(1, len(parts) + 1):
            name = "-".join(parts[:end]).replace("_", "-").lower()
            if name not in names and any(fnmatch.fnmatchcase(name, f) for f in families):
                names.append(name)
    return tuple(names)


@cache
def _distribution_files(name: str) -> frozenset[str]:
    """The paths of the files the installed distribution ``name`` lists in its RECORD."""
    try:
        distribution = importlib.metadata.distribution(name)
        base = os.path.realpath(str(distribution.locate_file("")))
        files = distribution.files or []
    except Exception:  # noqa: BLE001 - not installed, or unreadable metadata: verifies nothing
        return frozenset()
    return frozenset(os.path.normpath(os.path.join(base, str(file))) for file in files)


def iter_argument_values(arguments: Mapping[str, Any]) -> Iterator[ArgumentValue]:
    """Yield every leaf value of ``arguments``, depth first.

    Args:
        arguments: Named arguments, typically from :func:`bind_arguments`. A name that is
            an :class:`ArgumentName` is read by its :attr:`~ArgumentName.key`.

    Yields:
        One :class:`ArgumentValue` per leaf, mapping keys included.

    Raises:
        ArgumentNestingError: A value is nested deeper than :data:`MAX_DEPTH` or a
            container contains itself.
    """
    for name, value in arguments.items():
        path = str(name)
        key = name.key if isinstance(name, ArgumentName) else path
        yield from _walk(key, path, value, 0, ())


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
        # Every key is read too, under the mapping's own name: a key can be a path or a URL
        # (`files={"/etc/passwd": ...}`), and so can a URL object, or a tuple or frozenset
        # of paths. Until 0.10.28 only str, bytes and path-like keys were read.
        yield key, f"{path}[{name!r}]", item_key, True
        yield name, f"{path}.{name}", item, False


def _as_read(value: Any) -> Any:
    """A leaf as the gates read it: a ``memoryview`` as its bytes, a ``UserString`` as text.

    Until 0.10.28 neither was read by any gate: a pickle in a memoryview, or a path in a
    ``UserString``, walked past all three.
    """
    if isinstance(value, memoryview):
        try:
            return value.tobytes()
        except ValueError:  # a released view holds nothing to read
            return value
    if isinstance(value, UserString):
        return str(value)
    return value


def _walk(
    key: str,
    path: str,
    value: Any,
    depth: int,
    ancestors: tuple[int, ...],
    is_key: bool = False,
) -> Iterator[ArgumentValue]:
    children = _children(value, key, path)
    if children is None:
        yield ArgumentValue(key=key, path=path, value=_as_read(value), depth=depth, is_key=is_key)
        return
    if depth >= MAX_DEPTH:
        raise ArgumentNestingError(path, f"nested deeper than {MAX_DEPTH} levels")
    if id(value) in ancestors:
        raise ArgumentNestingError(path, "the container contains itself")
    inner = (*ancestors, id(value))
    for child_key, child_path, child, child_is_key in children:
        yield from _walk(child_key, child_path, child, depth + 1, inner, is_key or child_is_key)
