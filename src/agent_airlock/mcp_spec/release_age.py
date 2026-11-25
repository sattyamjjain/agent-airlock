"""When an npm or PyPI package version was published (v0.10.36, GHSA-h82f-cjm4-g22r).

GHSA-h82f-cjm4-g22r (published 2026-11-20T13:00:09Z, critical) is malicious code in the npm
package ``@guicai777/mcp-doctor``. Version 1.0.1 was published 2026-11-16T11:15:51Z and
stayed installable for about four days before any advisory existed, so no blast list, and no
refresh of one, could have named it in that time. The control that covers that window is a
cooldown: refuse a version younger than a minimum age, as pnpm (``minimumReleaseAge``), npm
(``--before``) and uv (``exclude-newer``) do at install time.

This module answers one question, when a version was published, for
:class:`~agent_airlock.mcp_spec.oidc_publish_window_guard.OIDCPublishWindowGuard`, which
applies the policy (``min_release_age``, ``release_time_lookup``).

- npm: ``GET https://registry.npmjs.org/<name>`` (``/`` in a scoped name escaped as ``%2f``),
  then ``time[<version>]``; with no version, the version ``dist-tags.latest`` names.
- PyPI: ``GET https://pypi.org/pypi/<name>/<version>/json``, the earliest
  ``upload_time_iso_8601`` among its files; with no version, ``/pypi/<name>/json``, whose
  files are those of ``info.version``.

"Not published there" and "could not be read" are two answers. A 404, or a package document
without that version, gives ``None``. A timeout, any other HTTP status, a network or JSON
error, a body over 32 MiB or a document of another shape raises
:class:`ReleaseTimeUnavailableError`: the guard asks both registries about a bare name, and a
registry that did not answer must not pass for one that does not have it. An exact version's
time is cached in process (1,024 entries, least recently used dropped first), since a publish
time does not change. The latest version's is not: a new release changes which version that
is.

Nothing in this module touches the network unless a caller builds
:func:`registry_release_time_lookup` and calls what it returns.

Primary source:
  https://github.com/advisories/GHSA-h82f-cjm4-g22r
"""

from __future__ import annotations

import json
import re
import threading
import urllib.error
import urllib.request
from collections import OrderedDict
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

from .._log import structlog
from ..exceptions import AirlockError

logger = structlog.get_logger("agent-airlock.mcp_spec.release_age")

#: ``(kind, normalised name, version or None)`` to the aware UTC time that version was
#: published, or None when the registry does not have it. Raise when it cannot be told: the
#: guard reads any exception as an unknown age. ``kind`` is ``"npm"`` or ``"pypi"``; ``None``
#: as the version means the version the registry installs by default.
ReleaseTimeLookup = Callable[[str, str, str | None], datetime | None]

#: ``(url, timeout in seconds)`` to the response body; raises on an HTTP error status.
RegistryOpener = Callable[[str, float], bytes]

_NPM_REGISTRY = "https://registry.npmjs.org/"
_PYPI_JSON_API = "https://pypi.org/pypi/"
_USER_AGENT = "agent-airlock-release-age"

#: How many exact-version answers one lookup keeps.
CACHE_ENTRIES = 1024

#: The largest response body read; a larger one is an unknown time. A full npm packument
#: carries every version's metadata, and a few packages' run to tens of megabytes.
_MAX_BODY_BYTES = 32 * 1024 * 1024

# Names are checked before they are put in a URL: anything else is an unknown time, never a
# request. npm names are lowercase (the guard normalises them); old mixed-case ones are not
# looked up.
_NPM_NAME = re.compile(r"(?:@[a-z0-9~-][a-z0-9._~-]*/)?[a-z0-9~-][a-z0-9._~-]*", re.ASCII)
_PYPI_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", re.ASCII)
_PYPI_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+!-]*", re.ASCII)


class ReleaseTimeUnavailableError(AirlockError):
    """A registry did not say when a version was published, though it may have it.

    Attributes:
        kind: ``"npm"`` or ``"pypi"``.
        package: The package name asked about.
        version: The version asked about, or None for the default one.
        reason: What went wrong, an exception's class name or a short phrase.
    """

    def __init__(self, kind: str, package: str, version: str | None, reason: str) -> None:
        self.kind = kind
        self.package = package
        self.version = version
        self.reason = reason
        super().__init__(f"the {kind} registry did not say when {package} was published: {reason}")


def _default_opener(url: str, timeout: float) -> bytes:
    request = urllib.request.Request(
        url, headers={"Accept": "application/json", "User-Agent": _USER_AGENT}
    )
    # Only the two fixed https registry bases above reach here, never a caller's URL.
    with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310 - fixed https registry URL
        body: bytes = response.read(_MAX_BODY_BYTES + 1)
    if len(body) > _MAX_BODY_BYTES:
        raise ValueError(f"response body over {_MAX_BODY_BYTES} bytes")
    return body


def parse_release_time(text: object) -> datetime | None:
    """An ISO 8601 publish time as an aware UTC ``datetime``, or None.

    Reads the registries' ``2026-11-16T11:15:51.940Z`` and ``...+00:00`` forms on every
    supported Python (3.10's ``fromisoformat`` does not take ``Z``). A time with no zone is
    read as UTC.
    """
    if not isinstance(text, str) or not text.strip():
        return None
    value = text.strip()
    if value[-1] in "Zz":
        value = value[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


class _Recent:
    """A thread-safe mapping that keeps the ``size`` entries used last."""

    def __init__(self, size: int) -> None:
        self._size = size
        self._items: OrderedDict[tuple[str, str, str], datetime] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: tuple[str, str, str]) -> datetime | None:
        with self._lock:
            value = self._items.get(key)
            if value is not None:
                self._items.move_to_end(key)
            return value

    def put(self, key: tuple[str, str, str], value: datetime) -> None:
        with self._lock:
            self._items[key] = value
            self._items.move_to_end(key)
            while len(self._items) > self._size:
                self._items.popitem(last=False)


def _document(body: bytes) -> dict[str, Any]:
    parsed = json.loads(body.decode("utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError("response is not a JSON object")
    return parsed


def _read_time(text: object) -> datetime:
    parsed = parse_release_time(text)
    if parsed is None:
        raise ValueError("publish time cannot be read")
    return parsed


def _npm_time(
    fetch: RegistryOpener, timeout: float, name: str, version: str | None
) -> datetime | None:
    if not _NPM_NAME.fullmatch(name):
        return None
    url = _NPM_REGISTRY + quote(name, safe="@").replace("%2F", "%2f")
    document = _document(fetch(url, timeout))
    times = document.get("time")
    if not isinstance(times, dict):
        raise ValueError("package document has no time map")
    if version is None:
        tags = document.get("dist-tags")
        version = tags.get("latest") if isinstance(tags, dict) else None
        if not isinstance(version, str):
            raise ValueError("package document names no latest version")
    elif version not in times:
        return None
    return _read_time(times.get(version))


def _pypi_time(
    fetch: RegistryOpener, timeout: float, name: str, version: str | None
) -> datetime | None:
    if not _PYPI_NAME.fullmatch(name):
        return None
    if version is None:
        url = f"{_PYPI_JSON_API}{name}/json"
    elif _PYPI_VERSION.fullmatch(version):
        url = f"{_PYPI_JSON_API}{name}/{quote(version, safe='')}/json"
    else:
        return None
    files = _document(fetch(url, timeout)).get("urls")
    if not isinstance(files, list):
        raise ValueError("release document has no file list")
    times = [
        parse_release_time(item.get("upload_time_iso_8601"))
        for item in files
        if isinstance(item, dict)
    ]
    found = [time for time in times if time is not None]
    if not found:
        raise ValueError("release document has no upload time")
    return min(found)


def registry_release_time_lookup(
    *, timeout: float = 3.0, opener: RegistryOpener | None = None
) -> ReleaseTimeLookup:
    """A :data:`ReleaseTimeLookup` that asks the npm registry and PyPI.

    Args:
        timeout: Seconds per request.
        opener: ``(url, timeout) -> body``, raising on an HTTP error. Defaults to
            :mod:`urllib.request` with an ``Accept: application/json`` header. Tests pass a
            stub; nothing else should need to.

    Returns:
        The lookup. Calling it makes at most one request. It returns None when the registry
        does not have that package or version, and raises
        :class:`ReleaseTimeUnavailableError`, nothing else, when the time cannot be read.

    Raises:
        TypeError: ``timeout`` is not a number, or ``opener`` is not callable.
        ValueError: ``timeout`` is not positive.
    """
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise TypeError(f"timeout must be a number of seconds; got {type(timeout).__name__}")
    if not timeout > 0:
        raise ValueError(f"timeout must be positive; got {timeout!r}")
    if opener is not None and not callable(opener):
        raise TypeError(f"opener must be callable; got {type(opener).__name__}")
    fetch: RegistryOpener = opener if opener is not None else _default_opener
    seconds = float(timeout)
    recent = _Recent(CACHE_ENTRIES)

    def lookup(kind: str, name: str, version: str | None) -> datetime | None:
        if version is not None:
            cached = recent.get((kind, name, version))
            if cached is not None:
                return cached
        try:
            if kind == "npm":
                found = _npm_time(fetch, seconds, name, version)
            elif kind == "pypi":
                found = _pypi_time(fetch, seconds, name, version)
            else:
                return None
        except Exception as error:  # noqa: BLE001 - an unreadable answer is an unknown time
            if isinstance(error, urllib.error.HTTPError) and error.code == 404:
                return None
            logger.warning(
                "release_time_lookup_failed",
                kind=kind,
                package=name,
                version=version,
                error=type(error).__name__,
            )
            raise ReleaseTimeUnavailableError(kind, name, version, type(error).__name__) from error
        if version is not None and found is not None:
            recent.put((kind, name, version), found)
        return found

    return lookup


__all__ = [
    "CACHE_ENTRIES",
    "RegistryOpener",
    "ReleaseTimeLookup",
    "ReleaseTimeUnavailableError",
    "parse_release_time",
    "registry_release_time_lookup",
]
