"""Cross-origin WebSocket-hijack guard (v0.8.27+, CVE-2026-44211 anchor).

CVE-2026-44211 (Cline Kanban server, npm ``kanban`` < 2.13.0, CVSS 9.7,
CWE-1385 + CWE-306): the Cline VS Code agent starts a control WebSocket
server on ``127.0.0.1:3484`` and accepts every upgrade **without validating
the ``Origin`` header**. Browsers do *not* apply the same-origin policy /
CORS to ``ws://`` connections the way they do to HTTP, so any website the
developer visits can silently open a WebSocket to the loopback control
server and drive the agent — leak workspace paths, task content, and chat
history, inject prompts into the running agent's terminal (RCE), or kill
tasks. Binding to ``127.0.0.1`` is **not** a mitigation: the cross-origin
WebSocket reaches loopback from the browser regardless.

The exploit class is not Cline-specific: any agent / IDE / control surface
that exposes a local WebSocket (or HTTP-upgrade) endpoint without an
explicit ``Origin`` allow-list is exposed to the same drive-by hijack. This
module is the reusable, CVE-agnostic primitive, with two surfaces:

(a) **Static exposure audit** — :meth:`WebSocketOriginGuard.audit_endpoint`
    flags an agent-exposed WS/HTTP control endpoint that does not enforce an
    ``Origin``/host allow-list (the misconfiguration behind the CVE).

(b) **Runtime upgrade gate** — :meth:`WebSocketOriginGuard.check_upgrade` /
    :meth:`WebSocketOriginGuard.enforce_upgrade` reject a WebSocket upgrade
    whose ``Origin`` is not in an explicit allow-list, and
    :meth:`WebSocketOriginGuard.wrap_handler` wraps an existing
    (sync or async) upgrade handler so the rejection happens before the
    handler runs.

Deny-by-default posture
-----------------------
An upgrade with an ``Origin`` outside the allow-list is rejected; so is an
upgrade carrying **no** ``Origin`` header at all (a browser always sends one,
so its absence on a control surface is treated as untrusted). The allow-list
is explicit — an empty allow-list rejects every cross-origin upgrade. The
runtime gate reads an ``Origin`` given as ``str``, Latin-1 ``bytes`` or a list
of the values it arrived with, and refuses one that is not text or that
arrives with two different values (``DENY_UNINSPECTABLE``, v0.10.28). The
handler wrapper's default getter, :func:`extract_origin`, hands it every
``Origin`` value the call carries; until 0.10.28 it took the first one it
found, so the wrapper ran a handler whose upgrade also carried a forged one.

Why structural (no server)
--------------------------
The guard never opens a socket — it inspects an endpoint descriptor (audit)
or a single ``Origin`` string (runtime) and returns a decision. It therefore
carries no listening surface of its own.

Primary sources (retrieved 2026-06-21):
  https://advisories.gitlab.com/npm/cline/CVE-2026-44211/
  https://www.oasis.security/blog/cline-kanban-websocket-hijack
  https://cwe.mitre.org/data/definitions/1385.html
"""

from __future__ import annotations

import enum
import functools
import inspect
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, TypeVar

from .._log import structlog
from ..exceptions import AirlockError

logger = structlog.get_logger("agent-airlock.mcp_spec.ws_origin_guard")

_T = TypeVar("_T")

# The Cline Kanban control server's default loopback bind (CVE-2026-44211).
DEFAULT_CONTROL_WS_PORT = 3484


class WebSocketOriginVerdict(str, enum.Enum):
    """Stable reason codes for :class:`WebSocketOriginDecision`."""

    ALLOW = "allow"
    ALLOW_ORIGIN_ALLOWLISTED = "allow_origin_allowlisted"
    # Static audit (surface a): the endpoint enforces no Origin allow-list.
    DENY_MISSING_ORIGIN_ALLOWLIST = "deny_missing_origin_allowlist"
    # Runtime gate (surface b): the upgrade Origin is not allow-listed.
    DENY_FORBIDDEN_ORIGIN = "deny_forbidden_origin"
    # Runtime gate (surface b): the upgrade carries no Origin header at all.
    DENY_MISSING_ORIGIN_HEADER = "deny_missing_origin_header"
    # Runtime gate (surface b): an Origin the guard cannot read — not text, or two
    # different values for the one header (0.10.28).
    DENY_UNINSPECTABLE = "deny_uninspectable"


@dataclass(frozen=True)
class WebSocketOriginDecision:
    """Outcome of an :class:`WebSocketOriginGuard` audit or upgrade check.

    Mirrors the v0.7.x / v0.8.x guard decision family — every guard exposes
    ``allowed: bool`` so integrators can chain on one short-circuit predicate.

    Attributes:
        allowed: True iff the endpoint enforces an allow-list (audit) or the
            upgrade Origin is allow-listed (runtime). False = fail-closed.
        verdict: A stable :class:`WebSocketOriginVerdict` value.
        detail: Free-form human-readable explanation.
        matched_origin: The Origin that was evaluated (runtime checks), or
            ``None`` for an audit / a missing-Origin upgrade.
        fix_hints: LLM/operator-actionable remediation hints. Carries the
            advisory / CVE reference when the guard was constructed with one.
    """

    allowed: bool
    verdict: WebSocketOriginVerdict
    detail: str
    matched_origin: str | None = None
    fix_hints: list[str] = field(default_factory=list)


class WebSocketOriginHijackError(AirlockError):
    """Raised on a rejected WebSocket upgrade / exposed endpoint (fail-closed).

    Carries the :class:`WebSocketOriginDecision` and exposes ``fix_hints`` so
    an upstream airlock layer can surface the refusal.

    Attributes:
        decision: The decision that triggered the refusal.
        fix_hints: Operator-actionable remediation hints.
    """

    def __init__(self, decision: WebSocketOriginDecision) -> None:
        self.decision = decision
        self.fix_hints = decision.fix_hints
        super().__init__(decision.detail)


def _normalize_origin(origin: str) -> str:
    """Normalize an Origin for case-insensitive scheme/host comparison.

    The ``Origin`` header is ``scheme://host[:port]``. Scheme and host are
    case-insensitive; the port is significant. We lowercase the whole token
    and strip any trailing slash so ``HTTP://Evil.com`` and ``http://evil.com/``
    compare equal, without parsing away the port.
    """
    return origin.strip().rstrip("/").lower()


class WebSocketOriginGuard:
    """Deny-by-default gate on cross-origin WebSocket upgrades (CVE-2026-44211).

    Args:
        allowed_origins: Iterable of explicitly trusted Origins
            (``scheme://host[:port]``). Compared case-insensitively on
            scheme/host with the port preserved. Empty / None (default)
            rejects every cross-origin upgrade.
        advisory: Optional advisory / CVE id (e.g. ``"CVE-2026-44211"``)
            surfaced in every deny ``fix_hints``.
        advisory_url: Optional primary-source URL surfaced alongside.

    Raises:
        TypeError: ``allowed_origins`` is a bare ``str`` (a footgun that
            would be iterated character-by-character).
    """

    def __init__(
        self,
        *,
        allowed_origins: Iterable[str] | None = None,
        advisory: str | None = None,
        advisory_url: str | None = None,
    ) -> None:
        if isinstance(allowed_origins, str):
            raise TypeError(
                f"allowed_origins must be an iterable of str, not a bare str: {allowed_origins!r}"
            )
        self._allowed: frozenset[str] = frozenset(
            _normalize_origin(o) for o in (allowed_origins or ())
        )
        self._advisory = advisory
        self._advisory_url = advisory_url

    @property
    def allowed_origins(self) -> frozenset[str]:
        """The normalized allow-list this guard enforces."""
        return self._allowed

    # -- surface (a): static exposure audit -------------------------------

    def audit_endpoint(
        self,
        *,
        host: str,
        port: int | None = None,
        scheme: str = "ws",
        origin_allowlist_enforced: bool,
    ) -> WebSocketOriginDecision:
        """Flag an agent-exposed control endpoint that lacks Origin allow-listing.

        This is the static, config-time surface: it does not look at any
        request. An agent / IDE control WebSocket (or HTTP-upgrade) endpoint
        that does not enforce an ``Origin``/host allow-list is the
        CVE-2026-44211 misconfiguration — and a loopback ``host`` is **not** a
        mitigation, since a browser can open a cross-origin WebSocket to
        ``127.0.0.1`` without same-origin/CORS enforcement.

        Args:
            host: The bind host the endpoint listens on (e.g. ``"127.0.0.1"``).
            port: The bind port, if known (for the report only).
            scheme: The endpoint scheme (``"ws"`` / ``"wss"`` / ``"http"`` …).
            origin_allowlist_enforced: Whether the endpoint validates the
                upgrade ``Origin`` against an explicit allow-list.

        Returns:
            :class:`WebSocketOriginDecision`. ``allowed=False`` maps to a
            refusal / finding at the audit boundary.
        """
        where = f"{scheme}://{host}" + (f":{port}" if port is not None else "")
        if origin_allowlist_enforced:
            return WebSocketOriginDecision(
                allowed=True,
                verdict=WebSocketOriginVerdict.ALLOW,
                detail=f"control endpoint {where} enforces an Origin allow-list",
                matched_origin=None,
            )
        logger.warning(
            "ws_origin_endpoint_unguarded",
            host=host,
            port=port,
            scheme=scheme,
            advisory=self._advisory,
        )
        return WebSocketOriginDecision(
            allowed=False,
            verdict=WebSocketOriginVerdict.DENY_MISSING_ORIGIN_ALLOWLIST,
            detail=(
                f"agent control endpoint {where} accepts WebSocket upgrades "
                "without validating the Origin header — any visited website "
                "can drive the agent (binding to loopback is not a mitigation)"
            ),
            matched_origin=None,
            fix_hints=self._hints(
                "Validate the Origin header on every WebSocket upgrade against "
                "an explicit allow-list; reject upgrades with a missing or "
                "non-allow-listed Origin. Loopback binding does not protect a "
                "WebSocket from a cross-origin browser connection.",
            ),
        )

    # -- surface (b): runtime upgrade gate --------------------------------

    def check_upgrade(
        self, origin: str | bytes | Sequence[str | bytes] | None
    ) -> WebSocketOriginDecision:
        """Decide a single WebSocket upgrade by its ``Origin`` header.

        Args:
            origin: The ``Origin`` request-header value, or ``None`` when the
                upgrade carried no ``Origin`` header. ``bytes`` are decoded as
                Latin-1 (ASGI header bytes), and a list / tuple is every value
                the header arrived with. A value that is not text, or two
                different values, is refused as ``DENY_UNINSPECTABLE``: until
                v0.10.28 a list or bytes value raised ``AttributeError`` /
                ``TypeError`` instead of a verdict.

        Returns:
            :class:`WebSocketOriginDecision`. ``allowed=False`` maps to a
            refusal of the upgrade.
        """
        read, why = _read_origin(origin)
        if why is not None:
            logger.warning("ws_origin_uninspectable", reason=why, advisory=self._advisory)
            return WebSocketOriginDecision(
                allowed=False,
                verdict=WebSocketOriginVerdict.DENY_UNINSPECTABLE,
                detail=f"{why}; refusing the upgrade rather than guessing which Origin counts",
                matched_origin=None,
                fix_hints=self._hints(
                    "Pass the upgrade's Origin header as one text value (or None when the "
                    "upgrade carried none).",
                ),
            )
        origin = read
        if origin is None or not origin.strip():
            logger.warning("ws_origin_missing_header", advisory=self._advisory)
            return WebSocketOriginDecision(
                allowed=False,
                verdict=WebSocketOriginVerdict.DENY_MISSING_ORIGIN_HEADER,
                detail=(
                    "WebSocket upgrade carried no Origin header; a control "
                    "surface rejects unattributed upgrades by default"
                ),
                matched_origin=None,
                fix_hints=self._hints(
                    "Send an allow-listed Origin header, or add this client's "
                    "Origin to the allow-list if it is trusted.",
                ),
            )

        normalized = _normalize_origin(origin)
        if normalized in self._allowed:
            return WebSocketOriginDecision(
                allowed=True,
                verdict=WebSocketOriginVerdict.ALLOW_ORIGIN_ALLOWLISTED,
                detail=f"Origin {origin!r} is allow-listed",
                matched_origin=origin,
            )

        logger.warning(
            "ws_origin_forbidden",
            origin=origin,
            advisory=self._advisory,
        )
        return WebSocketOriginDecision(
            allowed=False,
            verdict=WebSocketOriginVerdict.DENY_FORBIDDEN_ORIGIN,
            detail=(
                f"WebSocket upgrade Origin {origin!r} is not in the allow-list "
                f"({sorted(self._allowed) or '<empty>'}) — refusing the upgrade"
            ),
            matched_origin=origin,
            fix_hints=self._hints(
                f"Origin {origin!r} is not trusted. Add it to the allow-list "
                "only if it is a known agent UI; otherwise this is a "
                "cross-origin hijack attempt and the refusal is correct.",
            ),
        )

    def enforce_upgrade(self, origin: str | bytes | Sequence[str | bytes] | None) -> None:
        """Raise :class:`WebSocketOriginHijackError` on a rejected upgrade."""
        decision = self.check_upgrade(origin)
        if not decision.allowed:
            raise WebSocketOriginHijackError(decision)

    def wrap_handler(
        self,
        handler: Callable[..., _T],
        *,
        origin_getter: Callable[..., str | bytes | Sequence[str | bytes] | None] | None = None,
    ) -> Callable[..., _T]:
        """Wrap a WebSocket-upgrade handler with a fail-closed Origin gate.

        The returned callable extracts the upgrade ``Origin`` (via
        ``origin_getter``, defaulting to :func:`extract_origin` over the
        handler's call arguments), rejects a missing / non-allow-listed
        Origin, and two different Origin values, by raising
        :class:`WebSocketOriginHijackError`, and otherwise delegates to
        ``handler`` unchanged. Both sync and ``async`` handlers are supported.

        Args:
            handler: The upgrade handler to protect (e.g. an ASGI app, a
                ``websockets`` handler, or any callable invoked per upgrade).
            origin_getter: Optional callable that returns the ``Origin`` from
                the handler's call args, in any shape :meth:`check_upgrade`
                reads. Defaults to :func:`extract_origin`.

        Returns:
            A handler with the same call signature, gated on the Origin.
        """
        get_origin = origin_getter or extract_origin

        if inspect.iscoroutinefunction(handler):

            @functools.wraps(handler)
            async def _async_wrapped(*args: Any, **kwargs: Any) -> Any:
                self.enforce_upgrade(get_origin(*args, **kwargs))
                return await handler(*args, **kwargs)

            return _async_wrapped  # type: ignore[return-value]

        @functools.wraps(handler)
        def _wrapped(*args: Any, **kwargs: Any) -> _T:
            self.enforce_upgrade(get_origin(*args, **kwargs))
            return handler(*args, **kwargs)

        return _wrapped

    # -- internals --------------------------------------------------------

    def _hints(self, *extra: str) -> list[str]:
        prefix = f"({self._advisory}) " if self._advisory else ""
        hints = [f"{prefix}{extra[0]}", *extra[1:]] if extra else []
        if self._advisory_url:
            hints.append(f"See: {self._advisory_url}")
        return hints


@dataclass(frozen=True)
class _UnreadableHeaders:
    """A header container :func:`extract_origin` could not read whole; refused as such."""

    why: str


def _read_origin(origin: object) -> tuple[str | None, str | None]:
    """``(origin, None)`` read from any accepted shape, or ``(None, why)`` when unreadable.

    ``None`` is a missing header; ``str`` is read as is; ``bytes`` as Latin-1; a list /
    tuple is every value the header arrived with — none is a missing header, values that
    normalise alike are one Origin, and two different values are unreadable, as is a
    header container :func:`extract_origin` could not read whole.
    """
    if origin is None:
        return None, None
    items = origin if isinstance(origin, (list, tuple)) else [origin]
    values: list[str] = []
    for item in items:
        if isinstance(item, _UnreadableHeaders):
            return None, item.why
        if isinstance(item, (bytes, bytearray)):
            item = bytes(item).decode("latin-1")
        if not isinstance(item, str):
            return None, f"the Origin value is a {type(item).__name__}, not text"
        values.append(item)
    if not values:
        return None, None
    if len({_normalize_origin(v) for v in values}) > 1:
        return None, "the upgrade carries more than one Origin value"
    return values[0], None


def extract_origin(*args: Any, **kwargs: Any) -> str | list[Any] | None:
    """Every ``Origin`` a handler call carries, read from its arguments.

    Handles the common upgrade-handler shapes without taking a web-framework
    dependency:

    - an explicit ``origin=`` keyword;
    - a request/scope object exposing a ``headers`` mapping (case-insensitive
      ``origin`` lookup);
    - an ASGI ``scope`` dict whose ``headers`` is a list of ``(bytes, bytes)``
      pairs;
    - a plain headers ``Mapping`` passed positionally.

    Every argument and every header entry is read: a header name may be ``str``
    or ``bytes``, and a value ``str``, ``bytes`` or a list of them.

    Returns:
        ``None`` when the call carries no ``Origin``; the ``Origin`` as text when
        every value found names the same one; otherwise the list of every value
        found, which :meth:`WebSocketOriginGuard.check_upgrade` refuses as
        ``DENY_UNINSPECTABLE`` (two different Origins, a value that is not text,
        or an ASGI header list holding an entry that is not a ``(name, value)``
        pair). Until 0.10.28 the first ``Origin`` found was returned, so an
        allow-listed ``origin`` header ahead of a forged one, or a mapping with
        both ``Origin`` and ``origin``, ran the wrapped handler.
    """
    values: list[Any] = []
    if kwargs.get("origin") is not None:
        _add_header_values(values, kwargs["origin"])
    for obj in (*args, *(value for key, value in kwargs.items() if key != "origin")):
        values.extend(_origins_in_obj(obj))
    if not values:
        return None
    if all(isinstance(v, str) for v in values) and len({_normalize_origin(v) for v in values}) == 1:
        return str(values[0])
    return values


def _origins_in_obj(obj: Any) -> list[Any]:
    """Every Origin value in a headers mapping, an ASGI scope, or a request's ``headers``."""
    found: list[Any] = []
    # ASGI scope: {"headers": [(b"origin", b"https://evil.com"), ...]}, or a headers mapping.
    if isinstance(obj, Mapping):
        found += _origins_in_headers(obj.get("headers", obj))
    # Request-like object exposing `.headers` (a Starlette connection is a mapping too).
    headers_attr = getattr(obj, "headers", None)
    if headers_attr is not None:
        found += _origins_in_headers(headers_attr)
    return found


def _origins_in_headers(headers: Any) -> list[Any]:
    """Every ``origin`` value (name compared case-insensitively) in a mapping or ASGI list."""
    if isinstance(headers, Mapping):
        pairs: list[tuple[Any, Any]] = list(headers.items())
    elif isinstance(headers, (list, tuple)):
        # ASGI header list: [(b"origin", b"https://evil.com"), ...]
        pairs = []
        for item in headers:
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                return [_UnreadableHeaders("an ASGI header entry is not a (name, value) pair")]
            pairs.append((item[0], item[1]))
    else:
        return []
    found: list[Any] = []
    for key, value in pairs:
        name = _latin1(key)
        if isinstance(name, str) and name.lower() == "origin":
            _add_header_values(found, value)
    return found


def _add_header_values(found: list[Any], value: Any) -> None:
    """Add one header's value: ``bytes`` as Latin-1, a list / tuple item by item.

    Anything else is kept as it is, for :meth:`WebSocketOriginGuard.check_upgrade` to
    refuse as not text.
    """
    for item in value if isinstance(value, (list, tuple)) else (value,):
        found.append(_latin1(item))


def _latin1(value: Any) -> Any:
    """``bytes`` decoded as Latin-1 (how ASGI carries header bytes); anything else as is."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).decode("latin-1")
    return value


__all__ = [
    "DEFAULT_CONTROL_WS_PORT",
    "WebSocketOriginDecision",
    "WebSocketOriginGuard",
    "WebSocketOriginHijackError",
    "WebSocketOriginVerdict",
    "extract_origin",
]
