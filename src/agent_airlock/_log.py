"""Zero-dependency logging shim (v0.8.59+).

The airlock core is Pydantic-only: ``structlog`` is an optional ``[logging]``
extra, **not** a core runtime dependency. Every internal module logs through the
single name this module exports — ``from ._log import structlog`` — so the choice
of real dependency vs. fallback is made in exactly one place:

* When ``structlog`` is installed (the default for ``[dev]`` / ``[logging]`` /
  ``[all]`` installs, and every CI job that installs an extra), the ``structlog``
  exported here **is** the real module. Behaviour and structured-JSON output are
  byte-for-byte unchanged — the shim adds nothing to that path.
* On a bare ``pip install agent-airlock`` (Pydantic only), ``structlog`` here is
  a tiny stdlib-``logging``-backed fallback that accepts structlog's
  keyword-event call form. Log records still emit; they are plain-formatted
  rather than structured JSON.

The fallback deliberately covers only the API surface the library actually uses:
``get_logger`` (the ``logger = structlog.get_logger(...)`` sites across the
package) plus the ``configure`` / ``make_filtering_bound_logger`` /
``PrintLoggerFactory`` / ``processors`` / ``dev`` names touched by the four CLI
benchmark entrypoints. Install the real dependency for structured output::

    pip install "agent-airlock[logging]"
"""

from __future__ import annotations

import logging
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

__all__ = ["structlog"]


def _noop(*_args: Any, **_kwargs: Any) -> None:
    """Accept and ignore any arguments — a stand-in for a structlog processor."""
    return None


class _ShimBoundLogger:
    """stdlib-``logging``-backed stand-in for a structlog bound logger.

    structlog callers pass a positional ``event`` string plus arbitrary keyword
    context (``logger.info("blocked", tool=name, reason=why)``). stdlib
    ``logging`` rejects unknown keyword arguments, so the context is folded into
    the message here — that formatting difference is the one genuine
    incompatibility between the fallback and the real dependency.
    """

    __slots__ = ("_log",)

    def __init__(self, name: str) -> None:
        self._log = logging.getLogger(name)

    @staticmethod
    def _render(event: object, context: dict[str, Any]) -> str:
        if not context:
            return str(event)
        rendered = " ".join(f"{key}={value!r}" for key, value in context.items())
        return f"{event} {rendered}"

    def debug(self, event: object = "", **context: Any) -> None:
        self._log.debug(self._render(event, context))

    def info(self, event: object = "", **context: Any) -> None:
        self._log.info(self._render(event, context))

    def warning(self, event: object = "", **context: Any) -> None:
        self._log.warning(self._render(event, context))

    def error(self, event: object = "", **context: Any) -> None:
        self._log.error(self._render(event, context))

    def critical(self, event: object = "", **context: Any) -> None:
        self._log.critical(self._render(event, context))

    def exception(self, event: object = "", **context: Any) -> None:
        self._log.error(self._render(event, context), exc_info=True)

    def bind(self, **_context: Any) -> _ShimBoundLogger:
        # structlog.bind() returns a new bound logger; the fallback drops the
        # context (stdlib logging has no equivalent) and returns itself.
        return self


class _StructlogShim:
    """Module-shaped fallback exposing the structlog names the library uses."""

    @staticmethod
    def get_logger(name: str = "agent-airlock", *_args: Any, **_kwargs: Any) -> _ShimBoundLogger:
        return _ShimBoundLogger(name)

    @staticmethod
    def configure(*_args: Any, **_kwargs: Any) -> None:
        return None

    @staticmethod
    def make_filtering_bound_logger(*_args: Any, **_kwargs: Any) -> type[_ShimBoundLogger]:
        return _ShimBoundLogger

    @staticmethod
    def PrintLoggerFactory(*_args: Any, **_kwargs: Any) -> None:
        return None

    # ``configure`` is a no-op in the fallback, so these processor names only
    # need to exist and be callable; the CLI benches pass them into a config
    # that is discarded.
    processors = SimpleNamespace(add_log_level=_noop, TimeStamper=_noop)
    dev = SimpleNamespace(ConsoleRenderer=_noop)


if TYPE_CHECKING:
    import structlog
else:
    try:
        import structlog
    except ModuleNotFoundError:  # pragma: no cover - exercised only in the bare-install CI job
        structlog = _StructlogShim()
