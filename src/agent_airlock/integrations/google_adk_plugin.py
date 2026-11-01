"""Google ADK run lifecycle: one Airlock run per invocation, cleaned up as it ends (V0.10.29).

:class:`AirlockAdkPlugin` is an optional ADK plugin, for ``Runner(..., plugins=[...])`` or
``App(plugins=[...])``, beside the tool walker in :mod:`.google_adk`. It sees what the
walker cannot: the run around the tool calls.

* Each ADK invocation is one Airlock run. When nothing around the run names a
  ``session_id``, ``before_run_callback`` sets an ``AirlockContext`` whose ``session_id`` is
  ``adk-invocation:<invocation id>``, the host's agent id, roles and metadata carried over,
  so the per-run state the policies keep (the amplification ledger, the sequence guard's
  trace, the action-contradiction gate's flag) counts that run alone rather than every run
  in one anonymous ledger.
* ``after_run_callback`` and ``on_run_error_callback`` log how the run ended
  (``adk_invocation_finished``: ``completed``, ``error``, or ``cancelled`` when
  ``invocation_context.is_aborted`` is set, which ADK has from v2.10.0) and drop the run's
  entries from the policies (:meth:`~agent_airlock.policy.SecurityPolicy.reset_run`).
* ADK calls neither hook for a run cancelled other than by an abort or an early close
  (google/adk-python#7770, still so in v2.13.0), nor for an aborted run cancelled before
  v2.12.0. That run's entries stay until ``close()``, which ADK calls as the runner
  closes, or until the policies' own ``max_sessions`` bounds evict them, least recently
  used first.

ADK is imported when the plugin is built, so this module imports without it.
"""

from __future__ import annotations

import dataclasses
import threading
import time
from collections import OrderedDict
from typing import Any, cast

from .._log import structlog
from ..context import AirlockContext, get_current_context
from ..policy import SecurityPolicy
from .google_adk import _INSTALL_HINT, GoogleADKMissingError

logger = structlog.get_logger("agent-airlock.integrations.google_adk_plugin")

__all__ = ["RUN_KEY_PREFIX", "AirlockAdkPlugin"]

#: The ``session_id`` prefix of a run the plugin names: ``adk-invocation:<invocation id>``.
RUN_KEY_PREFIX = "adk-invocation:"


@dataclasses.dataclass
class _Run:
    """One invocation in flight: its run key, and the context the plugin set, if it did."""

    key: str
    context: AirlockContext[Any] | None
    started: float = dataclasses.field(default_factory=time.monotonic)


def _plugin_type() -> type:
    """``AirlockAdkPlugin`` built on the installed ADK's ``BasePlugin``, once per base.

    Raises:
        GoogleADKMissingError: google-adk is not installed.
    """
    try:
        from google.adk.plugins.base_plugin import BasePlugin
    except ImportError as exc:
        raise GoogleADKMissingError(_INSTALL_HINT) from exc
    with _TYPES_LOCK:
        built = _TYPES.get(BasePlugin)
        if built is None:
            namespace = {"__module__": __name__, "__qualname__": "AirlockAdkPlugin"}
            built = _TYPES[BasePlugin] = type(
                "AirlockAdkPlugin", (AirlockAdkPlugin, BasePlugin), namespace
            )
        return built


_TYPES: dict[type, type] = {}
_TYPES_LOCK = threading.Lock()


def _invocation_id(invocation_context: Any) -> str:
    found = getattr(invocation_context, "invocation_id", None)
    return found if isinstance(found, str) else ""


def _aborted(invocation_context: Any) -> bool:
    """``invocation_context.is_aborted``; False on an ADK older than v2.10.0."""
    return bool(getattr(invocation_context, "is_aborted", False))


class AirlockAdkPlugin:
    """An ADK plugin running each invocation as one Airlock run (see the module docstring).

    ``AirlockAdkPlugin(policy)`` builds an instance of this class on the installed ADK's
    ``BasePlugin``, so ADK and ``App(plugins=[...])`` accept it as a plugin.

    Args:
        *policies: The policies the agent's tools are guarded with; their per-run state is
            dropped as each run ends.
        name: The plugin's name, unique among a runner's plugins.
        max_runs: How many invocations in flight the plugin keeps track of. Past it the
            least recently started one is forgotten (``adk_invocation_evicted``), and its
            entries are left to the policies' own bounds.

    Raises:
        GoogleADKMissingError: google-adk is not installed.
        ValueError: ``max_runs`` is not a whole number of 1 or more.
    """

    def __new__(cls, *_args: Any, **_kwargs: Any) -> AirlockAdkPlugin:
        built = _plugin_type() if cls is AirlockAdkPlugin else cls
        return cast(AirlockAdkPlugin, object.__new__(built))

    def __init__(
        self, *policies: SecurityPolicy, name: str = "airlock", max_runs: int = 10_000
    ) -> None:
        if isinstance(max_runs, bool) or not isinstance(max_runs, int) or max_runs < 1:
            raise ValueError(f"max_runs must be a whole number of 1 or more; got {max_runs!r}")
        super().__init__(name)  # type: ignore[call-arg]  # BasePlugin's, beneath this class
        self._policies = policies
        self._max_runs = max_runs
        self._runs: OrderedDict[str, _Run] = OrderedDict()
        self._lock = threading.Lock()

    async def before_run_callback(self, *, invocation_context: Any) -> None:
        """Start the invocation's run, naming it when nothing around the run does."""
        invocation_id = _invocation_id(invocation_context)
        if not invocation_id:
            logger.warning("adk_invocation_without_id")
            return
        ambient = get_current_context()
        context: AirlockContext[Any] | None = None
        if ambient is not None and ambient.session_id:
            key = ambient.session_id  # the host's own run: its state is the host's to drop
        else:
            key = RUN_KEY_PREFIX + invocation_id
            context = (
                AirlockContext(session_id=key)
                if ambient is None
                else dataclasses.replace(ambient, session_id=key, _token=None)
            )
            context.__enter__()
        self._track(invocation_id, _Run(key, context))

    async def after_run_callback(self, *, invocation_context: Any) -> None:
        """End the run: ``cancelled`` when it was aborted, else ``completed``."""
        outcome = "cancelled" if _aborted(invocation_context) else "completed"
        self._finish(invocation_context, outcome)

    async def on_run_error_callback(self, *, invocation_context: Any, error: Exception) -> None:
        """End the run: ``cancelled`` when it was aborted, else ``error``."""
        outcome = "cancelled" if _aborted(invocation_context) else "error"
        self._finish(invocation_context, outcome, error)

    async def close(self) -> None:
        """Drop the state of every run no hook ended, as the runner closes."""
        with self._lock:
            runs = list(self._runs.items())
            self._runs.clear()
        for invocation_id, run in runs:
            self._release(run)
            logger.warning("adk_invocation_unfinished", invocation_id=invocation_id, run=run.key)

    def _track(self, invocation_id: str, run: _Run) -> None:
        with self._lock:
            self._runs[invocation_id] = run
            self._runs.move_to_end(invocation_id)
            while len(self._runs) > self._max_runs:
                evicted, dropped = self._runs.popitem(last=False)
                logger.warning(
                    "adk_invocation_evicted",
                    invocation_id=evicted,
                    run=dropped.key,
                    max_runs=self._max_runs,
                )

    def _finish(
        self, invocation_context: Any, outcome: str, error: Exception | None = None
    ) -> None:
        invocation_id = _invocation_id(invocation_context)
        with self._lock:
            run = self._runs.pop(invocation_id, None)
        if run is None:
            logger.warning("adk_invocation_untracked", invocation_id=invocation_id, outcome=outcome)
            return
        self._release(run)
        logger.info(
            "adk_invocation_finished",
            invocation_id=invocation_id,
            run=run.key,
            outcome=outcome,
            seconds=round(time.monotonic() - run.started, 3),
            error_type=type(error).__name__ if error is not None else None,
        )

    def _release(self, run: _Run) -> None:
        """Unset the context the plugin set, and drop the run's state if it named the run."""
        if run.context is None:
            return
        try:
            run.context.__exit__(None, None, None)
        except ValueError:
            # Set in another task's context, which ended with it.
            run.context._token = None
        for policy in self._policies:
            policy.reset_run(run.key)
