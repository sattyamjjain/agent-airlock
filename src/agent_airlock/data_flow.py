"""Gate outward-acting tools once untrusted content has entered the run (V0.10.29).

``@source(trust="untrusted")`` marks a tool whose output is content nobody in the run
wrote: a fetched page, an inbox, a file from outside. ``@sink`` marks a tool that acts
outward: it sends, posts, pays or writes. Both are read like ``@requires``, above or below
``@Airlock``.

Every call of an untrusted source that reaches execution taints its run when it returns or
raises, whatever policy guards the source itself, since the gate is the sink's. With
``SecurityPolicy(data_flow_policy=DataFlowPolicy(...))`` on a sink, a call of it in a
tainted run is refused (``deny``) or held for the policy's approver (``escalate``), until
the host calls ``clear_taint()`` on the run's context. The taint is the run's, not one
output's, so output a later tool derives from the untrusted content (a summary of the
page) stays tainted: tagging only the source's own output misses it
(MervinPraison/PraisonAI#5061, google/adk-python#7103).

Parallel calls: a sink is gated by the sources that completed before its check. With
``serialize_batch`` a sink first waits for the run's sources still running, and on the
async path lets the other calls of its batch start before it looks. See
``docs/guide/data-flow.md`` for exactly which orderings that covers.

The design follows CaMeL (Debenedetti et al., arXiv:2503.18813) at a coarser grain: one
taint per run rather than capabilities on each value (``PRIOR_ART.md``).
"""

from __future__ import annotations

import math
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal, TypeVar, overload

from .capabilities import _airlock_wrappers_beneath

__all__ = [
    "DataFlowPolicy",
    "RunFlow",
    "SinkTag",
    "SourceTag",
    "TaintEntry",
    "flow_tags",
    "output_provenance",
    "sink",
    "source",
]

F = TypeVar("F", bound=Callable[..., Any])

Trust = Literal["untrusted", "trusted"]
SinkAction = Literal["deny", "escalate"]

_SOURCE_ATTR = "__airlock_source__"
_SINK_ATTR = "__airlock_sink__"


@dataclass(frozen=True)
class SourceTag:
    """What ``@source`` declared: whether the tool's output is trusted, and its kind."""

    trust: Trust
    kind: str


@dataclass(frozen=True)
class SinkTag:
    """What ``@sink`` declared: the kind of outward action the tool takes."""

    kind: str


@dataclass(frozen=True)
class TaintEntry:
    """One untrusted source call that completed in a run: the tool and its kind."""

    tool: str
    kind: str


def _check_kind(kind: object, decorator: str) -> str:
    if not isinstance(kind, str) or not kind.strip():
        raise ValueError(f"@{decorator}(kind=...) must be a non-empty string, got {kind!r}")
    return kind


def _mark(target: Callable[..., Any], attr: str, tag: SourceTag | SinkTag) -> None:
    """Put ``tag`` on ``target`` and on every ``@Airlock`` wrapper beneath it."""
    setattr(target, attr, tag)
    for guarded in _airlock_wrappers_beneath(target):
        setattr(guarded, attr, tag)


def source(*, trust: Trust = "untrusted", kind: str = "external_content") -> Callable[[F], F]:
    """Declare a tool whose output enters the run from outside it.

    Args:
        trust: ``"untrusted"`` (the default) taints the run when the tool completes.
            ``"trusted"`` records the output's provenance without tainting.
        kind: What the content is (``"web"``, ``"email"``), carried on the taint and on
            the output's provenance tag.

    Raises:
        ValueError: ``trust`` is not ``"untrusted"`` or ``"trusted"``, or ``kind`` is empty.
    """
    if trust not in ("untrusted", "trusted"):
        raise ValueError(f"@source(trust=...) must be 'untrusted' or 'trusted', got {trust!r}")
    tag = SourceTag(trust=trust, kind=_check_kind(kind, "source"))

    def decorator(func: F) -> F:
        _mark(func, _SOURCE_ATTR, tag)
        return func

    return decorator


@overload
def sink(func: F, /) -> F: ...


@overload
def sink(*, kind: str = "outward_action") -> Callable[[F], F]: ...


def sink(func: Any = None, /, *, kind: str = "outward_action") -> Any:
    """Declare a tool that acts outward: it sends, posts, pays or writes.

    Usable bare (``@sink``) or with a kind (``@sink(kind="email")``).

    Raises:
        ValueError: ``kind`` is empty.
    """
    tag = SinkTag(kind=_check_kind(kind, "sink"))

    def decorator(target: F) -> F:
        _mark(target, _SINK_ATTR, tag)
        return target

    return decorator(func) if func is not None else decorator


def flow_tags(func: Callable[..., Any]) -> tuple[SourceTag | None, SinkTag | None]:
    """The source and sink tags of ``func`` or of a callable down its ``__wrapped__`` chain."""
    found_source: SourceTag | None = None
    found_sink: SinkTag | None = None
    seen: set[int] = set()
    current: Any = func
    for _ in range(32):  # bounded, like get_required_capabilities
        if current is None or id(current) in seen:
            break
        seen.add(id(current))
        if found_source is None and isinstance(getattr(current, _SOURCE_ATTR, None), SourceTag):
            found_source = getattr(current, _SOURCE_ATTR)
        if found_sink is None and isinstance(getattr(current, _SINK_ATTR, None), SinkTag):
            found_sink = getattr(current, _SINK_ATTR)
        current = getattr(current, "__wrapped__", None)
    return found_source, found_sink


class _SourceTicket:
    """An untrusted source call in flight: :meth:`finish` taints the run and releases it."""

    def __init__(self, flow: RunFlow, entry: TaintEntry) -> None:
        self._flow = flow
        self._entry = entry
        self._done = False

    def finish(self, *, ran: bool) -> None:
        """Taint the run when the call ran, and stop counting it as running. Idempotent."""
        with self._flow._cond:
            if self._done:
                return
            self._done = True
            self._flow._in_flight -= 1
            if ran:
                self._flow._taint.append(self._entry)
            self._flow._cond.notify_all()


class RunFlow:
    """A run's taint: the untrusted sources that completed in it, and those still running.

    One lives on every ``AirlockContext``. ``_share_run_state`` points a call's context at
    its run's, so the taint a source leaves is the one a later sink reads.
    """

    def __init__(self) -> None:
        self._cond = threading.Condition()
        self._taint: list[TaintEntry] = []
        self._in_flight = 0

    def begin_source(self, entry: TaintEntry) -> _SourceTicket:
        """Count an untrusted source call as running until its ticket finishes."""
        with self._cond:
            self._in_flight += 1
        return _SourceTicket(self, entry)

    def sources(self) -> tuple[TaintEntry, ...]:
        """The untrusted source calls that completed since the taint was last cleared."""
        with self._cond:
            return tuple(self._taint)

    def running(self) -> int:
        """How many untrusted source calls of the run are still running."""
        with self._cond:
            return self._in_flight

    def wait_quiet(self, timeout: float) -> bool:
        """Wait up to ``timeout`` seconds for no source to be running; True if none is."""
        with self._cond:
            return self._cond.wait_for(lambda: self._in_flight == 0, timeout)

    def clear(self) -> None:
        """Forget the completed sources. One still running taints the run when it ends."""
        with self._cond:
            self._taint.clear()


@dataclass(frozen=True)
class DataFlowPolicy:
    """What a sink's policy does with a call made after untrusted content entered its run.

    Attributes:
        on_sink_after_source: ``"deny"`` refuses the call; ``"escalate"`` holds it for the
            policy's ``approver``, and with none registered refuses it.
        serialize_batch: Before its check, a sink waits for the run's untrusted sources
            still running, and on the async path first lets the other calls of its batch
            reach the gate, so a source dispatched in the same batch is seen.
        batch_wait_seconds: How long a sink waits under ``serialize_batch``. A source still
            running when the wait ends is counted as having tainted the run.
    """

    on_sink_after_source: SinkAction = "deny"
    serialize_batch: bool = False
    batch_wait_seconds: float = 30.0

    def __post_init__(self) -> None:
        """Refuse a setting the gate cannot apply.

        Raises:
            ValueError: An unknown action, or a wait that is negative, NaN or infinite.
            TypeError: ``serialize_batch`` is not a bool.
        """
        if self.on_sink_after_source not in ("deny", "escalate"):
            raise ValueError(
                "DataFlowPolicy.on_sink_after_source must be 'deny' or 'escalate', got "
                f"{self.on_sink_after_source!r}"
            )
        if not isinstance(self.serialize_batch, bool):
            raise TypeError("DataFlowPolicy.serialize_batch must be a bool")
        wait = self.batch_wait_seconds
        if isinstance(wait, bool) or not isinstance(wait, int | float) or not math.isfinite(wait):
            raise ValueError(
                f"DataFlowPolicy.batch_wait_seconds must be a finite number, got {wait!r}"
            )
        if wait < 0:
            raise ValueError(f"DataFlowPolicy.batch_wait_seconds must be >= 0, got {wait!r}")

    def canonical(self) -> dict[str, object]:
        """The fields a policy digest covers."""
        return {
            "on_sink_after_source": self.on_sink_after_source,
            "serialize_batch": self.serialize_batch,
            "batch_wait_seconds": self.batch_wait_seconds,
        }


def output_provenance(
    source_tag: SourceTag | None, taint: tuple[TaintEntry, ...]
) -> dict[str, object] | None:
    """The provenance tag of a call's output, or None for output nothing untrusted touched.

    An untrusted source's own output crossed the run's boundary. Any other output produced
    while the run is tainted is derived from what crossed it, and says from which kinds.
    """
    if source_tag is not None and source_tag.trust == "untrusted":
        return {"trust": "untrusted", "source": source_tag.kind, "crossed_boundary": True}
    if taint:
        return {
            "trust": "untrusted",
            "source": "derived",
            "crossed_boundary": False,
            "derived_from": sorted({entry.kind for entry in taint}),
        }
    if source_tag is not None:
        return {"trust": "trusted", "source": source_tag.kind, "crossed_boundary": False}
    return None
