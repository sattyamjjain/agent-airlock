"""0.10.29: ``AirlockAdkPlugin`` runs each ADK invocation as one Airlock run and cleans
up after it.

Raised in google/adk-python#7770: a ``CancelledError`` that isn't an early close reaches
neither the after-run nor the error hook. The stand-ins mirror google-adk v2.13.0:
``BasePlugin(name)`` with a no-op per callback, an ``InvocationContext`` with
``invocation_id`` and ``is_aborted``, and ``_run`` below, which calls the hooks the way
``Runner._exec_with_plugin`` does (``after_run_callback`` on completion or a cancel of an
aborted run, ``on_run_error_callback`` for an ``Exception``, neither for any other
``CancelledError``).
"""

from __future__ import annotations

import asyncio
import contextlib
import sys
import types
from collections.abc import Awaitable, Callable, Iterator
from typing import Any

import pytest

from agent_airlock import Airlock, AirlockContext, SecurityPolicy
from agent_airlock.amplification import AmplificationBudget
from agent_airlock.context import get_current_context
from agent_airlock.integrations import google_adk_plugin as plugin_module
from agent_airlock.integrations.google_adk import GoogleADKMissingError
from agent_airlock.integrations.google_adk_plugin import AirlockAdkPlugin
from agent_airlock.sequence_guard import ENTRY_SENTINEL, SequenceGuard


class _BasePlugin:
    """``google.adk.plugins.base_plugin.BasePlugin``: a name, and a no-op per callback."""

    def __init__(self, name: str) -> None:
        super().__init__()
        self.name = name

    async def before_run_callback(self, *, invocation_context: Any) -> None:
        return None

    async def after_run_callback(self, *, invocation_context: Any) -> None:
        return None

    async def on_run_error_callback(self, *, invocation_context: Any, error: Exception) -> None:
        return None

    async def close(self) -> None:
        return None


@pytest.fixture(autouse=True)
def adk(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """google-adk as far as the plugin imports it; the parent packages seeded too."""
    names = ["google", "google.adk", "google.adk.plugins", "google.adk.plugins.base_plugin"]
    modules = [types.ModuleType(name) for name in names]
    modules[-1].BasePlugin = _BasePlugin  # type: ignore[attr-defined]
    for parent, child, name in zip(modules, modules[1:], names[1:], strict=False):
        setattr(parent, name.rsplit(".", 1)[1], child)
    for name, module in zip(names, modules, strict=True):
        monkeypatch.setitem(sys.modules, name, module)
    yield


class _InvocationContext:
    def __init__(self, invocation_id: str) -> None:
        self.invocation_id = invocation_id
        self._aborted = False

    @property
    def is_aborted(self) -> bool:
        return self._aborted

    def abort(self) -> None:
        self._aborted = True


async def _run(plugin: Any, ic: Any, body: Callable[[], Awaitable[None]]) -> None:
    """``Runner._exec_with_plugin``'s plugin calls, as v2.13.0 makes them."""
    run_error: BaseException | None = None
    try:
        await plugin.before_run_callback(invocation_context=ic)
        await body()
    except Exception as error:
        run_error = error
        await plugin.on_run_error_callback(invocation_context=ic, error=error)
        raise
    except asyncio.CancelledError as error:
        if not getattr(ic, "is_aborted", False):
            run_error = error  # neither hook: google/adk-python#7770
        raise
    finally:
        if run_error is None:
            await plugin.after_run_callback(invocation_context=ic)


class _Recorder:
    """Stands in for a module's logger and records ``(level, event, fields)``."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def __getattr__(self, level: str) -> Any:
        def record(event: str = "", **fields: Any) -> None:
            self.calls.append((level, event, fields))

        return record

    def events(self, event: str) -> list[dict[str, Any]]:
        return [fields for _, name, fields in self.calls if name == event]


@pytest.fixture
def logs(monkeypatch: pytest.MonkeyPatch) -> _Recorder:
    recorder = _Recorder()
    monkeypatch.setattr(plugin_module, "logger", recorder)
    return recorder


def _policy(**kwargs: Any) -> SecurityPolicy:
    dag = {ENTRY_SENTINEL: {"search"}, "search": {"search"}}
    return SecurityPolicy(
        amplification_budget=AmplificationBudget(max_calls_per_run=2),
        sequence_guard=SequenceGuard(mode="declared", dag=dag),
        **kwargs,
    )


def _guarded(policy: SecurityPolicy) -> tuple[Callable[..., Any], list[tuple[Any, Any]]]:
    seen: list[tuple[Any, Any]] = []

    @Airlock(policy=policy)
    def search(query: str) -> str:
        context = get_current_context()
        seen.append((context.agent_id, context.session_id) if context else (None, None))
        return query

    return search, seen


def _entries(policy: SecurityPolicy) -> list[str]:
    assert policy._amplification_guard is not None and policy.sequence_guard is not None
    return [*policy._amplification_guard._ledgers, *policy.sequence_guard._traces]


class TestThePlugin:
    def test_it_is_an_adk_plugin(self) -> None:
        plugin = AirlockAdkPlugin(_policy())
        assert isinstance(plugin, _BasePlugin) and isinstance(plugin, AirlockAdkPlugin)
        assert plugin.name == "airlock"
        assert type(AirlockAdkPlugin(name="other")) is type(plugin)  # built once per base

    def test_without_adk_it_says_what_to_install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setitem(sys.modules, "google.adk.plugins.base_plugin", None)
        with pytest.raises(GoogleADKMissingError, match="agent-airlock\\[google-adk\\]"):
            AirlockAdkPlugin()

    def test_a_bad_bound(self) -> None:
        for bad in (0, -1, True):
            with pytest.raises(ValueError, match="max_runs"):
                AirlockAdkPlugin(max_runs=bad)


class TestEachInvocationIsARun:
    def test_calls_count_against_their_own_run(self) -> None:
        policy = _policy()
        search, seen = _guarded(policy)
        plugin = AirlockAdkPlugin(policy)

        async def two_calls() -> None:
            assert search(query="a") == "a" and search(query="b") == "b"

        for invocation in ("inv-1", "inv-2"):
            asyncio.run(_run(plugin, _InvocationContext(invocation), two_calls))
        assert [session for _, session in seen] == [
            *["adk-invocation:inv-1"] * 2,
            *["adk-invocation:inv-2"] * 2,
        ]

    def test_without_the_plugin_every_run_is_one(self) -> None:
        search, _ = _guarded(_policy())
        assert search(query="a") == "a" and search(query="b") == "b"
        refused = search(query="c")  # the next run's call, in the same anonymous ledger
        assert refused["block_reason"] == "amplification_exceeded"

    def test_a_finished_run_leaves_nothing_behind(self) -> None:
        policy = _policy()
        search, _ = _guarded(policy)
        plugin = AirlockAdkPlugin(policy)

        async def invocation() -> Any:
            async def one_call() -> None:
                search(query="a")

            await _run(plugin, _InvocationContext("inv-1"), one_call)
            return get_current_context()

        assert asyncio.run(invocation()) is None
        assert _entries(policy) == [] and len(plugin._runs) == 0

    def test_the_hosts_agent_and_roles_are_carried(self) -> None:
        policy = _policy()
        search, seen = _guarded(policy)
        plugin = AirlockAdkPlugin(policy)

        async def one_call() -> None:
            search(query="a")

        with AirlockContext(agent_id="agent-1", roles=["analyst"]):
            asyncio.run(_run(plugin, _InvocationContext("inv-1"), one_call))
        assert seen == [("agent-1", "adk-invocation:inv-1")]

    def test_a_hosts_own_session_is_left_to_the_host(self) -> None:
        policy = _policy()
        search, seen = _guarded(policy)
        plugin = AirlockAdkPlugin(policy)

        async def one_call() -> None:
            search(query="a")

        with AirlockContext(session_id="host-run"):
            asyncio.run(_run(plugin, _InvocationContext("inv-1"), one_call))
        assert seen == [(None, "host-run")] and _entries(policy) == ["host-run", "host-run"]

    def test_a_task_started_inside_the_run_is_in_it(self) -> None:
        policy = _policy()
        search, seen = _guarded(policy)

        async def in_a_task() -> None:
            await asyncio.create_task(asyncio.to_thread(search, query="a"))

        asyncio.run(_run(AirlockAdkPlugin(policy), _InvocationContext("inv-1"), in_a_task))
        assert seen == [(None, "adk-invocation:inv-1")]

    def test_an_invocation_without_an_id_is_not_named(self, logs: _Recorder) -> None:
        policy = _policy()
        search, seen = _guarded(policy)

        async def one_call() -> None:
            search(query="a")

        asyncio.run(_run(AirlockAdkPlugin(policy), _InvocationContext(""), one_call))
        assert seen == [(None, None)] and logs.events("adk_invocation_without_id") == [{}]


class TestHowARunEnds:
    def _end(self, body: Callable[[Callable[..., Any], Any], Awaitable[None]]) -> tuple[Any, Any]:
        policy = _policy()
        search, _ = _guarded(policy)
        plugin = AirlockAdkPlugin(policy)
        ic = _InvocationContext("inv-1")

        async def run() -> None:
            await body(search, ic)

        with contextlib.suppress(RuntimeError, asyncio.CancelledError):  # re-raised by ADK
            asyncio.run(_run(plugin, ic, run))
        return policy, plugin

    def test_a_completed_run(self, logs: _Recorder) -> None:
        async def body(search: Any, ic: Any) -> None:
            search(query="a")

        policy, _ = self._end(body)
        assert [e["outcome"] for e in logs.events("adk_invocation_finished")] == ["completed"]
        assert _entries(policy) == []

    def test_an_error(self, logs: _Recorder) -> None:
        async def body(search: Any, ic: Any) -> None:
            search(query="a")
            raise RuntimeError("the model provider is down")

        policy, _ = self._end(body)
        (finished,) = logs.events("adk_invocation_finished")
        assert finished["outcome"] == "error" and finished["error_type"] == "RuntimeError"
        assert _entries(policy) == []

    def test_an_aborted_run_is_cancelled_and_cleaned_up(self, logs: _Recorder) -> None:
        async def body(search: Any, ic: Any) -> None:
            search(query="a")
            ic.abort()
            raise asyncio.CancelledError  # ADK cancels the aborted run

        policy, plugin = self._end(body)
        assert [e["outcome"] for e in logs.events("adk_invocation_finished")] == ["cancelled"]
        assert _entries(policy) == [] and len(plugin._runs) == 0

    def test_an_aborted_run_that_errors_is_cancelled(self, logs: _Recorder) -> None:
        async def body(search: Any, ic: Any) -> None:
            ic.abort()
            raise RuntimeError("raised while aborting")

        self._end(body)
        assert [e["outcome"] for e in logs.events("adk_invocation_finished")] == ["cancelled"]

    def test_a_cancel_no_hook_sees_waits_for_close(self, logs: _Recorder) -> None:
        async def body(search: Any, ic: Any) -> None:
            search(query="a")
            raise asyncio.CancelledError  # not an abort: neither hook runs

        policy, plugin = self._end(body)
        assert logs.events("adk_invocation_finished") == []
        assert _entries(policy) == ["adk-invocation:inv-1"] * 2 and list(plugin._runs) == ["inv-1"]
        asyncio.run(plugin.close())
        assert _entries(policy) == [] and len(plugin._runs) == 0
        assert logs.events("adk_invocation_unfinished") == [
            {"invocation_id": "inv-1", "run": "adk-invocation:inv-1"}
        ]

    def test_an_adk_without_is_aborted(self, logs: _Recorder) -> None:
        plugin = AirlockAdkPlugin()
        ic = types.SimpleNamespace(invocation_id="inv-1")  # before v2.10.0

        async def nothing() -> None:
            return None

        asyncio.run(_run(plugin, ic, nothing))
        assert [e["outcome"] for e in logs.events("adk_invocation_finished")] == ["completed"]


class TestTheRunsInFlight:
    def test_the_plugins_own_records_are_bounded(self, logs: _Recorder) -> None:
        plugin = AirlockAdkPlugin(max_runs=3)

        async def start(invocation: str) -> None:
            await plugin.before_run_callback(invocation_context=_InvocationContext(invocation))

        for invocation in range(5):
            asyncio.run(start(f"inv-{invocation}"))
        assert list(plugin._runs) == ["inv-2", "inv-3", "inv-4"]
        assert [e["invocation_id"] for e in logs.events("adk_invocation_evicted")] == [
            "inv-0",
            "inv-1",
        ]

    def test_an_end_for_a_run_it_does_not_know_is_logged(self, logs: _Recorder) -> None:
        plugin = AirlockAdkPlugin()
        asyncio.run(plugin.after_run_callback(invocation_context=_InvocationContext("inv-9")))
        assert logs.events("adk_invocation_untracked") == [
            {"invocation_id": "inv-9", "outcome": "completed"}
        ]
