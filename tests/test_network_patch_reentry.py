"""The airgap's patch section, entered again by the thread already inside it.

The garbage collector closes an abandoned, half-read guarded stream wherever it happens to
run, and the stream's cleanup opens and closes an airgap of its own. Until 0.10.36 that could
happen while the thread held ``network._patch_lock``, a plain ``Lock``, so the thread waited
on itself for good (two CI ``test (3.13)`` jobs stopped in ``test_execution_0_10_28.py``).
"""

from __future__ import annotations

import gc
import os
import socket
import subprocess
import sys
import textwrap
from collections.abc import Callable, Generator, Iterator
from pathlib import Path
from typing import Any

import pytest

from agent_airlock import Airlock, AirlockConfig
from agent_airlock import network as network_module
from agent_airlock.network import NetworkBlockedError, NetworkPolicy, network_airgap

_NO_EGRESS = NetworkPolicy(allow_egress=False)
_REPO = Path(__file__).resolve().parents[1]


def _lookup() -> str:
    try:
        socket.getaddrinfo("127.0.0.1", 9)
    except NetworkBlockedError:
        return "refused"
    return "allowed"


@pytest.fixture(autouse=True)
def _nothing_left_patched() -> Iterator[None]:
    before = [getattr(owner, name) for _, owner, name, _ in network_module._patch_targets()]
    yield
    left_open = network_module._interceptor_ref_count
    network_module._reset_interceptors()
    after = [getattr(owner, name) for _, owner, name, _ in network_module._patch_targets()]
    assert left_open == 0
    assert after == before


@pytest.mark.skipif(
    sys.version_info < (3, 12),
    reason="before 3.12 the collector also runs inside ContextVar.set, where cleanup that sets "
    "a ContextVar can crash the interpreter (CPython's own: it needs no Airlock code)",
)
class TestTheCollectorClosesAStreamAnywhere:
    @pytest.mark.parametrize("structlog", [True, False], ids=["structlog", "stdlib-shim"])
    def test_a_guarded_call_never_waits_on_itself(self, structlog: bool, tmp_path: Path) -> None:
        """Each pass leaves one abandoned stream and moves the point where the collector runs.

        Real objects and the real collector, in a child so a hang fails one test: the child
        kills itself after 25 s and prints where it was stuck. structlog's default
        ``PrintLogger`` writes under a plain ``Lock`` of its own, so the cleanup must not log.
        """
        child = textwrap.dedent(
            f"""
            import faulthandler, gc, sys, warnings
            faulthandler.dump_traceback_later(25, exit=True)
            warnings.simplefilter("ignore")
            if not {structlog!r}:
                sys.modules["structlog"] = None  # the import fails, as in a bare install
            from agent_airlock import Airlock, AirlockConfig
            from agent_airlock.network import NetworkPolicy

            config = AirlockConfig(
                network_policy=NetworkPolicy(allow_egress=False),
                enable_audit_log=False,
                startup_hook_check="off",
            )

            @Airlock(config=config)
            def stream_tool():
                yield "a"
                yield "b"

            @Airlock(config=config)
            def tool() -> str:
                return "ok"

            class Box:
                pass

            def abandon() -> None:
                box = Box()
                box.me = box
                box.stream = stream_tool()
                next(box.stream)

            tool(), list(stream_tool())
            for threshold in range(1, 400):
                gc.collect()
                gc.disable()
                abandon()
                gc.set_threshold(threshold, 1, 1)
                gc.enable()
                assert tool() == "ok"
            print("finished")
            """
        )
        done = subprocess.run(
            [sys.executable, "-c", child],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=tmp_path,
            env={**os.environ, "PYTHONPATH": str(_REPO / "src")},
        )
        assert done.returncode == 0, done.stderr[-2000:]
        assert done.stdout.endswith("finished\n")


def _enter_again_at(
    monkeypatch: pytest.MonkeyPatch, position: int, action: Callable[[], None]
) -> list[int]:
    """Run ``action`` once, when the next patch or restore loop reaches ``position``."""
    real = network_module._patch_targets
    entered: list[int] = []

    def targets() -> Generator[Any, None, None]:
        for index, target in enumerate(real()):
            if index == position and not entered:
                entered.append(index)
                action()
            yield target

    monkeypatch.setattr(network_module, "_patch_targets", targets)
    return entered


def _half_read_stream() -> Generator[str, None, None]:
    @Airlock(
        config=AirlockConfig(
            network_policy=_NO_EGRESS, enable_audit_log=False, startup_hook_check="off"
        )
    )
    def stream_tool() -> Generator[str, None, None]:
        yield "a"
        yield "b"

    stream: Generator[str, None, None] = stream_tool()
    next(stream)
    return stream


_POSITIONS = range(len(network_module._patch_targets()))


@pytest.mark.parametrize("position", _POSITIONS)
class TestEnteringAgainPartWay:
    """The same thread opens an airgap between any two functions of the loop."""

    def test_while_installing(self, position: int, monkeypatch: pytest.MonkeyPatch) -> None:
        stream = _half_read_stream()
        entered = _enter_again_at(monkeypatch, position, stream.close)

        with network_airgap(_NO_EGRESS):
            assert entered == [position]
            assert _lookup() == "refused"
            # An interceptor saved as its own original would call itself for ever.
            for name, _, _, interceptor in network_module._patch_targets():
                assert network_module._originals[name] is not interceptor

        assert _lookup() == "allowed"

    def test_while_restoring(self, position: int, monkeypatch: pytest.MonkeyPatch) -> None:
        stream = _half_read_stream()
        with network_airgap(_NO_EGRESS):
            entered = _enter_again_at(monkeypatch, position, stream.close)

        assert entered == [position]
        assert _lookup() == "allowed"

    def test_an_airgap_opened_while_restoring_is_enforced(
        self, position: int, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: list[str] = []

        def call() -> None:
            with network_airgap(_NO_EGRESS):
                seen.append(_lookup())

        with network_airgap(_NO_EGRESS):
            _enter_again_at(monkeypatch, position, call)

        assert seen == ["refused"]
        assert _lookup() == "allowed"

    def test_an_airgap_left_open_while_restoring_stays_enforced(
        self, position: int, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        inner = network_airgap(_NO_EGRESS)
        with network_airgap(_NO_EGRESS):
            _enter_again_at(monkeypatch, position, inner.__enter__)

        assert _lookup() == "refused"
        for _, owner, name, interceptor in network_module._patch_targets():
            assert getattr(owner, name) is interceptor
        inner.__exit__(None, None, None)
        assert _lookup() == "allowed"


def test_collecting_an_abandoned_stream_leaves_nothing_patched() -> None:
    stream = _half_read_stream()
    cycle: dict[str, Any] = {"stream": stream}
    cycle["me"] = cycle
    del stream, cycle
    gc.collect()

    assert network_module._interceptor_ref_count == 0
    assert _lookup() == "allowed"
