"""Regressions for the sandbox fixes in 0.10.17.

- An async tool run with ``sandbox=True`` came back as the string of its coroutine: the
  payload called the function and never awaited the result. Docker's copy of the payload
  had the same bug, and ``LocalBackend`` returned the coroutine itself.
- ``ModalBackend`` unpickled a result the sandbox printed. Code running in the sandbox
  controls that output, so a tool could run code on the host.
- ``execute_with_files`` never returned a result (markers the payload does not print, and
  E2B's list of output chunks read as a string), and its result path unpickled sandbox
  output as well.
- A used sandbox went back into the pool, a failed one included, so the next call ran next
  to whatever the last one left behind, and a pooled sandbox past its lifetime was handed
  out dead.
- One process-wide pool took its API key and timeout from the first config it saw.
- Every sandbox failure was answered as an "Unexpected error" tagged ``validation_error``.
- The local fallback caught an ImportError raised anywhere in the sandbox call, not only a
  failed import of ``agent_airlock.sandbox``.
- ``agent_airlock.sandbox.SandboxExecutionError`` was a second class, never raised.

The payload is run for real: stand-ins for E2B, Docker and Modal run the generated code in
a fresh interpreter, and the E2B one can run it inside a running event loop, which is how
E2B's Jupyter kernel runs it.
"""

from __future__ import annotations

import asyncio
import base64
import itertools
import pickle
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

import agent_airlock
import agent_airlock.core as core_module
import agent_airlock.sandbox as sandbox_module
from agent_airlock import Airlock, AirlockConfig
from agent_airlock.exceptions import AirlockError
from agent_airlock.sandbox import (
    MountedFile,
    SandboxPool,
    execute_in_sandbox,
    execute_with_files,
    get_sandbox_pool,
)
from agent_airlock.sandbox_backend import DockerBackend, E2BBackend, LocalBackend, ModalBackend

_ids = itertools.count()

# Runs a cell the way a Jupyter kernel does: inside a coroutine, with a loop running.
_IN_A_RUNNING_LOOP = """
import asyncio, sys
cell = sys.stdin.read()

async def kernel():
    exec(compile(cell, "<cell>", "exec"), {"__name__": "__main__"})

asyncio.run(kernel())
"""


def _run_python(code: str, *, running_loop: bool = False) -> subprocess.CompletedProcess[str]:
    if running_loop:
        argv, stdin = [sys.executable, "-c", _IN_A_RUNNING_LOOP], code
    else:
        argv, stdin = [sys.executable, "-c", code], None
    return subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=60)


class _FakeFiles:
    def write(self, path: str, content: bytes) -> None:
        Path(path).write_bytes(content)

    def read(self, path: str) -> bytes:
        return Path(path).read_bytes()


class _FakeSandbox:
    """Stands in for an E2B sandbox: runs each cell in a fresh interpreter."""

    def __init__(self, *, running_loop: bool = False) -> None:
        self.sandbox_id = f"fake-{next(_ids)}"
        self.running_loop = running_loop
        self.files = _FakeFiles()
        self.killed = False
        self.timeouts: list[int] = []

    def run_code(self, code: str) -> Any:
        done = _run_python(code, running_loop=self.running_loop)
        # E2B returns lists of output chunks, not strings.
        logs = SimpleNamespace(stdout=[done.stdout], stderr=[done.stderr])
        return SimpleNamespace(logs=logs, error=None)

    def set_timeout(self, timeout: int) -> None:
        self.timeouts.append(timeout)

    def kill(self) -> None:
        self.killed = True


@pytest.fixture
def fake_e2b(monkeypatch: pytest.MonkeyPatch) -> Iterator[SimpleNamespace]:
    """Every sandbox the pool creates is a _FakeSandbox; ``created`` lists them."""
    state = SimpleNamespace(created=[], running_loop=False)

    def create(self: SandboxPool) -> _FakeSandbox:
        sandbox = _FakeSandbox(running_loop=state.running_loop)
        state.created.append(sandbox)
        return sandbox

    monkeypatch.setattr(sandbox_module, "_check_e2b_available", lambda: True)
    monkeypatch.setattr(SandboxPool, "_create_sandbox", create)
    sandbox_module._reset_pool()
    yield state
    sandbox_module._reset_pool()


# A pickle that records being loaded. The fixed code must never load one from sandbox output.
_TRIPPED: list[str] = []


def _trip(tag: str) -> str:
    _TRIPPED.append(tag)
    return tag


class _Tripwire:
    def __reduce__(self) -> tuple[Any, tuple[str]]:
        return (_trip, ("unpickled on the host",))


def _tripwire_b64() -> str:
    payload = pickle.dumps(_Tripwire())
    # Control: loading this payload does trip the wire, so a clean run below means it was
    # never loaded, not that the wire is broken.
    _TRIPPED.clear()
    pickle.loads(payload)  # nosec B301 - the control for the tripwire, loading our own bytes
    assert _TRIPPED == ["unpickled on the host"]
    _TRIPPED.clear()
    return base64.b64encode(payload).decode("ascii")


class TestAsyncToolsAreAwaited:
    def test_in_a_plain_interpreter(self, fake_e2b: SimpleNamespace) -> None:
        async def add(x: int, y: int) -> int:
            await asyncio.sleep(0)
            return x + y

        result = execute_in_sandbox(add, (2, 3))

        assert (result.success, result.result) == (True, 5), result.error

    def test_inside_a_running_event_loop_as_in_a_jupyter_kernel(
        self, fake_e2b: SimpleNamespace
    ) -> None:
        fake_e2b.running_loop = True

        async def add(x: int, y: int) -> int:
            await asyncio.sleep(0)
            return x + y

        result = execute_in_sandbox(add, (2, 3))

        assert (result.success, result.result) == (True, 5), result.error

    def test_through_the_decorator(self, fake_e2b: SimpleNamespace) -> None:
        @Airlock(sandbox=True)
        async def add(x: int, y: int) -> int:
            await asyncio.sleep(0)
            return x + y

        assert asyncio.run(add(x=2, y=3)) == 5

    def test_an_async_tool_that_raises_is_the_tools_error(self, fake_e2b: SimpleNamespace) -> None:
        async def fail() -> None:
            await asyncio.sleep(0)
            raise ValueError("bad input")

        result = execute_in_sandbox(fail)

        assert result.success is False
        assert result.tool_failed is True
        assert result.error == "ValueError: bad input"


class TestToolFailuresAndSandboxFailures:
    def test_a_tool_raising_in_the_sandbox_is_answered_like_one_raising_locally(
        self, fake_e2b: SimpleNamespace
    ) -> None:
        def divide(x: int) -> float:
            return x / 0

        local = Airlock()(divide)(x=1)
        sandboxed = Airlock(sandbox=True)(divide)(x=1)

        assert sandboxed == local
        assert local["block_reason"] == "validation_error"

    def test_sys_exit_in_the_tool_is_the_tools_error(self, fake_e2b: SimpleNamespace) -> None:
        def leave() -> None:
            sys.exit(3)

        result = execute_in_sandbox(leave)

        assert (result.success, result.tool_failed) == (False, True)
        assert result.error == "SystemExit: 3"

    def test_a_result_json_cannot_encode_is_the_tools_error(
        self, fake_e2b: SimpleNamespace
    ) -> None:
        def tuple_keys() -> dict[tuple[int, int], str]:
            return {(1, 2): "x"}

        result = execute_in_sandbox(tuple_keys)

        assert (result.success, result.tool_failed) == (False, True)
        assert result.error is not None
        assert result.error.startswith("The result could not be encoded as JSON: TypeError")

    def test_a_missing_sandbox_is_a_sandbox_error_and_the_tool_does_not_run(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(sandbox_module, "_check_e2b_available", lambda: False)
        ran: list[int] = []

        @Airlock(sandbox=True)
        def record(x: int) -> int:
            ran.append(x)
            return x

        result = record(x=1)

        assert ran == []
        assert result["block_reason"] == "sandbox_error"
        assert result["error"] == "AIRLOCK_BLOCK: 'record' could not run in its sandbox"
        assert "Retrying may not help" in result["fix_hints"][0]

    def test_a_sandbox_that_prints_no_outcome_is_a_sandbox_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        silent = SandboxPool()
        sandbox = MagicMock(sandbox_id="silent")
        sandbox.run_code.return_value = SimpleNamespace(
            logs=SimpleNamespace(stdout=["nothing useful\n"], stderr=[]), error=None
        )
        monkeypatch.setattr(sandbox_module, "_check_e2b_available", lambda: True)
        monkeypatch.setattr(silent, "acquire", lambda: sandbox)
        monkeypatch.setattr(sandbox_module, "get_sandbox_pool", lambda config=None: silent)

        result = Airlock(sandbox=True)(lambda: 1)()

        assert result["block_reason"] == "sandbox_error"
        sandbox.kill.assert_called_once()


class TestTheHostNeverUnpicklesSandboxOutput:
    def test_modal_ignores_a_pickle_the_sandbox_printed(self) -> None:
        stdout = "__AIRLOCK_MODAL_RESULT__" + _tripwire_b64() + "\n"
        fake_modal, _ = _fake_modal(stdout=stdout)

        with patch.dict(sys.modules, {"modal": fake_modal}):
            result = ModalBackend(app_name="x", image_ref="py").execute(lambda: 1, (), {})

        assert _TRIPPED == []
        assert result.success is False
        assert result.error == "modal sandbox produced no result envelope"

    def test_modal_reads_the_outcome_as_json_even_after_a_pickle(self) -> None:
        stdout = (
            "__AIRLOCK_MODAL_RESULT__" + _tripwire_b64() + "\n"
            '__AIRLOCK_RESULT__\n{"success": true, "result": [1, 2], "error": null}\n'
            "__AIRLOCK_END__\n"
        )
        fake_modal, _ = _fake_modal(stdout=stdout)

        with patch.dict(sys.modules, {"modal": fake_modal}):
            result = ModalBackend(app_name="x", image_ref="py").execute(lambda: 1, (), {})

        assert _TRIPPED == []
        assert (result.success, result.result) == (True, [1, 2])

    def test_execute_with_files_ignores_a_pickle_the_sandbox_printed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        printed = "---RESULT_START---\n" + _tripwire_b64() + "\n---RESULT_END---\n"
        sandbox = MagicMock(sandbox_id="printer")
        sandbox.run_code.return_value = SimpleNamespace(
            logs=SimpleNamespace(stdout=[printed], stderr=[]), error=None
        )
        pool = SandboxPool()
        monkeypatch.setattr(sandbox_module, "_check_e2b_available", lambda: True)
        monkeypatch.setattr(pool, "acquire", lambda: sandbox)
        monkeypatch.setattr(sandbox_module, "get_sandbox_pool", lambda config=None: pool)

        result, _ = execute_with_files(lambda: 1)

        assert _TRIPPED == []
        assert result.success is False
        assert result.error == "Sandbox execution did not produce expected output"


class TestExecuteWithFiles:
    def test_mounts_runs_and_downloads(self, fake_e2b: SimpleNamespace, tmp_path: Path) -> None:
        source, target = str(tmp_path / "in.txt"), str(tmp_path / "out.txt")

        def shout(src: str, dst: str) -> int:
            with open(src) as f:
                text = f.read().upper()
            with open(dst, "w") as f:
                f.write(text)
            return len(text)

        result, files = execute_with_files(
            shout,
            (source, target),
            mount=[MountedFile(local_path="<content>", sandbox_path=source, content=b"hello")],
            download=[target],
        )

        assert (result.success, result.result) == (True, 5), result.error
        assert files == {target: b"HELLO"}
        assert fake_e2b.created[0].killed is True


class TestThePool:
    def test_a_used_sandbox_is_closed_not_pooled(self, fake_e2b: SimpleNamespace) -> None:
        execute_in_sandbox(lambda: 1)

        (used,) = fake_e2b.created
        assert used.killed is True
        assert get_sandbox_pool()._pool.qsize() == 0

    def test_a_second_call_gets_a_fresh_sandbox(self, fake_e2b: SimpleNamespace) -> None:
        execute_in_sandbox(lambda: 1)
        execute_in_sandbox(lambda: 2)

        first, second = fake_e2b.created
        assert first is not second

    def test_a_failed_call_closes_its_sandbox(self, fake_e2b: SimpleNamespace) -> None:
        pool = get_sandbox_pool()
        with pytest.raises(RuntimeError), pool.sandbox():
            raise RuntimeError("the kernel died")

        (failed,) = fake_e2b.created
        assert failed.killed is True
        assert pool._pool.qsize() == 0

    def test_a_pooled_sandbox_gets_a_fresh_lifetime(self, fake_e2b: SimpleNamespace) -> None:
        pool = SandboxPool(pool_size=1, timeout=45)
        pool.warm_up()

        acquired = pool.acquire()

        assert acquired.timeouts == [45]

    def test_an_expired_pooled_sandbox_is_skipped(self, fake_e2b: SimpleNamespace) -> None:
        pool = SandboxPool(pool_size=1)
        expired = MagicMock(sandbox_id="expired")
        expired.set_timeout.side_effect = RuntimeError("sandbox not found")
        pool._pool.put(expired)

        acquired = pool.acquire()

        assert acquired is not expired
        assert acquired is fake_e2b.created[0]
        expired.kill.assert_called_once()


class TestEachConfigGetsItsOwnPool:
    def test_a_second_api_key_is_not_ignored(self, fake_e2b: SimpleNamespace) -> None:
        first = get_sandbox_pool(AirlockConfig(e2b_api_key="team-a"))
        second = get_sandbox_pool(AirlockConfig(e2b_api_key="team-b"))

        assert first is not second
        assert (first.api_key, second.api_key) == ("team-a", "team-b")

    def test_a_second_timeout_is_not_ignored(self, fake_e2b: SimpleNamespace) -> None:
        short = get_sandbox_pool(AirlockConfig(sandbox_timeout=30))
        long = get_sandbox_pool(AirlockConfig(sandbox_timeout=300))

        assert (short.timeout, long.timeout) == (30, 300)

    def test_the_same_settings_share_a_pool(self, fake_e2b: SimpleNamespace) -> None:
        assert get_sandbox_pool(AirlockConfig(e2b_api_key="team-a")) is get_sandbox_pool(
            AirlockConfig(e2b_api_key="team-a")
        )

    def test_e2b_backend_shuts_down_its_own_pool(self, fake_e2b: SimpleNamespace) -> None:
        backend = E2BBackend(api_key="team-a", timeout=90)
        own = get_sandbox_pool(backend._config())
        default = get_sandbox_pool()

        backend.shutdown()

        assert (own._shutdown, default._shutdown) == (True, False)


class TestTheLocalFallbackIsOnlyForAFailedImport:
    def test_an_import_error_during_the_call_is_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def raise_inside(*args: Any, **kwargs: Any) -> None:
            raise ImportError("raised while running, not while importing")

        monkeypatch.setattr(sandbox_module, "execute_in_sandbox", raise_inside)
        ran: list[int] = []

        @Airlock(sandbox=True, sandbox_required=False)
        def record(x: int) -> int:
            ran.append(x)
            return x

        result = record(x=1)

        assert ran == []
        assert result["success"] is False

    def test_a_failed_import_falls_back_without_sandbox_required(self) -> None:
        @Airlock(sandbox=True, sandbox_required=False)
        def double(x: int) -> int:
            return x * 2

        with patch.dict(sys.modules, {"agent_airlock.sandbox": None}):
            assert double(x=4) == 8

    def test_a_failed_import_is_a_sandbox_error_with_sandbox_required(self) -> None:
        @Airlock(sandbox=True, sandbox_required=True)
        def double(x: int) -> int:
            return x * 2

        with patch.dict(sys.modules, {"agent_airlock.sandbox": None}):
            result = double(x=4)

        assert result["block_reason"] == "sandbox_error"


class TestOneClassPerName:
    def test_every_import_path_names_the_same_class(self) -> None:
        assert (
            agent_airlock.SandboxExecutionError
            is core_module.SandboxExecutionError
            is sandbox_module.SandboxExecutionError
        )
        assert agent_airlock.SandboxUnavailableError is core_module.SandboxUnavailableError

    def test_the_hierarchy(self) -> None:
        assert issubclass(agent_airlock.SandboxUnavailableError, sandbox_module.SandboxError)
        assert issubclass(
            agent_airlock.SandboxUnavailableError, sandbox_module.SandboxNotAvailableError
        )
        assert issubclass(sandbox_module.SandboxError, AirlockError)


def _fake_modal(*, stdout: str = "", run: bool = False) -> tuple[MagicMock, MagicMock]:
    """A modal module stand-in. With ``run``, the sandbox runs the harness for real."""
    fake = MagicMock(name="fake_modal")
    sandbox = MagicMock(name="fake_sandbox", object_id="sb-1")
    sandbox.stderr.read.return_value = ""

    def create(*argv: str, **kwargs: Any) -> MagicMock:
        if run:
            done = _run_python(argv[2])
            sandbox.stdout.read.return_value = done.stdout
            sandbox.stderr.read.return_value = done.stderr
        else:
            sandbox.stdout.read.return_value = stdout
        return sandbox

    fake.Sandbox.create.side_effect = create
    return fake, sandbox


def _fake_docker() -> MagicMock:
    """A docker module stand-in whose containers run the command in a local interpreter."""
    fake = MagicMock(name="fake_docker")
    client = fake.from_env.return_value

    def run(image: str, command: list[str], **kwargs: Any) -> MagicMock:
        done = subprocess.run(
            [sys.executable, *command[1:]], capture_output=True, text=True, timeout=60
        )
        container = MagicMock(name="container")
        container.wait.return_value = {"StatusCode": done.returncode}
        container.logs.return_value = (done.stdout + done.stderr).encode()
        return container

    client.containers.run.side_effect = run
    return fake


class TestBackendsRunTheSamePayload:
    def test_docker_awaits_an_async_function(self) -> None:
        async def add(x: int, y: int) -> int:
            await asyncio.sleep(0)
            return x + y

        with patch.dict(sys.modules, {"docker": _fake_docker()}):
            result = DockerBackend().execute(add, (2, 3), {})

        assert (result.success, result.result) == (True, 5), result.error

    def test_docker_marks_a_tool_failure(self) -> None:
        def fail() -> None:
            raise KeyError("missing")

        with patch.dict(sys.modules, {"docker": _fake_docker()}):
            result = DockerBackend().execute(fail, (), {})

        assert (result.success, result.tool_failed) == (False, True)
        assert result.error == "KeyError: 'missing'"

    def test_modal_awaits_an_async_function(self) -> None:
        async def add(x: int, y: int) -> int:
            await asyncio.sleep(0)
            return x + y

        fake_modal, _ = _fake_modal(run=True)
        with patch.dict(sys.modules, {"modal": fake_modal}):
            result = ModalBackend(app_name="x", image_ref="py").execute(add, (2, 3), {})

        assert (result.success, result.result) == (True, 5), result.error

    def test_local_awaits_an_async_function(self) -> None:
        async def add(x: int, y: int) -> int:
            await asyncio.sleep(0)
            return x + y

        result = LocalBackend(allow_unsafe=True).execute(add, (2, 3), {})

        assert (result.success, result.result) == (True, 5)

    def test_local_awaits_inside_a_running_loop(self) -> None:
        async def add(x: int, y: int) -> int:
            await asyncio.sleep(0)
            return x + y

        async def caller() -> Any:
            return LocalBackend(allow_unsafe=True).execute(add, (2, 3), {})

        result = asyncio.run(caller())

        assert (result.success, result.result) == (True, 5)

    def test_local_accepts_the_timeout_keyword_every_backend_takes(self) -> None:
        result = LocalBackend(allow_unsafe=True).execute(lambda: 1, (), {}, timeout=5)

        assert result.success is True
