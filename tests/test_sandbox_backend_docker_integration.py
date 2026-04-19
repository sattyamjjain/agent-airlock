"""Docker sandbox backend integration tests (v0.5.1+).

These tests require a running Docker daemon AND the ``python:3.11-slim``
image locally available. They are **opt-in** via ``pytest -m docker``:

    pytest -m docker tests/test_sandbox_backend_docker_integration.py

The default ``pytest`` invocation excludes them (see ``pyproject.toml``
``addopts = "... -m 'not docker'"``) so CI does not need Docker.

Scope: prove the four load-bearing claims DockerBackend actually makes.
We do NOT run these as part of the 80% coverage gate — they exist to
prevent the honesty bug in issue #2 from regressing.
"""

from __future__ import annotations

import time

import pytest

from agent_airlock.sandbox_backend import DockerBackend

pytestmark = pytest.mark.docker


def _skip_unless_docker() -> DockerBackend:
    backend = DockerBackend(image="python:3.11-slim")
    if not backend.is_available():
        pytest.skip("Docker daemon not reachable")
    return backend


def _trivial_success(x: int, y: int) -> int:
    return x + y


def _runaway_loop() -> None:
    import time as _t

    while True:
        _t.sleep(1)


def _network_probe() -> str:
    """Tries to reach 8.8.8.8 — must fail because network_mode='none'."""
    import socket

    try:
        socket.setdefaulttimeout(2.0)
        socket.create_connection(("8.8.8.8", 53))
        return "REACHED"
    except OSError as e:
        return f"BLOCKED: {e}"




class TestDockerBackendIntegration:
    def test_is_available_when_daemon_running(self) -> None:
        """The happy-path availability check — prerequisite for the rest."""
        backend = _skip_unless_docker()
        assert backend.is_available() is True
        assert backend.name == "docker"

    def test_executes_trivial_function(self) -> None:
        """A pure function returns its result from inside the container."""
        backend = _skip_unless_docker()
        result = backend.execute(_trivial_success, args=(2, 3), kwargs={})
        assert result.success is True, result.error
        assert result.result == 5
        assert result.backend == "docker"
        assert result.execution_time_ms > 0

    def test_timeout_kills_runaway_container(self) -> None:
        """Regression for the timeout TODO — infinite loop must be killed."""
        backend = _skip_unless_docker()
        started = time.time()
        result = backend.execute(_runaway_loop, args=(), kwargs={}, timeout=3)
        elapsed = time.time() - started
        assert result.success is False
        assert "timed out" in (result.error or "").lower()
        # Should have returned within ~timeout + a small cleanup margin.
        assert elapsed < 15, f"cleanup too slow: {elapsed:.1f}s"

    def test_network_isolation_blocks_egress(self) -> None:
        """network_mode='none' must prevent outbound socket connections."""
        backend = _skip_unless_docker()
        result = backend.execute(_network_probe, args=(), kwargs={})
        assert result.success is True, result.error
        assert isinstance(result.result, str)
        assert result.result.startswith("BLOCKED:"), result.result
