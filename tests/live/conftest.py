"""Fixtures for the live API contract tests.

These tests call the Anthropic API and spend API credit (well under $1 a run). The
default run never collects them (``addopts`` carries ``--ignore=tests/live``);
``make test-live`` names the directory and clears ``addopts``. Every test also skips
unless ``AIRLOCK_LIVE=1`` and ``ANTHROPIC_API_KEY`` are both set, so naming the
directory by accident spends nothing.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from typing import Any

import pytest

from ._live import LiveRecorder, session_env_to_remove


@pytest.fixture(scope="session", autouse=True)
def live_api_key() -> Iterator[str]:
    """The API key, after the session's other credentials and markers are removed."""
    if os.environ.get("AIRLOCK_LIVE") != "1":
        pytest.skip("live API tests run only with AIRLOCK_LIVE=1 (`make test-live`)")
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        pytest.skip("live API tests need ANTHROPIC_API_KEY")
    patch = pytest.MonkeyPatch()
    for name in session_env_to_remove(os.environ):
        patch.delenv(name)
    try:
        yield key
    finally:
        patch.undo()


@pytest.fixture(scope="session")
def anthropic_module(live_api_key: str) -> Any:
    """The ``anthropic`` package, 1.13 or newer (the first with Managed Agents)."""
    return pytest.importorskip("anthropic", minversion="1.13")


@pytest.fixture(scope="session")
def anthropic_client(anthropic_module: Any, live_api_key: str) -> Any:
    """A client given the key explicitly; no environment credential can stand in."""
    return anthropic_module.Anthropic(api_key=live_api_key, max_retries=2)


@pytest.fixture(scope="session")
def live_recorder(live_api_key: str) -> Iterator[LiveRecorder]:
    """Collects each test's observations; written to ``.results/`` when the run ends."""
    recorder = LiveRecorder(live_api_key)
    yield recorder
    path = recorder.write()
    print(f"\nlive results: {path}")
