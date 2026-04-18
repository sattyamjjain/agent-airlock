"""Tests for the ``ManagedSandboxBackend`` stub (Phase 1.5).

The backend deliberately does not execute arbitrary functions — Anthropic
Managed Agents runs complete agent loops, not single code blobs, so the
``SandboxBackend.execute()`` shape is wrong for it. These tests pin that
contract so we can't accidentally regress into silent misuse.
"""

from __future__ import annotations

import sys
import types

import pytest

from agent_airlock import ManagedSandboxBackend


def _sample(x: int) -> int:
    return x + 1


class TestManagedSandboxBackendAvailability:
    def test_not_available_without_anthropic_sdk(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SDK missing ⇒ unavailable regardless of API key."""
        monkeypatch.setitem(sys.modules, "anthropic", None)  # forces ImportError
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-xxx")
        backend = ManagedSandboxBackend()
        assert backend.is_available() is False

    def test_not_available_without_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """SDK present but no key anywhere ⇒ unavailable."""
        fake = types.ModuleType("anthropic")
        monkeypatch.setitem(sys.modules, "anthropic", fake)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        backend = ManagedSandboxBackend()
        assert backend.is_available() is False

    def test_available_with_sdk_and_env_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = types.ModuleType("anthropic")
        monkeypatch.setitem(sys.modules, "anthropic", fake)
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-xxx")
        backend = ManagedSandboxBackend()
        assert backend.is_available() is True

    def test_available_with_sdk_and_explicit_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = types.ModuleType("anthropic")
        monkeypatch.setitem(sys.modules, "anthropic", fake)
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        backend = ManagedSandboxBackend(api_key="sk-explicit")
        assert backend.is_available() is True


class TestManagedSandboxBackendExecuteContract:
    def test_name(self) -> None:
        assert ManagedSandboxBackend().name == "managed"

    def test_execute_returns_failure_with_pointer_to_right_abstraction(self) -> None:
        backend = ManagedSandboxBackend()
        result = backend.execute(_sample, (5,), {})
        assert result.success is False
        assert result.backend == "managed"
        assert result.error is not None
        # The error must direct the caller to the right abstraction so a
        # user who enabled this by mistake learns fast.
        assert "agent" in result.error.lower()
        assert "examples/anthropic_integration.py" in result.error

    def test_warmup_and_shutdown_are_noops(self) -> None:
        backend = ManagedSandboxBackend()
        assert backend.warmup() is None
        assert backend.shutdown() is None
