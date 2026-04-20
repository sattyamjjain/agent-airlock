"""Claude Opus 4.7 Auto Memory / Auto Dream guard regression tests (v0.5.2+).

Opus 4.7 GA (2026-04-16/17) introduced filesystem-backed persistent
notes. This suite proves tenant scoping + quota + redaction + OTel
observability.

Primary sources
---------------
- Anthropic — What's new in Claude 4.7 (2026-04-17):
  https://platform.claude.com/docs/en/about-claude/models/whats-new-claude-4-7
- Auto Dream mechanics:
  https://claudefa.st/blog/guide/mechanics/auto-dream
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from agent_airlock.exceptions import AirlockError
from agent_airlock.integrations.claude_auto_memory import (
    AutoMemoryAccessPolicy,
    AutoMemoryCrossTenantError,
    AutoMemoryQuotaError,
    guarded_read,
    guarded_write,
)


class TestAutoMemoryGuard:
    def test_01_same_tenant_read_passes(self) -> None:
        policy = AutoMemoryAccessPolicy(tenant_id="acct-42")
        data = guarded_read(
            policy,
            "/memory/acct-42/plan.md",
            lambda _: b"hello",
        )
        assert data == b"hello"

    def test_02_same_tenant_write_passes(self) -> None:
        policy = AutoMemoryAccessPolicy(tenant_id="acct-42")
        seen: dict[str, str] = {}

        def writer(p: str, c: str) -> None:
            seen[p] = c

        count = guarded_write(
            policy,
            "/memory/acct-42/plan.md",
            "no secrets here",
            writer,
        )
        assert count == 0
        assert seen["/memory/acct-42/plan.md"] == "no secrets here"

    def test_03_cross_tenant_read_raises(self) -> None:
        policy = AutoMemoryAccessPolicy(tenant_id="acct-42")
        with pytest.raises(AutoMemoryCrossTenantError) as exc:
            guarded_read(
                policy,
                "/memory/acct-99/secrets.md",
                lambda _: b"",
            )
        assert exc.value.tenant_id == "acct-42"
        assert exc.value.attempted_path == "/memory/acct-99/secrets.md"

    def test_04_oversize_read_raises(self) -> None:
        policy = AutoMemoryAccessPolicy(
            tenant_id="acct-42",
            max_read_bytes_per_call=100,
        )
        big = b"X" * 500
        with pytest.raises(AutoMemoryQuotaError) as exc:
            guarded_read(
                policy,
                "/memory/acct-42/big.md",
                lambda _: big,
            )
        assert exc.value.bytes_requested == 500
        assert exc.value.limit == 100

    def test_05_write_with_embedded_secret_is_redacted(self) -> None:
        """An AWS-key-shaped secret in the payload must be redacted
        BEFORE it touches persistent memory."""
        policy = AutoMemoryAccessPolicy(tenant_id="acct-42")
        seen: dict[str, str] = {}

        def writer(p: str, c: str) -> None:
            seen[p] = c

        count = guarded_write(
            policy,
            "/memory/acct-42/creds.md",
            "my key: AKIAIOSFODNN7EXAMPLE",
            writer,
        )
        assert count >= 1, "at least one detection expected"
        assert "AKIAIOSFODNN7EXAMPLE" not in seen["/memory/acct-42/creds.md"]


class TestOTelAttributes:
    """Verify the OTel span carries the documented attributes."""

    def test_read_emits_span_with_bytes_and_tenant(self) -> None:
        policy = AutoMemoryAccessPolicy(tenant_id="acct-42")
        with patch("agent_airlock.integrations.claude_auto_memory._emit_span") as emit:
            guarded_read(
                policy,
                "/memory/acct-42/x.md",
                lambda _: b"hello",
            )
            emit.assert_called_once()
            name, attrs = emit.call_args[0]
            assert name == "airlock.auto_memory.read"
            assert attrs["tenant_id"] == "acct-42"
            assert attrs["bytes"] == 5
            assert attrs["redacted_count"] == 0

    def test_write_emits_span_with_redacted_count(self) -> None:
        policy = AutoMemoryAccessPolicy(tenant_id="acct-42")
        with patch("agent_airlock.integrations.claude_auto_memory._emit_span") as emit:
            guarded_write(
                policy,
                "/memory/acct-42/y.md",
                "clean note",
                lambda _p, _c: None,
            )
            name, attrs = emit.call_args[0]
            assert name == "airlock.auto_memory.write"
            assert attrs["tenant_id"] == "acct-42"
            assert "redacted_count" in attrs


class TestErrorHierarchy:
    def test_cross_tenant_is_airlock_error(self) -> None:
        with pytest.raises(AirlockError):
            guarded_read(
                AutoMemoryAccessPolicy(tenant_id="a"),
                "/memory/b/x",
                lambda _: b"",
            )

    def test_quota_is_airlock_error(self) -> None:
        with pytest.raises(AirlockError):
            guarded_read(
                AutoMemoryAccessPolicy(tenant_id="a", max_read_bytes_per_call=1),
                "/memory/a/x",
                lambda _: b"XX",
            )
