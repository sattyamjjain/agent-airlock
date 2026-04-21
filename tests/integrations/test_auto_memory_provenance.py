"""Auto Memory provenance chain regression tests (v0.5.3+).

Motivating incidents:
- Anthropic 2026-04-19 default-on Auto Memory rollout controversy:
  https://support.claude.com/articles/memory-scope-default-2026-04-19
- Auto Dream mechanics:
  https://claudefa.st/blog/guide/mechanics/auto-dream

These tests prove HMAC signing round-trips, tamper detection,
chain-depth enforcement, and OTel attribute emission for
consolidation operations.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from agent_airlock.exceptions import AirlockError
from agent_airlock.integrations.claude_auto_memory import (
    MemoryChainTooDeepError,
    MemoryEntry,
    MemoryProvenanceError,
    consolidate_memory,
    sign_memory_entry,
    verify_memory_entry,
)


@pytest.fixture(autouse=True)
def _set_hmac_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every test gets a fresh known-fake HMAC key. Never in code."""
    monkeypatch.setenv(
        "AIRLOCK_MEMORY_HMAC_KEY",
        "test-fixture-key-0123456789abcdef",
    )


class TestSignAndVerify:
    def test_01_round_trip(self) -> None:
        """A freshly-signed entry must verify without raising."""
        entry = MemoryEntry(
            tenant_id="acct-42",
            path="/memory/acct-42/plan.md",
            content="next steps",
        )
        sign_memory_entry(entry)
        verify_memory_entry(entry)  # must not raise

    def test_02_tampered_content_fails_verify(self) -> None:
        entry = MemoryEntry(
            tenant_id="acct-42",
            path="/memory/acct-42/plan.md",
            content="original",
        )
        sign_memory_entry(entry)
        entry.content = "tampered"
        with pytest.raises(MemoryProvenanceError) as exc:
            verify_memory_entry(entry)
        assert exc.value.tenant_id == "acct-42"

    def test_03_tampered_chain_fails_verify(self) -> None:
        entry = MemoryEntry(
            tenant_id="acct-42",
            path="/memory/acct-42/plan.md",
            content="c",
            consolidation_chain=["s1", "s2"],
        )
        sign_memory_entry(entry)
        entry.consolidation_chain.append("attacker-session")
        with pytest.raises(MemoryProvenanceError):
            verify_memory_entry(entry)


class TestConsolidateChain:
    def test_04_chain_recorded_and_redacted(self) -> None:
        """A consolidation records every source session and the
        redaction count while signing the result."""
        entry = consolidate_memory(
            tenant_id="acct-42",
            path="/memory/acct-42/notes.md",
            content="secret: AKIAIOSFODNN7EXAMPLE",
            source_session_ids=["s1", "s2", "s3"],
        )
        assert entry.consolidation_chain == ["s1", "s2", "s3"]
        assert entry.consolidated_from_session_id == "s3"
        assert entry.redacted_token_count >= 1
        assert "AKIAIOSFODNN7EXAMPLE" not in entry.content
        # signature round-trips
        verify_memory_entry(entry)

    def test_05_over_deep_chain_rejected(self) -> None:
        """A chain longer than max_chain_depth is refused."""
        with pytest.raises(MemoryChainTooDeepError) as exc:
            consolidate_memory(
                tenant_id="acct-42",
                path="/memory/acct-42/x.md",
                content="",
                source_session_ids=[f"s{i}" for i in range(9)],
                max_chain_depth=8,
            )
        assert exc.value.depth == 9
        assert exc.value.limit == 8


class TestOTelAttribute:
    def test_06_chain_depth_attribute_emitted(self) -> None:
        """``airlock.auto_memory.consolidate`` span carries chain_depth."""
        with patch("agent_airlock.integrations.claude_auto_memory._emit_span") as emit:
            consolidate_memory(
                tenant_id="acct-42",
                path="/memory/acct-42/x.md",
                content="plain",
                source_session_ids=["s1", "s2"],
            )
            name, attrs = emit.call_args[0]
            assert name == "airlock.auto_memory.consolidate"
            assert attrs["chain_depth"] == 2
            assert attrs["tenant_id"] == "acct-42"


class TestErrorHierarchy:
    def test_provenance_is_airlock_error(self, monkeypatch) -> None:
        entry = MemoryEntry(tenant_id="t", path="/memory/t/x", content="c")
        sign_memory_entry(entry)
        entry.content = "tampered"
        with pytest.raises(AirlockError):
            verify_memory_entry(entry)

    def test_chain_too_deep_is_airlock_error(self) -> None:
        with pytest.raises(AirlockError):
            consolidate_memory(
                tenant_id="t",
                path="/memory/t/x",
                content="",
                source_session_ids=[f"s{i}" for i in range(50)],
                max_chain_depth=4,
            )
