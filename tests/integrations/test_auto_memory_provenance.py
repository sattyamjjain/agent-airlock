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
    AutoMemoryAccessPolicy,
    AutoMemoryCrossTenantError,
    AutoMemoryTenantIdError,
    MemoryChainTooDeepError,
    MemoryEntry,
    MemoryProvenanceError,
    consolidate_memory,
    guarded_read,
    guarded_write,
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


#: Ids with no single root of their own under ``/memory/``. ``""`` has the root ``/memory//``,
#: which no tenant owns; ``"a/b"`` has ``/memory/a/b/``, inside tenant ``"a"``'s root, so ``"a"``
#: passes the scope check for ``"a/b"``'s notes; ``".."`` has ``/memory/../``, above them all.
REFUSED_TENANT_IDS = [
    "",
    "  ",
    "\t",
    "\n",
    " ",
    "/",
    "a/b",
    "/a",
    "a/",
    "a\\b",
    "\\",
    "a\x00",
    "\x00",
    ".",
    "..",
    " .. ",
    "...",
    ". .",
]


class TestATenantIdHasToNameATenant:
    """0.10.32: ``AutoMemoryAccessPolicy(tenant_id="")`` was accepted.

    Its root is ``/memory//``, so ``/memory//x.md`` passed the scope check and landed in a root
    no tenant owns. agno-agi/agno#11422 raises the neighbouring case, where a missing user id
    reaches every user's memories.
    """

    @pytest.mark.parametrize("tenant_id", REFUSED_TENANT_IDS)
    def test_refused_at_construction(self, tenant_id: str) -> None:
        with pytest.raises(AutoMemoryTenantIdError) as exc:
            AutoMemoryAccessPolicy(tenant_id=tenant_id)
        assert exc.value.tenant_id == tenant_id
        assert exc.value.reason

    @pytest.mark.parametrize("tenant_id", REFUSED_TENANT_IDS)
    def test_refused_by_consolidate_memory(self, tenant_id: str) -> None:
        with pytest.raises(AutoMemoryTenantIdError):
            consolidate_memory(
                tenant_id=tenant_id,
                path=f"/memory/{tenant_id}/x.md",
                content="c",
                source_session_ids=["s1"],
            )

    @pytest.mark.parametrize("tenant_id", [None, 7, b"acct-42", ["acct-42"]])
    def test_a_non_string_is_refused_not_stringified(self, tenant_id: object) -> None:
        with pytest.raises(AutoMemoryTenantIdError, match="string"):
            AutoMemoryAccessPolicy(tenant_id=tenant_id)  # type: ignore[arg-type]
        with pytest.raises(AutoMemoryTenantIdError, match="string"):
            consolidate_memory(
                tenant_id=tenant_id,  # type: ignore[arg-type]
                path="/memory/None/x.md",
                content="c",
                source_session_ids=[],
            )

    @pytest.mark.parametrize(
        # "a.." was allowed here until 0.10.33: a trailing dot is stripped by some stores, so
        # it now names tenant "a"'s directory and is refused (tests/test_fixes_0_10_33.py).
        "tenant_id",
        ["acct-42", "t", "a.b", "..a", "acct 42", "ACME_1"],
    )
    def test_a_tenant_that_names_itself_is_allowed_as_today(self, tenant_id: str) -> None:
        policy = AutoMemoryAccessPolicy(tenant_id=tenant_id)
        path = f"/memory/{tenant_id}/x.md"
        assert guarded_read(policy, path, lambda _p: b"ok") == b"ok"
        guarded_write(policy, path, "ok", lambda _p, _c: None)
        entry = consolidate_memory(tenant_id, path, "c", ["s1"])
        assert (entry.tenant_id, entry.path) == (tenant_id, path)

    def test_the_policy_is_positional_as_before(self) -> None:
        assert AutoMemoryAccessPolicy("t1").tenant_id == "t1"

    def test_an_id_set_after_construction_cannot_reach_the_scope_check(self) -> None:
        """The dataclass is mutable, and a shared policy reassigned per request is plausible."""
        policy = AutoMemoryAccessPolicy(tenant_id="acct-42")
        policy.tenant_id = ""
        with pytest.raises(AutoMemoryTenantIdError):
            guarded_read(policy, "/memory//x.md", lambda _p: b"never")
        with pytest.raises(AutoMemoryTenantIdError):
            guarded_write(policy, "/memory//x.md", "never", lambda _p, _c: None)

    def test_the_refusal_is_an_airlock_error(self) -> None:
        with pytest.raises(AirlockError):
            AutoMemoryAccessPolicy(tenant_id="")

    def test_the_refusal_shows_control_characters_escaped(self) -> None:
        with pytest.raises(AutoMemoryTenantIdError) as exc:
            AutoMemoryAccessPolicy(tenant_id="a\x00")
        assert "\x00" not in str(exc.value)
        assert "a\\x00" in str(exc.value)


class TestConsolidateMemoryChecksItsPath:
    """0.10.32: the docstring said the path must start with the tenant's root; nothing checked,
    so a signed entry could be minted for tenant A at a path inside tenant B."""

    @pytest.mark.parametrize(
        "path",
        [
            "/memory/other/x.md",
            "/memory//x.md",
            "/memory/acct-42-evil/x.md",
            "/memory/acct-42/../other/x.md",
            "/memory/acct-42/x\x00.md",
            "x.md",
            "",
        ],
    )
    def test_a_path_outside_the_tenants_root_signs_nothing(self, path: str) -> None:
        with (
            patch("agent_airlock.integrations.claude_auto_memory.sign_memory_entry") as sign,
            pytest.raises(AutoMemoryCrossTenantError) as exc,
        ):
            consolidate_memory("acct-42", path, "c", ["s1"])
        sign.assert_not_called()
        assert exc.value.tenant_id == "acct-42"
        assert exc.value.attempted_path == path

    @pytest.mark.parametrize("path", [None, 7, b"/memory/acct-42/x.md"])
    def test_a_path_that_is_not_a_string_is_refused_not_a_crash(self, path: object) -> None:
        with pytest.raises(AutoMemoryCrossTenantError):
            consolidate_memory("acct-42", path, "c", ["s1"])  # type: ignore[arg-type]
        policy = AutoMemoryAccessPolicy(tenant_id="acct-42")
        with pytest.raises(AutoMemoryCrossTenantError):
            guarded_read(policy, path, lambda _p: b"never")  # type: ignore[arg-type]


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
