"""Tests for CVE-2026-41349 OpenClaw agentic consent-bypass (v0.5.5+).

Primary source (cited per v0.5.1+ convention):
- <https://www.thehackerwire.com/vulnerability/CVE-2026-41349/> (CVSS 8.8,
  disclosed 2026-04-23).

The fix surface is :meth:`SecurityPolicy.freeze` +
:meth:`SecurityPolicy.verify_frozen`, plus the
``openclaw_cve_2026_41349_defaults()`` preset that returns a frozen
policy pre-seeded with the advisory's named attack-surface deny
patterns.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_airlock import PolicyMutationError, SecurityPolicy
from agent_airlock.policy_presets import openclaw_cve_2026_41349_defaults

FIXTURE = Path(__file__).parent / "fixtures" / "cve_2026_41349_consent_bypass.json"


class TestFreezeBasics:
    """The freeze() primitive — before any preset work."""

    def test_unfrozen_policy_is_not_frozen(self) -> None:
        policy = SecurityPolicy(allowed_tools=["read_file"])
        assert policy.is_frozen() is False

    def test_freeze_produces_frozen_copy(self) -> None:
        policy = SecurityPolicy(allowed_tools=["read_file"])
        frozen = policy.freeze()
        assert frozen.is_frozen() is True
        # Original is untouched — freeze() is non-mutating
        assert policy.is_frozen() is False
        # Deep-copy semantics: distinct objects
        assert frozen is not policy
        assert frozen.allowed_tools == ["read_file"]

    def test_frozen_clean_verify_passes(self) -> None:
        policy = SecurityPolicy(allowed_tools=["read_file"]).freeze()
        policy.verify_frozen()  # no raise

    def test_verify_frozen_on_unfrozen_policy_raises(self) -> None:
        policy = SecurityPolicy()
        with pytest.raises(PolicyMutationError, match="unfrozen"):
            policy.verify_frozen()

    def test_freeze_is_idempotent(self) -> None:
        """Freezing an already-frozen policy yields the same canonical digest."""
        policy = SecurityPolicy(denied_tools=["rm_*"]).freeze()
        refrozen = policy.freeze()
        # Both snapshots describe identical public state → identical digest
        assert policy._frozen_digest == refrozen._frozen_digest


class TestMutationDetection:
    """The three attack patterns from fixtures/cve_2026_41349_consent_bypass.json."""

    def test_append_to_allowed_tools_is_detected(self) -> None:
        policy = SecurityPolicy(allowed_tools=["read_file"]).freeze()
        # Simulate the attacker rewriting allowed_tools mid-session
        policy.allowed_tools.append("delete_database")
        with pytest.raises(PolicyMutationError) as exc:
            policy.verify_frozen()
        assert exc.value.stored_digest is not None
        assert exc.value.actual_digest is not None
        assert exc.value.stored_digest != exc.value.actual_digest

    def test_remove_from_denied_tools_is_detected(self) -> None:
        policy = SecurityPolicy(denied_tools=["rm_*", "drop_*"]).freeze()
        policy.denied_tools.remove("rm_*")
        with pytest.raises(PolicyMutationError):
            policy.verify_frozen()

    def test_rate_limit_swap_is_detected(self) -> None:
        policy = SecurityPolicy(rate_limits={"*": "10/hour"}).freeze()
        policy.rate_limits["*"] = "9999/second"
        with pytest.raises(PolicyMutationError):
            policy.verify_frozen()

    def test_cross_session_digest_custody(self) -> None:
        """Caller can verify against an explicit digest passed in."""
        policy = SecurityPolicy(allowed_tools=["a", "b"]).freeze()
        stored = policy._frozen_digest
        assert stored is not None
        # Verify with explicit digest — success
        policy.verify_frozen(stored)
        # Verify against a bogus digest — fail
        with pytest.raises(PolicyMutationError, match="expected digest"):
            policy.verify_frozen("00" * 32)


class TestUnfrozenBackCompat:
    """Existing callers that don't call freeze() must see no behavior change."""

    def test_mutable_policy_is_unaffected(self) -> None:
        policy = SecurityPolicy(allowed_tools=["read_file"])
        policy.allowed_tools.append("write_file")
        assert policy.is_frozen() is False
        # No verification step applies — mutation is allowed
        assert "write_file" in policy.allowed_tools


class TestPreset:
    """``openclaw_cve_2026_41349_defaults()`` factory semantics."""

    def test_preset_returns_frozen_policy(self) -> None:
        policy = openclaw_cve_2026_41349_defaults()
        assert isinstance(policy, SecurityPolicy)
        assert policy.is_frozen() is True

    def test_preset_seeds_advisory_deny_patterns(self) -> None:
        policy = openclaw_cve_2026_41349_defaults()
        # Advisory's named attack-surface patterns must be denied
        assert "*config_patch*" in policy.denied_tools
        assert "*update_policy*" in policy.denied_tools
        assert "*mutate_policy*" in policy.denied_tools

    def test_preset_preserves_caller_policy(self) -> None:
        base = SecurityPolicy(allowed_tools=["read_file"], denied_tools=["rm_*"])
        merged = openclaw_cve_2026_41349_defaults(base_policy=base)
        assert "read_file" in merged.allowed_tools
        assert "rm_*" in merged.denied_tools
        # And still pre-seeds the advisory patterns
        assert "*config_patch*" in merged.denied_tools


class TestFixture:
    """The fixture file matches the module's primary-source contract."""

    def test_fixture_parses(self) -> None:
        data = json.loads(FIXTURE.read_text(encoding="utf-8"))
        assert data["cve"] == "CVE-2026-41349"
        assert data["cvss"] == 8.8
        assert data["airlock_preset"] == "openclaw_cve_2026_41349_defaults"
        assert data["primary_source"].startswith("https://")
        # Each payload names a mutation_type and a field that freeze() covers
        assert len(data["payloads"]) == 3
        for payload in data["payloads"]:
            assert payload["mutation_type"]
            assert payload["field"]
