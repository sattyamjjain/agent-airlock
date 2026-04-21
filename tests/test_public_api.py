"""Public API smoke tests (v0.5.3+).

These tests guard the re-export contract users rely on. Every preset,
error class, and guard-config type that the README / docs document as
importable from the top-level ``agent_airlock`` namespace or from
``agent_airlock.policy_presets`` must resolve — or this file fails fast
on the next commit.

Precedent: v0.5.2 shipped a class of error types (``OAuthAppBlocked``,
``SnapshotIntegrityError``, etc.) defined in submodules but NOT
re-exported at the top level. v0.5.3 closes that gap; this module keeps
the gap closed.
"""

from __future__ import annotations

import importlib


class TestTopLevelErrorReexports:
    """Every v0.5.2 error class must be importable from ``agent_airlock``."""

    def test_oauth_app_blocked(self) -> None:
        from agent_airlock import OAuthAppBlocked
        from agent_airlock.mcp_spec.oauth_audit import OAuthAppBlocked as Canonical

        assert OAuthAppBlocked is Canonical

    def test_oauth_policy_violation(self) -> None:
        from agent_airlock import OAuthPolicyViolation
        from agent_airlock.mcp_spec.oauth_audit import OAuthPolicyViolation as Canonical

        assert OAuthPolicyViolation is Canonical

    def test_snapshot_integrity_error(self) -> None:
        from agent_airlock import SnapshotIntegrityError
        from agent_airlock.mcp_spec.session_guard import SnapshotIntegrityError as Canonical

        assert SnapshotIntegrityError is Canonical

    def test_auto_memory_cross_tenant_error(self) -> None:
        from agent_airlock import AutoMemoryCrossTenantError
        from agent_airlock.integrations.claude_auto_memory import (
            AutoMemoryCrossTenantError as Canonical,
        )

        assert AutoMemoryCrossTenantError is Canonical

    def test_auto_memory_quota_error(self) -> None:
        from agent_airlock import AutoMemoryQuotaError
        from agent_airlock.integrations.claude_auto_memory import (
            AutoMemoryQuotaError as Canonical,
        )

        assert AutoMemoryQuotaError is Canonical

    def test_high_value_action_blocked(self) -> None:
        from agent_airlock import HighValueActionBlocked
        from agent_airlock.policy_presets import HighValueActionBlocked as Canonical

        assert HighValueActionBlocked is Canonical

    def test_all_six_errors_in_dunder_all(self) -> None:
        import agent_airlock

        for name in [
            "OAuthAppBlocked",
            "OAuthPolicyViolation",
            "SnapshotIntegrityError",
            "AutoMemoryCrossTenantError",
            "AutoMemoryQuotaError",
            "HighValueActionBlocked",
        ]:
            assert name in agent_airlock.__all__, f"{name!r} missing from __all__"


class TestPolicyPresetsReexports:
    """Every v0.5.x preset factory must resolve from ``policy_presets``.

    Historical note: the v0.5.2 brief flagged ``oauth_audit_vercel_2026_defaults``
    as "not re-exported". Verification showed it was in fact re-exported
    correctly. This test freezes that contract so no future refactor
    regresses it.
    """

    EXPECTED_FACTORIES = (
        # v0.5.0 presets
        "gtg_1002_defense_policy",
        "mex_gov_2026_policy",
        "owasp_mcp_top_10_2026_policy",
        "eu_ai_act_article_15_policy",
        "india_dpdp_2023_policy",
        # v0.5.1 preset
        "stdio_guard_ox_defaults",
        # v0.5.2 presets
        "oauth_audit_vercel_2026_defaults",
        "mcpwn_cve_2026_33032_defaults",
        "flowise_cve_2025_59528_defaults",
        "high_value_action_deny_by_default",
    )

    def test_every_documented_factory_resolves(self) -> None:
        module = importlib.import_module("agent_airlock.policy_presets")
        for name in self.EXPECTED_FACTORIES:
            assert hasattr(module, name), (
                f"policy_presets.{name} missing — README or CHANGELOG "
                "documents it as importable but the re-export is broken"
            )
            assert callable(getattr(module, name))

    def test_every_factory_in_dunder_all(self) -> None:
        module = importlib.import_module("agent_airlock.policy_presets")
        for name in self.EXPECTED_FACTORIES:
            assert name in module.__all__, f"{name!r} missing from __all__"
