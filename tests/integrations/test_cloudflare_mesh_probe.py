"""Tests for the v0.5.8 Cloudflare Mesh detection + dedupe probe.

Primary source:
- https://www.cloudflare.com/press/press-releases/2026/cloudflare-launches-mesh-to-secure-the-ai-agent-lifecycle/
"""

from __future__ import annotations

from agent_airlock.integrations.cloudflare_mesh_probe import (
    MESH_MARKER_HEADERS,
    MeshContext,
    PolicyChain,
    airlock_only_categories,
    dedupe_policies,
    detect_mesh,
)


class TestDetect:
    def test_no_headers_returns_none(self) -> None:
        assert detect_mesh(None) is None
        assert detect_mesh({}) is None

    def test_unrelated_headers_return_none(self) -> None:
        assert detect_mesh({"X-Request-Id": "abc"}) is None

    def test_mesh_markers_return_context(self) -> None:
        ctx = detect_mesh(
            {
                "cf-mesh-policy-id": "p1",
                "cf-mesh-tenant": "t-42",
                "cf-mesh-trace-id": "tr-x",
                "cf-mesh-applied-policies": "egress_allowlist,rate_limit",
            }
        )
        assert isinstance(ctx, MeshContext)
        assert ctx.policy_id == "p1"
        assert ctx.tenant == "t-42"
        assert ctx.applied_policies == ("egress_allowlist", "rate_limit")

    def test_case_insensitive(self) -> None:
        ctx = detect_mesh({"CF-Mesh-Policy-ID": "p1"})
        assert ctx is not None
        assert ctx.policy_id == "p1"

    def test_partial_mesh_headers(self) -> None:
        """A single marker is enough to know Mesh is upstream."""
        ctx = detect_mesh({"cf-mesh-trace-id": "tr-1"})
        assert ctx is not None
        assert ctx.policy_id == ""
        assert ctx.applied_policies == ()


class TestDedupe:
    def test_dedupe_skipped_when_no_mesh(self) -> None:
        local = PolicyChain(categories=("egress_allowlist", "manifest_only", "pr_metadata"))
        assert dedupe_policies(local, None) == local

    def test_dedupe_removes_mesh_overlap(self) -> None:
        local = PolicyChain(
            categories=(
                "egress_allowlist",
                "rate_limit",
                "manifest_only",
                "pr_metadata",
                "agent_commerce",
            )
        )
        mesh = MeshContext(
            policy_id="p",
            tenant="t",
            trace_id="x",
            applied_policies=("egress_allowlist", "rate_limit"),
        )
        deduped = dedupe_policies(local, mesh)
        # Mesh-covered categories drop; airlock-only stay.
        assert deduped.categories == ("manifest_only", "pr_metadata", "agent_commerce")

    def test_airlock_only_helper(self) -> None:
        local = (
            "egress_allowlist",
            "rate_limit",
            "manifest_only",
            "pr_metadata",
        )
        assert airlock_only_categories(local) == (
            "manifest_only",
            "pr_metadata",
        )


class TestHeaderSchemaPin:
    def test_marker_headers_locked(self) -> None:
        # If Cloudflare adds / renames a marker, this test forces
        # an explicit version bump rather than silent drift.
        assert (
            frozenset(
                {
                    "cf-mesh-policy-id",
                    "cf-mesh-tenant",
                    "cf-mesh-trace-id",
                    "cf-mesh-applied-policies",
                }
            )
            == MESH_MARKER_HEADERS
        )
