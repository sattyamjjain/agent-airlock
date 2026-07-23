"""MCP 2026-07-28 Tasks extension (SEP-2663) deny-by-default admission preset (v0.8.54+).

SEP-2663 finalises Tasks as an official extension a server may return unsolicited. This
preset is the admission-control layer: a task op is refused unless the client advertised
the Tasks extension, outstanding tasks are capped per principal + expire on a TTL (Akamai
hit-and-run DoS), and the handle→principal/scope binding + unsolicited-handle rejection are
reused verbatim from the shipped SEP-1686 lifecycle guard. **SEP-2663 is a spec id, not a
CVE.**
"""

from __future__ import annotations

import inspect

import pytest

from agent_airlock.mcp_spec.tasks_admission_guard import (
    TasksAdmissionError,
    TasksAdmissionState,
)
from agent_airlock.mcp_spec.tasks_lifecycle_guard import TaskLifecycleError
from agent_airlock.policy_presets import (
    MCP_TASKS_2026_07_28,
    list_active,
    mcp_tasks_2026_07_28_defaults,
    mcp_tasks_lifecycle_2026_07_defaults,
)

_ISS = "https://as.example.com"
_CAPS = {"tasks": {}}  # client advertised the Tasks extension


def _preset(**kw):
    return mcp_tasks_2026_07_28_defaults(**kw)


def _admitted_state(preset, principal: str = "alice", task_id: str = "task-1"):
    state = preset["new_state"]()
    preset["admit_task"](
        state,
        task_id,
        client_capabilities=_CAPS,
        scopes=["tasks.read", "tasks.write"],
        issuer=_ISS,
        principal=principal,
        now=0.0,
    )
    return state


class TestAllowedAndScopeChange:
    def test_allowed_task_under_matching_scope(self) -> None:
        preset = _preset()
        state = _admitted_state(preset)
        assert (
            preset["check_task_op"](
                state,
                "tasks/update",
                "task-1",
                client_capabilities=_CAPS,
                live_scopes=["tasks.read", "tasks.write"],
                live_issuer=_ISS,
                principal="alice",
                now=1.0,
            )
            is None
        )

    def test_denied_task_under_changed_scope(self) -> None:
        preset = _preset()
        state = _admitted_state(preset)
        with pytest.raises(TaskLifecycleError) as exc:
            preset["check_task_op"](
                state,
                "tasks/get",
                "task-1",
                client_capabilities=_CAPS,
                live_scopes=["tasks.read", "tasks.write", "admin.all"],
                live_issuer=_ISS,
                principal="alice",
                now=1.0,
            )
        assert exc.value.audit_event["reason"] == "scope_broadened"


class TestUnsolicitedHandle:
    def test_denied_unsolicited_handle(self) -> None:
        preset = _preset()
        state = _admitted_state(preset)
        with pytest.raises(TaskLifecycleError) as exc:
            preset["check_task_op"](
                state,
                "tasks/get",
                "task-never-issued",
                client_capabilities=_CAPS,
                live_scopes=["tasks.read", "tasks.write"],
                live_issuer=_ISS,
                principal="alice",
                now=1.0,
            )
        assert exc.value.audit_event["reason"] == "unknown_task_handle"


class TestCapabilityGate:
    def test_create_without_capability_denied(self) -> None:
        preset = _preset()
        state = preset["new_state"]()
        with pytest.raises(TasksAdmissionError) as exc:
            preset["admit_task"](
                state,
                "t",
                client_capabilities={},
                scopes=["s"],
                issuer=_ISS,
                principal="alice",
                now=0.0,
            )
        assert exc.value.audit_event["reason"] == "tasks_capability_not_advertised"

    def test_op_without_capability_denied(self) -> None:
        preset = _preset()
        state = _admitted_state(preset)
        with pytest.raises(TasksAdmissionError) as exc:
            preset["check_task_op"](
                state,
                "tasks/get",
                "task-1",
                client_capabilities={},
                live_scopes=["tasks.read", "tasks.write"],
                live_issuer=_ISS,
                principal="alice",
                now=1.0,
            )
        assert exc.value.audit_event["reason"] == "tasks_capability_not_advertised"

    def test_experimental_capability_shape_accepted(self) -> None:
        preset = _preset()
        state = preset["new_state"]()
        assert (
            preset["admit_task"](
                state,
                "t",
                client_capabilities={"experimental": {"tasks": {}}},
                scopes=["s"],
                issuer=_ISS,
                principal="alice",
                now=0.0,
            )
            is not None
        )


class TestQuotaAndTtl:
    def test_over_quota_deny(self) -> None:
        preset = _preset(max_outstanding_tasks=2)
        state = preset["new_state"]()
        for i in range(2):
            preset["admit_task"](
                state,
                f"t{i}",
                client_capabilities=_CAPS,
                scopes=["s"],
                issuer=_ISS,
                principal="alice",
                now=0.0,
            )
        with pytest.raises(TasksAdmissionError) as exc:
            preset["admit_task"](
                state,
                "t2",
                client_capabilities=_CAPS,
                scopes=["s"],
                issuer=_ISS,
                principal="alice",
                now=0.0,
            )
        assert exc.value.audit_event["reason"] == "task_quota_exceeded"

    def test_quota_is_per_principal(self) -> None:
        preset = _preset(max_outstanding_tasks=1)
        state = preset["new_state"]()
        preset["admit_task"](
            state,
            "a",
            client_capabilities=_CAPS,
            scopes=["s"],
            issuer=_ISS,
            principal="alice",
            now=0.0,
        )
        # bob has his own quota
        assert (
            preset["admit_task"](
                state,
                "b",
                client_capabilities=_CAPS,
                scopes=["s"],
                issuer=_ISS,
                principal="bob",
                now=0.0,
            )
            is not None
        )

    def test_ttl_exceeded_deny(self) -> None:
        preset = _preset(task_ttl_seconds=100.0)
        state = preset["new_state"]()
        preset["admit_task"](
            state,
            "t",
            client_capabilities=_CAPS,
            scopes=["s"],
            issuer=_ISS,
            principal="alice",
            now=0.0,
        )
        with pytest.raises(TasksAdmissionError) as exc:
            preset["check_task_op"](
                state,
                "tasks/get",
                "t",
                client_capabilities=_CAPS,
                live_scopes=["s"],
                live_issuer=_ISS,
                principal="alice",
                now=200.0,
            )
        assert exc.value.audit_event["reason"] == "task_ttl_exceeded"

    def test_ttl_sweep_frees_quota_slot(self) -> None:
        preset = _preset(max_outstanding_tasks=1, task_ttl_seconds=100.0)
        state = preset["new_state"]()
        preset["admit_task"](
            state,
            "old",
            client_capabilities=_CAPS,
            scopes=["s"],
            issuer=_ISS,
            principal="alice",
            now=0.0,
        )
        # After the TTL, the old handle is swept and a new admit succeeds under the quota.
        assert (
            preset["admit_task"](
                state,
                "new",
                client_capabilities=_CAPS,
                scopes=["s"],
                issuer=_ISS,
                principal="alice",
                now=200.0,
            )
            is not None
        )


class TestPresetMetadataAndReuse:
    def test_canonical_metadata(self) -> None:
        p = _preset()
        assert p["preset_id"] == "mcp_tasks_2026_07_28"
        assert p["default_action"] == "deny"
        assert p["spec"] == "SEP-2663"
        assert p["owasp"] == "MCP07"
        assert p["admission_error"] is TasksAdmissionError
        assert p["task_error"] is TaskLifecycleError
        assert (
            callable(p["admit_task"]) and callable(p["check_task_op"]) and callable(p["new_state"])
        )

    def test_named_constant_matches_factory(self) -> None:
        assert MCP_TASKS_2026_07_28["preset_id"] == "mcp_tasks_2026_07_28"

    def test_admission_error_is_lifecycle_error_subclass(self) -> None:
        # A caller can catch every Tasks refusal (lifecycle + admission) as one type.
        assert issubclass(TasksAdmissionError, TaskLifecycleError)

    def test_state_type(self) -> None:
        assert isinstance(_preset()["new_state"](), TasksAdmissionState)

    def test_cites_sep_2663_not_cve(self) -> None:
        src = inspect.getsource(mcp_tasks_2026_07_28_defaults)
        assert "SEP-2663" in src
        assert "CVE-" not in src

    def test_discoverable_via_list_active(self) -> None:
        assert "mcp_tasks_2026_07_28_defaults" in {m.preset_id for m in list_active()}

    def test_sibling_lifecycle_preset_unaffected(self) -> None:
        assert callable(mcp_tasks_lifecycle_2026_07_defaults()["check_task_op"])
