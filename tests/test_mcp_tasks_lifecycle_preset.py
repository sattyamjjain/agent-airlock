"""MCP 2026-07-28 Tasks-extension (SEP-1686) lifecycle guard preset (v0.8.53+).

The Tasks extension is call-now / fetch-later: a request returns a task *handle*, polled
via ``tasks/get`` / ``tasks/update`` / ``tasks/cancel``. This preset binds the handle at
admission to its authorising scope set + principal and refuses, deny-by-default: a task
op after the caller's scope dropped / stepped up to a different issuer / the token expired
(reusing the SEP-2350/2352 detector), and any cross-task enumeration (``tasks/list`` is
spec-removed; a handle the caller never received cannot be operated on).

**SEP-1686 is a spec id, not a CVE.** This preset EXTENDS the MCP-2026-07-28 family.
"""

from __future__ import annotations

import inspect

import pytest

from agent_airlock.mcp_spec.step_up_scope_guard import ScopeAccumulationError
from agent_airlock.mcp_spec.tasks_lifecycle_guard import (
    TaskAdmission,
    TaskLifecycleError,
    admit_task,
    check_task_op,
    new_registry,
)
from agent_airlock.policy_presets import (
    MCP_TASKS_LIFECYCLE_2026_07,
    list_active,
    mcp_step_up_scope_2026_07_defaults,
    mcp_tasks_lifecycle_2026_07_defaults,
)

_ISS = "https://as.example.com"
_OTHER_ISS = "https://evil-as.example.com"


def _registry_with_task(task_id: str = "task-1", principal: str = "alice") -> dict:
    reg = new_registry()
    admit_task(reg, task_id, scopes=["tasks.read", "tasks.write"], issuer=_ISS, principal=principal)
    return reg


class TestScopeChangeAfterAdmission:
    def test_get_after_scope_dropped_is_blocked(self) -> None:
        # Admitted under S = {tasks.read, tasks.write}; caller now only carries tasks.read.
        reg = _registry_with_task()
        with pytest.raises(TaskLifecycleError) as exc:
            check_task_op(
                reg,
                "tasks/get",
                "task-1",
                live_scopes=["tasks.read"],
                live_issuer=_ISS,
                principal="alice",
            )
        event = exc.value.audit_event
        assert event["event"] == "mcp.tasks_lifecycle.refuse"
        assert event["reason"] == "scope_narrowed"
        assert event["method"] == "tasks/get" and event["task"] == "task-1"

    def test_step_up_broadened_is_blocked(self) -> None:
        reg = _registry_with_task()
        with pytest.raises(TaskLifecycleError) as exc:
            check_task_op(
                reg,
                "tasks/update",
                "task-1",
                live_scopes=["tasks.read", "tasks.write", "admin.all"],
                live_issuer=_ISS,
                principal="alice",
            )
        assert exc.value.audit_event["reason"] == "scope_broadened"

    def test_same_scope_update_is_allowed(self) -> None:
        reg = _registry_with_task()
        assert (
            check_task_op(
                reg,
                "tasks/update",
                "task-1",
                live_scopes=["tasks.write", "tasks.read"],
                live_issuer=_ISS,
                principal="alice",
            )
            is None
        )

    def test_all_task_ops_allowed_under_same_scope(self) -> None:
        reg = _registry_with_task()
        for method in ("tasks/get", "tasks/update", "tasks/cancel"):
            assert (
                check_task_op(
                    reg,
                    method,
                    "task-1",
                    live_scopes=["tasks.read", "tasks.write"],
                    live_issuer=_ISS,
                    principal="alice",
                )
                is None
            )

    def test_different_issuer_is_blocked(self) -> None:
        reg = _registry_with_task()
        with pytest.raises(TaskLifecycleError) as exc:
            check_task_op(
                reg,
                "tasks/get",
                "task-1",
                live_scopes=["tasks.read", "tasks.write"],
                live_issuer=_OTHER_ISS,
                principal="alice",
            )
        assert exc.value.audit_event["reason"] == "issuer_mismatch"


class TestCrossTaskEnumerationBlocked:
    def test_tasks_list_is_removed_and_blocked(self) -> None:
        reg = _registry_with_task()
        with pytest.raises(TaskLifecycleError) as exc:
            check_task_op(
                reg,
                "tasks/list",
                "task-1",
                live_scopes=["tasks.read", "tasks.write"],
                live_issuer=_ISS,
                principal="alice",
            )
        assert exc.value.audit_event["reason"] == "tasks_list_removed"

    def test_op_on_unadmitted_handle_is_blocked(self) -> None:
        reg = _registry_with_task()
        with pytest.raises(TaskLifecycleError) as exc:
            check_task_op(
                reg,
                "tasks/get",
                "task-999",
                live_scopes=["tasks.read", "tasks.write"],
                live_issuer=_ISS,
                principal="alice",
            )
        assert exc.value.audit_event["reason"] == "unknown_task_handle"

    def test_cross_principal_access_is_blocked(self) -> None:
        # alice's handle cannot be operated on by bob.
        reg = _registry_with_task(principal="alice")
        with pytest.raises(TaskLifecycleError) as exc:
            check_task_op(
                reg,
                "tasks/get",
                "task-1",
                live_scopes=["tasks.read", "tasks.write"],
                live_issuer=_ISS,
                principal="bob",
            )
        assert exc.value.audit_event["reason"] == "principal_mismatch"

    def test_unknown_task_method_is_blocked(self) -> None:
        reg = _registry_with_task()
        with pytest.raises(TaskLifecycleError) as exc:
            check_task_op(
                reg,
                "tasks/enumerate",
                "task-1",
                live_scopes=["tasks.read", "tasks.write"],
                live_issuer=_ISS,
                principal="alice",
            )
        assert exc.value.audit_event["reason"] == "unknown_task_method"


class TestTokenExpiry:
    def test_expired_token_is_blocked(self) -> None:
        reg = new_registry()
        admit_task(reg, "t", scopes=["a"], issuer=_ISS, principal="alice", expires_at=1000.0)
        with pytest.raises(TaskLifecycleError) as exc:
            check_task_op(
                reg,
                "tasks/get",
                "t",
                live_scopes=["a"],
                live_issuer=_ISS,
                principal="alice",
                now=2000.0,
            )
        assert exc.value.audit_event["reason"] == "token_expired"

    def test_unexpired_token_is_allowed(self) -> None:
        reg = new_registry()
        admit_task(reg, "t", scopes=["a"], issuer=_ISS, principal="alice", expires_at=1000.0)
        assert (
            check_task_op(
                reg,
                "tasks/get",
                "t",
                live_scopes=["a"],
                live_issuer=_ISS,
                principal="alice",
                now=500.0,
            )
            is None
        )


class TestReuseAndComposition:
    def test_admit_task_reuses_step_up_snapshot(self) -> None:
        # (a) the handle carries the SEP-2350/2352 AdmissionScopeSnapshot verbatim.
        reg = new_registry()
        adm = admit_task(reg, "t", scopes=["s1", "s2"], issuer=_ISS, principal="p")
        assert isinstance(adm, TaskAdmission)
        assert adm.snapshot.scopes == frozenset({"s1", "s2"})
        assert adm.snapshot.issuer == _ISS
        assert adm.snapshot.tool_name == "t"

    def test_scope_change_reuses_step_up_detector(self) -> None:
        # Prove the underlying refusal is the step-up ScopeAccumulationError, wrapped.
        from agent_airlock.mcp_spec.step_up_scope_guard import (
            capture_admission_snapshot,
            verify_scope_unchanged,
        )

        snap = capture_admission_snapshot("t", scopes=["a", "b"], issuer=_ISS)
        with pytest.raises(ScopeAccumulationError):
            verify_scope_unchanged(snap, live_scopes=["a"], live_issuer=_ISS)


class TestPresetMetadata:
    def test_canonical_metadata(self) -> None:
        p = mcp_tasks_lifecycle_2026_07_defaults()
        assert p["preset_id"] == "mcp_tasks_lifecycle_2026_07"
        assert p["default_action"] == "deny"
        assert p["spec"] == "SEP-1686"
        assert p["owasp"] == "MCP07"
        assert (
            callable(p["admit_task"])
            and callable(p["check_task_op"])
            and callable(p["new_registry"])
        )
        assert p["task_error"] is TaskLifecycleError
        assert p["admission_type"] is TaskAdmission

    def test_named_constant_matches_factory(self) -> None:
        assert MCP_TASKS_LIFECYCLE_2026_07["preset_id"] == "mcp_tasks_lifecycle_2026_07"

    def test_preset_end_to_end(self) -> None:
        p = mcp_tasks_lifecycle_2026_07_defaults()
        reg = p["new_registry"]()
        p["admit_task"](reg, "T", scopes=["r"], issuer=_ISS, principal="alice")
        assert (
            p["check_task_op"](
                reg, "tasks/get", "T", live_scopes=["r"], live_issuer=_ISS, principal="alice"
            )
            is None
        )
        with pytest.raises(p["task_error"]):
            p["check_task_op"](
                reg,
                "tasks/get",
                "T",
                live_scopes=["r", "extra"],
                live_issuer=_ISS,
                principal="alice",
            )

    def test_cites_sep_not_cve(self) -> None:
        src = inspect.getsource(mcp_tasks_lifecycle_2026_07_defaults)
        assert "SEP-1686" in src
        assert "CVE-" not in src


class TestNoRegression:
    def test_discoverable_via_list_active(self) -> None:
        assert "mcp_tasks_lifecycle_2026_07_defaults" in {m.preset_id for m in list_active()}

    def test_sibling_step_up_preset_unaffected(self) -> None:
        assert callable(mcp_step_up_scope_2026_07_defaults()["check_execution"])
