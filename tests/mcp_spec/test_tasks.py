"""Tests for the MCP 2025-11-25 Tasks primitive (SEP-1686)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agent_airlock.mcp_spec.tasks import (
    Task,
    TaskCancelRequest,
    TaskGetRequest,
    TaskState,
    TaskStatus,
)


class TestTaskState:
    def test_lifecycle_states_present(self) -> None:
        assert TaskState.WORKING == "working"
        assert TaskState.INPUT_REQUIRED == "input_required"
        assert TaskState.COMPLETED == "completed"
        assert TaskState.FAILED == "failed"
        assert TaskState.CANCELLED == "cancelled"

    def test_all_contains_five_states(self) -> None:
        assert set(TaskState.ALL) == {
            "working",
            "input_required",
            "completed",
            "failed",
            "cancelled",
        }

    def test_terminal_states(self) -> None:
        assert frozenset({"completed", "failed", "cancelled"}) == TaskState.TERMINAL


class TestTaskStatus:
    def test_minimal_working(self) -> None:
        s = TaskStatus(state="working")
        assert s.state == "working"
        assert s.message is None

    def test_rejects_unknown_state(self) -> None:
        with pytest.raises(ValidationError):
            TaskStatus(state="bogus")

    def test_all_five_states_accepted(self) -> None:
        for s in TaskState.ALL:
            TaskStatus(state=s)  # type: ignore[arg-type]


class TestTask:
    def test_valid_working_task(self) -> None:
        t = Task(taskId="t-1", status=TaskStatus(state="working"))
        assert t.taskId == "t-1"
        assert t.status.state == "working"

    def test_valid_completed_task_with_result(self) -> None:
        t = Task(
            taskId="t-2",
            status=TaskStatus(state="completed"),
            method="tools/call",
            result={"value": 42},
        )
        assert t.result == {"value": 42}

    def test_rejects_empty_task_id(self) -> None:
        with pytest.raises(ValidationError):
            Task(taskId="", status=TaskStatus(state="working"))

    def test_extra_fields_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            Task.model_validate(
                {
                    "taskId": "t-1",
                    "status": {"state": "working"},
                    "rogue_field": "x",
                }
            )


class TestTaskGetRequest:
    def test_valid(self) -> None:
        r = TaskGetRequest(taskId="t-1")
        assert r.taskId == "t-1"

    def test_rejects_empty(self) -> None:
        with pytest.raises(ValidationError):
            TaskGetRequest(taskId="")

    def test_extra_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            TaskGetRequest.model_validate({"taskId": "t-1", "rogue": "x"})


class TestTaskCancelRequest:
    def test_valid_with_reason(self) -> None:
        r = TaskCancelRequest(taskId="t-1", reason="user_cancel")
        assert r.reason == "user_cancel"

    def test_valid_without_reason(self) -> None:
        r = TaskCancelRequest(taskId="t-1")
        assert r.reason is None

    def test_extra_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            TaskCancelRequest.model_validate({"taskId": "t", "rogue": "x"})
