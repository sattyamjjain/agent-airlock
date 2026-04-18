"""MCP 2025-11-25 Tasks primitive (SEP-1686) schema.

Source: https://modelcontextprotocol.io/specification/2025-11-25 +
https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1686
(retrieved 2026-04-18).

The Tasks primitive introduces a `call-now, fetch-later` pattern: any
JSON-RPC request MAY return a task handle; the client polls
`tasks/get` / `tasks/cancel` for state and results.

Scope here: Pydantic V2 strict models for validating task payloads on
the wire. We do NOT run tasks (that's the server's job); we only
enforce the envelope shape.

UNVERIFIED items (flagged in docs/research-log.md):

- Exact terminal-state spelling: search results indicated the state
  machine is `working / input_required / completed / failed / cancelled`.
  Confirmed by summary text; not confirmed by reading `schema.ts` line
  by line. `TaskState` here matches that set. If the normative proto
  uses different casing or an extra state, this module is the only
  place that needs updating.
- Whether `tasks/get`'s response uses `result: Task` or `result: TaskStatus`
  — the state-machine fields are on `Task.status` in our model.
- `tasks/resubscribe` semantics (listed as a method in the search
  results). We model `TaskGetRequest` + `TaskCancelRequest` only; a
  future PR can add `TaskResubscribeRequest` once the exact shape is
  pulled from `schema.ts`.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .oauth import BearerHeaderError as BearerHeaderError  # re-export convenience

# =============================================================================
# Task state machine
# =============================================================================


# Note: str enum so JSON-RPC serialisation is trivial. Order matches the
# lifecycle: working → (input_required ↔ working)* → completed|failed|cancelled.
class TaskState:
    """Task lifecycle states. Enumerated as a str class (not Enum) so that
    `state: TaskState` type annotations stay readable and the values match
    the on-the-wire JSON strings exactly."""

    WORKING: Literal["working"] = "working"
    INPUT_REQUIRED: Literal["input_required"] = "input_required"
    COMPLETED: Literal["completed"] = "completed"
    FAILED: Literal["failed"] = "failed"
    CANCELLED: Literal["cancelled"] = "cancelled"

    ALL: tuple[str, ...] = (
        "working",
        "input_required",
        "completed",
        "failed",
        "cancelled",
    )
    TERMINAL: frozenset[str] = frozenset({"completed", "failed", "cancelled"})


class TaskStatus(BaseModel):
    """Machine-readable status of a Task."""

    model_config = ConfigDict(strict=True, extra="allow")

    state: Literal["working", "input_required", "completed", "failed", "cancelled"]
    # RFC 3339 timestamp of the last state transition. Not required by spec
    # at the time of this writing; kept optional here.
    lastUpdated: str | None = None
    # Human-readable message associated with the current state (e.g. progress
    # description or failure reason). Spec hints at this via "progress tracking"
    # but we keep it loose.
    message: str | None = None


class Task(BaseModel):
    """A running or completed server task handle (SEP-1686)."""

    model_config = ConfigDict(strict=True, extra="forbid")

    taskId: str = Field(..., min_length=1)
    status: TaskStatus
    # The original request method that spawned the task, if the server
    # chooses to echo it back. Purely informational.
    method: str | None = None
    # Terminal `result` payload. Shape is method-specific; keep loose.
    result: Any | None = None


# =============================================================================
# JSON-RPC requests on the tasks/* methods
# =============================================================================


class TaskGetRequest(BaseModel):
    """`tasks/get` — fetch current state of a task handle.

    On the wire this is wrapped in a JSON-RPC 2.0 envelope; the
    agent-airlock A2A validator handles the envelope. This model is just
    the `params`.
    """

    model_config = ConfigDict(strict=True, extra="forbid")

    taskId: str = Field(..., min_length=1)


class TaskCancelRequest(BaseModel):
    """`tasks/cancel` — cancel a task handle."""

    model_config = ConfigDict(strict=True, extra="forbid")

    taskId: str = Field(..., min_length=1)
    # Optional client-provided reason surfaced in server logs / OTel spans.
    reason: str | None = None


__all__ = [
    "TaskState",
    "TaskStatus",
    "Task",
    "TaskGetRequest",
    "TaskCancelRequest",
]
