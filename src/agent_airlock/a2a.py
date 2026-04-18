"""A2A (Agent-to-Agent) protocol middleware (Phase 1.6).

Provides Pydantic V2 strict models for the A2A v1.0 JSON-RPC message shape,
plus a hook point `A2AValidator` that lets users plug custom validation
into agent-airlock's pipeline.

The A2A protocol was donated to the Linux Foundation and lives at
https://github.com/a2aproject/A2A (the older https://github.com/google/A2A
redirects there). The normative source is `spec/a2a.proto` in that repo;
the rendered spec is at https://a2a-protocol.org/latest/specification/.

Scope
-----

This module covers the JSON-RPC envelope + the core `Message` / `Task`
result shapes that every A2A binding uses. It does NOT implement the
transport layer (HTTP+SSE, gRPC, JSON-RPC over HTTP) — that belongs in
`a2a-sdk`, which you install alongside:

    pip install a2a-sdk

and then feed incoming request/response payloads to:

    from agent_airlock.a2a import A2AValidator

    validator = A2AValidator.strict()
    result = validator.validate_request(raw_json_rpc_body)
    if not result.ok:
        return {"jsonrpc": "2.0", "id": req_id, "error": {
            "code": -32602, "message": result.reason}}

`A2AValidator.strict()` uses Pydantic strict mode — no type coercion, no
extra fields.

Auth note
---------

Per the A2A v1.0 spec, identity lives on the HTTP layer (OAuth2 / OIDC
advertised in the AgentCard security schemes), NOT in the JSON-RPC body.
This module deliberately does NOT try to validate auth — do that with
your HTTP framework's auth middleware before calling this validator.

UNVERIFIED items (flagged in docs/research-log.md#2026-04-18-a2a-protocol-middleware):

- Exact v1.0 release date and any field-level changes between v0.3.0
  and v1.0. Models below mirror the v0.3.0 spec fields that search
  results indicated are still present in v1.0.
- Whether `Task.contextId` is required in v1.0 (currently modelled as
  optional, matching search results).
- AgentCard's exact required-vs-optional field split — the spec
  references the fields but we haven't verified every `required` annotation
  against `spec/a2a.proto` at HEAD.

Sources (retrieved 2026-04-18):
- https://github.com/a2aproject/A2A
- https://a2a-protocol.org/latest/specification/
- https://a2a-protocol.org/latest/whats-new-v1/
- https://a2a-protocol.org/latest/topics/a2a-and-mcp/
- https://pypi.org/project/a2a-sdk/
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal, Protocol, runtime_checkable

import structlog
from pydantic import BaseModel, ConfigDict, Field, ValidationError

logger = structlog.get_logger("agent-airlock.a2a")


# =============================================================================
# JSON-RPC 2.0 envelope
# =============================================================================


class JSONRPCRequest(BaseModel):
    """A JSON-RPC 2.0 request as defined by the A2A v1.0 spec.

    A2A is JSON-RPC 2.0 over HTTP(S). Methods include `message/send`,
    `message/stream`, `tasks/get`, `tasks/cancel`, `tasks/resubscribe`.
    """

    model_config = ConfigDict(strict=True, extra="forbid")

    jsonrpc: Literal["2.0"]
    id: str | int | None = None
    method: str
    params: dict[str, Any] | list[Any] | None = None


class JSONRPCError(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    code: int
    message: str
    data: Any = None


class JSONRPCResponse(BaseModel):
    """JSON-RPC 2.0 response. Either `result` or `error` is populated, not both."""

    model_config = ConfigDict(strict=True, extra="forbid")

    jsonrpc: Literal["2.0"]
    id: str | int | None = None
    result: Any | None = None
    error: JSONRPCError | None = None


# =============================================================================
# Core A2A types: Message and Task (v0.3.0 + v1.0 compatible)
# =============================================================================


class Part(BaseModel):
    """A single content part of a message.

    The A2A Part is a union of text / file / data variants. We model
    just enough to validate that at least `kind` is present; the
    runtime wire format may carry extra fields that a specific binding
    understands. Using `extra="allow"` here is deliberate — the
    validator at the Message level enforces the overall envelope; Part
    internals are up to the caller's tool.
    """

    model_config = ConfigDict(strict=True, extra="allow")

    kind: Literal["text", "file", "data"]


class Message(BaseModel):
    """An A2A message (user → agent or agent → user)."""

    model_config = ConfigDict(strict=True, extra="forbid")

    messageId: str = Field(..., min_length=1)
    role: Literal["user", "agent"]
    parts: list[Part] = Field(..., min_length=1)
    kind: Literal["message"] = "message"
    # Optional fields per v0.3.0+ spec
    taskId: str | None = None
    contextId: str | None = None
    referenceTaskIds: list[str] | None = None
    extensions: list[str] | None = None
    metadata: dict[str, Any] | None = None


class TaskStatus(BaseModel):
    """Minimal TaskStatus — full enum kept string-typed for forward-compat."""

    model_config = ConfigDict(strict=True, extra="allow")

    state: str  # e.g. "working" | "input_required" | "completed" | "failed" | "cancelled"


class Task(BaseModel):
    """An A2A task."""

    model_config = ConfigDict(strict=True, extra="forbid")

    id: str = Field(..., min_length=1)
    status: TaskStatus
    contextId: str | None = None
    history: list[Message] | None = None
    artifacts: list[dict[str, Any]] | None = None
    metadata: dict[str, Any] | None = None
    kind: Literal["task"] = "task"


# =============================================================================
# Validator hook + result
# =============================================================================


@dataclass
class A2AValidationResult:
    """The outcome of validating a single A2A message or JSON-RPC payload."""

    ok: bool
    reason: str = ""
    errors: list[str] | None = None
    parsed: Any = None  # the Pydantic model instance when ok=True


@runtime_checkable
class A2ACustomValidator(Protocol):
    """User-supplied extra validation hook.

    Called AFTER schema validation succeeds, so the argument is always a
    parsed model, never raw JSON. Returning a non-empty string rejects the
    message with that string as the reason.
    """

    def __call__(self, payload: Any) -> str | None:  # pragma: no cover - Protocol
        ...


class A2AValidator:
    """Schema + custom-hook validator for A2A traffic.

    Usage
    -----

        from agent_airlock.a2a import A2AValidator

        def reject_cross_tenant(msg):
            if msg.metadata and msg.metadata.get("tenant") != "acme":
                return "cross-tenant message rejected"
            return None

        validator = A2AValidator.strict(custom=reject_cross_tenant)
        result = validator.validate_request(raw_body)
        if not result.ok:
            # Return JSON-RPC error to the peer
            ...
    """

    def __init__(
        self,
        *,
        custom: A2ACustomValidator | None = None,
        allowed_methods: frozenset[str] | None = None,
    ) -> None:
        self.custom = custom
        self.allowed_methods = allowed_methods

    @classmethod
    def strict(
        cls,
        *,
        custom: A2ACustomValidator | None = None,
    ) -> A2AValidator:
        """Default validator with the v1.0 core method set allow-listed.

        See https://a2a-protocol.org/latest/specification/ for the full
        method list. If a server supports additional methods, pass an
        `allowed_methods` set directly to `__init__`.
        """
        return cls(
            custom=custom,
            allowed_methods=frozenset(
                {
                    "message/send",
                    "message/stream",
                    "tasks/get",
                    "tasks/cancel",
                    "tasks/resubscribe",
                }
            ),
        )

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def validate_request(self, body: dict[str, Any]) -> A2AValidationResult:
        """Validate a JSON-RPC request body."""
        return self._validate_envelope(body, kind="request")

    def validate_response(self, body: dict[str, Any]) -> A2AValidationResult:
        """Validate a JSON-RPC response body."""
        return self._validate_envelope(body, kind="response")

    def validate_message(self, body: dict[str, Any]) -> A2AValidationResult:
        """Validate a raw A2A Message (no JSON-RPC envelope)."""
        return self._validate_model(Message, body)

    def validate_task(self, body: dict[str, Any]) -> A2AValidationResult:
        """Validate a raw A2A Task."""
        return self._validate_model(Task, body)

    # -------------------------------------------------------------------------
    # Internal
    # -------------------------------------------------------------------------

    def _validate_envelope(
        self,
        body: dict[str, Any],
        *,
        kind: Literal["request", "response"],
    ) -> A2AValidationResult:
        if kind == "request":
            result = self._validate_model(JSONRPCRequest, body)
            if not result.ok:
                return result

            parsed: JSONRPCRequest = result.parsed
            if self.allowed_methods is not None and parsed.method not in self.allowed_methods:
                return A2AValidationResult(
                    ok=False,
                    reason=f"method not allowed: {parsed.method!r}",
                    errors=[f"method not in allow-list: {sorted(self.allowed_methods)}"],
                )

            custom_reason = self._run_custom(parsed)
            if custom_reason:
                return A2AValidationResult(ok=False, reason=custom_reason)
            return A2AValidationResult(ok=True, parsed=parsed)

        # response
        result = self._validate_model(JSONRPCResponse, body)
        if not result.ok:
            return result

        parsed_resp: JSONRPCResponse = result.parsed
        if parsed_resp.result is None and parsed_resp.error is None:
            return A2AValidationResult(
                ok=False,
                reason="JSON-RPC response must have either result or error",
            )
        if parsed_resp.result is not None and parsed_resp.error is not None:
            return A2AValidationResult(
                ok=False,
                reason="JSON-RPC response must not have both result and error",
            )

        custom_reason = self._run_custom(parsed_resp)
        if custom_reason:
            return A2AValidationResult(ok=False, reason=custom_reason)
        return A2AValidationResult(ok=True, parsed=parsed_resp)

    def _validate_model(
        self,
        model_cls: type[BaseModel],
        body: dict[str, Any],
    ) -> A2AValidationResult:
        try:
            parsed = model_cls.model_validate(body)
        except ValidationError as e:
            errors = [f"{'.'.join(str(x) for x in err['loc'])}: {err['msg']}" for err in e.errors()]
            return A2AValidationResult(
                ok=False,
                reason=f"A2A {model_cls.__name__} schema violation",
                errors=errors,
            )

        custom_reason = self._run_custom(parsed)
        if custom_reason:
            return A2AValidationResult(ok=False, reason=custom_reason)
        return A2AValidationResult(ok=True, parsed=parsed)

    def _run_custom(self, parsed: Any) -> str | None:
        if self.custom is None:
            return None
        try:
            return self.custom(parsed)
        except Exception as e:  # noqa: BLE001
            logger.warning("a2a_custom_validator_raised", error=str(e))
            return f"custom A2A validator raised: {e}"


__all__ = [
    "JSONRPCRequest",
    "JSONRPCResponse",
    "JSONRPCError",
    "Message",
    "Task",
    "TaskStatus",
    "Part",
    "A2AValidator",
    "A2AValidationResult",
    "A2ACustomValidator",
]
