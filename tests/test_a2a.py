"""Tests for the A2A (Agent-to-Agent) protocol middleware (Phase 1.6).

Schema-level validation of JSON-RPC envelopes, Message / Task / Part
payloads, and the `A2AValidator` custom-hook lifecycle.
"""

from __future__ import annotations

from typing import Any

import pytest

from agent_airlock.a2a import (
    A2AValidator,
    JSONRPCRequest,
    Message,
    Task,
)

# -----------------------------------------------------------------------------
# JSON-RPC envelope
# -----------------------------------------------------------------------------


class TestJSONRPCRequest:
    def test_valid_message_send(self) -> None:
        body = {
            "jsonrpc": "2.0",
            "id": "req-1",
            "method": "message/send",
            "params": {
                "message": {
                    "messageId": "m-1",
                    "role": "user",
                    "parts": [{"kind": "text", "text": "hi"}],
                    "kind": "message",
                }
            },
        }
        validator = A2AValidator.strict()
        result = validator.validate_request(body)
        assert result.ok, result.errors

    def test_missing_jsonrpc_version(self) -> None:
        body = {"id": "req-1", "method": "message/send"}
        validator = A2AValidator.strict()
        result = validator.validate_request(body)
        assert result.ok is False
        assert "jsonrpc" in " ".join(result.errors or [])

    def test_wrong_jsonrpc_version(self) -> None:
        body = {"jsonrpc": "1.0", "id": 1, "method": "message/send"}
        result = A2AValidator.strict().validate_request(body)
        assert result.ok is False

    def test_method_not_in_allowlist(self) -> None:
        body = {"jsonrpc": "2.0", "id": 1, "method": "agent/shutdown"}
        result = A2AValidator.strict().validate_request(body)
        assert result.ok is False
        assert "method not allowed" in result.reason

    def test_allowlist_override(self) -> None:
        """A caller can expand the allow-list for a custom method."""
        custom_methods = frozenset(
            {"message/send", "message/stream", "tasks/get", "agent/shutdown"}
        )
        validator = A2AValidator(allowed_methods=custom_methods)
        body = {"jsonrpc": "2.0", "id": 1, "method": "agent/shutdown"}
        result = validator.validate_request(body)
        assert result.ok, result.errors

    def test_extra_fields_forbidden(self) -> None:
        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "message/send",
            "evil_extra": "payload",
        }
        result = A2AValidator.strict().validate_request(body)
        assert result.ok is False


class TestJSONRPCResponse:
    def test_valid_result_response(self) -> None:
        body = {"jsonrpc": "2.0", "id": "req-1", "result": {"ok": True}}
        result = A2AValidator.strict().validate_response(body)
        assert result.ok

    def test_valid_error_response(self) -> None:
        body = {
            "jsonrpc": "2.0",
            "id": "req-1",
            "error": {"code": -32600, "message": "Invalid Request"},
        }
        result = A2AValidator.strict().validate_response(body)
        assert result.ok

    def test_rejects_both_result_and_error(self) -> None:
        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"ok": True},
            "error": {"code": -32600, "message": "boom"},
        }
        result = A2AValidator.strict().validate_response(body)
        assert result.ok is False
        assert "both result and error" in result.reason

    def test_rejects_neither_result_nor_error(self) -> None:
        body = {"jsonrpc": "2.0", "id": 1}
        result = A2AValidator.strict().validate_response(body)
        assert result.ok is False
        assert "either result or error" in result.reason


# -----------------------------------------------------------------------------
# Message
# -----------------------------------------------------------------------------


class TestMessage:
    def test_valid_user_message(self) -> None:
        body = {
            "messageId": "m-1",
            "role": "user",
            "parts": [{"kind": "text", "text": "hello"}],
            "kind": "message",
        }
        result = A2AValidator.strict().validate_message(body)
        assert result.ok
        assert isinstance(result.parsed, Message)
        assert result.parsed.messageId == "m-1"

    def test_valid_agent_message_with_metadata(self) -> None:
        body = {
            "messageId": "m-2",
            "role": "agent",
            "parts": [{"kind": "text", "text": "ok"}],
            "kind": "message",
            "contextId": "ctx-1",
            "metadata": {"tenant": "acme"},
        }
        result = A2AValidator.strict().validate_message(body)
        assert result.ok

    def test_rejects_invalid_role(self) -> None:
        body = {
            "messageId": "m-1",
            "role": "system",  # not allowed — only user|agent
            "parts": [{"kind": "text"}],
            "kind": "message",
        }
        result = A2AValidator.strict().validate_message(body)
        assert result.ok is False

    def test_rejects_empty_parts(self) -> None:
        body = {
            "messageId": "m-1",
            "role": "user",
            "parts": [],
            "kind": "message",
        }
        result = A2AValidator.strict().validate_message(body)
        assert result.ok is False
        assert any("parts" in e for e in (result.errors or []))

    def test_rejects_missing_message_id(self) -> None:
        body = {
            "role": "user",
            "parts": [{"kind": "text"}],
            "kind": "message",
        }
        result = A2AValidator.strict().validate_message(body)
        assert result.ok is False

    def test_rejects_wrong_kind(self) -> None:
        body = {
            "messageId": "m-1",
            "role": "user",
            "parts": [{"kind": "text"}],
            "kind": "not-a-message",
        }
        result = A2AValidator.strict().validate_message(body)
        assert result.ok is False


# -----------------------------------------------------------------------------
# Task
# -----------------------------------------------------------------------------


class TestTask:
    def test_valid_working_task(self) -> None:
        body = {
            "id": "t-1",
            "status": {"state": "working"},
            "kind": "task",
        }
        result = A2AValidator.strict().validate_task(body)
        assert result.ok
        assert isinstance(result.parsed, Task)

    def test_valid_task_with_history(self) -> None:
        body = {
            "id": "t-1",
            "status": {"state": "completed"},
            "kind": "task",
            "history": [
                {
                    "messageId": "m-1",
                    "role": "user",
                    "parts": [{"kind": "text"}],
                    "kind": "message",
                }
            ],
        }
        result = A2AValidator.strict().validate_task(body)
        assert result.ok

    def test_rejects_task_without_id(self) -> None:
        body = {"status": {"state": "working"}, "kind": "task"}
        result = A2AValidator.strict().validate_task(body)
        assert result.ok is False

    def test_rejects_task_with_bad_kind(self) -> None:
        body = {"id": "t-1", "status": {"state": "working"}, "kind": "job"}
        result = A2AValidator.strict().validate_task(body)
        assert result.ok is False


# -----------------------------------------------------------------------------
# Custom validator hook
# -----------------------------------------------------------------------------


class TestCustomValidator:
    def test_custom_reject_message(self) -> None:
        def reject_cross_tenant(payload: Any) -> str | None:
            if isinstance(payload, Message) and (payload.metadata or {}).get("tenant") != "acme":
                return "cross-tenant message rejected"
            return None

        validator = A2AValidator.strict(custom=reject_cross_tenant)

        cross = {
            "messageId": "m-1",
            "role": "user",
            "parts": [{"kind": "text"}],
            "kind": "message",
            "metadata": {"tenant": "wrong"},
        }
        result = validator.validate_message(cross)
        assert result.ok is False
        assert "cross-tenant" in result.reason

    def test_custom_accept_message(self) -> None:
        def reject_cross_tenant(payload: Any) -> str | None:
            if isinstance(payload, Message) and (payload.metadata or {}).get("tenant") != "acme":
                return "cross-tenant message rejected"
            return None

        validator = A2AValidator.strict(custom=reject_cross_tenant)
        allowed = {
            "messageId": "m-2",
            "role": "user",
            "parts": [{"kind": "text"}],
            "kind": "message",
            "metadata": {"tenant": "acme"},
        }
        result = validator.validate_message(allowed)
        assert result.ok

    def test_custom_raises_surfaces_as_reject(self) -> None:
        def boom(payload: Any) -> str | None:
            raise RuntimeError("fail")

        validator = A2AValidator.strict(custom=boom)
        body = {
            "messageId": "m-1",
            "role": "user",
            "parts": [{"kind": "text"}],
            "kind": "message",
        }
        result = validator.validate_message(body)
        assert result.ok is False
        assert "custom A2A validator raised" in result.reason


# -----------------------------------------------------------------------------
# Sanity: Pydantic strict types compile
# -----------------------------------------------------------------------------


class TestDirectModels:
    def test_message_extra_forbid(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            Message.model_validate(
                {
                    "messageId": "m-1",
                    "role": "user",
                    "parts": [{"kind": "text"}],
                    "kind": "message",
                    "rogue_field": "x",
                }
            )

    def test_jsonrpc_request_id_may_be_int_or_str_or_null(self) -> None:
        for id_value in (1, "one", None):
            JSONRPCRequest.model_validate(
                {"jsonrpc": "2.0", "id": id_value, "method": "message/send"}
            )
