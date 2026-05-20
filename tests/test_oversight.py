"""Tests for the v0.8.4 ``@requires_human_oversight`` decorator.

Honest scope
------------
This decorator is anchored on the Code-as-Harness survey
(arXiv:2605.18747, Ning et al., 2026-05-18), which identifies
"human oversight for safety-critical actions" as an open challenge
in harness engineering.

What this ships:
  - A decorator factory that wraps a tool function with an approval gate.
  - Pure data shapes: OversightRequest, OversightResponse, OversightVerdict.
  - Exception types: OversightDeniedError, OversightTimeoutError.
  - An InProcessRecordedApprover for testing.

What this does NOT ship:
  - An "audit_emitter.await_response" bidirectional RPC channel
    (the 2026-05-20 doc proposed this; the existing audit emitter is
    one-way only and grafting a request/response channel onto a sink
    is a transport decision we deliberately leave to the operator).
  - Slack/PagerDuty/CLI integration. The operator supplies the
    ``approver`` callable; agent-airlock ships the decorator + shapes.
  - Async wrapping. v0.8.4 ships the sync surface; async is a
    deferred follow-up.

Primary source
--------------
https://arxiv.org/abs/2605.18747
"""

from __future__ import annotations

import pytest

from agent_airlock.oversight import (
    InProcessRecordedApprover,
    OversightDeniedError,
    OversightRequest,
    OversightResponse,
    OversightTimeoutError,
    OversightVerdict,
    requires_human_oversight,
)

# ----------------------------------------------------------------------
# Fixtures
# ----------------------------------------------------------------------


def _grant_approver(_req: OversightRequest) -> OversightResponse:
    """Always grants. Echoes the request_id for round-trip verification."""
    return OversightResponse(
        request_id=_req.request_id,
        verdict=OversightVerdict.GRANT,
        detail="auto-grant for test",
        approver="test-grant-bot",
    )


def _deny_approver(_req: OversightRequest) -> OversightResponse:
    return OversightResponse(
        request_id=_req.request_id,
        verdict=OversightVerdict.DENY,
        detail="auto-deny for test",
        approver="test-deny-bot",
    )


def _timeout_approver(_req: OversightRequest) -> OversightResponse:
    return OversightResponse(
        request_id=_req.request_id,
        verdict=OversightVerdict.TIMEOUT,
        detail="auto-timeout for test",
        approver=None,
    )


# ----------------------------------------------------------------------
# Core decorator behaviour
# ----------------------------------------------------------------------


class TestGrant:
    """approver returns GRANT → wrapped function is called, return value returned."""

    def test_grant_calls_wrapped_function(self) -> None:
        @requires_human_oversight(approver=_grant_approver)
        def deploy_to_prod(version: str) -> str:
            return f"deployed {version}"

        result = deploy_to_prod("v1.0.0")
        assert result == "deployed v1.0.0"

    def test_grant_passes_kwargs(self) -> None:
        @requires_human_oversight(approver=_grant_approver)
        def make_payment(*, amount: float, recipient: str) -> dict:
            return {"amount": amount, "recipient": recipient}

        result = make_payment(amount=100.0, recipient="alice")
        assert result == {"amount": 100.0, "recipient": "alice"}


class TestDeny:
    """approver returns DENY → OversightDeniedError raised carrying the response."""

    def test_deny_raises(self) -> None:
        @requires_human_oversight(approver=_deny_approver)
        def deploy_to_prod(version: str) -> str:
            return f"deployed {version}"  # pragma: no cover — should be skipped

        with pytest.raises(OversightDeniedError) as exc_info:
            deploy_to_prod("v1.0.0")
        assert exc_info.value.response.verdict == OversightVerdict.DENY
        assert exc_info.value.response.approver == "test-deny-bot"

    def test_deny_exception_carries_request_and_response(self) -> None:
        @requires_human_oversight(approver=_deny_approver)
        def t() -> None:
            pass  # pragma: no cover

        with pytest.raises(OversightDeniedError) as exc_info:
            t()
        assert isinstance(exc_info.value.response, OversightResponse)
        assert isinstance(exc_info.value.request, OversightRequest)


class TestTimeout:
    """approver returns TIMEOUT → OversightTimeoutError raised."""

    def test_timeout_raises(self) -> None:
        @requires_human_oversight(approver=_timeout_approver, timeout_seconds=5.0)
        def t() -> None:
            pass  # pragma: no cover

        with pytest.raises(OversightTimeoutError) as exc_info:
            t()
        assert isinstance(exc_info.value.request, OversightRequest)
        assert exc_info.value.request.timeout_seconds == 5.0


class TestRequestRoundTrip:
    """The request_id sent to the approver matches the response's request_id."""

    def test_request_id_round_trip(self) -> None:
        captured: list[OversightRequest] = []

        def capture(req: OversightRequest) -> OversightResponse:
            captured.append(req)
            return OversightResponse(
                request_id=req.request_id, verdict=OversightVerdict.GRANT, detail=""
            )

        @requires_human_oversight(approver=capture)
        def t() -> str:
            return "ok"

        assert t() == "ok"
        assert len(captured) == 1
        assert captured[0].request_id  # non-empty UUID string

    def test_response_request_id_mismatch_raises(self) -> None:
        """A buggy approver returning a wrong request_id is treated as a protocol fault."""

        def buggy(req: OversightRequest) -> OversightResponse:
            return OversightResponse(
                request_id="bogus-id",
                verdict=OversightVerdict.GRANT,
                detail="bug",
            )

        @requires_human_oversight(approver=buggy)
        def t() -> None:
            pass  # pragma: no cover

        with pytest.raises(ValueError, match="request_id"):
            t()


class TestApproverReceivesContext:
    """The approver gets a fully-populated OversightRequest."""

    def test_approver_receives_tool_name_and_args(self) -> None:
        captured: list[OversightRequest] = []

        def capture(req: OversightRequest) -> OversightResponse:
            captured.append(req)
            return OversightResponse(
                request_id=req.request_id, verdict=OversightVerdict.GRANT, detail=""
            )

        @requires_human_oversight(approver=capture, channel="prod-deploys")
        def deploy_to_prod(version: str, *, dry_run: bool = False) -> None:
            pass

        deploy_to_prod("v1.0.0", dry_run=True)
        assert len(captured) == 1
        req = captured[0]
        assert req.tool_name == "deploy_to_prod"
        assert req.args["args"] == ("v1.0.0",)
        assert req.args["kwargs"] == {"dry_run": True}
        assert req.channel == "prod-deploys"
        assert req.timeout_seconds == 300.0  # default
        assert req.requested_at  # non-empty ISO timestamp


# ----------------------------------------------------------------------
# Audit emission (one-way; existing emitter API is honoured)
# ----------------------------------------------------------------------


class TestAuditEmitter:
    """The decorator emits oversight.request / .grant / .deny structured events."""

    def test_audit_emitter_receives_request_event(self) -> None:
        events: list[tuple[str, dict]] = []

        def emit(event_type: str, payload: dict) -> None:
            events.append((event_type, payload))

        @requires_human_oversight(approver=_grant_approver, audit_emitter=emit)
        def t() -> None:
            pass

        t()
        types = [e[0] for e in events]
        assert "oversight.request" in types
        # Find the request event and verify its payload shape
        request_event = next(e[1] for e in events if e[0] == "oversight.request")
        assert "request_id" in request_event
        assert "tool_name" in request_event

    def test_audit_emitter_receives_grant_event(self) -> None:
        events: list[tuple[str, dict]] = []

        def emit(event_type: str, payload: dict) -> None:
            events.append((event_type, payload))

        @requires_human_oversight(approver=_grant_approver, audit_emitter=emit)
        def t() -> None:
            pass

        t()
        types = [e[0] for e in events]
        assert "oversight.grant" in types

    def test_audit_emitter_receives_deny_event(self) -> None:
        events: list[tuple[str, dict]] = []

        def emit(event_type: str, payload: dict) -> None:
            events.append((event_type, payload))

        @requires_human_oversight(approver=_deny_approver, audit_emitter=emit)
        def t() -> None:
            pass  # pragma: no cover

        with pytest.raises(OversightDeniedError):
            t()
        types = [e[0] for e in events]
        assert "oversight.deny" in types


# ----------------------------------------------------------------------
# Data shape invariants — mirror v0.7.x / v0.8.x family
# ----------------------------------------------------------------------


class TestShape:
    """OversightRequest / OversightResponse are frozen dataclasses."""

    def test_request_is_frozen(self) -> None:
        req = OversightRequest(
            request_id="x",
            tool_name="t",
            args={},
            channel="c",
            timeout_seconds=1.0,
            requested_at="2026-05-20T00:00:00Z",
        )
        with pytest.raises((AttributeError, Exception)):  # FrozenInstanceError
            req.tool_name = "x"  # type: ignore[misc]

    def test_response_is_frozen(self) -> None:
        resp = OversightResponse(request_id="x", verdict=OversightVerdict.GRANT, detail="")
        with pytest.raises((AttributeError, Exception)):
            resp.verdict = OversightVerdict.DENY  # type: ignore[misc]


# ----------------------------------------------------------------------
# Decorator hygiene
# ----------------------------------------------------------------------


class TestDecoratorPreservesSignature:
    """functools.wraps applied so framework introspection still works."""

    def test_name_preserved(self) -> None:
        @requires_human_oversight(approver=_grant_approver)
        def my_named_tool() -> str:
            return "ok"

        assert my_named_tool.__name__ == "my_named_tool"

    def test_docstring_preserved(self) -> None:
        @requires_human_oversight(approver=_grant_approver)
        def my_tool() -> str:
            """My fine docstring."""
            return "ok"

        assert my_tool.__doc__ == "My fine docstring."


# ----------------------------------------------------------------------
# InProcessRecordedApprover (testing helper)
# ----------------------------------------------------------------------


class TestInProcessRecordedApprover:
    """The bundled testing approver returns pre-set responses per tool name."""

    def test_recorded_grant(self) -> None:
        approver = InProcessRecordedApprover(decisions={"deploy_to_prod": OversightVerdict.GRANT})

        @requires_human_oversight(approver=approver)
        def deploy_to_prod() -> str:
            return "deployed"

        assert deploy_to_prod() == "deployed"

    def test_recorded_deny(self) -> None:
        approver = InProcessRecordedApprover(decisions={"t": OversightVerdict.DENY})

        @requires_human_oversight(approver=approver)
        def t() -> None:
            pass  # pragma: no cover

        with pytest.raises(OversightDeniedError):
            t()

    def test_recorded_unknown_tool_defaults_to_timeout(self) -> None:
        """If the tool isn't in the recorded decisions, default to TIMEOUT."""
        approver = InProcessRecordedApprover(decisions={})

        @requires_human_oversight(approver=approver)
        def some_other_tool() -> None:
            pass  # pragma: no cover

        with pytest.raises(OversightTimeoutError):
            some_other_tool()

    def test_recorded_call_log(self) -> None:
        """The recorder logs every request for test assertions."""
        approver = InProcessRecordedApprover(decisions={"t": OversightVerdict.GRANT})

        @requires_human_oversight(approver=approver)
        def t(x: int) -> int:
            return x

        t(1)
        t(2)
        assert len(approver.calls) == 2
        assert approver.calls[0].tool_name == "t"
        assert approver.calls[0].args["args"] == (1,)


# ----------------------------------------------------------------------
# Construction-time validation
# ----------------------------------------------------------------------


class TestConstructionValidation:
    """Bad operator inputs are rejected up front."""

    def test_approver_must_be_callable(self) -> None:
        with pytest.raises(TypeError, match="approver"):
            requires_human_oversight(approver="not-callable")  # type: ignore[arg-type]

    def test_negative_timeout_rejected(self) -> None:
        with pytest.raises(ValueError, match="timeout_seconds"):
            requires_human_oversight(approver=_grant_approver, timeout_seconds=-1.0)
