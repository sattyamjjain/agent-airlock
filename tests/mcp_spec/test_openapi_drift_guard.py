"""Tests for the v0.8.1 OpenAPIDriftGuard primitive.

Runtime payload-shape validation against an operator-supplied OpenAPI 3.x
spec. Anchored on the Hermes paper (arXiv:2605.14312) finding that
production MCP/API agents frequently emit tool-call payloads that
violate the published spec — missing required fields, inventing fields
that don't exist, or sending values of the wrong type.

agent-airlock's existing guards catch *exploit shapes* (eval sinks,
shell metachars, vulnerable packages). This guard catches the
**spec-drift** class one layer earlier — the request-body never gets
to the eval guard because it never gets to the tool.

Three drift modes:

- ``strict`` (default): drift → deny.
- ``warn``: drift → allow but log structured warning.
- ``shadow``: drift → allow, record divergences, no log.

Spec source format (per 2026-05-17 operator decision): **caller
supplies a dict**. No PyYAML / no json-load helper imported by the
core; operators load their spec from disk / from the running server's
``/openapi.json`` endpoint themselves and pass the parsed dict.

Primary source
--------------
https://arxiv.org/abs/2605.14312 (Hermes: production OpenAPI agent
failure analysis, 2026-05-13)
"""

from __future__ import annotations

import pytest

from agent_airlock.mcp_spec.openapi_drift_guard import (
    OpenAPIDivergenceKind,
    OpenAPIDriftDecision,
    OpenAPIDriftGuard,
    OpenAPIDriftVerdict,
    OpenAPIDriftViolation,
    vaccinate_openapi,
)

# ----------------------------------------------------------------------
# Shared fixtures
# ----------------------------------------------------------------------


def _toy_spec() -> dict[str, object]:
    """A minimal OpenAPI 3.0 spec with one operation: ``createUser``.

    Body schema requires ``email`` (string) and ``age`` (integer).
    ``nickname`` (string) is optional. No other fields permitted.
    """
    return {
        "openapi": "3.0.3",
        "info": {"title": "Toy", "version": "1.0.0"},
        "paths": {
            "/users": {
                "post": {
                    "operationId": "createUser",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["email", "age"],
                                    "properties": {
                                        "email": {"type": "string"},
                                        "age": {"type": "integer"},
                                        "nickname": {"type": "string"},
                                    },
                                    "additionalProperties": False,
                                }
                            }
                        },
                    },
                }
            }
        },
    }


# ----------------------------------------------------------------------
# RED tests
# ----------------------------------------------------------------------


class TestCleanPayloadAllows:
    """A payload that matches the spec must pass cleanly in every mode."""

    def test_strict_mode_clean_payload(self) -> None:
        guard = OpenAPIDriftGuard(spec=_toy_spec(), drift_mode="strict")
        decision = guard.evaluate(
            operation_id="createUser",
            args={"email": "a@b.co", "age": 30, "nickname": "x"},
        )
        assert isinstance(decision, OpenAPIDriftDecision)
        assert decision.allowed is True
        assert decision.verdict == OpenAPIDriftVerdict.ALLOW
        assert decision.divergences == ()
        assert decision.operation_id == "createUser"

    def test_warn_mode_clean_payload_still_allows_with_ALLOW_verdict(self) -> None:
        guard = OpenAPIDriftGuard(spec=_toy_spec(), drift_mode="warn")
        decision = guard.evaluate(
            operation_id="createUser",
            args={"email": "a@b.co", "age": 30},
        )
        # No drift → vanilla ALLOW (not ALLOW_WARN; ALLOW_WARN is reserved
        # for "drift detected but mode is warn").
        assert decision.allowed is True
        assert decision.verdict == OpenAPIDriftVerdict.ALLOW
        assert decision.divergences == ()


class TestMissingRequiredField:
    """A required field absent from args must be detected."""

    def test_strict_mode_missing_required_denies(self) -> None:
        guard = OpenAPIDriftGuard(spec=_toy_spec(), drift_mode="strict")
        decision = guard.evaluate(
            operation_id="createUser",
            args={"email": "a@b.co"},  # age missing
        )
        assert decision.allowed is False
        assert decision.verdict == OpenAPIDriftVerdict.DENY_DRIFT
        assert any(
            d.kind == OpenAPIDivergenceKind.MISSING_REQUIRED and d.field == "age"
            for d in decision.divergences
        )

    def test_warn_mode_missing_required_allows_with_ALLOW_WARN(self) -> None:
        guard = OpenAPIDriftGuard(spec=_toy_spec(), drift_mode="warn")
        decision = guard.evaluate(
            operation_id="createUser",
            args={"email": "a@b.co"},
        )
        assert decision.allowed is True
        assert decision.verdict == OpenAPIDriftVerdict.ALLOW_WARN
        # divergences are still recorded so the operator can audit
        assert any(d.kind == OpenAPIDivergenceKind.MISSING_REQUIRED for d in decision.divergences)

    def test_shadow_mode_missing_required_allows_with_ALLOW_SHADOW(self) -> None:
        guard = OpenAPIDriftGuard(spec=_toy_spec(), drift_mode="shadow")
        decision = guard.evaluate(
            operation_id="createUser",
            args={"email": "a@b.co"},
        )
        assert decision.allowed is True
        assert decision.verdict == OpenAPIDriftVerdict.ALLOW_SHADOW
        assert decision.divergences != ()


class TestUnknownField:
    """A field not declared in the schema must be detected when additionalProperties=false."""

    def test_strict_mode_unknown_field_denies(self) -> None:
        guard = OpenAPIDriftGuard(spec=_toy_spec(), drift_mode="strict")
        decision = guard.evaluate(
            operation_id="createUser",
            args={
                "email": "a@b.co",
                "age": 30,
                "is_admin": True,  # invented field
            },
        )
        assert decision.allowed is False
        assert decision.verdict == OpenAPIDriftVerdict.DENY_DRIFT
        assert any(
            d.kind == OpenAPIDivergenceKind.UNKNOWN_FIELD and d.field == "is_admin"
            for d in decision.divergences
        )

    def test_additional_properties_default_true_allows_unknown(self) -> None:
        """If the spec doesn't say ``additionalProperties: false`` we don't flag unknowns."""
        spec = _toy_spec()
        # Remove the additionalProperties: false marker → permissive schema.
        del spec["paths"]["/users"]["post"]["requestBody"]["content"][  # type: ignore[index]
            "application/json"
        ]["schema"]["additionalProperties"]
        guard = OpenAPIDriftGuard(spec=spec, drift_mode="strict")
        decision = guard.evaluate(
            operation_id="createUser",
            args={"email": "a@b.co", "age": 30, "is_admin": True},
        )
        assert decision.allowed is True
        assert decision.verdict == OpenAPIDriftVerdict.ALLOW


class TestTypeMismatch:
    """A field with a value of the wrong JSON type must be detected."""

    def test_string_field_int_value_denies(self) -> None:
        guard = OpenAPIDriftGuard(spec=_toy_spec(), drift_mode="strict")
        decision = guard.evaluate(
            operation_id="createUser",
            args={"email": 42, "age": 30},  # email should be string
        )
        assert decision.allowed is False
        assert decision.verdict == OpenAPIDriftVerdict.DENY_DRIFT
        type_divs = [
            d for d in decision.divergences if d.kind == OpenAPIDivergenceKind.TYPE_MISMATCH
        ]
        assert len(type_divs) == 1
        assert type_divs[0].field == "email"
        assert type_divs[0].expected == "string"
        assert type_divs[0].observed == "integer"

    def test_integer_field_bool_value_denies(self) -> None:
        """Python's ``bool`` subclasses ``int`` — we must not accept it as JSON integer."""
        guard = OpenAPIDriftGuard(spec=_toy_spec(), drift_mode="strict")
        decision = guard.evaluate(
            operation_id="createUser",
            args={"email": "a@b.co", "age": True},
        )
        assert decision.allowed is False
        type_divs = [
            d for d in decision.divergences if d.kind == OpenAPIDivergenceKind.TYPE_MISMATCH
        ]
        assert any(d.field == "age" and d.observed == "boolean" for d in type_divs)


class TestUnknownOperation:
    """An ``operation_id`` not present in the spec must be flagged."""

    def test_strict_mode_unknown_op_denies(self) -> None:
        guard = OpenAPIDriftGuard(spec=_toy_spec(), drift_mode="strict")
        decision = guard.evaluate(operation_id="deleteUser", args={})
        assert decision.allowed is False
        assert decision.verdict == OpenAPIDriftVerdict.DENY_UNKNOWN_OPERATION
        assert decision.operation_id == "deleteUser"

    def test_warn_mode_unknown_op_allows(self) -> None:
        guard = OpenAPIDriftGuard(spec=_toy_spec(), drift_mode="warn")
        decision = guard.evaluate(operation_id="deleteUser", args={})
        # warn mode lets the call through but reports the verdict.
        assert decision.allowed is True
        assert decision.verdict == OpenAPIDriftVerdict.ALLOW_WARN


class TestConstructionValidation:
    """The guard rejects malformed construction up front."""

    def test_unknown_drift_mode_raises(self) -> None:
        with pytest.raises(ValueError, match="drift_mode"):
            OpenAPIDriftGuard(spec=_toy_spec(), drift_mode="loud")

    def test_non_dict_spec_raises(self) -> None:
        with pytest.raises(TypeError, match="spec"):
            OpenAPIDriftGuard(spec="not-a-dict", drift_mode="strict")  # type: ignore[arg-type]

    def test_spec_without_paths_raises(self) -> None:
        with pytest.raises(ValueError, match="paths"):
            OpenAPIDriftGuard(spec={"openapi": "3.0.0"}, drift_mode="strict")


class TestDecisionShape:
    """The decision dataclass mirrors the v0.7.x / v0.8.0 family shape."""

    def test_decision_is_frozen(self) -> None:
        guard = OpenAPIDriftGuard(spec=_toy_spec(), drift_mode="strict")
        decision = guard.evaluate(operation_id="createUser", args={"email": "a@b.co", "age": 30})
        with pytest.raises((AttributeError, Exception)):  # FrozenInstanceError or AttributeError
            decision.allowed = False  # type: ignore[misc]

    def test_divergence_is_frozen(self) -> None:
        guard = OpenAPIDriftGuard(spec=_toy_spec(), drift_mode="strict")
        decision = guard.evaluate(operation_id="createUser", args={"email": "a@b.co"})
        div = decision.divergences[0]
        with pytest.raises((AttributeError, Exception)):
            div.field = "nope"  # type: ignore[misc]

    def test_decision_exposes_allowed_bool(self) -> None:
        """Mirrors AllowlistVerdict / EvalRCEDecision shape — ``allowed`` is always present."""
        guard = OpenAPIDriftGuard(spec=_toy_spec(), drift_mode="strict")
        d1 = guard.evaluate(operation_id="createUser", args={"email": "a@b.co", "age": 30})
        d2 = guard.evaluate(operation_id="createUser", args={})
        assert isinstance(d1.allowed, bool)
        assert isinstance(d2.allowed, bool)


class TestVaccinateOpenAPIHelper:
    """``vaccinate_openapi`` is the decorator-factory wrapper for tool functions."""

    def test_vaccinate_returns_decorator_factory(self) -> None:
        vaccine = vaccinate_openapi(_toy_spec(), drift_mode="strict")
        assert callable(vaccine)

    def test_vaccinated_function_passes_clean_call(self) -> None:
        vaccine = vaccinate_openapi(_toy_spec(), drift_mode="strict")

        @vaccine("createUser")
        def create_user(*, email: str, age: int, nickname: str | None = None) -> dict:
            return {"email": email, "age": age, "nickname": nickname}

        result = create_user(email="a@b.co", age=30)
        assert result == {"email": "a@b.co", "age": 30, "nickname": None}

    def test_vaccinated_function_raises_on_drift_in_strict(self) -> None:
        vaccine = vaccinate_openapi(_toy_spec(), drift_mode="strict")

        @vaccine("createUser")
        def create_user(*, email: str, age: int, nickname: str | None = None) -> dict:
            return {"email": email, "age": age, "nickname": nickname}

        with pytest.raises(OpenAPIDriftViolation) as exc_info:
            create_user(email="a@b.co")  # age missing
        # The exception carries the decision for operator audit.
        assert isinstance(exc_info.value.decision, OpenAPIDriftDecision)
        assert exc_info.value.decision.verdict == OpenAPIDriftVerdict.DENY_DRIFT

    def test_vaccinated_function_allows_drift_in_warn(self) -> None:
        vaccine = vaccinate_openapi(_toy_spec(), drift_mode="warn")

        @vaccine("createUser")
        def create_user(**kwargs) -> dict:
            return kwargs

        # Missing required field — warn mode lets it through.
        result = create_user(email="a@b.co")
        assert result == {"email": "a@b.co"}
