"""Tests for the self_heal module."""

from pydantic import ValidationError

from agent_airlock.self_heal import (
    AirlockResponse,
    BlockReason,
    handle_ghost_argument_error,
    handle_policy_violation,
    handle_rate_limit,
    handle_validation_error,
)
from agent_airlock.validator import GhostArgumentError, create_strict_validator


class TestAirlockResponse:
    """Tests for AirlockResponse dataclass."""

    def test_success_response(self) -> None:
        response = AirlockResponse.success_response(result={"data": 123})

        assert response.success is True
        assert response.status == "completed"
        assert response.result == {"data": 123}
        assert response.error is None
        assert response.block_reason is None

    def test_success_response_with_warnings(self) -> None:
        response = AirlockResponse.success_response(
            result="ok",
            warnings=["Output was truncated"],
        )

        assert response.success is True
        assert response.warnings == ["Output was truncated"]

    def test_blocked_response(self) -> None:
        response = AirlockResponse.blocked_response(
            reason=BlockReason.VALIDATION_ERROR,
            error="Invalid input",
            fix_hints=["Check types"],
        )

        assert response.success is False
        assert response.status == "blocked"
        assert response.block_reason == BlockReason.VALIDATION_ERROR
        assert response.error == "Invalid input"
        assert response.fix_hints == ["Check types"]

    def test_to_dict(self) -> None:
        response = AirlockResponse.blocked_response(
            reason=BlockReason.GHOST_ARGUMENTS,
            error="Unknown args",
            fix_hints=["Remove 'force'"],
            metadata={"function": "test"},
        )

        result = response.to_dict()

        assert result["success"] is False
        assert result["status"] == "blocked"
        assert result["block_reason"] == "ghost_arguments"
        assert result["error"] == "Unknown args"
        assert result["fix_hints"] == ["Remove 'force'"]
        assert result["metadata"] == {"function": "test"}

    def test_to_dict_minimal(self) -> None:
        response = AirlockResponse.success_response(result=42)
        result = response.to_dict()

        assert result["success"] is True
        assert result["status"] == "completed"
        assert result["result"] == 42
        assert "error" not in result
        assert "block_reason" not in result


class TestHandleValidationError:
    """Tests for handle_validation_error function."""

    def test_handles_type_error(self) -> None:
        def func(x: int) -> int:
            return x

        validated = create_strict_validator(func)

        try:
            validated(x="not an int")
        except ValidationError as e:
            response = handle_validation_error(e, "func")

        assert response.success is False
        assert response.block_reason == BlockReason.VALIDATION_ERROR
        assert "func" in response.error
        assert "AIRLOCK_BLOCK" in response.error
        assert len(response.fix_hints) > 0

    def test_includes_metadata(self) -> None:
        def func(x: int, y: str) -> None:
            pass

        validated = create_strict_validator(func)

        try:
            validated(x="wrong", y=123)
        except ValidationError as e:
            response = handle_validation_error(e, "func")

        assert response.metadata["function"] == "func"
        assert response.metadata["error_count"] == 2
        assert "errors" in response.metadata


class TestHandleGhostArgumentError:
    """Tests for handle_ghost_argument_error function."""

    def test_basic_handling(self) -> None:
        error = GhostArgumentError("my_func", {"force", "extra"})
        response = handle_ghost_argument_error(error)

        assert response.success is False
        assert response.block_reason == BlockReason.GHOST_ARGUMENTS
        assert "force" in response.error or "extra" in response.error
        assert response.metadata["function"] == "my_func"
        assert set(response.metadata["ghost_arguments"]) == {"extra", "force"}

    def test_fix_hints(self) -> None:
        error = GhostArgumentError("test", {"unknown_arg"})
        response = handle_ghost_argument_error(error)

        assert len(response.fix_hints) >= 1
        assert any("unknown_arg" in hint for hint in response.fix_hints)


class TestHandlePolicyViolation:
    """Tests for handle_policy_violation function."""

    def test_basic_policy_violation(self) -> None:
        response = handle_policy_violation(
            func_name="delete_database",
            policy_name="STRICT",
            reason="Function not in allowed list",
        )

        assert response.success is False
        assert response.block_reason == BlockReason.POLICY_VIOLATION
        assert "delete_database" in response.error
        assert response.metadata["policy"] == "STRICT"


class TestHandleRateLimit:
    """Tests for handle_rate_limit function."""

    def test_basic_rate_limit(self) -> None:
        response = handle_rate_limit(
            func_name="api_call",
            limit="100/hour",
            reset_seconds=1800,
        )

        assert response.success is False
        assert response.block_reason == BlockReason.RATE_LIMIT
        assert "api_call" in response.error
        assert "100/hour" in response.fix_hints[0]
        assert "1800" in response.fix_hints[1]
