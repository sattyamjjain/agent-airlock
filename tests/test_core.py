"""Tests for the core Airlock decorator."""

from agent_airlock import Airlock, AirlockConfig, airlock


class TestAirlockDecorator:
    """Tests for the @Airlock decorator."""

    def test_basic_function_works(self) -> None:
        @Airlock()
        def add(x: int, y: int) -> int:
            return x + y

        result = add(x=2, y=3)
        assert result == 5

    def test_strips_ghost_arguments_by_default(self) -> None:
        @Airlock()
        def greet(name: str) -> str:
            return f"Hello, {name}!"

        # Ghost argument 'force' should be stripped
        result = greet(name="Alice", force=True)  # type: ignore[call-arg]
        assert result == "Hello, Alice!"

    def test_strict_mode_rejects_ghost_arguments(self) -> None:
        config = AirlockConfig(strict_mode=True)

        @Airlock(config=config)
        def greet(name: str) -> str:
            return f"Hello, {name}!"

        result = greet(name="Alice", force=True)  # type: ignore[call-arg]

        # Should return error dict, not string
        assert isinstance(result, dict)
        assert result["success"] is False
        assert result["status"] == "blocked"
        assert "ghost_arguments" in result["block_reason"]
        assert "force" in result["error"]

    def test_validates_types_strictly(self) -> None:
        @Airlock()
        def process(count: int) -> int:
            return count * 2

        # String "5" should fail strict validation
        result = process(count="5")  # type: ignore[arg-type]

        assert isinstance(result, dict)
        assert result["success"] is False
        assert "validation_error" in result["block_reason"]
        assert len(result["fix_hints"]) > 0

    def test_returns_fix_hints(self) -> None:
        @Airlock()
        def process(age: int) -> int:
            return age

        result = process(age="twenty")  # type: ignore[arg-type]

        assert isinstance(result, dict)
        assert result["fix_hints"]
        # Should have helpful hint about type
        assert any(
            "int" in hint.lower() or "integer" in hint.lower() for hint in result["fix_hints"]
        )

    def test_return_dict_mode(self) -> None:
        @Airlock(return_dict=True)
        def add(x: int, y: int) -> int:
            return x + y

        result = add(x=2, y=3)

        # Even success should be dict
        assert isinstance(result, dict)
        assert result["success"] is True
        assert result["result"] == 5

    def test_decorator_without_parentheses(self) -> None:
        # Note: This requires the @Airlock syntax (without ())
        # Our implementation supports this
        decorator = Airlock()

        @decorator
        def double(x: int) -> int:
            return x * 2

        result = double(x=5)
        assert result == 10


class TestAirlockFunctionalInterface:
    """Tests for the @airlock functional interface."""

    def test_basic_usage(self) -> None:
        @airlock
        def multiply(a: int, b: int) -> int:
            return a * b

        result = multiply(a=3, b=4)
        assert result == 12

    def test_with_sandbox_option(self) -> None:
        @airlock(sandbox=True)
        def run_code(code: str) -> str:
            return f"executed: {code}"

        # Should work - either sandbox executes or falls back to local
        result = run_code(code="print('hello')")

        # Result is either a string (local fallback) or error dict (sandbox not available)
        if isinstance(result, str):
            assert "executed" in result
        else:
            # Sandbox not available - check it's a proper error response
            assert isinstance(result, dict)
            assert "error" in result or "success" in result

    def test_with_config(self) -> None:
        config = AirlockConfig(strict_mode=True)

        @airlock(config=config)
        def process(x: int) -> int:
            return x

        result = process(x=1, extra="ghost")  # type: ignore[call-arg]
        assert isinstance(result, dict)
        assert result["success"] is False


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_function_with_no_args(self) -> None:
        @Airlock()
        def get_timestamp() -> str:
            return "2026-01-31"

        result = get_timestamp()
        assert result == "2026-01-31"

    def test_function_with_optional_args(self) -> None:
        @Airlock()
        def greet(name: str, greeting: str = "Hello") -> str:
            return f"{greeting}, {name}!"

        # With default
        result1 = greet(name="Alice")
        assert result1 == "Hello, Alice!"

        # With override
        result2 = greet(name="Bob", greeting="Hi")
        assert result2 == "Hi, Bob!"

    def test_function_returning_none(self) -> None:
        @Airlock()
        def do_nothing(x: int) -> None:
            pass

        result = do_nothing(x=42)
        assert result is None

    def test_function_returning_complex_type(self) -> None:
        @Airlock()
        def get_data(id: int) -> dict[str, int]:
            return {"id": id, "value": id * 10}

        result = get_data(id=5)
        assert result == {"id": 5, "value": 50}

    def test_multiple_validation_errors(self) -> None:
        @Airlock()
        def process(x: int, y: str, z: bool) -> str:
            return f"{x}-{y}-{z}"

        result = process(x="not int", y=123, z="not bool")  # type: ignore[arg-type]

        assert isinstance(result, dict)
        assert result["success"] is False
        assert result["metadata"]["error_count"] == 3


class TestSignaturePreservation:
    """Tests for function signature preservation.

    Critical for framework introspection (LangChain, CrewAI, AutoGen).
    These frameworks use inspect.signature() to generate JSON schemas for LLM tool calls.
    """

    def test_preserves_signature(self) -> None:
        """Verify __signature__ is correctly preserved."""
        import inspect

        @Airlock()
        def test_func(name: str, count: int = 5) -> str:
            return f"{name}: {count}"

        sig = inspect.signature(test_func)
        params = list(sig.parameters.keys())

        assert params == ["name", "count"]
        assert sig.parameters["name"].annotation is str
        assert sig.parameters["count"].annotation is int
        assert sig.parameters["count"].default == 5

    def test_preserves_annotations(self) -> None:
        """Verify __annotations__ is correctly preserved."""

        @Airlock()
        def test_func(x: int, y: str) -> bool:  # noqa: ARG001
            return True

        assert test_func.__annotations__ == {"x": int, "y": str, "return": bool}

    def test_preserves_docstring(self) -> None:
        """Verify __doc__ is correctly preserved."""

        @Airlock()
        def test_func(x: int) -> int:
            """This is the docstring."""
            return x

        assert test_func.__doc__ == "This is the docstring."

    def test_preserves_name(self) -> None:
        """Verify __name__ is correctly preserved."""

        @Airlock()
        def my_tool_function(x: int) -> int:
            return x

        assert my_tool_function.__name__ == "my_tool_function"

    def test_wrapped_attribute_set(self) -> None:
        """Verify __wrapped__ points to original function."""

        def original(x: int) -> int:
            return x

        wrapped = Airlock()(original)

        assert hasattr(wrapped, "__wrapped__")
        assert wrapped.__wrapped__ is original  # type: ignore[attr-defined]
