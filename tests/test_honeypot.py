"""Tests for the honeypot deception module (V0.3.0)."""

from __future__ import annotations

import time
from typing import Any

from agent_airlock.honeypot import (
    MONITORING_CONFIG,
    STRICT_HONEYPOT_CONFIG,
    TRANSPARENT_CONFIG,
    BlockStrategy,
    DefaultHoneypotGenerator,
    HoneypotConfig,
    create_honeypot_response,
    should_soft_block,
    should_use_honeypot,
)


class TestBlockStrategy:
    """Tests for BlockStrategy enum."""

    def test_hard_block_value(self) -> None:
        """Test HARD_BLOCK strategy value."""
        assert BlockStrategy.HARD_BLOCK.value == "hard_block"

    def test_soft_block_value(self) -> None:
        """Test SOFT_BLOCK strategy value."""
        assert BlockStrategy.SOFT_BLOCK.value == "soft_block"

    def test_honeypot_value(self) -> None:
        """Test HONEYPOT strategy value."""
        assert BlockStrategy.HONEYPOT.value == "honeypot"

    def test_from_string(self) -> None:
        """Test creating strategy from string."""
        assert BlockStrategy("hard_block") == BlockStrategy.HARD_BLOCK
        assert BlockStrategy("soft_block") == BlockStrategy.SOFT_BLOCK
        assert BlockStrategy("honeypot") == BlockStrategy.HONEYPOT


class TestHoneypotConfig:
    """Tests for HoneypotConfig dataclass."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = HoneypotConfig()
        assert config.strategy == BlockStrategy.HARD_BLOCK
        assert config.generator is None
        assert config.fake_delay_ms == 0
        assert config.log_honeypot_hits is True
        assert config.include_tracking_id is False

    def test_honeypot_strategy_config(self) -> None:
        """Test configuration with honeypot strategy."""
        config = HoneypotConfig(
            strategy=BlockStrategy.HONEYPOT,
            fake_delay_ms=100,
        )
        assert config.strategy == BlockStrategy.HONEYPOT
        assert config.fake_delay_ms == 100

    def test_custom_generator(self) -> None:
        """Test configuration with custom generator."""

        class CustomGenerator:
            def generate(
                self,
                _tool_name: str,
                _args: dict[str, Any],
                _return_type: type[Any] | None,
            ) -> str:
                return "custom_fake_data"

        generator = CustomGenerator()
        config = HoneypotConfig(
            strategy=BlockStrategy.HONEYPOT,
            generator=generator,
        )

        assert config.get_generator() is generator

    def test_get_default_generator(self) -> None:
        """Test get_generator returns default when none configured."""
        config = HoneypotConfig()
        generator = config.get_generator()
        assert isinstance(generator, DefaultHoneypotGenerator)

    def test_predefined_strict_config(self) -> None:
        """Test predefined STRICT_HONEYPOT_CONFIG."""
        config = STRICT_HONEYPOT_CONFIG
        assert config.strategy == BlockStrategy.HONEYPOT
        assert config.fake_delay_ms == 50
        assert config.include_tracking_id is True

    def test_predefined_monitoring_config(self) -> None:
        """Test predefined MONITORING_CONFIG."""
        config = MONITORING_CONFIG
        assert config.strategy == BlockStrategy.SOFT_BLOCK
        assert config.log_honeypot_hits is True

    def test_predefined_transparent_config(self) -> None:
        """Test predefined TRANSPARENT_CONFIG."""
        config = TRANSPARENT_CONFIG
        assert config.strategy == BlockStrategy.HARD_BLOCK


class TestDefaultHoneypotGenerator:
    """Tests for DefaultHoneypotGenerator."""

    def test_file_reading_env_file(self) -> None:
        """Test fake content for .env files."""
        generator = DefaultHoneypotGenerator()
        result = generator.generate(
            "read_file",
            {"filename": "/app/.env"},
            str,
        )

        assert isinstance(result, str)
        assert "API_KEY" in result or "SECRET" in result.upper()

    def test_file_reading_json_file(self) -> None:
        """Test fake content for JSON files."""
        generator = DefaultHoneypotGenerator()
        result = generator.generate(
            "load_file",
            {"path": "config.json"},
            str,
        )

        assert isinstance(result, str)
        # Should look like JSON
        assert "{" in result or "config" in result.lower()

    def test_file_reading_pem_file(self) -> None:
        """Test fake content for PEM files."""
        generator = DefaultHoneypotGenerator()
        result = generator.generate(
            "get_file",
            {"file": "private.pem"},
            str,
        )

        assert isinstance(result, str)
        assert "CERTIFICATE" in result or "FAKE" in result

    def test_api_key_retrieval(self) -> None:
        """Test fake API key generation."""
        generator = DefaultHoneypotGenerator()
        result = generator.generate(
            "get_api_key",
            {},
            str,
        )

        assert isinstance(result, str)
        # Should look like an API key or credential
        result_lower = result.lower()
        assert any(
            x in result_lower
            for x in ["sk-", "test", "fake", "api", "key", "development", "placeholder"]
        )

    def test_password_retrieval(self) -> None:
        """Test fake password generation."""
        generator = DefaultHoneypotGenerator()
        result = generator.generate(
            "get_password",
            {},
            str,
        )

        assert isinstance(result, str)

    def test_database_query(self) -> None:
        """Test fake database query result."""
        generator = DefaultHoneypotGenerator()
        result = generator.generate(
            "query_database",
            {"sql": "SELECT * FROM users"},
            list,
        )

        assert isinstance(result, list)
        assert len(result) > 0
        assert "id" in result[0]

    def test_list_operation(self) -> None:
        """Test fake list/directory result."""
        generator = DefaultHoneypotGenerator()
        result = generator.generate(
            "list_files",
            {"path": "/app"},
            list,
        )

        assert isinstance(result, list)
        assert len(result) > 0

    def test_status_check(self) -> None:
        """Test fake status/health check."""
        generator = DefaultHoneypotGenerator()
        result = generator.generate(
            "health_check",
            {},
            dict,
        )

        assert isinstance(result, dict)
        assert result.get("status") == "ok" or result.get("healthy") is True

    def test_unknown_tool_string_return(self) -> None:
        """Test fallback for unknown tool with string return type."""
        generator = DefaultHoneypotGenerator()
        result = generator.generate(
            "unknown_tool",
            {},
            str,
        )

        assert isinstance(result, str)

    def test_unknown_tool_int_return(self) -> None:
        """Test fallback for unknown tool with int return type."""
        generator = DefaultHoneypotGenerator()
        result = generator.generate(
            "unknown_tool",
            {},
            int,
        )

        assert isinstance(result, int)
        assert result == 0

    def test_unknown_tool_bool_return(self) -> None:
        """Test fallback for unknown tool with bool return type."""
        generator = DefaultHoneypotGenerator()
        result = generator.generate(
            "unknown_tool",
            {},
            bool,
        )

        assert isinstance(result, bool)
        assert result is True

    def test_unknown_tool_no_return_type(self) -> None:
        """Test fallback for unknown tool with no return type."""
        generator = DefaultHoneypotGenerator()
        result = generator.generate(
            "unknown_tool",
            {},
            None,
        )

        assert isinstance(result, dict)
        assert "status" in result


class TestCreateHoneypotResponse:
    """Tests for create_honeypot_response function."""

    def test_honeypot_strategy_returns_fake_data(self) -> None:
        """Test that honeypot strategy returns fake data."""
        config = HoneypotConfig(strategy=BlockStrategy.HONEYPOT)
        result = create_honeypot_response(
            "read_file",
            {"filename": ".env"},
            config,
            str,
            "policy_violation",
        )

        assert result is not None
        assert isinstance(result, str)

    def test_hard_block_returns_none(self) -> None:
        """Test that hard block strategy returns None."""
        config = HoneypotConfig(strategy=BlockStrategy.HARD_BLOCK)
        result = create_honeypot_response(
            "read_file",
            {"filename": ".env"},
            config,
        )

        assert result is None

    def test_soft_block_returns_none(self) -> None:
        """Test that soft block strategy returns None."""
        config = HoneypotConfig(strategy=BlockStrategy.SOFT_BLOCK)
        result = create_honeypot_response(
            "read_file",
            {"filename": ".env"},
            config,
        )

        assert result is None

    def test_fake_delay_applied(self) -> None:
        """Test that fake delay is applied."""
        config = HoneypotConfig(
            strategy=BlockStrategy.HONEYPOT,
            fake_delay_ms=100,
        )

        start = time.time()
        create_honeypot_response("tool", {}, config)
        elapsed = time.time() - start

        # Should have delayed at least 100ms
        assert elapsed >= 0.1

    def test_tracking_id_in_dict_response(self) -> None:
        """Test tracking ID is added to dict responses."""
        config = HoneypotConfig(
            strategy=BlockStrategy.HONEYPOT,
            include_tracking_id=True,
        )

        result = create_honeypot_response(
            "health_check",
            {},
            config,
            dict,
        )

        assert isinstance(result, dict)
        assert "_request_id" in result

    def test_tracking_id_in_string_response(self) -> None:
        """Test tracking ID is added to string responses."""
        config = HoneypotConfig(
            strategy=BlockStrategy.HONEYPOT,
            include_tracking_id=True,
        )

        result = create_honeypot_response(
            "read_file",
            {"filename": "test.txt"},
            config,
            str,
        )

        assert isinstance(result, str)
        assert "rid:" in result

    def test_hit_counter_increments(self) -> None:
        """Test that hit counter increments."""
        config = HoneypotConfig(
            strategy=BlockStrategy.HONEYPOT,
            log_honeypot_hits=True,
        )

        initial_count = config._hit_counter

        create_honeypot_response("tool1", {}, config)
        assert config._hit_counter == initial_count + 1

        create_honeypot_response("tool2", {}, config)
        assert config._hit_counter == initial_count + 2

    def test_custom_generator_used(self) -> None:
        """Test that custom generator is used when provided."""

        class CustomGenerator:
            def generate(
                self,
                _tool_name: str,
                _args: dict[str, Any],
                _return_type: type[Any] | None,
            ) -> str:
                return "CUSTOM_RESPONSE"

        config = HoneypotConfig(
            strategy=BlockStrategy.HONEYPOT,
            generator=CustomGenerator(),
        )

        result = create_honeypot_response("any_tool", {}, config, str)
        assert result == "CUSTOM_RESPONSE"


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_should_use_honeypot_true(self) -> None:
        """Test should_use_honeypot returns True for honeypot strategy."""
        config = HoneypotConfig(strategy=BlockStrategy.HONEYPOT)
        assert should_use_honeypot(config) is True

    def test_should_use_honeypot_false_hard_block(self) -> None:
        """Test should_use_honeypot returns False for hard block."""
        config = HoneypotConfig(strategy=BlockStrategy.HARD_BLOCK)
        assert should_use_honeypot(config) is False

    def test_should_use_honeypot_none_config(self) -> None:
        """Test should_use_honeypot with None config."""
        assert should_use_honeypot(None) is False

    def test_should_soft_block_true(self) -> None:
        """Test should_soft_block returns True for soft block strategy."""
        config = HoneypotConfig(strategy=BlockStrategy.SOFT_BLOCK)
        assert should_soft_block(config) is True

    def test_should_soft_block_false_hard_block(self) -> None:
        """Test should_soft_block returns False for hard block."""
        config = HoneypotConfig(strategy=BlockStrategy.HARD_BLOCK)
        assert should_soft_block(config) is False

    def test_should_soft_block_none_config(self) -> None:
        """Test should_soft_block with None config."""
        assert should_soft_block(None) is False


class TestHoneypotDataGeneratorProtocol:
    """Tests for HoneypotDataGenerator protocol compliance."""

    def test_protocol_implementation(self) -> None:
        """Test that classes implementing the protocol work correctly."""

        class MyGenerator:
            def generate(
                self,
                tool_name: str,
                _args: dict[str, Any],
                _return_type: type[Any] | None,
            ) -> dict[str, str]:
                return {"tool": tool_name, "fake": "data"}

        generator = MyGenerator()
        result = generator.generate("test_tool", {"arg": "value"}, dict)

        assert result["tool"] == "test_tool"
        assert result["fake"] == "data"


class TestEdgeCases:
    """Tests for edge cases."""

    def test_empty_args(self) -> None:
        """Test with empty arguments."""
        config = HoneypotConfig(strategy=BlockStrategy.HONEYPOT)
        result = create_honeypot_response("tool", {}, config)
        assert result is not None

    def test_complex_args(self) -> None:
        """Test with complex arguments."""
        config = HoneypotConfig(strategy=BlockStrategy.HONEYPOT)
        result = create_honeypot_response(
            "complex_tool",
            {
                "nested": {"key": "value"},
                "list": [1, 2, 3],
                "number": 42,
            },
            config,
        )
        assert result is not None

    def test_generator_file_patterns(self) -> None:
        """Test generator handles various file patterns."""
        generator = DefaultHoneypotGenerator()

        # CSV file
        result = generator.generate("read", {"path": "data.csv"}, str)
        assert isinstance(result, str)

        # Generic text file
        result = generator.generate("load", {"file": "notes.txt"}, str)
        assert isinstance(result, str)

    def test_zero_delay(self) -> None:
        """Test with zero delay."""
        config = HoneypotConfig(
            strategy=BlockStrategy.HONEYPOT,
            fake_delay_ms=0,
        )

        start = time.time()
        create_honeypot_response("tool", {}, config)
        elapsed = time.time() - start

        # Should be very fast with no delay
        assert elapsed < 0.1

    def test_no_logging(self) -> None:
        """Test with logging disabled."""
        config = HoneypotConfig(
            strategy=BlockStrategy.HONEYPOT,
            log_honeypot_hits=False,
        )

        # Should not raise even with logging disabled
        result = create_honeypot_response("tool", {}, config)
        assert result is not None

    def test_all_return_types(self) -> None:
        """Test handling of all basic return types."""
        generator = DefaultHoneypotGenerator()

        # Test all types from _fake_by_return_type
        assert isinstance(generator._fake_by_return_type(str), str)
        assert isinstance(generator._fake_by_return_type(int), int)
        assert isinstance(generator._fake_by_return_type(float), float)
        assert isinstance(generator._fake_by_return_type(bool), bool)
        assert isinstance(generator._fake_by_return_type(list), list)
        assert isinstance(generator._fake_by_return_type(dict), dict)
