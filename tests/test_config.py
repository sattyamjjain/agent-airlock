"""Tests for the config module."""

from pathlib import Path
from tempfile import NamedTemporaryFile

import pytest

from agent_airlock.config import DEFAULT_CONFIG, AirlockConfig


class TestAirlockConfig:
    """Tests for AirlockConfig class."""

    def test_default_values(self) -> None:
        config = AirlockConfig()

        assert config.strict_mode is False
        assert config.max_output_tokens == 5000
        assert config.mask_pii is True
        assert config.mask_secrets is True
        assert config.enable_audit_log is True
        assert config.sandbox_timeout == 60
        assert config.sandbox_pool_size == 2

    def test_custom_values(self) -> None:
        config = AirlockConfig(
            strict_mode=True,
            max_output_tokens=1000,
            mask_pii=False,
            sandbox_timeout=120,
        )

        assert config.strict_mode is True
        assert config.max_output_tokens == 1000
        assert config.mask_pii is False
        assert config.sandbox_timeout == 120

    def test_e2b_api_key_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("E2B_API_KEY", "test-api-key-123")

        config = AirlockConfig()

        assert config.e2b_api_key == "test-api-key-123"

    def test_e2b_api_key_constructor_priority(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("E2B_API_KEY", "env-key")

        # Constructor should be used when provided
        config = AirlockConfig(e2b_api_key="constructor-key")

        # But env var takes priority in __post_init__ if not None
        # Let's check the actual behavior
        assert config.e2b_api_key == "constructor-key"

    def test_env_var_overrides(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AIRLOCK_STRICT_MODE", "true")
        monkeypatch.setenv("AIRLOCK_MAX_OUTPUT_TOKENS", "2000")

        config = AirlockConfig()

        assert config.strict_mode is True
        assert config.max_output_tokens == 2000

    def test_env_var_false_values(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AIRLOCK_STRICT_MODE", "false")

        config = AirlockConfig(strict_mode=True)  # Explicit True

        assert config.strict_mode is False  # Env var overrides


class TestConfigFromToml:
    """Tests for loading config from TOML files."""

    def test_from_toml(self) -> None:
        toml_content = """
[airlock]
strict_mode = true
max_output_tokens = 3000
mask_pii = false
sandbox_timeout = 90
"""
        with NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(toml_content)
            f.flush()

            config = AirlockConfig.from_toml(f.name)

            assert config.strict_mode is True
            assert config.max_output_tokens == 3000
            assert config.mask_pii is False
            assert config.sandbox_timeout == 90

            # Cleanup
            Path(f.name).unlink()

    def test_from_toml_missing_file(self) -> None:
        with pytest.raises(FileNotFoundError):
            AirlockConfig.from_toml("nonexistent.toml")

    def test_from_toml_if_exists_with_file(self) -> None:
        toml_content = """
[airlock]
strict_mode = true
"""
        with NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(toml_content)
            f.flush()

            config = AirlockConfig.from_toml_if_exists(f.name)

            assert config.strict_mode is True

            Path(f.name).unlink()

    def test_from_toml_if_exists_without_file(self) -> None:
        config = AirlockConfig.from_toml_if_exists("nonexistent.toml")

        # Should return default config
        assert config.strict_mode is False
        assert config.max_output_tokens == 5000


class TestDefaultConfig:
    """Tests for the DEFAULT_CONFIG singleton."""

    def test_default_config_exists(self) -> None:
        assert DEFAULT_CONFIG is not None
        assert isinstance(DEFAULT_CONFIG, AirlockConfig)

    def test_default_config_values(self) -> None:
        assert DEFAULT_CONFIG.strict_mode is False
        assert DEFAULT_CONFIG.max_output_tokens == 5000
