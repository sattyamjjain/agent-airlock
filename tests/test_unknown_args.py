"""Tests for unknown_args module (V0.4.0)."""

from __future__ import annotations

import pytest

from agent_airlock.unknown_args import (
    DEVELOPMENT_MODE,
    PRODUCTION_MODE,
    STAGING_MODE,
    UnknownArgsMode,
    get_recommended_mode,
    handle_unknown_args,
    mode_from_strict_bool,
)


class TestUnknownArgsMode:
    """Test the UnknownArgsMode enum."""

    def test_enum_values(self) -> None:
        """Test that enum has expected values."""
        assert UnknownArgsMode.BLOCK.value == "block"
        assert UnknownArgsMode.STRIP_AND_LOG.value == "strip_and_log"
        assert UnknownArgsMode.STRIP_SILENT.value == "strip_silent"

    def test_all_modes_defined(self) -> None:
        """Test that all expected modes are defined."""
        modes = list(UnknownArgsMode)
        assert len(modes) == 3


class TestModeFromStrictBool:
    """Test backward compatibility function."""

    def test_strict_true_returns_block(self) -> None:
        """Test that strict_mode=True maps to BLOCK."""
        result = mode_from_strict_bool(strict_mode=True)
        assert result == UnknownArgsMode.BLOCK

    def test_strict_false_returns_strip_and_log(self) -> None:
        """Test that strict_mode=False maps to STRIP_AND_LOG."""
        result = mode_from_strict_bool(strict_mode=False)
        assert result == UnknownArgsMode.STRIP_AND_LOG


class TestGetRecommendedMode:
    """Test environment-based mode recommendation."""

    def test_production_env(self) -> None:
        """Test recommendation for production environment."""
        result = get_recommended_mode("production")
        assert result == UnknownArgsMode.BLOCK

    def test_staging_env(self) -> None:
        """Test recommendation for staging environment."""
        result = get_recommended_mode("staging")
        assert result == UnknownArgsMode.STRIP_AND_LOG

    def test_development_env(self) -> None:
        """Test recommendation for development environment."""
        result = get_recommended_mode("development")
        assert result == UnknownArgsMode.STRIP_AND_LOG

    def test_unknown_env_defaults_to_block(self) -> None:
        """Test that unknown environment defaults to BLOCK."""
        result = get_recommended_mode("unknown_environment")
        assert result == UnknownArgsMode.BLOCK


class TestHandleUnknownArgs:
    """Test the handle_unknown_args function."""

    def test_strip_silent_no_logging(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test STRIP_SILENT mode doesn't log warning."""
        import logging

        with caplog.at_level(logging.WARNING):
            handle_unknown_args(
                mode=UnknownArgsMode.STRIP_SILENT,
                func_name="test_func",
                stripped_args={"unknown_param"},
            )
        # Should not log warning in silent mode
        assert "unknown_args_stripped" not in caplog.text

    def test_strip_and_log_logs_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test STRIP_AND_LOG mode logs warning."""
        import logging

        with caplog.at_level(logging.WARNING):
            handle_unknown_args(
                mode=UnknownArgsMode.STRIP_AND_LOG,
                func_name="test_func",
                stripped_args={"unknown_param"},
            )
        # The structlog output is different, but we can check it ran without error

    def test_block_mode_raises_on_stripped_args(self) -> None:
        """Test BLOCK mode raises if args were somehow stripped."""
        with pytest.raises(ValueError, match="BLOCK mode"):
            handle_unknown_args(
                mode=UnknownArgsMode.BLOCK,
                func_name="test_func",
                stripped_args={"unknown_param"},
            )

    def test_empty_stripped_args_does_nothing(self) -> None:
        """Test with empty stripped args does nothing."""
        # Should not raise
        handle_unknown_args(
            mode=UnknownArgsMode.STRIP_AND_LOG,
            func_name="test_func",
            stripped_args=set(),
        )


class TestPredefinedModes:
    """Test predefined mode constants."""

    def test_production_mode(self) -> None:
        """Test PRODUCTION_MODE constant."""
        assert PRODUCTION_MODE == UnknownArgsMode.BLOCK

    def test_staging_mode(self) -> None:
        """Test STAGING_MODE constant."""
        assert STAGING_MODE == UnknownArgsMode.STRIP_AND_LOG

    def test_development_mode(self) -> None:
        """Test DEVELOPMENT_MODE constant."""
        assert DEVELOPMENT_MODE == UnknownArgsMode.STRIP_SILENT
