"""Configuration management for Agent-Airlock.

Supports configuration from:
1. Environment variables (highest priority)
2. Constructor arguments
3. TOML config files (airlock.toml)
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[import-not-found]


@dataclass
class AirlockConfig:
    """Configuration for Airlock decorator behavior.

    Attributes:
        strict_mode: If True, reject unknown arguments. If False, strip them silently.
        max_output_tokens: Maximum tokens in tool output before truncation. 0 = unlimited.
        max_output_chars: Maximum characters in output before truncation. 0 = unlimited.
        mask_pii: Auto-detect and mask PII (SSN, credit cards, emails) in output.
        mask_secrets: Auto-detect and mask API keys, passwords in output.
        sanitize_output: If True, apply output sanitization (PII masking, truncation).
        enable_audit_log: Write all tool calls to audit log file.
        audit_log_path: Path to audit log file.
        e2b_api_key: API key for E2B sandbox. Falls back to E2B_API_KEY env var.
        sandbox_timeout: Timeout in seconds for sandbox execution.
        sandbox_pool_size: Number of warm sandboxes to keep ready.
    """

    strict_mode: bool = False
    max_output_tokens: int = 5000
    max_output_chars: int = 20000
    mask_pii: bool = True
    mask_secrets: bool = True
    sanitize_output: bool = True
    enable_audit_log: bool = True
    audit_log_path: Path = field(default_factory=lambda: Path("airlock_audit.json"))
    e2b_api_key: str | None = None
    sandbox_timeout: int = 60
    sandbox_pool_size: int = 2

    def __post_init__(self) -> None:
        """Apply environment variable overrides after initialization."""
        # E2B API key priority: env var > constructor > config file
        if self.e2b_api_key is None:
            self.e2b_api_key = os.environ.get("E2B_API_KEY")

        # Allow env var overrides for common settings
        if os.environ.get("AIRLOCK_STRICT_MODE"):
            self.strict_mode = os.environ["AIRLOCK_STRICT_MODE"].lower() in ("true", "1", "yes")

        if os.environ.get("AIRLOCK_MAX_OUTPUT_TOKENS"):
            self.max_output_tokens = int(os.environ["AIRLOCK_MAX_OUTPUT_TOKENS"])

    @classmethod
    def from_toml(cls, path: Path | str = "airlock.toml") -> AirlockConfig:
        """Load configuration from a TOML file.

        Args:
            path: Path to the TOML configuration file.

        Returns:
            AirlockConfig instance with values from the file.

        Raises:
            FileNotFoundError: If the config file doesn't exist.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {path}")

        with open(path, "rb") as f:
            data = tomllib.load(f)

        airlock_config = data.get("airlock", {})
        return cls(**cls._parse_config(airlock_config))

    @classmethod
    def from_toml_if_exists(cls, path: Path | str = "airlock.toml") -> AirlockConfig:
        """Load configuration from TOML file if it exists, otherwise use defaults.

        Args:
            path: Path to the TOML configuration file.

        Returns:
            AirlockConfig instance.
        """
        path = Path(path)
        if path.exists():
            return cls.from_toml(path)
        return cls()

    @staticmethod
    def _parse_config(data: dict[str, Any]) -> dict[str, Any]:
        """Parse and validate config data from TOML."""
        result: dict[str, Any] = {}

        # Boolean fields
        for key in ("strict_mode", "mask_pii", "mask_secrets", "sanitize_output", "enable_audit_log"):
            if key in data:
                result[key] = bool(data[key])

        # Integer fields
        for key in ("max_output_tokens", "max_output_chars", "sandbox_timeout", "sandbox_pool_size"):
            if key in data:
                result[key] = int(data[key])

        # String fields
        if "e2b_api_key" in data:
            result["e2b_api_key"] = str(data["e2b_api_key"])

        # Path fields
        if "audit_log_path" in data:
            result["audit_log_path"] = Path(data["audit_log_path"])

        return result


# Default configuration instance
DEFAULT_CONFIG = AirlockConfig()
