"""Configuration management for Agent-Airlock.

Supports configuration from:
1. Environment variables (highest priority)
2. Constructor arguments
3. TOML config files (airlock.toml)
"""

from __future__ import annotations

import os
import sys
import warnings
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from pydantic import ValidationError

    from .capabilities import CapabilityPolicy
    from .filesystem import FilesystemPolicy
    from .honeypot import HoneypotConfig
    from .network import NetworkPolicy

from .unknown_args import UnknownArgsMode, mode_from_strict_bool

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # pragma: no cover

logger = structlog.get_logger("agent-airlock.config")


@dataclass
class AirlockConfig:
    """Configuration for Airlock decorator behavior.

    Attributes:
        unknown_args: How to handle unknown/hallucinated arguments (V0.4.0+).
            - BLOCK: Reject the call with an error (production recommended)
            - STRIP_AND_LOG: Strip unknown args and emit audit event
            - STRIP_SILENT: Strip silently (dangerous, dev only)
        strict_mode: DEPRECATED (will be removed in v1.0.0). Use unknown_args instead.
            If True, maps to BLOCK. If False, maps to STRIP_AND_LOG.
        max_output_tokens: Maximum tokens in tool output before truncation. 0 = unlimited.
        max_output_chars: Maximum characters in output before truncation. 0 = unlimited.
        mask_pii: Auto-detect and mask PII (SSN, credit cards, emails) in output.
        mask_secrets: Auto-detect and mask API keys, passwords in output.
        sanitize_output: If True, apply output sanitization (PII masking, truncation).
        enable_audit_log: Write all tool calls to audit log file.
        audit_log_path: Path to audit log file.
        audit_otel_enabled: If True, export audit events to OpenTelemetry (V0.4.0+).
        audit_otel_endpoint: OpenTelemetry collector endpoint (V0.4.0+).
        audit_include_args_hash: Include SHA256 hash of args in audit (V0.4.0+).
        e2b_api_key: API key for E2B sandbox. Falls back to E2B_API_KEY env var.
        sandbox_timeout: Timeout in seconds for sandbox execution.
        sandbox_pool_size: Number of warm sandboxes to keep ready.
        on_validation_error: Callback invoked when Pydantic validation fails.
            Signature: (tool_name: str, error: ValidationError) -> None
        on_blocked: Callback invoked when a tool call is blocked by policy.
            Signature: (tool_name: str, reason: str, context: dict) -> None
        on_rate_limit: Callback invoked when rate limit is exceeded.
            Signature: (tool_name: str, retry_after_seconds: int) -> None
        filesystem_policy: Filesystem security policy for path validation.
            Validates paths against allowed roots, deny patterns, and symlink rules.
        network_policy: Network egress policy for blocking data exfiltration.
            Controls which hosts/ports can be accessed during tool execution.
        honeypot_config: Honeypot configuration for deception-based security.
            Returns fake data instead of errors to prevent agent exploitation.
        capability_policy: Capability gating policy for per-tool permissions (V0.4.0+).
    """

    # V0.4.0: New explicit unknown args handling
    unknown_args: UnknownArgsMode = UnknownArgsMode.STRIP_AND_LOG

    # DEPRECATED: Use unknown_args instead. Will be removed in v1.0.0
    strict_mode: bool = False
    _strict_mode_explicitly_set: bool = field(default=False, repr=False)

    max_output_tokens: int = 5000
    max_output_chars: int = 20000
    mask_pii: bool = True
    mask_secrets: bool = True
    sanitize_output: bool = True
    enable_audit_log: bool = True
    audit_log_path: Path = field(default_factory=lambda: Path("airlock_audit.json"))
    audit_otel_enabled: bool = False
    audit_otel_endpoint: str | None = None
    audit_include_args_hash: bool = True
    e2b_api_key: str | None = None
    sandbox_timeout: int = 60
    sandbox_pool_size: int = 2

    # Error recovery hooks - callbacks invoked on specific events
    on_validation_error: Callable[[str, ValidationError], None] | None = None
    on_blocked: Callable[[str, str, dict[str, Any]], None] | None = None
    on_rate_limit: Callable[[str, int], None] | None = None

    # V0.3.0 Security Policies
    filesystem_policy: FilesystemPolicy | None = None
    network_policy: NetworkPolicy | None = None
    honeypot_config: HoneypotConfig | None = None

    # V0.4.0 Capability Policy
    capability_policy: CapabilityPolicy | None = None

    def __post_init__(self) -> None:
        """Apply environment variable overrides after initialization."""
        # E2B API key priority: env var > constructor > config file
        if self.e2b_api_key is None:
            self.e2b_api_key = os.environ.get("E2B_API_KEY")

        # V0.4.0: Handle strict_mode deprecation
        # If strict_mode was explicitly set (not default), emit warning and convert
        if self._strict_mode_explicitly_set or self.strict_mode:
            warnings.warn(
                "strict_mode is deprecated and will be removed in v1.0.0. "
                "Use unknown_args=UnknownArgsMode.BLOCK instead. "
                "Migration: strict_mode=True -> unknown_args=UnknownArgsMode.BLOCK, "
                "strict_mode=False -> unknown_args=UnknownArgsMode.STRIP_AND_LOG",
                DeprecationWarning,
                stacklevel=2,
            )
            # Convert to new mode if still at default
            if self.unknown_args == UnknownArgsMode.STRIP_AND_LOG:
                self.unknown_args = mode_from_strict_bool(self.strict_mode)

        # Allow env var overrides for common settings
        if os.environ.get("AIRLOCK_UNKNOWN_ARGS"):
            env_mode = os.environ["AIRLOCK_UNKNOWN_ARGS"].lower()
            try:
                self.unknown_args = UnknownArgsMode(env_mode)
            except ValueError:
                logger.warning(
                    "invalid_unknown_args_env",
                    value=env_mode,
                    valid_values=[m.value for m in UnknownArgsMode],
                )

        # Legacy: AIRLOCK_STRICT_MODE still works but is deprecated
        if os.environ.get("AIRLOCK_STRICT_MODE"):
            warnings.warn(
                "AIRLOCK_STRICT_MODE environment variable is deprecated and will be removed "
                "in v1.0.0. Use AIRLOCK_UNKNOWN_ARGS=block instead.",
                DeprecationWarning,
                stacklevel=2,
            )
            self.strict_mode = os.environ["AIRLOCK_STRICT_MODE"].lower() in ("true", "1", "yes")
            self.unknown_args = mode_from_strict_bool(self.strict_mode)

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

        # Known configuration keys
        known_keys = {
            "strict_mode",  # DEPRECATED
            "unknown_args",  # V0.4.0
            "mask_pii",
            "mask_secrets",
            "sanitize_output",
            "enable_audit_log",
            "max_output_tokens",
            "max_output_chars",
            "sandbox_timeout",
            "sandbox_pool_size",
            "e2b_api_key",
            "audit_log_path",
            "audit_otel_enabled",  # V0.4.0
            "audit_otel_endpoint",  # V0.4.0
            "audit_include_args_hash",  # V0.4.0
            # V0.3.0 nested config sections
            "filesystem",
            "network",
            "honeypot",
            # V0.4.0 nested config sections
            "capabilities",
        }

        # SECURITY: Warn about unknown keys (likely typos)
        unknown_keys = set(data.keys()) - known_keys
        if unknown_keys:
            logger.warning(
                "unknown_config_keys",
                unknown_keys=sorted(unknown_keys),
                hint="These keys will be ignored. Check for typos.",
            )

        # Boolean fields
        for key in (
            "strict_mode",  # DEPRECATED
            "mask_pii",
            "mask_secrets",
            "sanitize_output",
            "enable_audit_log",
            "audit_otel_enabled",  # V0.4.0
            "audit_include_args_hash",  # V0.4.0
        ):
            if key in data:
                result[key] = bool(data[key])

        # V0.4.0: Parse unknown_args mode
        if "unknown_args" in data:
            try:
                result["unknown_args"] = UnknownArgsMode(str(data["unknown_args"]).lower())
            except ValueError:
                logger.warning(
                    "invalid_unknown_args_config",
                    value=data["unknown_args"],
                    valid_values=[m.value for m in UnknownArgsMode],
                    using_default="strip_and_log",
                )

        # Integer fields
        for key in (
            "max_output_tokens",
            "max_output_chars",
            "sandbox_timeout",
            "sandbox_pool_size",
        ):
            if key in data:
                result[key] = int(data[key])

        # String fields
        if "e2b_api_key" in data:
            result["e2b_api_key"] = str(data["e2b_api_key"])
        if "audit_otel_endpoint" in data:
            result["audit_otel_endpoint"] = str(data["audit_otel_endpoint"])

        # Path fields
        if "audit_log_path" in data:
            result["audit_log_path"] = Path(data["audit_log_path"])

        # V0.3.0 nested config sections
        if "filesystem" in data:
            result["filesystem_policy"] = _parse_filesystem_policy(data["filesystem"])

        if "network" in data:
            result["network_policy"] = _parse_network_policy(data["network"])

        if "honeypot" in data:
            result["honeypot_config"] = _parse_honeypot_config(data["honeypot"])

        # V0.4.0 nested config sections
        if "capabilities" in data:
            result["capability_policy"] = _parse_capability_policy(data["capabilities"])

        return result


def _parse_filesystem_policy(data: dict[str, Any]) -> FilesystemPolicy:
    """Parse filesystem policy from TOML data."""
    from .filesystem import FilesystemPolicy

    return FilesystemPolicy(
        allowed_roots=[Path(p) for p in data.get("allowed_roots", [])],
        allow_symlinks=bool(data.get("allow_symlinks", False)),
        deny_patterns=list(data.get("deny_patterns", [])),
        max_path_depth=int(data.get("max_path_depth", 20)),
    )


def _parse_network_policy(data: dict[str, Any]) -> NetworkPolicy:
    """Parse network policy from TOML data."""
    from .network import NetworkPolicy

    return NetworkPolicy(
        allow_egress=bool(data.get("allow_egress", True)),
        allowed_hosts=list(data.get("allowed_hosts", [])),
        allowed_ports=list(data.get("allowed_ports", [])),
        block_dns=bool(data.get("block_dns", False)),
    )


def _parse_honeypot_config(data: dict[str, Any]) -> HoneypotConfig:
    """Parse honeypot config from TOML data."""
    from .honeypot import BlockStrategy, HoneypotConfig

    strategy_str = data.get("strategy", "hard_block")
    strategy = BlockStrategy(strategy_str)

    return HoneypotConfig(
        strategy=strategy,
        fake_delay_ms=int(data.get("fake_delay_ms", 0)),
        log_honeypot_hits=bool(data.get("log_honeypot_hits", True)),
        include_tracking_id=bool(data.get("include_tracking_id", False)),
    )


def _parse_capability_policy(data: dict[str, Any]) -> CapabilityPolicy:
    """Parse capability policy from TOML data (V0.4.0)."""
    from .capabilities import Capability, CapabilityPolicy

    def parse_capabilities(caps: list[str]) -> Capability:
        """Parse list of capability strings into Capability flags."""
        result = Capability.NONE
        for cap_str in caps:
            try:
                cap = Capability[cap_str.upper()]
                result |= cap
            except KeyError:
                logger.warning("unknown_capability", capability=cap_str)
        return result

    granted = parse_capabilities(data.get("granted", []))
    denied = parse_capabilities(data.get("denied", []))
    require_sandbox_for = parse_capabilities(data.get("require_sandbox_for", ["DANGEROUS"]))

    return CapabilityPolicy(
        granted=granted,
        denied=denied,
        require_sandbox_for=require_sandbox_for,
    )


# Default configuration instance
DEFAULT_CONFIG = AirlockConfig()
