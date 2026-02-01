"""Honeypot and deception protocol module for Agent-Airlock.

Provides strategies for handling blocked tool calls beyond simple rejection.
Instead of returning an error that may cause agent loops or expose security
policies, honeypots can return plausible fake data.

Use Case: Agent tries to read `.env` → return `API_KEY=mickey_mouse_123`
instead of an error, preventing the agent from knowing access was blocked.
"""

from __future__ import annotations

import asyncio
import hashlib
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol

import structlog

logger = structlog.get_logger("agent-airlock.honeypot")


class BlockStrategy(str, Enum):
    """Strategies for handling blocked tool calls.

    Attributes:
        HARD_BLOCK: Return an error response (current default behavior).
                   Agent knows the call was blocked and may retry or escalate.
        SOFT_BLOCK: Log the violation but allow the call to proceed.
                   Useful for monitoring without disrupting agent operation.
        HONEYPOT: Return fake success data instead of an error.
                 Agent doesn't know the call was blocked; prevents loops.
    """

    HARD_BLOCK = "hard_block"
    SOFT_BLOCK = "soft_block"
    HONEYPOT = "honeypot"


class HoneypotDataGenerator(Protocol):
    """Protocol for custom honeypot data generators.

    Implement this protocol to provide domain-specific fake data.

    Example:
        class MyGenerator:
            def generate(self, tool_name: str, args: dict, return_type: type) -> Any:
                if tool_name == "read_api_key":
                    return "sk-fake-" + "x" * 48
                return {"status": "success"}
    """

    def generate(
        self,
        tool_name: str,
        args: dict[str, Any],
        return_type: type[Any] | None,
    ) -> Any:
        """Generate fake data for a blocked tool call.

        Args:
            tool_name: Name of the blocked tool.
            args: Arguments that were passed to the tool.
            return_type: Expected return type (may be None if unknown).

        Returns:
            Fake data appropriate for the tool.
        """
        ...


class DefaultHoneypotGenerator:
    """Default honeypot data generator with sensible fake responses.

    Generates plausible fake data based on tool name patterns and return types.
    """

    # Common fake values for different scenarios
    FAKE_API_KEYS = [
        "sk-fake-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
        "test_api_key_do_not_use_in_production_12345678",
        "development_key_placeholder_00000000000000000",
    ]

    FAKE_CREDENTIALS = {
        "username": "test_user",
        "password": "P@ssw0rd123!",  # nosec B105 - intentionally fake
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake.token",
    }

    FAKE_ENV_CONTENT = """# Fake environment configuration
APP_ENV=development
DEBUG=false
API_KEY=mickey_mouse_123
DATABASE_URL=postgres://user:pass@localhost/testdb
SECRET_KEY=not-a-real-secret-key-for-testing-only
"""

    def generate(
        self,
        tool_name: str,
        args: dict[str, Any],
        return_type: type[Any] | None,
    ) -> Any:
        """Generate fake data based on tool name and context.

        Args:
            tool_name: Name of the blocked tool.
            args: Arguments that were passed to the tool.
            return_type: Expected return type (may be None if unknown).

        Returns:
            Plausible fake data.
        """
        tool_lower = tool_name.lower()

        # File reading operations
        if any(x in tool_lower for x in ["read_file", "get_file", "load_file", "cat"]):
            return self._fake_file_content(args)

        # API key / secret retrieval
        if any(x in tool_lower for x in ["api_key", "secret", "credential", "token", "password"]):
            return self._fake_credential(tool_lower)

        # Database queries
        if any(x in tool_lower for x in ["query", "select", "fetch", "get_record"]):
            return self._fake_query_result()

        # List operations
        if any(x in tool_lower for x in ["list", "ls", "dir", "enumerate"]):
            return self._fake_list_result()

        # Status / health checks
        if any(x in tool_lower for x in ["status", "health", "ping", "check"]):
            return {"status": "ok", "healthy": True}

        # Default based on return type
        return self._fake_by_return_type(return_type)

    def _fake_file_content(self, args: dict[str, Any]) -> str:
        """Generate fake file content based on filename."""
        filename = str(args.get("filename", args.get("path", args.get("file", ""))))
        filename_lower = filename.lower()

        if ".env" in filename_lower:
            return self.FAKE_ENV_CONTENT

        if any(ext in filename_lower for ext in [".json", ".yaml", ".yml"]):
            return '{"config": "development", "debug": false}'

        if any(ext in filename_lower for ext in [".pem", ".key", ".crt"]):
            return (
                "-----BEGIN FAKE CERTIFICATE-----\n"
                "MIIBkTCB+wIJAKHBf...\n"
                "-----END FAKE CERTIFICATE-----\n"
            )

        if any(ext in filename_lower for ext in [".csv"]):
            return "id,name,value\n1,test,100\n2,sample,200\n"

        # Generic text content
        return f"# Placeholder content for {filename}\nThis file is not accessible."

    def _fake_credential(self, tool_name: str) -> str | dict[str, str]:
        """Generate fake credential data."""
        if "password" in tool_name:
            return self.FAKE_CREDENTIALS["password"]
        if "token" in tool_name:
            return self.FAKE_CREDENTIALS["token"]
        if "api_key" in tool_name or "apikey" in tool_name:
            return random.choice(self.FAKE_API_KEYS)
        return self.FAKE_CREDENTIALS

    def _fake_query_result(self) -> list[dict[str, Any]]:
        """Generate fake database query result."""
        return [
            {"id": 1, "name": "Test Record 1", "created_at": "2026-01-01T00:00:00Z"},
            {"id": 2, "name": "Test Record 2", "created_at": "2026-01-02T00:00:00Z"},
        ]

    def _fake_list_result(self) -> list[str]:
        """Generate fake directory/list result."""
        return ["file1.txt", "file2.txt", "data/", "README.md"]

    def _fake_by_return_type(self, return_type: type[Any] | None) -> Any:
        """Generate fake data based on return type."""
        if return_type is None:
            return {"status": "success", "message": "Operation completed"}

        if return_type is str:
            return "Operation completed successfully"
        if return_type is int:
            return 0
        if return_type is float:
            return 0.0
        if return_type is bool:
            return True
        if return_type is list:
            return []
        if return_type is dict:
            return {}

        return {"status": "success"}


@dataclass
class HoneypotConfig:
    """Configuration for honeypot behavior.

    Attributes:
        strategy: How to handle blocked calls (HARD_BLOCK, SOFT_BLOCK, HONEYPOT).
        generator: Custom data generator (uses DefaultHoneypotGenerator if None).
        fake_delay_ms: Artificial delay in milliseconds to simulate real execution.
                      Helps hide the fact that a call was intercepted.
        log_honeypot_hits: If True, log when honeypot responses are returned.
        include_tracking_id: If True, embed a unique ID in fake responses for
                            forensic tracking. The ID is hashed to avoid detection.
    """

    strategy: BlockStrategy = BlockStrategy.HARD_BLOCK
    generator: HoneypotDataGenerator | None = None
    fake_delay_ms: int = 0
    log_honeypot_hits: bool = True
    include_tracking_id: bool = False

    # Internal tracking (not configurable)
    _hit_counter: int = field(default=0, repr=False)

    def get_generator(self) -> HoneypotDataGenerator:
        """Get the configured generator or default."""
        if self.generator is not None:
            return self.generator
        return DefaultHoneypotGenerator()


def _generate_tracking_id(tool_name: str, args: dict[str, Any]) -> str:
    """Generate a unique tracking ID for honeypot forensics.

    The ID is a truncated SHA256 hash that can be embedded in fake data
    without being obviously identifiable as a tracking mechanism.
    """
    data = f"{tool_name}:{sorted(args.items())}:{time.time()}"
    return hashlib.sha256(data.encode()).hexdigest()[:12]


def create_honeypot_response(
    tool_name: str,
    args: dict[str, Any],
    config: HoneypotConfig,
    return_type: type[Any] | None = None,
    block_reason: str | None = None,
) -> Any:
    """Create a honeypot response for a blocked tool call.

    Args:
        tool_name: Name of the blocked tool.
        args: Arguments that were passed to the tool.
        config: Honeypot configuration.
        return_type: Expected return type (for type-appropriate fakes).
        block_reason: Why the call was blocked (for logging).

    Returns:
        Fake data appropriate for the tool, or None if not using honeypot strategy.
    """
    if config.strategy != BlockStrategy.HONEYPOT:
        return None

    # Apply artificial delay if configured
    if config.fake_delay_ms > 0:
        time.sleep(config.fake_delay_ms / 1000.0)

    # Generate fake data
    generator = config.get_generator()
    fake_data = generator.generate(tool_name, args, return_type)

    # Add tracking ID if configured
    if config.include_tracking_id:
        tracking_id = _generate_tracking_id(tool_name, args)
        if isinstance(fake_data, dict):
            # Embed as a plausible field name
            fake_data["_request_id"] = tracking_id
        elif isinstance(fake_data, str):
            # Append as a comment-like suffix that won't break parsing
            fake_data = f"{fake_data}\n# rid:{tracking_id}"

    # Log the honeypot hit
    if config.log_honeypot_hits:
        config._hit_counter += 1
        logger.info(
            "honeypot_response_generated",
            tool_name=tool_name,
            block_reason=block_reason,
            hit_number=config._hit_counter,
            fake_data_type=type(fake_data).__name__,
        )

    return fake_data


async def create_honeypot_response_async(
    tool_name: str,
    args: dict[str, Any],
    config: HoneypotConfig,
    return_type: type[Any] | None = None,
    block_reason: str | None = None,
) -> Any:
    """Async version of create_honeypot_response.

    Use this in async contexts to avoid blocking the event loop with time.sleep().

    Args:
        tool_name: Name of the blocked tool.
        args: Arguments that were passed to the tool.
        config: Honeypot configuration.
        return_type: Expected return type (for type-appropriate fakes).
        block_reason: Why the call was blocked (for logging).

    Returns:
        Fake data appropriate for the tool, or None if not using honeypot strategy.
    """
    if config.strategy != BlockStrategy.HONEYPOT:
        return None

    # Apply artificial delay if configured (non-blocking)
    if config.fake_delay_ms > 0:
        await asyncio.sleep(config.fake_delay_ms / 1000.0)

    # Generate fake data
    generator = config.get_generator()
    fake_data = generator.generate(tool_name, args, return_type)

    # Add tracking ID if configured
    if config.include_tracking_id:
        tracking_id = _generate_tracking_id(tool_name, args)
        if isinstance(fake_data, dict):
            fake_data["_request_id"] = tracking_id
        elif isinstance(fake_data, str):
            fake_data = f"{fake_data}\n# rid:{tracking_id}"

    # Log the honeypot hit
    if config.log_honeypot_hits:
        config._hit_counter += 1
        logger.info(
            "honeypot_response_generated",
            tool_name=tool_name,
            block_reason=block_reason,
            hit_number=config._hit_counter,
            fake_data_type=type(fake_data).__name__,
        )

    return fake_data


def should_use_honeypot(config: HoneypotConfig | None) -> bool:
    """Check if honeypot strategy should be used."""
    return config is not None and config.strategy == BlockStrategy.HONEYPOT


def should_soft_block(config: HoneypotConfig | None) -> bool:
    """Check if soft block strategy should be used (log only, allow through)."""
    return config is not None and config.strategy == BlockStrategy.SOFT_BLOCK


# Predefined configurations for common use cases

STRICT_HONEYPOT_CONFIG = HoneypotConfig(
    strategy=BlockStrategy.HONEYPOT,
    fake_delay_ms=50,  # Small delay to look realistic
    log_honeypot_hits=True,
    include_tracking_id=True,
)
"""Aggressive honeypot configuration for high-security environments."""


MONITORING_CONFIG = HoneypotConfig(
    strategy=BlockStrategy.SOFT_BLOCK,
    log_honeypot_hits=True,
)
"""Soft-block configuration for monitoring without disruption."""


TRANSPARENT_CONFIG = HoneypotConfig(
    strategy=BlockStrategy.HARD_BLOCK,
    log_honeypot_hits=True,
)
"""Standard hard-block configuration (default behavior)."""
