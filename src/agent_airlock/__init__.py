"""Agent-Airlock: The Pydantic-based Firewall for MCP Servers.

Stops hallucinated tool calls, validates schemas, and sandboxes dangerous operations.

Example:
    from agent_airlock import Airlock, AirlockConfig

    @Airlock()
    def read_file(filename: str) -> str:
        with open(filename) as f:
            return f.read()

    @Airlock(sandbox=True)
    def run_code(code: str) -> str:
        exec(code)
        return "executed"
"""

from typing import TYPE_CHECKING

from .audit import AuditLogger, AuditRecord, get_audit_logger
from .config import DEFAULT_CONFIG, AirlockConfig
from .context import (
    AirlockContext,
    ContextExtractor,
    create_context_from_args,
    get_current_context,
    reset_context,
    set_current_context,
)
from .conversation import (
    ConversationConstraints,
    ConversationState,
    ConversationTracker,
    ToolCall,
    get_conversation_tracker,
    reset_conversation_tracker,
)
from .core import Airlock, SandboxExecutionError, SandboxUnavailableError, airlock
from .policy import (
    BUSINESS_HOURS_POLICY,
    PERMISSIVE_POLICY,
    READ_ONLY_POLICY,
    STRICT_POLICY,
    AgentIdentity,
    PolicyViolation,
    RateLimit,
    SecurityPolicy,
    TimeWindow,
    ViolationType,
)
from .sanitizer import (
    MaskingStrategy,
    SanitizationConfig,
    SanitizationResult,
    SensitiveDataType,
    WorkspacePIIConfig,
    detect_sensitive_data,
    mask_sensitive_data,
    sanitize_output,
    sanitize_with_workspace_config,
)
from .self_heal import AirlockResponse, BlockReason
from .streaming import (
    StreamingAirlock,
    StreamingState,
    create_streaming_wrapper,
    is_async_generator_function,
    is_generator_function,
)
from .validator import GhostArgumentError

__version__ = "0.1.5"

__all__ = [
    # Core
    "Airlock",
    "airlock",
    # Config
    "AirlockConfig",
    "DEFAULT_CONFIG",
    # Policy
    "SecurityPolicy",
    "PolicyViolation",
    "ViolationType",
    "AgentIdentity",
    "TimeWindow",
    "RateLimit",
    # Predefined policies
    "PERMISSIVE_POLICY",
    "STRICT_POLICY",
    "READ_ONLY_POLICY",
    "BUSINESS_HOURS_POLICY",
    # Sanitization
    "sanitize_output",
    "sanitize_with_workspace_config",
    "detect_sensitive_data",
    "mask_sensitive_data",
    "SanitizationResult",
    "SanitizationConfig",
    "SensitiveDataType",
    "MaskingStrategy",
    "WorkspacePIIConfig",
    # Response types
    "AirlockResponse",
    "BlockReason",
    # Exceptions
    "GhostArgumentError",
    "SandboxExecutionError",
    "SandboxUnavailableError",
    # Audit
    "AuditLogger",
    "AuditRecord",
    "get_audit_logger",
    # Context
    "AirlockContext",
    "ContextExtractor",
    "get_current_context",
    "set_current_context",
    "reset_context",
    "create_context_from_args",
    # Streaming
    "StreamingAirlock",
    "StreamingState",
    "create_streaming_wrapper",
    "is_generator_function",
    "is_async_generator_function",
    # Conversation
    "ConversationTracker",
    "ConversationState",
    "ConversationConstraints",
    "ToolCall",
    "get_conversation_tracker",
    "reset_conversation_tracker",
    # Version
    "__version__",
]


def get_sandbox_pool(config: AirlockConfig | None = None) -> "SandboxPool":
    """Get the global sandbox pool for E2B execution.

    Requires: pip install agent-airlock[sandbox]
    """
    from .sandbox import SandboxPool  # noqa: F401
    from .sandbox import get_sandbox_pool as _get_pool

    return _get_pool(config)


def get_mcp_airlock() -> type:
    """Get the MCPAirlock class for FastMCP integration.

    Requires: pip install agent-airlock[mcp]

    Returns:
        MCPAirlock class.
    """
    from .mcp import MCPAirlock

    return MCPAirlock


def get_secure_tool() -> "Callable[..., object]":
    """Get the secure_tool decorator for FastMCP integration.

    Requires: pip install agent-airlock[mcp]

    Returns:
        secure_tool decorator function.
    """
    from .mcp import secure_tool

    return secure_tool


def create_secure_mcp_server(
    name: str,
    *,
    config: AirlockConfig | None = None,
    default_policy: SecurityPolicy | None = None,
) -> tuple[object, "Callable[..., object]"]:
    """Create a FastMCP server with pre-configured Airlock security.

    Requires: pip install agent-airlock[mcp]

    Args:
        name: Name of the MCP server.
        config: Default Airlock configuration.
        default_policy: Default security policy for all tools.

    Returns:
        Tuple of (FastMCP instance, secure_tool decorator).
    """
    from .mcp import create_secure_mcp_server as _create

    return _create(name, config=config, default_policy=default_policy)


if TYPE_CHECKING:
    from collections.abc import Callable

    from .sandbox import SandboxPool
