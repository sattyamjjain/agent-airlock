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

V0.4.0 "Enterprise" Features:
    - UnknownArgsMode: Explicit BLOCK/STRIP_AND_LOG/STRIP_SILENT modes (replaces strict_mode)
    - SafePath/SafeURL: Built-in safe types with automatic validation
    - Capability Gating: Per-tool capabilities (filesystem.read, network.http, etc.)
    - Pluggable Sandbox Backends: E2B, Docker, or Local (UNSAFE)
    - OpenTelemetry Audit Export: Enterprise observability
    - MCP Proxy Guard: Token passthrough prevention, session binding
    - CLI Tools: airlock doctor, airlock verify

V0.3.0 "Vaccine" Features:
    - Filesystem path validation (prevent directory traversal)
    - Network egress control (prevent data exfiltration)
    - Honeypot deception (return fake data instead of errors)
    - Framework vaccination (automatic security for LangChain, OpenAI SDK, etc.)
"""

from typing import TYPE_CHECKING

from .audit import AuditLogger, AuditRecord, get_audit_logger

# V0.4.0 OTel audit
from .audit_otel import (
    EnhancedAuditRecord,
    OTelAuditExporter,
    create_enhanced_record,
    get_otel_exporter,
)

# V0.4.0 Capability gating
from .capabilities import (
    NO_NETWORK_CAPABILITY_POLICY,
    PERMISSIVE_CAPABILITY_POLICY,
    READ_ONLY_CAPABILITY_POLICY,
    STRICT_CAPABILITY_POLICY,
    Capability,
    CapabilityDeniedError,
    CapabilityPolicy,
    capabilities_to_list,
    get_required_capabilities,
    requires,
)

# V0.4.0 Circuit Breaker
from .circuit_breaker import (
    AGGRESSIVE_BREAKER,
    CONSERVATIVE_BREAKER,
    DEFAULT_BREAKER,
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerError,
    CircuitState,
    CircuitStats,
    get_all_circuit_breakers,
    get_circuit_breaker,
    reset_all_circuit_breakers,
)
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

# V0.4.0 Cost Tracking
from .cost_tracking import (
    BudgetConfig,
    BudgetExceededError,
    CostCallback,
    CostContext,
    CostRecord,
    CostSummary,
    CostTracker,
    TokenUsage,
    get_global_tracker,
    set_global_tracker,
)

# V0.3.0 Filesystem security
from .filesystem import (
    RESTRICTIVE_FILESYSTEM_POLICY,
    SANDBOX_FILESYSTEM_POLICY,
    FilesystemPolicy,
    PathValidationError,
    is_path_within_roots,
    validate_path,
)

# V0.3.0 Honeypot deception
from .honeypot import (
    MONITORING_CONFIG,
    STRICT_HONEYPOT_CONFIG,
    TRANSPARENT_CONFIG,
    BlockStrategy,
    DefaultHoneypotGenerator,
    HoneypotConfig,
    HoneypotDataGenerator,
    create_honeypot_response,
    create_honeypot_response_async,
    should_soft_block,
    should_use_honeypot,
)

# V0.4.0 MCP Proxy Guard
from .mcp_proxy_guard import (
    DEFAULT_PROXY_CONFIG,
    PERMISSIVE_PROXY_CONFIG,
    STRICT_PROXY_CONFIG,
    MCPProxyConfig,
    MCPProxyGuard,
    MCPSecurityError,
    MCPSession,
)

# V0.3.0 Network egress control
from .network import (
    HTTPS_ONLY_POLICY,
    INTERNAL_ONLY_POLICY,
    NO_NETWORK_POLICY,
    NetworkBlockedError,
    NetworkPolicy,
    network_airgap,
)

# V0.4.0 Observability (OTEL)
from .observability import (
    NoOpProvider,
    ObservabilityProvider,
    OpenTelemetryProvider,
    SpanContext,
    end_span,
    get_provider,
    observe,
    record_metric,
    start_span,
    track_event,
)
from .observability import (
    configure as configure_observability,
)
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

# V0.4.0 Retry Policies
from .retry import (
    AGGRESSIVE_RETRY,
    FAST_RETRY,
    NETWORK_EXCEPTIONS,
    NO_RETRY,
    PATIENT_RETRY,
    STANDARD_RETRY,
    RetryConfig,
    RetryExhaustedError,
    RetryPolicy,
    RetryState,
    retry,
)

# V0.4.0 Safe types
from .safe_types import (
    DEFAULT_PATH_DENY_PATTERNS,
    SafePath,
    SafePathInTmp,
    SafePathStrict,
    SafePathValidationError,
    SafePathValidator,
    SafeURL,
    SafeURLAllowHttp,
    SafeURLValidationError,
    SafeURLValidator,
    create_safe_path_type,
    create_safe_url_type,
)

# V0.4.0 Sandbox backends
from .sandbox_backend import (
    DockerBackend,
    E2BBackend,
    LocalBackend,
    SandboxBackend,
    SandboxResult,
    get_default_backend,
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

# Testing utilities
from .testing import (
    reset_all,
    reset_audit_logger,
    reset_circuit_breakers,
    reset_cost_tracker,
    reset_network_interceptors,
    reset_observability,
    reset_sandbox_pool,
)

# Note: reset_context is imported from .context above
# Note: reset_conversation_tracker is imported from .conversation above
# V0.4.0 Unknown args handling
from .unknown_args import (
    DEVELOPMENT_MODE,
    PRODUCTION_MODE,
    STAGING_MODE,
    UnknownArgsMode,
    get_recommended_mode,
    mode_from_strict_bool,
)

# V0.3.0 Framework vaccination
from .vaccine import (
    FRAMEWORK_DECORATORS,
    VaccinationResult,
    get_supported_frameworks,
    get_vaccinated_tools,
    is_vaccinated,
    unvaccinate,
    vaccinate,
)
from .validator import GhostArgumentError

__version__ = "0.4.0"

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
    # V0.3.0 Filesystem
    "FilesystemPolicy",
    "PathValidationError",
    "validate_path",
    "is_path_within_roots",
    "RESTRICTIVE_FILESYSTEM_POLICY",
    "SANDBOX_FILESYSTEM_POLICY",
    # V0.3.0 Network
    "NetworkPolicy",
    "NetworkBlockedError",
    "network_airgap",
    "NO_NETWORK_POLICY",
    "INTERNAL_ONLY_POLICY",
    "HTTPS_ONLY_POLICY",
    # V0.3.0 Honeypot
    "BlockStrategy",
    "HoneypotConfig",
    "HoneypotDataGenerator",
    "DefaultHoneypotGenerator",
    "create_honeypot_response",
    "create_honeypot_response_async",
    "should_use_honeypot",
    "should_soft_block",
    "STRICT_HONEYPOT_CONFIG",
    "MONITORING_CONFIG",
    "TRANSPARENT_CONFIG",
    # V0.3.0 Vaccine
    "vaccinate",
    "unvaccinate",
    "VaccinationResult",
    "get_supported_frameworks",
    "get_vaccinated_tools",
    "is_vaccinated",
    "FRAMEWORK_DECORATORS",
    # V0.4.0 Unknown Args
    "UnknownArgsMode",
    "mode_from_strict_bool",
    "get_recommended_mode",
    "PRODUCTION_MODE",
    "STAGING_MODE",
    "DEVELOPMENT_MODE",
    # V0.4.0 Safe Types
    "SafePath",
    "SafePathStrict",
    "SafePathInTmp",
    "SafeURL",
    "SafeURLAllowHttp",
    "SafePathValidator",
    "SafeURLValidator",
    "SafePathValidationError",
    "SafeURLValidationError",
    "create_safe_path_type",
    "create_safe_url_type",
    "DEFAULT_PATH_DENY_PATTERNS",
    # V0.4.0 Capabilities
    "Capability",
    "CapabilityPolicy",
    "CapabilityDeniedError",
    "requires",
    "get_required_capabilities",
    "capabilities_to_list",
    "PERMISSIVE_CAPABILITY_POLICY",
    "STRICT_CAPABILITY_POLICY",
    "READ_ONLY_CAPABILITY_POLICY",
    "NO_NETWORK_CAPABILITY_POLICY",
    # V0.4.0 Sandbox Backends
    "SandboxBackend",
    "SandboxResult",
    "E2BBackend",
    "DockerBackend",
    "LocalBackend",
    "get_default_backend",
    # V0.4.0 OTel Audit
    "OTelAuditExporter",
    "EnhancedAuditRecord",
    "get_otel_exporter",
    "create_enhanced_record",
    # V0.4.0 MCP Proxy Guard
    "MCPProxyGuard",
    "MCPProxyConfig",
    "MCPSession",
    "MCPSecurityError",
    "DEFAULT_PROXY_CONFIG",
    "STRICT_PROXY_CONFIG",
    "PERMISSIVE_PROXY_CONFIG",
    # V0.4.0 Circuit Breaker
    "CircuitBreaker",
    "CircuitBreakerConfig",
    "CircuitBreakerError",
    "CircuitState",
    "CircuitStats",
    "get_circuit_breaker",
    "get_all_circuit_breakers",
    "reset_all_circuit_breakers",
    "AGGRESSIVE_BREAKER",
    "CONSERVATIVE_BREAKER",
    "DEFAULT_BREAKER",
    # V0.4.0 Cost Tracking
    "CostTracker",
    "CostRecord",
    "CostSummary",
    "CostContext",
    "CostCallback",
    "TokenUsage",
    "BudgetConfig",
    "BudgetExceededError",
    "get_global_tracker",
    "set_global_tracker",
    # V0.4.0 Retry Policies
    "RetryPolicy",
    "RetryConfig",
    "RetryState",
    "RetryExhaustedError",
    "retry",
    "NO_RETRY",
    "FAST_RETRY",
    "STANDARD_RETRY",
    "AGGRESSIVE_RETRY",
    "PATIENT_RETRY",
    "NETWORK_EXCEPTIONS",
    # V0.4.0 Observability (OTEL)
    "ObservabilityProvider",
    "NoOpProvider",
    "OpenTelemetryProvider",
    "SpanContext",
    "configure_observability",
    "get_provider",
    "start_span",
    "end_span",
    "record_metric",
    "track_event",
    "observe",
    # Testing utilities
    "reset_all",
    "reset_audit_logger",
    "reset_sandbox_pool",
    "reset_conversation_tracker",
    "reset_cost_tracker",
    "reset_observability",
    "reset_network_interceptors",
    "reset_circuit_breakers",
    # Note: reset_context is in Context section above
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
