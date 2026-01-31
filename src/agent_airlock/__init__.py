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

from .config import DEFAULT_CONFIG, AirlockConfig
from .core import Airlock, SandboxExecutionError, airlock
from .self_heal import AirlockResponse, BlockReason
from .validator import GhostArgumentError

__version__ = "0.1.0"

__all__ = [
    # Core
    "Airlock",
    "airlock",
    # Config
    "AirlockConfig",
    "DEFAULT_CONFIG",
    # Response types
    "AirlockResponse",
    "BlockReason",
    # Exceptions
    "GhostArgumentError",
    "SandboxExecutionError",
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


# Import SandboxPool type for annotation only
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .sandbox import SandboxPool
