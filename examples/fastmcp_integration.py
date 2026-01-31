"""FastMCP integration example for Agent-Airlock.

This example demonstrates how to build a secure MCP server using Agent-Airlock.
It shows:
1. Basic tool protection with @Airlock
2. Using MCPAirlock for MCP-specific features
3. The secure_tool convenience decorator
4. Policy enforcement for different tool types
5. Sandbox execution for dangerous operations
6. Secure path validation patterns

Requirements:
    pip install agent-airlock[mcp]
    # or
    pip install agent-airlock fastmcp

To run this server:
    python examples/fastmcp_integration.py

To test with Claude Desktop, add to your claude_desktop_config.json:
    {
        "mcpServers": {
            "secure-server": {
                "command": "python",
                "args": ["/path/to/examples/fastmcp_integration.py"]
            }
        }
    }

SECURITY NOTES:
    - sandbox_required=True is used for exec() to prevent local execution fallback
    - Path validation prevents directory traversal attacks
    - Always validate and sanitize file paths before use
"""

from pathlib import Path

# Check if FastMCP is available
try:
    from fastmcp import FastMCP
except ImportError:
    print("FastMCP is required for this example.")
    print("Install with: pip install agent-airlock[mcp]")
    raise SystemExit(1)

from agent_airlock import (
    Airlock,
    AirlockConfig,
    READ_ONLY_POLICY,
    SecurityPolicy,
)
from agent_airlock.mcp import MCPAirlock, secure_tool

# Create FastMCP server
mcp = FastMCP("Secure File Server")

# Configuration for this server
config = AirlockConfig(
    strict_mode=True,  # Reject unknown arguments
    mask_pii=True,  # Mask PII in outputs
    mask_secrets=True,  # Mask secrets in outputs
    max_output_chars=10000,  # Limit output size
)


# =============================================================================
# Example 1: Basic @Airlock protection
# =============================================================================
# The simplest way - just add @Airlock after @mcp.tool


@mcp.tool
@Airlock(config=config)
def get_current_directory() -> str:
    """Get the current working directory."""
    return str(Path.cwd())


# =============================================================================
# Example 2: MCPAirlock with progress reporting
# =============================================================================
# Use MCPAirlock for MCP-specific features like progress reporting


@mcp.tool
@MCPAirlock(config=config, report_progress=True)
def list_files(directory: str = ".") -> list[str]:
    """List files in a directory.

    Args:
        directory: Path to the directory (default: current directory)
    """
    path = Path(directory)
    if not path.exists():
        return [f"Error: Directory '{directory}' does not exist"]
    if not path.is_dir():
        return [f"Error: '{directory}' is not a directory"]

    return [str(f.name) for f in path.iterdir()]


# =============================================================================
# Example 3: Read-only policy enforcement
# =============================================================================
# Apply a read-only policy to prevent modifications


# Define allowed directories for file operations (security best practice)
ALLOWED_DIRECTORIES = [Path.cwd(), Path.home() / "Documents"]


def validate_path(path: str, allowed_dirs: list[Path]) -> tuple[bool, Path | str]:
    """Validate a path is within allowed directories.

    SECURITY: Prevents path traversal attacks like '../../etc/passwd'

    Returns:
        Tuple of (is_valid, resolved_path_or_error_message)
    """
    try:
        resolved = Path(path).resolve()
        for allowed in allowed_dirs:
            try:
                resolved.relative_to(allowed.resolve())
                return True, resolved
            except ValueError:
                continue
        return False, f"Access denied: Path must be within {[str(d) for d in allowed_dirs]}"
    except Exception as e:
        return False, f"Invalid path: {e}"


@mcp.tool
@Airlock(config=config, policy=READ_ONLY_POLICY)
def read_file(path: str) -> str:
    """Read contents of a file.

    This tool is protected by:
    - READ_ONLY_POLICY (prevents write operations)
    - Path validation (prevents directory traversal)

    Args:
        path: Path to the file to read
    """
    # SECURITY: Validate path to prevent directory traversal
    is_valid, result = validate_path(path, ALLOWED_DIRECTORIES)
    if not is_valid:
        return f"Error: {result}"

    file_path = result  # Now it's a validated Path object
    if not file_path.exists():
        return f"Error: File '{path}' does not exist"
    if not file_path.is_file():
        return f"Error: '{path}' is not a file"

    return file_path.read_text()


# =============================================================================
# Example 4: Custom policy with rate limiting
# =============================================================================
# Create a custom policy for potentially expensive operations

SEARCH_POLICY = SecurityPolicy(
    allowed_tools=["search_*", "find_*"],
    rate_limits={"search_*": "10/minute"},  # Limit to 10 searches per minute
)


@mcp.tool
@Airlock(config=config, policy=SEARCH_POLICY)
def search_files(pattern: str, directory: str = ".") -> list[str]:
    """Search for files matching a pattern.

    Rate limited to 10 searches per minute.

    Args:
        pattern: Glob pattern to match (e.g., "*.py", "**/*.txt")
        directory: Directory to search in
    """
    path = Path(directory)
    if not path.exists():
        return [f"Error: Directory '{directory}' does not exist"]

    matches = list(path.glob(pattern))
    return [str(m) for m in matches[:100]]  # Limit results


# =============================================================================
# Example 5: Using secure_tool convenience decorator
# =============================================================================
# This combines @mcp.tool and @Airlock in one decorator


@secure_tool(mcp, config=config)
def get_file_info(path: str) -> dict[str, str]:
    """Get information about a file.

    Args:
        path: Path to the file
    """
    file_path = Path(path)
    if not file_path.exists():
        return {"error": f"File '{path}' does not exist"}

    stat = file_path.stat()
    return {
        "name": file_path.name,
        "size": f"{stat.st_size} bytes",
        "is_file": str(file_path.is_file()),
        "is_dir": str(file_path.is_dir()),
    }


# =============================================================================
# Example 6: Sandbox execution for dangerous operations
# =============================================================================
# Use sandbox=True for operations that could be dangerous
# Note: Requires E2B API key and pip install agent-airlock[sandbox]


# =============================================================================
# SECURITY: sandbox_required=True ensures exec() NEVER runs locally
# =============================================================================
@mcp.tool
@Airlock(config=config, sandbox=True, sandbox_required=True)
def execute_python(code: str) -> str:
    """Execute Python code in a secure sandbox.

    SECURITY:
        - sandbox_required=True ensures this ONLY runs in E2B sandbox
        - If E2B is not available, raises SandboxUnavailableError
        - NEVER falls back to local execution (unlike sandbox=True alone)

    The code runs in an isolated E2B Firecracker MicroVM.

    Args:
        code: Python code to execute
    """
    # This code will ONLY run in the sandbox, never locally
    import io
    import sys

    old_stdout = sys.stdout
    sys.stdout = io.StringIO()

    try:
        exec(code)  # noqa: S102 - Safe because sandbox_required=True
        output = sys.stdout.getvalue()
    except Exception as e:
        output = f"Error: {e}"
    finally:
        sys.stdout = old_stdout

    return output


# =============================================================================
# Example 7: Time-restricted operations
# =============================================================================
# Some operations should only be allowed during business hours

BUSINESS_HOURS_WRITE_POLICY = SecurityPolicy(
    allowed_tools=["write_*"],
    time_restrictions={"write_*": "09:00-17:00"},
)


@mcp.tool
@Airlock(config=config, policy=BUSINESS_HOURS_WRITE_POLICY)
def write_file(path: str, content: str) -> str:
    """Write content to a file.

    Protected by:
    - Business hours restriction (9 AM - 5 PM)
    - Path validation (prevents directory traversal)

    Args:
        path: Path to the file
        content: Content to write
    """
    # SECURITY: Validate path to prevent directory traversal
    is_valid, result = validate_path(path, ALLOWED_DIRECTORIES)
    if not is_valid:
        return f"Error: {result}"

    file_path = result
    file_path.write_text(content)
    return f"Successfully wrote {len(content)} characters to {path}"


# =============================================================================
# Example 8: Combining multiple protections
# =============================================================================
# For critical operations, combine multiple security layers

ADMIN_POLICY = SecurityPolicy(
    require_agent_id=True,
    allowed_roles=["admin", "operator"],
    denied_tools=["delete_*", "drop_*"],
    rate_limits={"*": "100/hour"},
)


@mcp.tool
@Airlock(config=config, policy=ADMIN_POLICY, sandbox=True)
def admin_operation(command: str) -> str:
    """Execute an admin command.

    Protected by:
    - Requires agent identity
    - Only admin/operator roles
    - Rate limited to 100/hour
    - Runs in sandbox
    - PII/secrets masked in output

    Args:
        command: Admin command to execute
    """
    # Simulate admin operation
    return f"Admin command executed: {command}"


# =============================================================================
# Main entry point
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("Agent-Airlock Secure MCP Server")
    print("=" * 60)
    print()
    print("Available tools:")
    print("  - get_current_directory: Get current directory")
    print("  - list_files: List files (with progress reporting)")
    print("  - read_file: Read file (read-only policy)")
    print("  - search_files: Search files (rate limited)")
    print("  - get_file_info: Get file info")
    print("  - execute_python: Execute Python (sandboxed)")
    print("  - write_file: Write file (business hours only)")
    print("  - admin_operation: Admin command (restricted)")
    print()
    print("Starting server...")
    print("=" * 60)

    # Run the server
    mcp.run()
