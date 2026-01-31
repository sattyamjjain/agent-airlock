"""E2B Sandbox execution examples for Agent-Airlock.

This file demonstrates how to use the sandbox feature to execute
functions in isolated E2B Firecracker MicroVMs.

Prerequisites:
    1. Install sandbox dependencies:
       pip install agent-airlock[sandbox]

    2. Set E2B API key:
       export E2B_API_KEY=your_api_key_here

    3. Get your API key at: https://e2b.dev/dashboard

SECURITY WARNING:
    When sandbox=True but E2B is not available, functions will fall back
    to LOCAL execution by default. For dangerous operations like exec(),
    ALWAYS use sandbox_required=True to prevent accidental local execution.
"""

import os

from agent_airlock import Airlock, AirlockConfig, SandboxUnavailableError


# Check if E2B is configured
def check_e2b_configured() -> bool:
    """Check if E2B API key is set."""
    return bool(os.environ.get("E2B_API_KEY"))


# Example 1: Basic sandbox execution (safe to fall back)
@Airlock(sandbox=True)
def calculate_factorial(n: int) -> int:
    """Calculate factorial - runs in isolated sandbox.

    This is safe to fall back to local execution since it's just math.
    """
    if n <= 1:
        return 1
    result = 1
    for i in range(2, n + 1):
        result *= i
    return result


# Example 2: DANGEROUS operation - MUST use sandbox_required=True
# ================================================================
# SECURITY: sandbox_required=True ensures this NEVER runs locally.
# If E2B is not available, it will raise SandboxUnavailableError
# instead of executing arbitrary code on your machine.
# ================================================================
@Airlock(sandbox=True, sandbox_required=True)
def execute_python_code(code: str) -> str:
    """Execute arbitrary Python code safely in sandbox.

    SECURITY WARNING:
        This function uses exec() which is extremely dangerous.
        The sandbox_required=True flag ensures this ONLY runs
        inside an E2B sandbox, never on your local machine.

        If E2B is not configured, this will raise an error
        rather than executing code locally.
    """
    import io
    import sys

    # Capture stdout
    old_stdout = sys.stdout
    sys.stdout = captured = io.StringIO()

    try:
        exec(code)
        output = captured.getvalue()
    except Exception as e:
        output = f"Error: {type(e).__name__}: {e}"
    finally:
        sys.stdout = old_stdout

    return output


# Example 3: File operations in sandbox (isolated filesystem)
@Airlock(sandbox=True)
def create_and_read_file(filename: str, content: str) -> str:
    """Create a file and read it back - all in sandbox filesystem.

    Safe to fall back since file operations are limited to sandbox paths.
    """
    with open(filename, "w") as f:
        f.write(content)

    with open(filename) as f:
        return f.read()


# Example 4: Network operations in sandbox
@Airlock(sandbox=True)
def fetch_url_info(url: str) -> dict:
    """Fetch basic info about a URL - runs in sandbox with network access."""
    import urllib.request

    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            return {
                "status": response.status,
                "content_type": response.headers.get("Content-Type"),
                "content_length": response.headers.get("Content-Length"),
            }
    except Exception as e:
        return {"error": str(e)}


# Example 5: Custom config for sandbox
sandbox_config = AirlockConfig(
    sandbox_timeout=120,  # 2 minutes timeout
    sandbox_pool_size=3,  # Keep 3 warm sandboxes
    strict_mode=True,  # Reject ghost arguments
)


@Airlock(sandbox=True, config=sandbox_config)
def long_running_task(iterations: int) -> dict:
    """A task that might take a while - uses custom timeout."""
    import time

    start = time.time()
    total = 0
    for i in range(iterations):
        total += i * i

    elapsed = time.time() - start
    return {
        "iterations": iterations,
        "result": total,
        "elapsed_seconds": round(elapsed, 3),
    }


def main() -> None:
    """Run sandbox examples."""
    print("=" * 60)
    print("Agent-Airlock E2B Sandbox Examples")
    print("=" * 60)

    if not check_e2b_configured():
        print("\n⚠️  E2B_API_KEY not set!")
        print("   Set your API key: export E2B_API_KEY=your_key")
        print("   Get your key at: https://e2b.dev/dashboard")
        print("\n   Some examples will fall back to local execution.")
        print("   Functions with sandbox_required=True will raise errors.\n")

    # Example 1: Basic calculation
    print("\n1. Calculate factorial in sandbox:")
    result = calculate_factorial(n=10)
    if isinstance(result, dict) and "error" in result:
        print(f"   Error: {result['error']}")
    else:
        print(f"   10! = {result}")

    # Example 2: Execute code (REQUIRES sandbox - will error if unavailable)
    print("\n2. Execute Python code in sandbox (sandbox_required=True):")
    try:
        code = """
import platform
print(f"Python: {platform.python_version()}")
print(f"OS: {platform.system()}")
print("Hello from the sandbox!")
"""
        result = execute_python_code(code=code)
        if isinstance(result, dict) and "error" in result:
            print(f"   Error: {result['error']}")
        else:
            print(f"   Output:\n{result}")
    except SandboxUnavailableError as e:
        print(f"   SECURITY: {e}")
        print("   This is expected behavior - exec() requires a real sandbox!")

    # Example 3: File operations
    print("\n3. File operations in sandbox:")
    result = create_and_read_file(
        filename="/tmp/test_airlock.txt",
        content="This file exists only in the sandbox!",
    )
    if isinstance(result, dict) and "error" in result:
        print(f"   Error: {result['error']}")
    else:
        print(f"   Read back: '{result}'")

    # Example 4: Type validation still works
    print("\n4. Type validation with sandbox:")
    result = calculate_factorial(n="not a number")  # type: ignore
    if isinstance(result, dict):
        print(f"   Blocked: {result.get('error', 'Unknown error')}")
        if result.get("fix_hints"):
            print(f"   Fix hints: {result['fix_hints']}")
    else:
        print(f"   Result: {result}")

    print("\n" + "=" * 60)
    print("Examples complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
