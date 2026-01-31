"""Basic usage examples for Agent-Airlock.

This file demonstrates the core features of Agent-Airlock:
1. Basic validation with @Airlock
2. Ghost argument stripping
3. Strict mode for type validation
4. Self-healing error responses
"""

from pydantic import BaseModel, Field

from agent_airlock import Airlock, AirlockConfig


# Example 1: Basic validation
@Airlock()
def read_file(filename: str, encoding: str = "utf-8") -> str:
    """Read a file and return its contents."""
    with open(filename, encoding=encoding) as f:
        return f.read()


# Example 2: With Pydantic model for complex validation
class DeployArgs(BaseModel):
    """Arguments for deploying a service."""

    service_name: str = Field(..., pattern=r"^[a-z0-9-]+$")
    replicas: int = Field(..., gt=0, lt=10)
    environment: str = Field(default="staging")


@Airlock()
def deploy_service(args: DeployArgs) -> dict:
    """Deploy a service with validated arguments."""
    return {
        "status": "deployed",
        "service": args.service_name,
        "replicas": args.replicas,
        "environment": args.environment,
    }


# Example 3: Strict mode - rejects ghost arguments instead of stripping
strict_config = AirlockConfig(strict_mode=True)


@Airlock(config=strict_config)
def delete_record(table: str, record_id: int) -> dict:
    """Delete a record - strict mode for extra safety."""
    return {"deleted": True, "table": table, "id": record_id}


# Example 4: Sandbox mode (placeholder - full implementation in Phase 2)
@Airlock(sandbox=True)
def run_code(code: str) -> str:
    """Execute code in a sandbox."""
    # In Phase 2, this will run in E2B MicroVM
    return f"Would execute: {code}"


# Example 5: Return dict mode - always returns structured response
@Airlock(return_dict=True)
def calculate(x: int, y: int, operation: str = "add") -> int:
    """Perform a calculation."""
    if operation == "add":
        return x + y
    elif operation == "multiply":
        return x * y
    else:
        return 0


def main() -> None:
    """Run examples to demonstrate Agent-Airlock features."""
    print("=" * 60)
    print("Agent-Airlock Basic Usage Examples")
    print("=" * 60)

    # Test 1: Valid call
    print("\n1. Valid function call:")
    try:
        result = deploy_service(args=DeployArgs(service_name="my-api", replicas=3))
        print(f"   Result: {result}")
    except Exception as e:
        print(f"   Error: {e}")

    # Test 2: Ghost argument stripping
    print("\n2. Ghost argument stripping (force=True is stripped):")
    result = read_file.__wrapped__(  # Access underlying for demo
        filename="README.md",
        encoding="utf-8",
    )
    print("   (In real usage, extra 'force=True' would be silently stripped)")

    # Test 3: Type validation failure
    print("\n3. Type validation failure (string instead of int):")
    result = calculate(x="not a number", y=5)  # type: ignore
    print(f"   Result: {result}")
    if isinstance(result, dict) and not result.get("success"):
        print(f"   Fix hints: {result.get('fix_hints', [])}")

    # Test 4: Strict mode with ghost arguments
    print("\n4. Strict mode rejects ghost arguments:")
    result = delete_record(table="users", record_id=123, force=True)  # type: ignore
    print(f"   Result: {result}")

    # Test 5: Return dict mode
    print("\n5. Return dict mode (always structured response):")
    result = calculate(x=10, y=5, operation="multiply")
    print(f"   Result: {result}")

    print("\n" + "=" * 60)
    print("Examples complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
