"""Policy engine examples for Agent-Airlock.

This file demonstrates the security policy features:
1. Allow/deny tool lists
2. Time-based restrictions
3. Rate limiting
4. Agent identity and roles
5. Predefined policies
"""

from datetime import datetime

from agent_airlock import (
    BUSINESS_HOURS_POLICY,
    READ_ONLY_POLICY,
    AgentIdentity,
    Airlock,
    PolicyViolation,
    SecurityPolicy,
)

# Example 1: Simple allow/deny lists
read_only_policy = SecurityPolicy(
    allowed_tools=["read_*", "list_*", "get_*"],
    denied_tools=["delete_*", "drop_*"],
)


@Airlock(policy=read_only_policy)
def read_database(table: str, query: str) -> dict:
    """Read from database - allowed by policy."""
    return {"table": table, "query": query, "rows": 10}


@Airlock(policy=read_only_policy)
def delete_user(user_id: int) -> dict:
    """Delete user - blocked by policy."""
    return {"deleted": True, "user_id": user_id}


# Example 2: Rate limiting
rate_limited_policy = SecurityPolicy(
    rate_limits={
        "*": "100/hour",  # Default limit for all tools
        "expensive_*": "5/minute",  # Stricter limit for expensive operations
    }
)


@Airlock(policy=rate_limited_policy)
def search_database(query: str) -> dict:
    """Search database - rate limited to 100/hour."""
    return {"query": query, "results": []}


@Airlock(policy=rate_limited_policy)
def expensive_operation(data: str) -> dict:
    """Expensive operation - rate limited to 5/minute."""
    return {"processed": data}


# Example 3: Time-based restrictions
time_restricted_policy = SecurityPolicy(
    time_restrictions={
        "delete_*": "09:00-17:00",  # Deletions only during business hours
        "*_production": "10:00-16:00",  # Production ops only 10am-4pm
    }
)


@Airlock(policy=time_restricted_policy)
def delete_logs(days_old: int) -> dict:
    """Delete old logs - only during business hours."""
    return {"deleted_days_old": days_old}


@Airlock(policy=time_restricted_policy)
def deploy_production(version: str) -> dict:
    """Deploy to production - restricted hours."""
    return {"deployed": version, "environment": "production"}


# Example 4: Role-based access control
admin_policy = SecurityPolicy(
    require_agent_id=True,
    allowed_roles=["admin", "operator"],
    denied_tools=["format_disk"],
)


@Airlock(policy=admin_policy)
def manage_users(action: str, user_id: int) -> dict:
    """Manage users - requires admin or operator role."""
    return {"action": action, "user_id": user_id}


# Example 5: Combined policy
strict_production_policy = SecurityPolicy(
    allowed_tools=["read_*", "get_*", "deploy_*"],
    denied_tools=["delete_*", "drop_*", "truncate_*"],
    time_restrictions={"deploy_*": "09:00-17:00"},
    rate_limits={"deploy_*": "10/hour"},
    require_agent_id=True,
    allowed_roles=["deployer", "admin"],
)


@Airlock(policy=strict_production_policy)
def deploy_service(name: str, version: str) -> dict:
    """Deploy service - multiple policy restrictions."""
    return {"name": name, "version": version, "status": "deployed"}


def main() -> None:
    """Run examples to demonstrate policy features."""
    print("=" * 60)
    print("Agent-Airlock Policy Engine Examples")
    print("=" * 60)

    # Test 1: Allowed tool
    print("\n1. Allowed tool (read_database):")
    result = read_database(table="users", query="SELECT * FROM users")
    print(f"   Result: {result}")

    # Test 2: Denied tool
    print("\n2. Denied tool (delete_user):")
    result = delete_user(user_id=123)
    print(f"   Result: {result}")
    if isinstance(result, dict) and not result.get("success"):
        print("   ✗ Blocked by policy")

    # Test 3: Rate limiting (first few calls succeed)
    print("\n3. Rate limiting (expensive_operation):")
    for i in range(7):
        result = expensive_operation(data=f"batch-{i}")
        if isinstance(result, dict):
            if result.get("success", True) and "processed" in result:
                print(f"   Call {i + 1}: ✓ Success")
            else:
                print(f"   Call {i + 1}: ✗ Rate limited")
                break

    # Test 4: Time restriction (simulate different times)
    print("\n4. Time restrictions (delete_logs):")
    print("   (Behavior depends on current time)")
    result = delete_logs(days_old=30)
    if isinstance(result, dict) and result.get("success") is False:
        print("   ✗ Outside allowed hours")
    else:
        print(f"   Result: {result}")

    # Test 5: Using predefined policies
    print("\n5. Predefined READ_ONLY_POLICY:")
    try:
        READ_ONLY_POLICY.check("read_file")
        print("   ✓ read_file allowed")
    except PolicyViolation:
        print("   ✗ read_file denied")

    try:
        READ_ONLY_POLICY.check("delete_file")
        print("   ✓ delete_file allowed")
    except PolicyViolation:
        print("   ✗ delete_file denied")

    # Test 6: Agent identity
    print("\n6. Agent identity and roles:")
    admin_agent = AgentIdentity(
        agent_id="claude-agent-001",
        session_id="session-abc",
        roles=["admin", "analyst"],
        metadata={"model": "claude-3-opus"},
    )

    guest_agent = AgentIdentity(
        agent_id="guest-agent",
        roles=["guest"],
    )

    # Check admin policy manually
    try:
        admin_policy.check("manage_users", agent=admin_agent)
        print("   ✓ Admin agent can manage_users")
    except PolicyViolation as e:
        print(f"   ✗ Admin blocked: {e.message}")

    try:
        admin_policy.check("manage_users", agent=guest_agent)
        print("   ✓ Guest agent can manage_users")
    except PolicyViolation as e:
        print(f"   ✗ Guest blocked: {e.violation_type}")

    # Test 7: BUSINESS_HOURS_POLICY
    print("\n7. BUSINESS_HOURS_POLICY:")
    current_hour = datetime.now().hour
    print(f"   Current hour: {current_hour}:00")
    try:
        BUSINESS_HOURS_POLICY.check("delete_file")
        print("   ✓ delete_file allowed at current time")
    except PolicyViolation:
        print("   ✗ delete_file blocked (outside business hours)")

    print("\n" + "=" * 60)
    print("Policy Examples Complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
