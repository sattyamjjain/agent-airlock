"""Async Tools Example - Demonstrating async function support with Airlock.

This example shows how to use @Airlock with async functions,
including async generators and concurrent tool execution.

Run with: python examples/async_tools.py
"""

from __future__ import annotations

import asyncio
from typing import Any

from agent_airlock import Airlock, AirlockConfig, SecurityPolicy


# Basic async tool
@Airlock()
async def fetch_user(user_id: int) -> dict[str, Any]:
    """Fetch user data asynchronously.

    Simulates an async database or API call.
    """
    await asyncio.sleep(0.1)  # Simulate network delay
    return {
        "id": user_id,
        "name": f"User {user_id}",
        "email": f"user{user_id}@example.com",
    }


# Async tool with policy
policy = SecurityPolicy(
    allowed_tools=["search_products"],
    rate_limits={"search_products": "10/minute"},
)


@Airlock(policy=policy)
async def search_products(query: str, limit: int = 10) -> list[dict[str, Any]]:
    """Search products asynchronously.

    Rate-limited to 10 calls per minute.
    """
    await asyncio.sleep(0.05)  # Simulate search
    return [
        {"id": i, "name": f"Product matching '{query}' #{i}", "price": 9.99 + i}
        for i in range(limit)
    ]


# Async tool with strict validation
config = AirlockConfig(strict_mode=True, sanitize_output=True, mask_pii=True)


@Airlock(config=config)
async def send_notification(
    recipient_email: str,
    subject: str,
    body: str,
    priority: str = "normal",
) -> dict[str, bool]:
    """Send a notification asynchronously.

    Strict mode rejects unknown arguments.
    PII masking enabled for output.
    """
    await asyncio.sleep(0.02)

    # The email will be masked in the output
    return {
        "sent": True,
        "recipient": recipient_email,
        "priority": priority,
    }


# Concurrent async tool execution
async def process_batch(user_ids: list[int]) -> list[dict[str, Any]]:
    """Process multiple users concurrently.

    Demonstrates running multiple Airlock-protected async tools in parallel.
    """
    tasks = [fetch_user(user_id=uid) for uid in user_ids]
    results = await asyncio.gather(*tasks)
    return list(results)


async def main() -> None:
    """Run async examples."""
    print("=" * 60)
    print("Async Tools Example")
    print("=" * 60)

    # Example 1: Basic async tool
    print("\n1. Basic async tool:")
    user = await fetch_user(user_id=123)
    print(f"   Fetched user: {user}")

    # Example 2: Async tool with policy
    print("\n2. Async tool with rate limiting:")
    products = await search_products(query="laptop", limit=3)
    print(f"   Found {len(products)} products")
    for p in products:
        print(f"   - {p['name']}: ${p['price']}")

    # Example 3: Strict validation
    print("\n3. Strict validation (ghost args rejected):")
    try:
        # This would fail with ghost argument in strict mode
        result = await send_notification(
            recipient_email="test@example.com",
            subject="Hello",
            body="Test message",
        )
        print(f"   Notification sent: {result}")
    except Exception as e:
        print(f"   Error: {e}")

    # Example 4: Concurrent execution
    print("\n4. Concurrent async execution:")
    user_ids = [1, 2, 3, 4, 5]
    start = asyncio.get_event_loop().time()
    users = await process_batch(user_ids)
    elapsed = asyncio.get_event_loop().time() - start
    print(f"   Fetched {len(users)} users in {elapsed:.3f}s")
    print("   (Sequential would take ~0.5s, concurrent takes ~0.1s)")

    # Example 5: Error handling in async
    print("\n5. Async validation error handling:")
    result = await fetch_user(user_id="not_an_int")  # type: ignore
    if isinstance(result, dict) and result.get("status") == "blocked":
        print(f"   Validation blocked: {result.get('error', 'Unknown error')[:50]}...")
    else:
        print(f"   Result: {result}")

    print("\n" + "=" * 60)
    print("Async examples completed!")


if __name__ == "__main__":
    asyncio.run(main())
