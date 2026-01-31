"""Streaming Example - Demonstrating generator and streaming support.

This example shows how to use Airlock with generator functions
for streaming responses, with per-chunk sanitization and truncation.

Run with: python examples/streaming.py
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator, Generator
from typing import Any

from agent_airlock import AirlockConfig, StreamingAirlock, create_streaming_wrapper


# Configuration for streaming
config = AirlockConfig(
    sanitize_output=True,
    mask_pii=True,
    mask_secrets=True,
    max_output_chars=500,  # Low limit to demonstrate truncation
)


# Sync generator example
def generate_report_chunks() -> Generator[str, None, None]:
    """Generate a report in chunks.

    Simulates streaming data from a database or API.
    """
    yield "# Sales Report\n\n"
    yield "## Summary\n"
    yield "Total sales: $1,234,567\n"
    yield "Top customer: john.doe@example.com\n"  # PII - will be masked
    yield "\n## Details\n"
    for i in range(10):
        yield f"- Transaction {i + 1}: ${'%.2f' % (100 + i * 10)}\n"
    yield "\n## Confidential\n"
    yield "API Key: sk-1234567890abcdefghijklmnop\n"  # Secret - will be masked


# Async generator example
async def stream_search_results(query: str) -> AsyncGenerator[str, None]:
    """Stream search results asynchronously.

    Simulates streaming results from a search engine.
    """
    yield f"Searching for: {query}\n\n"

    for i in range(5):
        await asyncio.sleep(0.1)  # Simulate async fetch
        yield f"Result {i + 1}: Found match for '{query}'\n"
        yield f"  Contact: user{i}@example.com\n"  # PII - will be masked

    yield "\nSearch complete.\n"


def demonstrate_sync_streaming() -> None:
    """Demonstrate synchronous streaming with sanitization."""
    print("\n1. Sync Generator Streaming:")
    print("-" * 40)

    # Create streaming wrapper
    streaming = StreamingAirlock(config)
    wrapped_gen = streaming.wrap_generator(generate_report_chunks())

    # Consume the stream
    full_output = ""
    for chunk in wrapped_gen:
        print(chunk, end="")
        full_output += chunk

    print("\n")
    print(f"Total output length: {len(full_output)} chars")
    print(f"Was truncated: {streaming.state.truncated}")
    print(f"Chunks processed: {streaming.state.total_chunks}")


async def demonstrate_async_streaming() -> None:
    """Demonstrate asynchronous streaming with sanitization."""
    print("\n2. Async Generator Streaming:")
    print("-" * 40)

    # Create streaming wrapper
    streaming = StreamingAirlock(config)
    wrapped_gen = streaming.wrap_async_generator(stream_search_results("python"))

    # Consume the stream
    full_output = ""
    async for chunk in wrapped_gen:
        print(chunk, end="")
        full_output += chunk

    print("\n")
    print(f"Total output length: {len(full_output)} chars")
    print(f"Was truncated: {streaming.state.truncated}")


def demonstrate_wrapper_function() -> None:
    """Demonstrate the create_streaming_wrapper helper."""
    print("\n3. Using create_streaming_wrapper:")
    print("-" * 40)

    # Define a generator function
    def data_stream(count: int) -> Generator[str, None, None]:
        """Stream data items."""
        for i in range(count):
            yield f"Item {i + 1}: Data with email test{i}@secret.com\n"

    # Wrap it with sanitization
    wrapped_stream = create_streaming_wrapper(data_stream, config)

    # Use the wrapped function
    for chunk in wrapped_stream(count=5):
        print(f"  {chunk}", end="")


def demonstrate_truncation() -> None:
    """Demonstrate output truncation in streaming."""
    print("\n4. Stream Truncation:")
    print("-" * 40)

    # Generator that produces a lot of output
    def large_output() -> Generator[str, None, None]:
        for i in range(100):
            yield f"Line {i + 1}: " + "x" * 50 + "\n"

    # Create streaming wrapper with small limit
    small_config = AirlockConfig(max_output_chars=200)
    streaming = StreamingAirlock(small_config)
    wrapped = streaming.wrap_generator(large_output())

    chunks = list(wrapped)
    total = "".join(chunks)

    print(f"Output preview: {total[:100]}...")
    print(f"Total length: {len(total)} chars (limited to ~200)")
    print(f"Truncated: {streaming.state.truncated}")


def main() -> None:
    """Run streaming examples."""
    print("=" * 60)
    print("Streaming Example")
    print("=" * 60)

    # Sync streaming
    demonstrate_sync_streaming()

    # Async streaming
    asyncio.run(demonstrate_async_streaming())

    # Wrapper function
    demonstrate_wrapper_function()

    # Truncation
    demonstrate_truncation()

    print("\n" + "=" * 60)
    print("Streaming examples completed!")
    print("\nKey features demonstrated:")
    print("- Per-chunk PII/secret masking")
    print("- Output truncation with streaming")
    print("- Both sync and async generators")
    print("- create_streaming_wrapper helper")


if __name__ == "__main__":
    main()
