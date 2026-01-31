"""Tests for context management functionality."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from agent_airlock.context import (
    AirlockContext,
    ContextExtractor,
    create_context_from_args,
    get_current_context,
    reset_context,
    set_current_context,
)


class TestAirlockContext:
    """Tests for AirlockContext dataclass."""

    def test_default_values(self) -> None:
        """Test default context values."""
        ctx = AirlockContext()
        assert ctx.agent_id is None
        assert ctx.session_id is None
        assert ctx.workspace_id is None
        assert ctx.user_id is None
        assert ctx.roles == []
        assert ctx.user_context is None
        assert ctx.metadata == {}

    def test_custom_values(self) -> None:
        """Test context with custom values."""
        ctx = AirlockContext(
            agent_id="agent-123",
            session_id="session-456",
            workspace_id="workspace-789",
            user_id="user-001",
            roles=["admin", "reader"],
            metadata={"key": "value"},
        )
        assert ctx.agent_id == "agent-123"
        assert ctx.session_id == "session-456"
        assert ctx.workspace_id == "workspace-789"
        assert ctx.user_id == "user-001"
        assert ctx.roles == ["admin", "reader"]
        assert ctx.metadata == {"key": "value"}

    def test_with_metadata(self) -> None:
        """Test creating a copy with additional metadata."""
        ctx = AirlockContext(
            agent_id="agent-123",
            metadata={"existing": "value"},
        )
        new_ctx = ctx.with_metadata(new_key="new_value")

        # Original unchanged
        assert ctx.metadata == {"existing": "value"}
        # New context has merged metadata
        assert new_ctx.metadata == {"existing": "value", "new_key": "new_value"}
        assert new_ctx.agent_id == ctx.agent_id

    def test_to_dict(self) -> None:
        """Test serialization to dictionary."""
        ctx = AirlockContext(
            agent_id="agent-123",
            session_id="session-456",
            roles=["admin"],
            metadata={"key": "value"},
        )
        d = ctx.to_dict()

        assert d["agent_id"] == "agent-123"
        assert d["session_id"] == "session-456"
        assert d["roles"] == ["admin"]
        assert d["metadata"] == {"key": "value"}
        # user_context is not in to_dict
        assert "user_context" not in d
        assert "_token" not in d

    def test_context_manager_sync(self) -> None:
        """Test using context as sync context manager."""
        ctx = AirlockContext(agent_id="test-agent")

        assert get_current_context() is None

        with ctx:
            current = get_current_context()
            assert current is not None
            assert current.agent_id == "test-agent"

        assert get_current_context() is None

    @pytest.mark.asyncio
    async def test_context_manager_async(self) -> None:
        """Test using context as async context manager."""
        ctx = AirlockContext(agent_id="async-agent")

        assert get_current_context() is None

        async with ctx:
            current = get_current_context()
            assert current is not None
            assert current.agent_id == "async-agent"

        assert get_current_context() is None

    def test_nested_context_managers(self) -> None:
        """Test nested context managers restore correctly."""
        outer = AirlockContext(agent_id="outer")
        inner = AirlockContext(agent_id="inner")

        with outer:
            assert get_current_context().agent_id == "outer"  # type: ignore[union-attr]
            with inner:
                assert get_current_context().agent_id == "inner"  # type: ignore[union-attr]
            assert get_current_context().agent_id == "outer"  # type: ignore[union-attr]

        assert get_current_context() is None


class TestContextVariables:
    """Tests for context variable functions."""

    def test_set_and_get_context(self) -> None:
        """Test setting and getting context."""
        ctx = AirlockContext(agent_id="test")
        token = set_current_context(ctx)

        try:
            current = get_current_context()
            assert current is not None
            assert current.agent_id == "test"
        finally:
            reset_context(token)

        assert get_current_context() is None

    def test_reset_restores_previous(self) -> None:
        """Test that reset restores the previous context."""
        first = AirlockContext(agent_id="first")
        second = AirlockContext(agent_id="second")

        token1 = set_current_context(first)
        token2 = set_current_context(second)

        assert get_current_context().agent_id == "second"  # type: ignore[union-attr]

        reset_context(token2)
        assert get_current_context().agent_id == "first"  # type: ignore[union-attr]

        reset_context(token1)
        assert get_current_context() is None


class TestContextExtractor:
    """Tests for ContextExtractor."""

    def test_extract_empty_args(self) -> None:
        """Test extraction with no arguments."""
        ctx = ContextExtractor.extract_from_args((), {})
        assert ctx.agent_id is None
        assert ctx.session_id is None
        assert ctx.user_context is None

    def test_extract_from_context_wrapper(self) -> None:
        """Test extraction from an object with .context attribute."""

        @dataclass
        class InnerContext:
            agent_id: str
            session_id: str
            workspace_id: str = "default-ws"

        @dataclass
        class ContextWrapper:
            context: InnerContext

        inner = InnerContext(agent_id="agent-1", session_id="session-1")
        wrapper = ContextWrapper(context=inner)

        ctx = ContextExtractor.extract_from_args((wrapper,), {})
        assert ctx.agent_id == "agent-1"
        assert ctx.session_id == "session-1"
        assert ctx.workspace_id == "default-ws"
        assert ctx.user_context is wrapper

    def test_extract_from_object_with_ids(self) -> None:
        """Test extraction from object with ID fields directly."""

        @dataclass
        class DirectContext:
            agent_id: str
            session_id: str
            user_id: str
            roles: list[str]

        obj = DirectContext(
            agent_id="direct-agent",
            session_id="direct-session",
            user_id="user-42",
            roles=["reader", "writer"],
        )

        ctx = ContextExtractor.extract_from_args((obj,), {})
        # Won't match because DirectContext doesn't have "context" attribute
        # So it will try to extract from DirectContext itself
        assert ctx.user_context is None  # No context attr found

    def test_extract_with_ctx_attribute(self) -> None:
        """Test extraction from object with .ctx attribute."""

        @dataclass
        class InnerData:
            agent_id: str
            workspace_id: str

        @dataclass
        class CtxWrapper:
            ctx: InnerData

        inner = InnerData(agent_id="ctx-agent", workspace_id="ws-123")
        wrapper = CtxWrapper(ctx=inner)

        ctx = ContextExtractor.extract_from_args((wrapper,), {})
        assert ctx.agent_id == "ctx-agent"
        assert ctx.workspace_id == "ws-123"
        assert ctx.user_context is wrapper

    def test_extract_roles_list(self) -> None:
        """Test extraction of roles as list."""

        @dataclass
        class Inner:
            roles: list[str]

        @dataclass
        class Wrapper:
            context: Inner

        inner = Inner(roles=["admin", "user"])
        wrapper = Wrapper(context=inner)

        ctx = ContextExtractor.extract_from_args((wrapper,), {})
        assert ctx.roles == ["admin", "user"]

    def test_extract_roles_tuple(self) -> None:
        """Test extraction of roles as tuple."""

        @dataclass
        class Inner:
            permissions: tuple[str, ...]

        @dataclass
        class Wrapper:
            context: Inner

        inner = Inner(permissions=("read", "write"))
        wrapper = Wrapper(context=inner)

        ctx = ContextExtractor.extract_from_args((wrapper,), {})
        assert ctx.roles == ["read", "write"]

    def test_extract_metadata(self) -> None:
        """Test extraction of metadata."""

        @dataclass
        class Inner:
            metadata: dict[str, Any]

        @dataclass
        class Wrapper:
            context: Inner

        inner = Inner(metadata={"request_id": "req-123", "trace_id": "tr-456"})
        wrapper = Wrapper(context=inner)

        ctx = ContextExtractor.extract_from_args((wrapper,), {})
        assert ctx.metadata == {"request_id": "req-123", "trace_id": "tr-456"}

    def test_alternative_field_names(self) -> None:
        """Test alternative field names for IDs."""

        @dataclass
        class Inner:
            assistant_id: str  # Alternative for agent_id
            conversation_id: str  # Alternative for session_id
            tenant_id: str  # Alternative for workspace_id
            end_user_id: str  # Alternative for user_id

        @dataclass
        class Wrapper:
            context: Inner

        inner = Inner(
            assistant_id="asst-1",
            conversation_id="conv-1",
            tenant_id="tenant-1",
            end_user_id="enduser-1",
        )
        wrapper = Wrapper(context=inner)

        ctx = ContextExtractor.extract_from_args((wrapper,), {})
        assert ctx.agent_id == "asst-1"
        assert ctx.session_id == "conv-1"
        assert ctx.workspace_id == "tenant-1"
        assert ctx.user_id == "enduser-1"

    def test_extract_from_none(self) -> None:
        """Test extraction handles None gracefully."""
        ctx = ContextExtractor.extract_from_args((None,), {})
        assert ctx.agent_id is None
        assert ctx.session_id is None


class TestCreateContextFromArgs:
    """Tests for create_context_from_args convenience function."""

    def test_delegates_to_extractor(self) -> None:
        """Test that create_context_from_args delegates properly."""

        @dataclass
        class Inner:
            agent_id: str

        @dataclass
        class Wrapper:
            context: Inner

        inner = Inner(agent_id="test-agent")
        wrapper = Wrapper(context=inner)

        ctx = create_context_from_args((wrapper,), {})
        assert ctx.agent_id == "test-agent"
        assert ctx.user_context is wrapper


@dataclass
class MockUserContext:
    """Mock context for integration tests."""

    agent_id: str
    session_id: str = ""


@dataclass
class MockRunContextWrapper:
    """Mock wrapper for integration tests."""

    context: MockUserContext


@dataclass
class MockCtxWrapper:
    """Mock wrapper with ctx attribute."""

    ctx: MockUserContext


class TestContextIntegrationWithAirlock:
    """Integration tests for context with @Airlock decorator."""

    def test_context_available_during_execution(self) -> None:
        """Test that context is available inside decorated function."""
        from agent_airlock import Airlock

        captured_context: list[AirlockContext[Any] | None] = []

        @Airlock()
        def my_tool(_ctx: MockRunContextWrapper, query: str) -> str:
            captured_context.append(get_current_context())
            return f"Query: {query}"

        wrapper = MockRunContextWrapper(
            context=MockUserContext(agent_id="agent-x", session_id="sess-y")
        )
        result = my_tool(wrapper, query="test")

        assert result == "Query: test"
        assert len(captured_context) == 1
        assert captured_context[0] is not None
        assert captured_context[0].agent_id == "agent-x"
        assert captured_context[0].session_id == "sess-y"

    @pytest.mark.asyncio
    async def test_context_available_in_async_function(self) -> None:
        """Test that context is available inside async decorated function."""
        from agent_airlock import Airlock

        captured_context: list[AirlockContext[Any] | None] = []

        @Airlock()
        async def async_tool(_ctx: MockCtxWrapper, data: str) -> str:
            captured_context.append(get_current_context())
            return data.upper()

        wrapper = MockCtxWrapper(ctx=MockUserContext(agent_id="async-agent"))
        result = await async_tool(wrapper, data="hello")

        assert result == "HELLO"
        assert len(captured_context) == 1
        assert captured_context[0] is not None
        assert captured_context[0].agent_id == "async-agent"

    def test_context_not_available_without_wrapper(self) -> None:
        """Test that context has None values when no wrapper provided."""
        from agent_airlock import Airlock

        captured_context: list[AirlockContext[Any] | None] = []

        @Airlock()
        def simple_tool(x: int) -> int:
            captured_context.append(get_current_context())
            return x * 2

        result = simple_tool(x=5)

        assert result == 10
        assert len(captured_context) == 1
        assert captured_context[0] is not None
        assert captured_context[0].agent_id is None
        assert captured_context[0].session_id is None


@dataclass
class PolicyMockInner:
    """Inner context for policy tests."""

    agent_id: str


@dataclass
class PolicyMockWrapper:
    """Wrapper for policy tests."""

    context: PolicyMockInner


class TestDynamicPolicyResolution:
    """Tests for dynamic policy resolution based on context."""

    def test_policy_resolver_called_with_context(self) -> None:
        """Test that policy resolver receives context."""
        from agent_airlock import Airlock, SecurityPolicy

        received_contexts: list[AirlockContext[Any]] = []

        def policy_resolver(ctx: AirlockContext[Any]) -> SecurityPolicy:
            received_contexts.append(ctx)
            return SecurityPolicy(allowed_tools=["resolver_test_tool"])

        @Airlock(policy=policy_resolver)
        def resolver_test_tool(_ctx: PolicyMockWrapper, x: int) -> int:
            return x

        wrapper = PolicyMockWrapper(context=PolicyMockInner(agent_id="policy-agent"))
        result = resolver_test_tool(wrapper, x=42)

        assert result == 42
        assert len(received_contexts) == 1
        assert received_contexts[0].agent_id == "policy-agent"

    def test_policy_resolver_can_deny(self) -> None:
        """Test that policy resolver can return a denying policy."""
        from agent_airlock import Airlock, SecurityPolicy

        def strict_resolver(_ctx: AirlockContext[Any]) -> SecurityPolicy:
            # Deny by putting the tool in denied_tools
            return SecurityPolicy(denied_tools=["denied_tool_v2"])

        @Airlock(policy=strict_resolver)
        def denied_tool_v2(x: int) -> int:
            return x

        result = denied_tool_v2(x=10)

        assert isinstance(result, dict)
        assert result.get("success") is False
        assert result.get("status") == "blocked"

    def test_policy_resolver_error_handling(self) -> None:
        """Test that policy resolver errors are handled gracefully."""
        from agent_airlock import Airlock

        def failing_resolver(_ctx: AirlockContext[Any]) -> None:
            raise ValueError("Resolver failed!")

        @Airlock(policy=failing_resolver)  # type: ignore[arg-type]
        def tool_with_failing_resolver(x: int) -> int:
            return x

        result = tool_with_failing_resolver(x=5)

        assert isinstance(result, dict)
        assert result.get("success") is False
        assert result.get("status") == "blocked"
        assert "Resolver failed" in str(result.get("error", ""))

    def test_static_policy_still_works(self) -> None:
        """Test that static SecurityPolicy still works."""
        from agent_airlock import Airlock, SecurityPolicy

        policy = SecurityPolicy(allowed_tools=["static_tool"])

        @Airlock(policy=policy)
        def static_tool(x: int) -> int:
            return x * 2

        result = static_tool(x=3)
        assert result == 6
