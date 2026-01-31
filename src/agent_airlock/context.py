"""Context management for Agent-Airlock.

Provides request-scoped context that persists across the decorator boundary.
This enables features like:
- Session isolation for multi-tenant applications
- Workspace-specific policy resolution
- Agent identity tracking
- Audit logging with full context

Uses Python's contextvars for thread-safe, async-safe context propagation.

Example:
    from agent_airlock import Airlock
    from agent_airlock.context import AirlockContext, get_current_context

    @Airlock()
    async def my_tool(ctx: RunContextWrapper[WorkspaceContext], query: str) -> str:
        # Context is automatically extracted and available
        current = get_current_context()
        print(f"Workspace: {current.workspace_id}")
        print(f"Agent: {current.agent_id}")
        return result
"""

from __future__ import annotations

from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar

import structlog

logger = structlog.get_logger("agent-airlock.context")

T = TypeVar("T")

# Context variable for current request/session
_current_context: ContextVar[AirlockContext[Any]] = ContextVar(
    "airlock_context",
    default=None,  # type: ignore[arg-type]
)


@dataclass
class AirlockContext(Generic[T]):
    """Context holder for request-scoped data.

    This context is automatically populated when @Airlock decorator
    intercepts a tool call. It's available throughout the request
    via get_current_context().

    Attributes:
        agent_id: Identifier of the AI agent making the call.
        session_id: Session or conversation identifier.
        workspace_id: Workspace/tenant identifier for multi-tenant apps.
        user_id: End-user identifier (if available).
        roles: List of roles for RBAC.
        user_context: The original context object (e.g., RunContextWrapper).
        metadata: Additional arbitrary metadata.

    Example:
        # Access context from anywhere in the call stack
        ctx = get_current_context()
        if ctx and ctx.workspace_id == "enterprise":
            # Apply enterprise-specific logic
            pass
    """

    agent_id: str | None = None
    session_id: str | None = None
    workspace_id: str | None = None
    user_id: str | None = None
    roles: list[str] = field(default_factory=list)
    user_context: T | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    _token: Token[AirlockContext[Any]] | None = field(default=None, repr=False)

    def __enter__(self) -> AirlockContext[T]:
        """Enter the context, making it the current context."""
        self._token = _current_context.set(self)
        return self

    def __exit__(self, *args: Any) -> None:
        """Exit the context, restoring the previous context."""
        if self._token is not None:
            _current_context.reset(self._token)
            self._token = None

    async def __aenter__(self) -> AirlockContext[T]:
        """Async enter (same as sync, contextvars work with async)."""
        return self.__enter__()

    async def __aexit__(self, *args: Any) -> None:
        """Async exit (same as sync)."""
        self.__exit__(*args)

    def with_metadata(self, **kwargs: Any) -> AirlockContext[T]:
        """Create a copy with additional metadata.

        Args:
            **kwargs: Metadata key-value pairs to add.

        Returns:
            New context with merged metadata.
        """
        new_metadata = {**self.metadata, **kwargs}
        return AirlockContext(
            agent_id=self.agent_id,
            session_id=self.session_id,
            workspace_id=self.workspace_id,
            user_id=self.user_id,
            roles=list(self.roles),
            user_context=self.user_context,
            metadata=new_metadata,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization/logging."""
        return {
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "workspace_id": self.workspace_id,
            "user_id": self.user_id,
            "roles": self.roles,
            "metadata": self.metadata,
        }


def get_current_context() -> AirlockContext[Any] | None:
    """Get the current Airlock context.

    Returns:
        The current context if inside an @Airlock-decorated call, else None.

    Example:
        @Airlock()
        def my_tool(query: str) -> str:
            ctx = get_current_context()
            if ctx:
                print(f"Agent: {ctx.agent_id}")
            return "result"
    """
    return _current_context.get()


def set_current_context(context: AirlockContext[Any]) -> Token[AirlockContext[Any]]:
    """Set the current Airlock context.

    This is primarily used internally by the @Airlock decorator.
    For normal usage, use AirlockContext as a context manager.

    Args:
        context: The context to set.

    Returns:
        Token for resetting the context later.
    """
    return _current_context.set(context)


def reset_context(token: Token[AirlockContext[Any]]) -> None:
    """Reset the context to its previous value.

    Args:
        token: Token from set_current_context.
    """
    _current_context.reset(token)


class ContextExtractor:
    """Extracts context from function arguments.

    Inspects function arguments to find context objects that match
    known patterns (e.g., RunContextWrapper, custom context classes).

    This is used by the @Airlock decorator to automatically extract
    context from tool calls.
    """

    # Known context attribute names to look for
    CONTEXT_ATTRS = frozenset(
        {
            "context",  # OpenAI Agents SDK RunContextWrapper.context
            "ctx",
            "request_context",
            "session_context",
        }
    )

    # Known ID field names
    AGENT_ID_ATTRS = frozenset({"agent_id", "agent", "assistant_id"})
    SESSION_ID_ATTRS = frozenset({"session_id", "session", "conversation_id", "thread_id"})
    WORKSPACE_ID_ATTRS = frozenset({"workspace_id", "workspace", "tenant_id", "org_id"})
    USER_ID_ATTRS = frozenset({"user_id", "user", "end_user_id"})

    @classmethod
    def extract_from_args(
        cls,
        args: tuple[Any, ...],
        _kwargs: dict[str, Any],
    ) -> AirlockContext[Any]:
        """Extract context from function arguments.

        Looks for context objects in positional and keyword arguments.

        Args:
            args: Positional arguments to the function.
            kwargs: Keyword arguments to the function.

        Returns:
            Extracted context (may have None values if not found).
        """
        # Check first positional arg (common pattern: ctx as first arg)
        user_context = None
        inner_context = None

        if args:
            first_arg = args[0]
            # Check if it looks like a context wrapper
            for attr in cls.CONTEXT_ATTRS:
                if hasattr(first_arg, attr):
                    user_context = first_arg
                    inner_context = getattr(first_arg, attr, None)
                    break

        # Extract IDs from the inner context or user context
        source = inner_context or user_context

        return AirlockContext(
            agent_id=cls._extract_field(source, cls.AGENT_ID_ATTRS),
            session_id=cls._extract_field(source, cls.SESSION_ID_ATTRS),
            workspace_id=cls._extract_field(source, cls.WORKSPACE_ID_ATTRS),
            user_id=cls._extract_field(source, cls.USER_ID_ATTRS),
            roles=cls._extract_roles(source),
            user_context=user_context,
            metadata=cls._extract_metadata(source),
        )

    @classmethod
    def _extract_field(cls, obj: Any, field_names: frozenset[str]) -> str | None:
        """Extract a field value from an object.

        Args:
            obj: Object to extract from.
            field_names: Possible field names.

        Returns:
            Field value as string, or None.
        """
        if obj is None:
            return None

        for name in field_names:
            value = getattr(obj, name, None)
            if value is not None:
                return str(value)

        return None

    @classmethod
    def _extract_roles(cls, obj: Any) -> list[str]:
        """Extract roles from an object.

        Args:
            obj: Object to extract from.

        Returns:
            List of role strings.
        """
        if obj is None:
            return []

        for attr in ("roles", "permissions", "scopes"):
            value = getattr(obj, attr, None)
            if value is not None:
                if isinstance(value, (list, tuple, set, frozenset)):
                    return [str(r) for r in value]
                return [str(value)]

        return []

    @classmethod
    def _extract_metadata(cls, obj: Any) -> dict[str, Any]:
        """Extract metadata from an object.

        Args:
            obj: Object to extract from.

        Returns:
            Metadata dictionary.
        """
        if obj is None:
            return {}

        for attr in ("metadata", "extra", "context_data"):
            value = getattr(obj, attr, None)
            if isinstance(value, dict):
                return dict(value)

        return {}


def create_context_from_args(
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
) -> AirlockContext[Any]:
    """Create an AirlockContext from function arguments.

    Convenience function that uses ContextExtractor.

    Args:
        args: Positional arguments.
        kwargs: Keyword arguments.

    Returns:
        Extracted context.
    """
    return ContextExtractor.extract_from_args(args, kwargs)
