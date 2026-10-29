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

import dataclasses
import enum
import numbers
from collections.abc import Iterable, Mapping, Sequence, Set
from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Generic, TypeVar

from pydantic import BaseModel

from ._arg_walk import is_framework_object
from ._log import structlog

if TYPE_CHECKING:
    from pydantic import GetCoreSchemaHandler
    from pydantic_core import CoreSchema

    from .amplification import AmplificationDecision

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
    # V0.8.6 camouflage-resistant guard. Counter of completed invocations
    # whose output has flowed back into the model context (each one a
    # potential domain-camouflaged injection vector per arXiv:2605.22001).
    # SecurityPolicy.check_reauthorization() reads these.
    untrusted_reinvocation_count: dict[str, int] = field(default_factory=dict)
    # V0.8.74 per-run amplification decision (issue #142). Written by the
    # @Airlock seam right after the policy check and read at audit time, so
    # every audit call site can carry the run's call/token counters without
    # threading a new parameter through each one.
    _amplification: AmplificationDecision | None = field(default=None, repr=False)
    _authorized_once: set[str] = field(default_factory=set, repr=False)
    _token: Token[AirlockContext[Any]] | None = field(default=None, repr=False)

    def __class_getitem__(cls, params: Any) -> Any:
        """``AirlockContext[X]`` is ``AirlockContext`` at run time; type checkers still
        read the parameter.

        Pydantic builds a parametrized standard-library dataclass from a dict without
        asking :meth:`__get_pydantic_core_schema__`, so until 0.10.28 a field typed
        ``AirlockContext[Any]`` let a model's JSON construct one.
        """
        return cls

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        """Pydantic accepts an existing instance and never builds one from JSON or a dict.

        An ``AirlockContext`` carries identity, roles and host metadata (the access-token
        claims, the budget tags), so only host code may make one: a run wrapper whose
        context is an ``AirlockContext`` is read as the host's
        (:meth:`ContextExtractor.run_wrapper`).
        """
        from pydantic_core import core_schema

        return core_schema.is_instance_schema(cls)

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
        clone: AirlockContext[T] = AirlockContext(
            agent_id=self.agent_id,
            session_id=self.session_id,
            workspace_id=self.workspace_id,
            user_id=self.user_id,
            roles=list(self.roles),
            user_context=self.user_context,
            metadata=new_metadata,
            untrusted_reinvocation_count=dict(self.untrusted_reinvocation_count),
        )
        clone._authorized_once = set(self._authorized_once)
        return clone

    def authorize_once(self, tool_name: str) -> None:
        """Grant a single subsequent invocation of ``tool_name`` past the
        camouflage-resistant reauthorization threshold.

        The grant is consumed by the next ``SecurityPolicy.check_reauthorization``
        for this tool. Use when the harness has independently verified that
        the next call's arguments did NOT originate from prior tool output.
        """
        self._authorized_once.add(tool_name)

    def mark_untrusted_output(self, tool_name: str) -> None:
        """Record that ``tool_name`` produced output that flows back into
        the model context, so any subsequent invocation past threshold
        requires a fresh ``authorize_once`` grant under
        ``reauth_on_untrusted_reinvocation``.
        """
        self.untrusted_reinvocation_count[tool_name] = (
            self.untrusted_reinvocation_count.get(tool_name, 0) + 1
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


#: What :func:`_read_attribute` returns for an attribute an object does not have.
_ABSENT = object()


def _read_attribute(obj: Any, name: str) -> Any:
    """``obj.<name>``, or :data:`_ABSENT` when it has none or reading it raised."""
    try:
        return getattr(obj, name)
    except Exception:  # noqa: BLE001 - an attribute that cannot be read is not there
        return _ABSENT


@dataclass(frozen=True)
class RunWrapper:
    """A first positional argument ``@Airlock`` reads as the host's run wrapper.

    Attributes:
        wrapper: The argument itself.
        attribute: The :attr:`ContextExtractor.CONTEXT_ATTRS` name its context is read
            from: the first of them it has.
        context: The value at that attribute. The call's identity, roles and metadata are
            read from it.
        host_object: True when model JSON cannot have built the wrapper itself (an agent
            framework's object, or a plain host object), so steps 2.7, 3 and 5 do not walk
            it. False when only its ``AirlockContext`` vouches for it: a dataclass, model
            or tuple wrapper is walked like any other argument, its ``AirlockContext``
            aside, since its other fields may be the model's.
    """

    wrapper: Any
    attribute: str
    context: Any
    host_object: bool


def _model_json_cannot_build(value: Any) -> bool:
    """Whether ``value`` is a plain host object: one no model JSON can have produced.

    Pydantic builds models, dataclasses (its own and the standard library's), mappings,
    sequences, sets, named tuples, strings, bytes, numbers and enums from JSON, and any
    type that defines ``__get_pydantic_core_schema__`` however that schema says. An
    instance of any other type came from host code.
    """
    if isinstance(value, type):
        return False
    if isinstance(
        value,
        (BaseModel, Mapping, Sequence, Set, str, bytes, bytearray, memoryview, numbers.Number),
    ):
        return False
    if isinstance(value, enum.Enum) or dataclasses.is_dataclass(value):
        return False
    return not hasattr(type(value), "__get_pydantic_core_schema__")


class ContextExtractor:
    """Reads the context the host passed with a call.

    A framework passes the host's run wrapper (the OpenAI Agents SDK's
    ``RunContextWrapper``, say) as a tool's first positional argument, carrying a context
    object at one of :attr:`CONTEXT_ATTRS`; ``@Airlock`` reads the call's identity, roles
    and metadata from that object. Only an argument model JSON cannot have built counts
    as a run wrapper (:meth:`run_wrapper`). Until 0.10.28 any first argument with an
    attribute of one of those names did, so a tool author's own model with a ``context``
    or ``ctx`` field let the model write the call's identity, roles, budget tags and
    access-token claims, and hid that argument from the value gates.
    """

    #: The attribute names a run wrapper carries its context at, in the order they are
    #: read: the first one an object has is the one read. A frozenset until 0.10.28, so
    #: which of two present names won depended on ``PYTHONHASHSEED``.
    CONTEXT_ATTRS: tuple[str, ...] = ("context", "ctx", "request_context", "session_context")

    # The names each id is read from, in order: the first one present wins.
    AGENT_ID_ATTRS: tuple[str, ...] = ("agent_id", "agent", "assistant_id")
    SESSION_ID_ATTRS: tuple[str, ...] = ("session_id", "session", "conversation_id", "thread_id")
    WORKSPACE_ID_ATTRS: tuple[str, ...] = ("workspace_id", "workspace", "tenant_id", "org_id")
    USER_ID_ATTRS: tuple[str, ...] = ("user_id", "user", "end_user_id")

    @classmethod
    def run_wrapper(cls, value: Any) -> RunWrapper | None:
        """``value`` as the host's run wrapper, or None when it is an ordinary argument.

        ``value`` must carry a context at one of :attr:`CONTEXT_ATTRS`, and model JSON
        must be unable to have built it:

        - it is an agent framework's own object, verified against the framework's
          installed distribution (``_arg_walk.is_framework_object``), and not a pydantic
          model, which JSON builds however the framework defines it;
        - or the context it carries is an :class:`AirlockContext`, which pydantic never
          builds from JSON or a dict;
        - or it is a plain host object: not a pydantic model, dataclass, mapping,
          sequence, set, named tuple, string, bytes, number or enum, and of a type that
          defines no ``__get_pydantic_core_schema__``.

        Anything else, a tool author's own model, dataclass, TypedDict or named tuple with
        a ``context`` field included, is an ordinary argument: never read for identity or
        metadata, and walked by steps 2.7, 3 and 5.

        Args:
            value: The call's first positional argument.

        Returns:
            The :class:`RunWrapper`, or None.
        """
        found = cls._context_attribute(value)
        if found is None:
            return None
        attribute, carried = found
        if (is_framework_object(value) and not isinstance(value, BaseModel)) or (
            _model_json_cannot_build(value)
        ):
            return RunWrapper(value, attribute, carried, host_object=True)
        if isinstance(carried, AirlockContext):
            return RunWrapper(value, attribute, carried, host_object=False)
        return None

    @classmethod
    def _context_attribute(cls, value: Any) -> tuple[str, Any] | None:
        """The first :attr:`CONTEXT_ATTRS` name ``value`` has, and the value there."""
        for attribute in cls.CONTEXT_ATTRS:
            carried = _read_attribute(value, attribute)
            if carried is not _ABSENT:
                return attribute, carried
        return None

    @classmethod
    def extract_from_args(
        cls,
        args: tuple[Any, ...],
        _kwargs: dict[str, Any],
    ) -> AirlockContext[Any]:
        """Read the context the host passed with a call: from its first positional argument.

        Only ``args[0]`` is read, and only when :meth:`run_wrapper` accepts it as the
        host's run wrapper. Keyword arguments are not read (``_kwargs`` is accepted for
        compatibility), so a FastMCP ``ctx``, which arrives by keyword, is not either.
        The identity, roles and metadata come from the context the wrapper carries; when
        that is falsy, nothing is read. Until 0.10.28 the wrapper itself was then read, so
        a model's object with ``context=None`` supplied them.

        Args:
            args: Positional arguments to the function.
            _kwargs: Keyword arguments to the function; not read.

        Returns:
            The extracted context, with ``user_context`` set to the run wrapper; every
            field empty when the call carries none.
        """
        found = cls.run_wrapper(args[0]) if args else None
        if found is None:
            return AirlockContext()
        source = found.context
        return AirlockContext(
            agent_id=cls._extract_field(source, cls.AGENT_ID_ATTRS),
            session_id=cls._extract_field(source, cls.SESSION_ID_ATTRS),
            workspace_id=cls._extract_field(source, cls.WORKSPACE_ID_ATTRS),
            user_id=cls._extract_field(source, cls.USER_ID_ATTRS),
            roles=cls._extract_roles(source),
            user_context=found.wrapper,
            metadata=cls._extract_metadata(source),
        )

    @classmethod
    def _extract_field(cls, obj: Any, field_names: Iterable[str]) -> str | None:
        """Extract a field value from an object.

        Args:
            obj: Object to extract from.
            field_names: Possible field names, in the order they are tried.

        Returns:
            Field value as string, or None.
        """
        if obj is None:
            return None

        for name in field_names:
            value = _read_attribute(obj, name)
            if value is not _ABSENT and value is not None:
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
            value = _read_attribute(obj, attr)
            if value is not _ABSENT and value is not None:
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
            value = _read_attribute(obj, attr)
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


def _reset_context() -> None:
    """Reset the global context state for testing.

    This function should only be used in tests to ensure isolation
    between test cases. Note that contextvars are automatically
    isolated per asyncio.Task, so this mainly clears any stale state.
    """
    import contextlib

    # ContextVars don't have a global reset, but we can set to None
    # This only affects the current context (thread/task)
    with contextlib.suppress(ValueError):
        _current_context.set(None)  # type: ignore[arg-type]
