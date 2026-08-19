"""Handle validation — a bearer capability in the argument stream, checked like one.

Why this exists
---------------
The MCP **2026-07-28** revision removed the protocol-level session (SEP-2575). A server
that needs cross-call state now *mints a handle from one tool and the model passes it back
as an argument to another* (SEP-2567). That moves a value which grants continuity out of
trusted transport state and into the same channel as attacker-influenced tool inputs.

A handle in the argument stream is a **bearer capability**: possession is authority. Type
validation alone accepts three distinct forgeries, because all three are well-typed strings:

1. **Cross-scope replay.** A model that has seen handle ``H`` issued for scope *A* passes
   ``H`` to a tool operating on scope *B*.
2. **Expiry replay.** A handle that was valid an hour ago is presented again.
3. **Read-from-context.** A handle the model *read* (out of a transcript, a log, another
   tenant's output) rather than one that was *issued to this run*.

A fourth follows from the first: a handle minted by a different tool than the field expects
is a confused-deputy hand-off, even inside the right scope.

What this module adds over ``mcp_spec.handle_trust``
----------------------------------------------------
:mod:`agent_airlock.mcp_spec.handle_trust` already ships
:func:`~agent_airlock.mcp_spec.handle_trust.validate_handle_minted`, but the operator has to
supply the ``minted`` set themselves — nothing in airlock *tracks* issuance, and nothing
records who minted a handle, for what, or for how long. This module supplies the missing
ledger and makes the check a **declared part of the tool contract** rather than a call the
operator has to remember to write:

.. code-block:: python

    @Airlock()
    def read_checkpoint(session: HandleField(issuer="mnemo.checkpoint", scope="workspace")) -> str:
        ...

:meth:`HandleLedger.minted` returns exactly the set that primitive wants, so the two compose
rather than duplicate — see ``docs/mcp/stateless-trust-boundary.md``.

How it composes with the layers already in the pipeline
--------------------------------------------------------
* **Ghost-argument stripping** runs first (step 1 of ``@Airlock``) and this validation runs
  inside Pydantic strict validation (step 7), so a handle the model *invented* on a tool
  that never declared one is gone before it is ever looked up. The declaration is what makes
  the handle checkable at all, which is the same trust distinction SEP-2567 draws.
  **Known limit:** a tool whose signature ends in ``**kwargs`` declares nothing, so a handle
  smuggled through it is neither ghost-stripped nor ``HandleField``-validated. That hole is
  closed by the existing ``mcp_spec_2026_07_28_handle_trust`` preset's ``check_tool_call``,
  and :func:`assert_handles_declared` is the one-line front door to it.
* **Second known limit — ``sandbox=True``.** When a real sandbox backend is available,
  ``@Airlock`` serialises the *undecorated* function into the micro-VM instead of calling
  the Pydantic-validated wrapper, so **no** ``Annotated`` validator runs — ``SafePath`` and
  ``SafeURL`` are in exactly the same position, and have been since they shipped. This is a
  property of the sandbox dispatch path, not of this module, and it is not something a
  per-run ledger could paper over anyway: the ledger is in-process by design, and shipping
  it into a remote VM would mean the network call this module refuses to make. Validate
  handles in the parent process (the default, non-sandboxed path), or keep the minting and
  consuming tools outside the sandbox. Pinned by
  ``TestSandboxDispatchSkipsTheCheck`` so the behaviour cannot change unnoticed.
* **The verdict set does not grow.** A rejection is a *deny*, expressed through the
  ``AirlockResponse`` shape that already exists, with its own :class:`BlockReason` so the
  four cases stay distinguishable in the audit log. allow / deny / escalate remain the only
  three verdicts.

Deny-by-default
---------------
Every failure mode denies, and so does the absence of the mechanism: with **no ledger bound
to the run at all**, a declared handle argument has by definition not been issued here, and
is rejected. There is deliberately no "observe only" mode — a knob that downgrades a
capability check to a warning is the thing this module exists to remove.

The ledger is per-run and in-memory. No database, no network call, no cloud mode, no new
runtime dependency: stdlib plus the Pydantic that airlock's core already requires.
"""

from __future__ import annotations

import secrets
import threading
import time
from collections.abc import Generator
from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from enum import Enum
from typing import Annotated, Any

from pydantic import AfterValidator

from ._log import structlog

logger = structlog.get_logger("agent-airlock.handles")

__all__ = [
    "HandleField",
    "HandleLedger",
    "HandleRejection",
    "HandleRejectionReason",
    "IssuedHandle",
    "assert_handles_declared",
    "bind_ledger",
    "current_ledger",
    "handle_run",
    "issue_handle",
]

#: Prefix on every handle this ledger mints. Not a security control — a debugging aid, so an
#: opaque string in a log is identifiable as an airlock handle rather than a UUID or a JWT.
HANDLE_PREFIX = "ah_"

#: Bytes of entropy per minted handle. 32 bytes → 256 bits, well past guessing range; the
#: threat model here is replay and confusion, not brute force, but there is no reason to
#: leave the weaker property on the table.
_HANDLE_ENTROPY_BYTES = 32

#: Stable sentinel that opens every rejection message. :func:`handle_rejection_from` uses it
#: as a fallback route back to the structured reason when Pydantic does not hand back the
#: original exception object (the ``ctx["error"]`` contract is not pinned across the
#: ``pydantic>=2.0,<3.0`` range airlock supports).
REJECTION_SENTINEL = "AIRLOCK_HANDLE"


class HandleRejectionReason(str, Enum):
    """Why a presented handle was refused. One member per failure mode, deliberately.

    Collapsing these into a single "bad handle" hides the difference between *an integration
    that was never wired up* (``NOT_ISSUED`` on every call) and *an agent replaying a
    capability across scopes* (``WRONG_SCOPE`` on some calls). Those need different responses
    from whoever reads the audit log.
    """

    NOT_ISSUED = "handle_not_issued"
    """Never minted in this run — includes the case where no ledger is bound at all."""

    WRONG_ISSUER = "handle_wrong_issuer"
    """Minted in this run, but by a different tool than the field declares."""

    WRONG_SCOPE = "handle_wrong_scope"
    """Minted in this run by the right tool, but for a different scope."""

    EXPIRED = "handle_expired"
    """Minted correctly, but past its TTL at the moment it was presented."""


def redact(handle: object) -> str:
    """Return a log-safe preview of a handle.

    A handle is a bearer capability, so echoing it whole into an error message would push the
    capability straight back into model context — and into the audit log, and into whatever
    ships those logs onward. Enough characters survive to correlate two records; not enough
    to replay.
    """
    text = handle if isinstance(handle, str) else repr(handle)
    keep = len(HANDLE_PREFIX) + 6
    return text if len(text) <= keep else f"{text[:keep]}…({len(text)} chars)"


class HandleRejection(ValueError):
    """A presented handle failed its contract.

    Subclasses ``ValueError`` so that raising it from a Pydantic ``AfterValidator`` is wrapped
    into the ordinary ``ValidationError`` flow — which is how the rejection reaches
    ``@Airlock``'s existing self-healing response path without a new branch in ``core.py``.
    """

    def __init__(
        self,
        reason: HandleRejectionReason,
        message: str,
        *,
        field_name: str | None = None,
        expected_issuer: str | None = None,
        expected_scope: str | None = None,
        handle_preview: str = "",
    ) -> None:
        super().__init__(f"{REJECTION_SENTINEL}[{reason.value}]: {message}")
        #: Which of the four failure modes this is.
        self.reason = reason
        #: The declared parameter that carried the handle, when known.
        self.field_name = field_name
        #: The issuer the contract declared (never the one the handle actually had — that
        #: would leak another tool's minting activity back to the model).
        self.expected_issuer = expected_issuer
        #: The scope the contract declared.
        self.expected_scope = expected_scope
        #: Redacted preview of the offending value.
        self.handle_preview = handle_preview

    @property
    def audit_event(self) -> dict[str, Any]:
        """Structured, machine-readable description of the rejection."""
        return {
            "event": "airlock.handle.reject",
            "spec": "SEP-2567",
            "reason": self.reason.value,
            "field": self.field_name,
            "expected_issuer": self.expected_issuer,
            "expected_scope": self.expected_scope,
            "handle": self.handle_preview,
        }


@dataclass(frozen=True)
class IssuedHandle:
    """One entry in the issuance ledger.

    Frozen: an entry is a record of something that already happened. Expiry is evaluated
    against ``issued_at + ttl_seconds`` at presentation time rather than by mutating the
    record, so the ledger never needs a sweeper thread.
    """

    handle: str
    issuer: str
    """The tool that minted it. Compared against the ``issuer`` the field declares."""
    scope: str
    """What it was minted *for*. Compared against the ``scope`` the field declares."""
    run_id: str
    issued_at: float
    """Wall-clock epoch seconds, from :func:`time.time`."""
    ttl_seconds: float | None = None
    """``None`` means it lives as long as the run does."""

    def expires_at(self) -> float | None:
        """Epoch second at which this handle stops being valid, or ``None`` if it does not."""
        return None if self.ttl_seconds is None else self.issued_at + self.ttl_seconds

    def is_expired(self, now: float | None = None) -> bool:
        """Whether the TTL has elapsed. A handle with no TTL is never expired."""
        deadline = self.expires_at()
        if deadline is None:
            return False
        return (time.time() if now is None else now) >= deadline


class HandleLedger:
    """Per-run, in-process record of every handle minted during the run.

    Thread-safe: a run can fan out across threads, and two of them minting concurrently must
    not lose an entry. The lock is held only around dict mutation, never across user code.

    The ledger is intentionally *not* persisted. A handle's authority is scoped to the run
    that was issued it, so a ledger that outlived the run would be re-introducing the durable
    ambient session that SEP-2575 removed.
    """

    def __init__(self, run_id: str | None = None) -> None:
        #: Identifier for the run this ledger belongs to. Recorded on every entry so an audit
        #: reader can tell "issued in this run" from "issued in a run that happened to reuse
        #: the process".
        self.run_id = run_id or f"run_{secrets.token_hex(8)}"
        self._entries: dict[str, IssuedHandle] = {}
        self._lock = threading.Lock()

    # -- minting ---------------------------------------------------------------

    def issue(
        self,
        *,
        issuer: str,
        scope: str,
        ttl_seconds: float | None = None,
        handle: str | None = None,
    ) -> str:
        """Mint a handle and record it.

        Args:
            issuer: The tool doing the minting. A field declaring a different issuer will
                refuse the resulting handle.
            scope: What the handle grants access to (a workspace, a tenant, a document id —
                whatever the server's unit of isolation is).
            ttl_seconds: Optional lifetime. ``None`` means "as long as the run".
            handle: Supply the value instead of generating one. For tests and for servers
                that mint their own identifiers; a caller-supplied value gets no entropy
                guarantee from us.

        Returns:
            The handle string, to be returned to the model as this tool's output.

        Raises:
            ValueError: If ``issuer`` or ``scope`` is empty, or ``ttl_seconds`` is not
                positive. An empty scope would make every scope comparison vacuous.
        """
        if not issuer:
            raise ValueError("issuer must be a non-empty string")
        if not scope:
            raise ValueError("scope must be a non-empty string")
        if ttl_seconds is not None and ttl_seconds <= 0:
            raise ValueError(f"ttl_seconds must be positive, got {ttl_seconds!r}")

        if handle is not None:
            value = handle
        else:
            value = f"{HANDLE_PREFIX}{secrets.token_urlsafe(_HANDLE_ENTROPY_BYTES)}"
        entry = IssuedHandle(
            handle=value,
            issuer=issuer,
            scope=scope,
            run_id=self.run_id,
            issued_at=time.time(),
            ttl_seconds=ttl_seconds,
        )
        with self._lock:
            self._entries[value] = entry

        logger.debug(
            "handle_issued",
            issuer=issuer,
            scope=scope,
            run_id=self.run_id,
            ttl_seconds=ttl_seconds,
            handle=redact(value),
        )
        return value

    def revoke(self, handle: str) -> bool:
        """Drop a handle from the ledger. Returns whether it was there."""
        with self._lock:
            return self._entries.pop(handle, None) is not None

    # -- reading ---------------------------------------------------------------

    def lookup(self, handle: object) -> IssuedHandle | None:
        """Return the ledger entry for ``handle``, or ``None`` if it was never minted here."""
        if not isinstance(handle, str):
            return None
        with self._lock:
            return self._entries.get(handle)

    def minted(self) -> frozenset[str]:
        """Every handle this run has issued.

        This is exactly the ``minted`` argument
        :func:`~agent_airlock.mcp_spec.handle_trust.validate_handle_minted` expects, so the
        SEP-2567 primitive and this ledger compose instead of drifting apart.
        """
        with self._lock:
            return frozenset(self._entries)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    # -- checking --------------------------------------------------------------

    def validate(
        self,
        handle: object,
        *,
        issuer: str,
        scope: str,
        field_name: str | None = None,
        now: float | None = None,
    ) -> IssuedHandle:
        """Check a presented handle against the contract, or raise.

        The four checks run in the order a reader would want them reported: existence, then
        who minted it, then what for, then whether it is still alive. Reporting "expired"
        for a handle that was never issued would be a misleading diagnosis.

        Args:
            handle: The value the model supplied.
            issuer: Issuer the field declares.
            scope: Scope the field declares.
            field_name: Parameter name, for the error message.
            now: Epoch seconds to evaluate expiry against. Injectable so the TTL case is
                testable without sleeping.

        Returns:
            The matching :class:`IssuedHandle`.

        Raises:
            HandleRejection: With :attr:`~HandleRejection.reason` set to whichever of the
                four cases fired.
        """
        preview = redact(handle)
        entry = self.lookup(handle)

        if entry is None:
            raise HandleRejection(
                HandleRejectionReason.NOT_ISSUED,
                f"handle {preview} was not issued in this run "
                f"(run_id={self.run_id!r}); a handle is a bearer capability and is "
                f"honoured only where it was minted",
                field_name=field_name,
                expected_issuer=issuer,
                expected_scope=scope,
                handle_preview=preview,
            )

        if entry.issuer != issuer:
            raise HandleRejection(
                HandleRejectionReason.WRONG_ISSUER,
                f"handle {preview} was minted by a different tool than "
                f"{field_name or 'this parameter'} accepts (declared issuer={issuer!r})",
                field_name=field_name,
                expected_issuer=issuer,
                expected_scope=scope,
                handle_preview=preview,
            )

        if entry.scope != scope:
            raise HandleRejection(
                HandleRejectionReason.WRONG_SCOPE,
                f"handle {preview} was minted for a different scope than "
                f"{field_name or 'this parameter'} operates on (declared scope={scope!r})",
                field_name=field_name,
                expected_issuer=issuer,
                expected_scope=scope,
                handle_preview=preview,
            )

        if entry.is_expired(now):
            raise HandleRejection(
                HandleRejectionReason.EXPIRED,
                f"handle {preview} expired {entry.ttl_seconds}s after issue and cannot be "
                f"replayed; mint a fresh one",
                field_name=field_name,
                expected_issuer=issuer,
                expected_scope=scope,
                handle_preview=preview,
            )

        return entry


# ---------------------------------------------------------------------------
# Run binding
# ---------------------------------------------------------------------------
#
# A contextvar, matching how AirlockContext is propagated (see context.py): it is
# task-local under asyncio and thread-local otherwise, which is the behaviour a per-run
# ledger needs when one process serves several runs at once.

_ACTIVE_LEDGER: ContextVar[HandleLedger | None] = ContextVar("airlock_handle_ledger", default=None)


def current_ledger() -> HandleLedger | None:
    """The ledger bound to the current run, or ``None`` if no run is bound.

    ``None`` is not a permissive state. A declared handle argument with no ledger in scope is
    rejected as :attr:`HandleRejectionReason.NOT_ISSUED`.
    """
    return _ACTIVE_LEDGER.get()


def bind_ledger(ledger: HandleLedger | None) -> Token[HandleLedger | None]:
    """Bind ``ledger`` to the current context and return the reset token.

    Prefer :func:`handle_run`; this is the manual form for callers that own their own
    scoping (a framework adapter driving a run across several entry points, say).
    """
    return _ACTIVE_LEDGER.set(ledger)


def reset_ledger(token: Token[HandleLedger | None]) -> None:
    """Undo a :func:`bind_ledger`."""
    _ACTIVE_LEDGER.reset(token)


@contextmanager
def handle_run(
    run_id: str | None = None,
    ledger: HandleLedger | None = None,
) -> Generator[HandleLedger, None, None]:
    """Scope a handle ledger to a run.

    .. code-block:: python

        with handle_run("run-42") as ledger:
            token = open_session()          # mints into `ledger`
            read_checkpoint(session=token)  # validated against `ledger`

    On exit the previous binding is restored, so nesting works and a run cannot leak its
    capabilities into whatever ran before it.

    Args:
        run_id: Identifier recorded on every entry. Generated if omitted.
        ledger: Bind an existing ledger instead of creating one.

    Yields:
        The bound :class:`HandleLedger`.
    """
    active = ledger if ledger is not None else HandleLedger(run_id)
    token = bind_ledger(active)
    try:
        yield active
    finally:
        reset_ledger(token)


def issue_handle(*, issuer: str, scope: str, ttl_seconds: float | None = None) -> str:
    """Mint a handle into the ledger bound to the current run.

    Raises:
        RuntimeError: If no run is bound. Silently minting into a throwaway ledger would
            produce a handle that fails validation later, at a call site far from the bug.
    """
    ledger = current_ledger()
    if ledger is None:
        raise RuntimeError(
            "issue_handle() needs a ledger bound to the current run; wrap the run in "
            "`with handle_run(): ...` (or call HandleLedger.issue directly)"
        )
    return ledger.issue(issuer=issuer, scope=scope, ttl_seconds=ttl_seconds)


# ---------------------------------------------------------------------------
# The contract type
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _HandleValidator:
    """The ``AfterValidator`` callable behind :func:`HandleField`.

    A frozen dataclass rather than a closure so that two ``HandleField`` declarations with
    the same issuer and scope compare equal — which keeps ``@Airlock``'s signature
    preservation and any schema diffing stable across re-imports.
    """

    issuer: str
    scope: str
    field_name: str | None = field(default=None)

    def __call__(self, value: str) -> str:
        ledger = current_ledger()
        if ledger is None:
            preview = redact(value)
            raise HandleRejection(
                HandleRejectionReason.NOT_ISSUED,
                f"handle {preview} cannot be honoured: no handle ledger is bound to this "
                f"run, so nothing was issued here. Deny-by-default — wrap the run in "
                f"`with handle_run(): ...`",
                field_name=self.field_name,
                expected_issuer=self.issuer,
                expected_scope=self.scope,
                handle_preview=preview,
            )
        ledger.validate(
            value,
            issuer=self.issuer,
            scope=self.scope,
            field_name=self.field_name,
        )
        return value


def HandleField(  # noqa: N802 — names a type, so it reads as one at the call site
    *,
    issuer: str,
    scope: str,
    field_name: str | None = None,
) -> Any:
    """Declare a parameter as a server-minted capability handle.

    Use it exactly where a ``str`` annotation would go. Pydantic strict validation rejects a
    non-string first; this validator then checks the value against the run's issuance ledger.

    .. code-block:: python

        @Airlock()
        def read_checkpoint(
            session: HandleField(issuer="mnemo.checkpoint", scope="workspace"),
        ) -> str:
            ...

    Args:
        issuer: The tool permitted to have minted the handle. A handle from any other tool is
            refused even inside the right scope — that hand-off is a confused deputy.
        scope: The isolation unit the handle must have been minted for.
        field_name: Name used in the error message. Optional because the parameter name is
            already in the Pydantic error location; supply it when you want the tool's own
            vocabulary in the message the model reads.

    Returns:
        An ``Annotated[str, AfterValidator(...)]`` suitable for a function signature.

    Raises:
        ValueError: If ``issuer`` or ``scope`` is empty. A field that declares no scope
            cannot check one, and would quietly accept every handle in the run.
    """
    if not issuer:
        raise ValueError("HandleField requires a non-empty issuer")
    if not scope:
        raise ValueError("HandleField requires a non-empty scope")
    return Annotated[str, AfterValidator(_HandleValidator(issuer, scope, field_name))]


def assert_handles_declared(
    tool: Any,
    kwargs: Any,
    *,
    state_params: Any = None,
) -> None:
    """Refuse a handle smuggled through ``**kwargs`` instead of a declared parameter.

    ``HandleField`` can only check a handle the tool *declares*. A tool whose signature ends
    in ``**kwargs`` declares nothing, so a handle arriving that way is validated by nobody —
    ghost-argument stripping treats it as legitimate (the signature does accept it) and no
    ``AfterValidator`` is attached to it.

    This is a one-line front door to the primitive that already closes that hole,
    :func:`~agent_airlock.mcp_spec.statelessness.validate_state_handle_declared`, so callers
    do not have to know it lives under ``mcp_spec``.

    Args:
        tool: The callable whose declared contract is inspected.
        kwargs: The arguments it was called with.
        state_params: Argument names treated as handles. Defaults to
            :data:`~agent_airlock.mcp_spec.statelessness.DEFAULT_STATE_PARAMS`.

    Raises:
        GhostArgumentError: If a handle argument is not an explicitly declared parameter.
    """
    from .mcp_spec.statelessness import DEFAULT_STATE_PARAMS, validate_state_handle_declared

    validate_state_handle_declared(
        tool,
        kwargs,
        state_params=DEFAULT_STATE_PARAMS if state_params is None else state_params,
    )


def handle_rejection_from(error: BaseException | None, message: str = "") -> HandleRejection | None:
    """Recover the :class:`HandleRejection` behind a Pydantic validation error, if any.

    Pydantic 2 hands the original exception back under ``ctx["error"]``, which is what this
    tries first. That contract is not pinned across the ``pydantic>=2.0,<3.0`` range airlock
    supports, so a message-sentinel fallback follows it: every rejection message opens with
    ``AIRLOCK_HANDLE[<reason>]``. Two independent routes, neither of which needs shared state.

    Returns ``None`` when the error is an ordinary validation failure — the caller then falls
    through to the generic path, which is the correct behaviour, not a degraded one.
    """
    if isinstance(error, HandleRejection):
        return error

    text = message or (str(error) if error is not None else "")
    marker = f"{REJECTION_SENTINEL}["
    start = text.find(marker)
    if start == -1:
        return None
    end = text.find("]", start)
    if end == -1:
        return None
    try:
        reason = HandleRejectionReason(text[start + len(marker) : end])
    except ValueError:
        return None
    return HandleRejection(reason, text[end + 2 :].strip() or text)
