"""A handle in the argument stream is a bearer capability, so check it like one.

MCP 2026-07-28 removed the protocol session (SEP-2575) and moved cross-call state onto the
tool-argument channel: a server mints a handle from one tool and the model passes it back as
an argument to another (SEP-2567). Nothing in airlock distinguished that value from an
ordinary string, and a type check accepts all four forgeries below because every one of them
is a well-typed string.

The first class is the one that matters. With **no ledger bound at all** a declared handle
argument must be refused — an absent mechanism is not a permissive one. If that case ever
passes, every other test in this file is measuring a check that can be turned off by
forgetting to turn it on.

Tracked against the MCP 2026-07-28 specification (SEP-2567).
"""

from __future__ import annotations

import dataclasses
import threading
import time

import pytest
from pydantic import ValidationError

from agent_airlock import (
    Airlock,
    HandleField,
    HandleLedger,
    HandleRejection,
    HandleRejectionReason,
    SecurityPolicy,
    handle_run,
    issue_handle,
)
from agent_airlock.handles import (
    HANDLE_PREFIX,
    REJECTION_SENTINEL,
    bind_ledger,
    current_ledger,
    handle_rejection_from,
    redact,
    reset_ledger,
)
from agent_airlock.self_heal import BlockReason
from agent_airlock.validator import GhostArgumentError

ISSUER = "mnemo.checkpoint"
SCOPE = "workspace"


def _tool():
    """The tool under test: one declared handle parameter, one ordinary one."""

    @Airlock()
    def read_checkpoint(
        session: HandleField(issuer=ISSUER, scope=SCOPE),
        note: str = "",
    ) -> str:
        return f"READ:{note}"

    return read_checkpoint


class TestNoLedgerIsDenied:
    """Deny-by-default: the absence of the mechanism must not be the absence of the check."""

    def test_declared_handle_with_no_ledger_bound_is_blocked(self) -> None:
        tool = _tool()
        result = tool(session="ah_looks-perfectly-well-formed")

        assert isinstance(result, dict), "a refused call must return the structured response"
        assert result["success"] is False
        assert result["block_reason"] == BlockReason.HANDLE_NOT_ISSUED.value

    def test_the_no_ledger_message_says_what_to_do_rather_than_only_what_failed(self) -> None:
        result = _tool()(session="ah_anything")
        assert "handle_run" in result["error"]

    def test_current_ledger_is_none_outside_a_run(self) -> None:
        assert current_ledger() is None

    def test_a_run_does_not_leak_its_ledger_after_it_exits(self) -> None:
        with handle_run("run-a") as ledger:
            assert current_ledger() is ledger
        assert current_ledger() is None


class TestTheFourRejections:
    """One distinct, machine-readable reason per failure mode."""

    def test_a_handle_never_issued_in_this_run_is_rejected(self) -> None:
        with handle_run("run-1"):
            result = _tool()(session="ah_read-out-of-a-transcript")
        assert result["block_reason"] == BlockReason.HANDLE_NOT_ISSUED.value

    def test_a_handle_from_a_different_issuer_is_rejected(self) -> None:
        with handle_run("run-1") as ledger:
            other = ledger.issue(issuer="unrelated.tool", scope=SCOPE)
            result = _tool()(session=other)
        assert result["block_reason"] == BlockReason.HANDLE_WRONG_ISSUER.value

    def test_a_handle_from_a_different_scope_is_rejected(self) -> None:
        with handle_run("run-1") as ledger:
            other_tenant = ledger.issue(issuer=ISSUER, scope="another-tenant")
            result = _tool()(session=other_tenant)
        assert result["block_reason"] == BlockReason.HANDLE_WRONG_SCOPE.value

    def test_an_expired_handle_is_rejected(self) -> None:
        with handle_run("run-1") as ledger:
            short = ledger.issue(issuer=ISSUER, scope=SCOPE, ttl_seconds=0.01)
            time.sleep(0.02)
            result = _tool()(session=short)
        assert result["block_reason"] == BlockReason.HANDLE_EXPIRED.value

    def test_every_reason_maps_to_its_own_block_reason(self) -> None:
        """No two failure modes collapse onto one audit value."""
        from agent_airlock.self_heal import _HANDLE_BLOCK_REASONS

        mapped = {_HANDLE_BLOCK_REASONS[reason.value] for reason in HandleRejectionReason}
        assert len(mapped) == len(list(HandleRejectionReason)) == 4

    def test_a_handle_correct_in_every_respect_is_accepted(self) -> None:
        with handle_run("run-1"):
            good = issue_handle(issuer=ISSUER, scope=SCOPE)
            assert _tool()(session=good, note="ok") == "READ:ok"


class TestRejectionOrderIsDiagnostic:
    """Report the first thing that is wrong, not the last check that happened to fail."""

    def test_an_unissued_handle_is_not_reported_as_expired(self) -> None:
        ledger = HandleLedger("run-1")
        with pytest.raises(HandleRejection) as caught:
            ledger.validate("ah_never-seen", issuer=ISSUER, scope=SCOPE)
        assert caught.value.reason is HandleRejectionReason.NOT_ISSUED

    def test_a_wrong_issuer_is_reported_before_a_wrong_scope(self) -> None:
        ledger = HandleLedger("run-1")
        handle = ledger.issue(issuer="other.tool", scope="other-scope")
        with pytest.raises(HandleRejection) as caught:
            ledger.validate(handle, issuer=ISSUER, scope=SCOPE)
        assert caught.value.reason is HandleRejectionReason.WRONG_ISSUER

    def test_an_expired_handle_with_the_wrong_scope_reports_the_scope(self) -> None:
        """Scope is the security failure; expiry is housekeeping. Report the sharper one."""
        ledger = HandleLedger("run-1")
        handle = ledger.issue(issuer=ISSUER, scope="other-scope", ttl_seconds=0.01)
        time.sleep(0.02)
        with pytest.raises(HandleRejection) as caught:
            ledger.validate(handle, issuer=ISSUER, scope=SCOPE)
        assert caught.value.reason is HandleRejectionReason.WRONG_SCOPE


class TestTheVerdictSetDoesNotGrow:
    """A handle rejection is a *deny*. allow / deny / escalate stays the whole set."""

    def test_a_rejection_is_an_ordinary_blocked_response(self) -> None:
        with handle_run("run-1"):
            result = _tool()(session="ah_nope")

        # Same keys a policy denial produces — no new top-level verdict field.
        assert result["success"] is False
        assert result["status"] == "blocked"
        assert "block_reason" in result
        assert "escalation" not in result
        assert "verdict" not in result

    def test_the_block_reason_is_a_reason_not_a_fourth_verdict(self) -> None:
        for reason in HandleRejectionReason:
            assert BlockReason(reason.value) is not None

    def test_the_response_carries_a_fix_hint_that_does_not_say_retry_this_value(self) -> None:
        """A capability cannot be reformatted into validity; the hint must not imply it can."""
        with handle_run("run-1"):
            result = _tool()(session="ah_nope")
        hints = " ".join(result["fix_hints"]).lower()
        assert "mint" in hints or "call the tool that mints" in hints


class TestCoOccurringErrorsAreNotLostSilently:
    """`block_reason` holds one value, so the other errors need somewhere to be counted."""

    @staticmethod
    def _tool_with_two_fields():
        @Airlock()
        def read(
            session: HandleField(issuer=ISSUER, scope=SCOPE),
            count: int = 1,
        ) -> str:
            return f"READ:{count}"

        return read

    def test_the_handle_failure_is_the_one_reported(self) -> None:
        """A capability failure outranks a type error; mixing them dilutes the signal."""
        with handle_run("run-1"):
            result = self._tool_with_two_fields()(session="ah_nope", count="5")
        assert result["block_reason"] == BlockReason.HANDLE_NOT_ISSUED.value

    def test_the_other_errors_are_counted_rather_than_dropped(self) -> None:
        with handle_run("run-1"):
            result = self._tool_with_two_fields()(session="ah_nope", count="5")
        assert result["metadata"]["other_error_count"] == 1
        assert any("other validation error" in hint for hint in result["fix_hints"])

    def test_a_lone_handle_failure_reports_no_others(self) -> None:
        with handle_run("run-1"):
            result = self._tool_with_two_fields()(session="ah_nope", count=5)
        assert result["metadata"]["other_error_count"] == 0
        assert not any("other validation error" in hint for hint in result["fix_hints"])

    def test_the_remaining_error_surfaces_once_the_handle_is_valid(self) -> None:
        """The promise the fix hint makes has to be true."""
        with handle_run("run-1"):
            good = issue_handle(issuer=ISSUER, scope=SCOPE)
            result = self._tool_with_two_fields()(session=good, count="5")
        assert result["block_reason"] == BlockReason.VALIDATION_ERROR.value


class TestHandlesAreRedacted:
    """Possession is authority, so a handle must not be echoed back at full length."""

    def test_the_error_message_does_not_contain_the_whole_handle(self) -> None:
        with handle_run("run-1") as ledger:
            leaked = ledger.issue(issuer=ISSUER, scope="elsewhere")
            result = _tool()(session=leaked)
        assert leaked not in result["error"]
        assert leaked[: len(HANDLE_PREFIX) + 6] in result["error"]

    def test_a_short_value_is_left_alone_because_there_is_nothing_to_hide(self) -> None:
        assert redact("ah_short") == "ah_short"

    def test_redact_handles_a_non_string_without_raising(self) -> None:
        assert redact(12345) == "12345"

    def test_a_handle_argument_is_redacted_in_the_audit_preview(self, tmp_path) -> None:
        """`AUDIT_REDACT_PARAMS` matches on substring, so any *_handle parameter is covered."""
        from agent_airlock.audit import AuditLogger

        log = tmp_path / "audit.jsonl"
        logger = AuditLogger(log, enabled=True)
        logger.log(tool_name="t", blocked=False, args={"session_handle": "ah_secret-value"})
        logger.flush()

        contents = log.read_text(encoding="utf-8")
        assert "ah_secret-value" not in contents
        assert "[REDACTED]" in contents


class TestComposesWithGhostArgumentStripping:
    """The declaration is what makes a handle checkable, which is the SEP-2567 trust split."""

    def test_an_undeclared_handle_never_reaches_the_ledger(self) -> None:
        """Step 1 strips it, so the capability check is not even consulted."""

        @Airlock()
        def no_handle_here(note: str) -> str:
            return f"OK:{note}"

        with handle_run("run-1"):
            assert no_handle_here(note="hi", session="ah_invented-by-the-model") == "OK:hi"

    def test_kwargs_absorption_is_the_known_hole_and_the_shipped_primitive_closes_it(
        self,
    ) -> None:
        """A ``**kwargs`` tool declares nothing, so HandleField cannot attach to anything.

        This is stated as a limit in the module docstring rather than papered over. The
        assertion below is the *evidence* for that limit, and then the evidence that
        ``assert_handles_declared`` closes it.
        """
        from agent_airlock import assert_handles_declared

        @Airlock()
        def wide_open(note: str = "", **kwargs: object) -> str:
            return "OK"

        with handle_run("run-1"):
            # Not ghost-stripped (the signature accepts it) and not HandleField-validated
            # (no annotation to attach to). The handle sails through.
            assert wide_open(state="ah_smuggled") == "OK"

        # The front door to the existing mcp_spec primitive refuses it.
        with pytest.raises(GhostArgumentError):
            assert_handles_declared(wide_open.__wrapped__, {"state": "ah_smuggled"})

    def test_a_declared_handle_is_not_treated_as_a_ghost_argument(self) -> None:
        with handle_run("run-1"):
            good = issue_handle(issuer=ISSUER, scope=SCOPE)
            assert _tool()(session=good) == "READ:"


class TestSandboxDispatchSkipsTheCheck:
    """A stated limit, pinned so it cannot change unnoticed.

    With a real sandbox backend available, `@Airlock` serialises the **undecorated** function
    into the micro-VM rather than calling the Pydantic-validated wrapper. No `Annotated`
    validator runs on that path — `SafePath` and `SafeURL` have been in the same position
    since they shipped, so this is a property of the sandbox dispatch path and not of
    `HandleField`.

    It is asserted here rather than only written in a docstring because a security check that
    silently does not apply is worse than one that visibly does not exist. Without E2B
    installed the decorator falls back to local execution *with* validation, so the hole is
    invisible on this machine — which is exactly why it needs a test that does not depend on
    having E2B.
    """

    def test_the_sandbox_path_receives_the_unvalidated_function(self, monkeypatch) -> None:
        import agent_airlock.core as core_module

        seen: dict[str, object] = {}

        class _FakeResult:
            success = True
            result = "SANDBOX-RAN"
            sandbox_id = "fake"
            execution_time_ms = 0.0

        def fake_execute_in_sandbox(func, args, kwargs, config):  # noqa: ANN001, ANN202, ARG001
            seen["func"] = func
            return _FakeResult()

        # Stand in for the [sandbox] extra so the ImportError fallback (which *does*
        # validate) is not the path under test.
        monkeypatch.setattr(
            core_module.Airlock,
            "_execute_in_sandbox",
            lambda self, func, *a, **kw: fake_execute_in_sandbox(func, a, kw, None).result,
        )

        @Airlock(sandbox=True)
        def sandboxed(session: HandleField(issuer=ISSUER, scope=SCOPE)) -> str:
            return "REACHED THE BODY"

        with handle_run("run-1"):
            # A handle that was never issued. On the ordinary path this is a hard block.
            result = sandboxed(session="ah_never-issued-anywhere")

        assert result == "SANDBOX-RAN", (
            "the sandbox branch no longer bypasses validation — if this now blocks, the "
            "limit documented in agent_airlock.handles has been fixed and the docstring "
            "should be updated to say so"
        )

    def test_the_same_call_is_blocked_on_the_ordinary_path(self) -> None:
        """The contrast is the point: the check works, the sandbox dispatch skips it."""
        with handle_run("run-1"):
            assert _tool()(session="ah_never-issued-anywhere")["block_reason"] == (
                BlockReason.HANDLE_NOT_ISSUED.value
            )


class TestComposesWithFreeze:
    """v0.8.74 fixed `freeze()` dropping fields. This release must not reintroduce it."""

    def test_every_public_policy_field_still_survives_a_freeze(self) -> None:
        policy = SecurityPolicy(
            allowed_tools=["read_checkpoint"],
            stdio_mode="disabled",
            escalate_tools={"pay": "over limit"},
        )
        frozen = policy.freeze()
        dropped = [
            spec.name
            for spec in dataclasses.fields(policy)
            if not spec.name.startswith("_")
            and getattr(policy, spec.name) != getattr(frozen, spec.name)
        ]
        assert dropped == []

    def test_handle_validation_adds_no_policy_field_to_drop(self) -> None:
        """The contract lives on the *type*, like SafePath — deliberately not on the policy.

        A policy field would need a value meaning "handles are not checked here", and a knob
        that downgrades a capability check to a warning is exactly what this feature removes.
        Recorded as a test so the reasoning is checkable rather than only written down.
        """
        names = {spec.name for spec in dataclasses.fields(SecurityPolicy)}
        assert not {name for name in names if "handle" in name}


class TestLedgerMechanics:
    def test_issue_records_issuer_scope_and_run(self) -> None:
        ledger = HandleLedger("run-7")
        handle = ledger.issue(issuer=ISSUER, scope=SCOPE)
        entry = ledger.lookup(handle)
        assert entry is not None
        assert (entry.issuer, entry.scope, entry.run_id) == (ISSUER, SCOPE, "run-7")

    def test_a_minted_handle_carries_the_prefix_and_real_entropy(self) -> None:
        ledger = HandleLedger()
        handles = {ledger.issue(issuer=ISSUER, scope=SCOPE) for _ in range(50)}
        assert len(handles) == 50
        assert all(h.startswith(HANDLE_PREFIX) for h in handles)

    def test_a_caller_supplied_handle_is_recorded_as_given(self) -> None:
        """For servers that mint their own identifiers. We record it; we do not rewrite it."""
        ledger = HandleLedger("run-7")
        returned = ledger.issue(issuer=ISSUER, scope=SCOPE, handle="srv-session-0001")
        assert returned == "srv-session-0001"
        entry = ledger.lookup("srv-session-0001")
        assert entry is not None
        assert entry.issuer == ISSUER

    def test_a_caller_supplied_handle_gets_no_entropy_guarantee_from_us(self) -> None:
        """Documented as the caller's problem — assert it rather than implying otherwise."""
        ledger = HandleLedger()
        assert ledger.issue(issuer=ISSUER, scope=SCOPE, handle="1") == "1"

    def test_an_empty_issuer_or_scope_is_refused_at_mint_time(self) -> None:
        ledger = HandleLedger()
        with pytest.raises(ValueError, match="issuer"):
            ledger.issue(issuer="", scope=SCOPE)
        with pytest.raises(ValueError, match="scope"):
            ledger.issue(issuer=ISSUER, scope="")

    def test_a_non_positive_ttl_is_refused_rather_than_silently_meaning_forever(self) -> None:
        ledger = HandleLedger()
        with pytest.raises(ValueError, match="ttl_seconds"):
            ledger.issue(issuer=ISSUER, scope=SCOPE, ttl_seconds=0)

    def test_a_handle_with_no_ttl_never_expires(self) -> None:
        ledger = HandleLedger()
        handle = ledger.issue(issuer=ISSUER, scope=SCOPE)
        entry = ledger.lookup(handle)
        assert entry is not None
        assert entry.expires_at() is None
        assert entry.is_expired(now=time.time() + 10_000) is False

    def test_revoke_removes_it_and_reports_whether_it_was_there(self) -> None:
        ledger = HandleLedger()
        handle = ledger.issue(issuer=ISSUER, scope=SCOPE)
        assert ledger.revoke(handle) is True
        assert ledger.revoke(handle) is False
        assert ledger.lookup(handle) is None

    def test_lookup_of_a_non_string_returns_none_rather_than_raising(self) -> None:
        assert HandleLedger().lookup(object()) is None

    def test_minted_feeds_the_shipped_sep_2567_primitive(self) -> None:
        """The two must compose; a second, drifting notion of "minted" would be worse."""
        from agent_airlock.mcp_spec.handle_trust import HandleTrustError, validate_handle_minted

        ledger = HandleLedger()
        handle = ledger.issue(issuer=ISSUER, scope=SCOPE)

        validate_handle_minted(handle, minted=ledger.minted())
        with pytest.raises(HandleTrustError):
            validate_handle_minted("ah_not-ours", minted=ledger.minted())

    def test_two_runs_do_not_honour_each_others_handles(self) -> None:
        with handle_run("run-a") as first:
            borrowed = first.issue(issuer=ISSUER, scope=SCOPE)

        with handle_run("run-b"):
            result = _tool()(session=borrowed)
        assert result["block_reason"] == BlockReason.HANDLE_NOT_ISSUED.value

    def test_nested_runs_restore_the_outer_binding(self) -> None:
        with handle_run("outer") as outer:
            with handle_run("inner") as inner:
                assert current_ledger() is inner
            assert current_ledger() is outer

    def test_bind_and_reset_are_usable_without_the_context_manager(self) -> None:
        ledger = HandleLedger("manual")
        token = bind_ledger(ledger)
        try:
            assert current_ledger() is ledger
        finally:
            reset_ledger(token)
        assert current_ledger() is None

    def test_concurrent_minting_loses_nothing(self) -> None:
        ledger = HandleLedger()
        errors: list[BaseException] = []

        def mint() -> None:
            try:
                for _ in range(40):
                    ledger.issue(issuer=ISSUER, scope=SCOPE)
            except BaseException as exc:  # pragma: no cover - only on a locking bug
                errors.append(exc)

        threads = [threading.Thread(target=mint) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert errors == []
        assert len(ledger) == 8 * 40

    def test_issue_handle_without_a_run_raises_rather_than_minting_into_the_void(self) -> None:
        """A handle minted nowhere would fail validation later, far from the actual bug."""
        with pytest.raises(RuntimeError, match="handle_run"):
            issue_handle(issuer=ISSUER, scope=SCOPE)


class TestTheAsyncPath:
    """`@Airlock` treats async as first-class, and contextvars behave differently there.

    A task inherits a *copy* of the context at creation, so the binding propagates into child
    tasks — and because the copy points at the same `HandleLedger` object, a handle minted in
    a child is visible to the parent. That is the behaviour a per-run ledger needs, and it is
    subtle enough to be worth pinning rather than assuming.
    """

    @staticmethod
    def _async_tool():
        @Airlock()
        async def read_async(session: HandleField(issuer=ISSUER, scope=SCOPE)) -> str:
            return "ASYNC-OK"

        return read_async

    async def test_a_valid_handle_is_accepted_on_the_async_wrapper(self) -> None:
        tool = self._async_tool()
        with handle_run("run-async"):
            good = issue_handle(issuer=ISSUER, scope=SCOPE)
            assert await tool(session=good) == "ASYNC-OK"

    async def test_an_unissued_handle_is_refused_on_the_async_wrapper(self) -> None:
        tool = self._async_tool()
        with handle_run("run-async"):
            result = await tool(session="ah_nope")
        assert result["block_reason"] == BlockReason.HANDLE_NOT_ISSUED.value

    async def test_no_ledger_bound_blocks_on_the_async_wrapper_too(self) -> None:
        result = await self._async_tool()(session="ah_anything")
        assert result["block_reason"] == BlockReason.HANDLE_NOT_ISSUED.value

    async def test_a_handle_minted_in_a_child_task_is_honoured_by_the_parent(self) -> None:
        import asyncio

        tool = self._async_tool()
        with handle_run("run-async"):

            async def child() -> str:
                return issue_handle(issuer=ISSUER, scope=SCOPE)

            from_child = await asyncio.create_task(child())
            assert await tool(session=from_child) == "ASYNC-OK"

    async def test_concurrent_validation_does_not_interfere(self) -> None:
        import asyncio

        tool = self._async_tool()
        with handle_run("run-async"):
            good = issue_handle(issuer=ISSUER, scope=SCOPE)
            results = await asyncio.gather(*[tool(session=good) for _ in range(20)])
        assert set(results) == {"ASYNC-OK"}


class TestHandleFieldDeclaration:
    def test_an_empty_issuer_or_scope_is_refused_at_declaration_time(self) -> None:
        with pytest.raises(ValueError, match="issuer"):
            HandleField(issuer="", scope=SCOPE)
        with pytest.raises(ValueError, match="scope"):
            HandleField(issuer=ISSUER, scope="")

    def test_strict_typing_still_runs_first(self) -> None:
        """A non-string is a type error, not a capability error. Do not mislabel it."""
        with handle_run("run-1"):
            result = _tool()(session=12345)
        assert result["block_reason"] == BlockReason.VALIDATION_ERROR.value

    def test_two_identical_declarations_compare_equal(self) -> None:
        """Keeps signature preservation and schema diffing stable across re-imports."""
        from agent_airlock.handles import _HandleValidator

        assert _HandleValidator(ISSUER, SCOPE) == _HandleValidator(ISSUER, SCOPE)
        assert _HandleValidator(ISSUER, SCOPE) != _HandleValidator(ISSUER, "other")

    def test_the_decorated_signature_is_preserved(self) -> None:
        """Framework introspection must still see the parameter."""
        import inspect

        assert "session" in inspect.signature(_tool()).parameters


class TestRejectionRecoveryFromPydantic:
    """The reason must survive the trip through Pydantic, or the audit record degrades.

    Pydantic 2 returns the original exception under ``ctx["error"]``. That is not pinned
    across the ``pydantic>=2.0,<3.0`` range airlock supports, so there is a message-sentinel
    fallback. Both routes are asserted here: if a future Pydantic drops ``ctx``, the first
    test fails loudly instead of every handle rejection quietly becoming ``validation_error``.
    """

    def test_the_primary_ctx_route_works_on_the_installed_pydantic(self) -> None:
        from pydantic import ConfigDict, validate_call

        @validate_call(config=ConfigDict(strict=True))
        def probe(session: HandleField(issuer=ISSUER, scope=SCOPE)) -> str:
            return session

        with pytest.raises(ValidationError) as caught:
            probe(session="ah_nope")

        errors = caught.value.errors()
        inner = (errors[0].get("ctx") or {}).get("error")
        assert isinstance(inner, HandleRejection), (
            "pydantic no longer returns the original exception under ctx['error']; the "
            "message-sentinel fallback is now load-bearing"
        )

    def test_the_message_fallback_recovers_the_reason_without_the_exception(self) -> None:
        message = f"Value error, {REJECTION_SENTINEL}[handle_wrong_scope]: minted elsewhere"
        recovered = handle_rejection_from(None, message)
        assert recovered is not None
        assert recovered.reason is HandleRejectionReason.WRONG_SCOPE

    def test_an_ordinary_validation_error_is_not_mistaken_for_a_handle_rejection(self) -> None:
        assert handle_rejection_from(ValueError("just a string problem")) is None

    def test_an_unknown_sentinel_reason_falls_through_rather_than_guessing(self) -> None:
        assert handle_rejection_from(None, f"{REJECTION_SENTINEL}[not_a_real_reason]: x") is None

    def test_a_truncated_sentinel_falls_through_rather_than_raising(self) -> None:
        """A log pipeline that clips the message must degrade to the generic path, not crash."""
        assert handle_rejection_from(None, f"{REJECTION_SENTINEL}[handle_expi") is None

    def test_no_error_and_no_message_is_not_a_handle_rejection(self) -> None:
        assert handle_rejection_from(None) is None
