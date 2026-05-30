"""Tests for the behavioral tool-call sequence guard (v0.8.12, arXiv:2605.27901).

Coverage matrix (per the brief's #5):

- Clean declared-DAG run admits a permitted sequence end-to-end.
- DAG violation in ``block`` mode raises :class:`SequenceViolation`.
- DAG violation in ``warn`` mode does NOT raise (logs + emits OTel attr).
- BASELINE mode flags a low-probability transition after the cold-start
  window passes.
- BASELINE mode does NOT flag while the sample size is below
  ``min_baseline_samples`` (cold-start).
- ``args_shape_hash`` is stable across value variation but distinguishes
  arg-count / type / keyword shape.
- The persisted baseline JSON never contains argument values.
- The ``@Airlock`` integration: a DAG violation surfaces through the
  existing ``handle_policy_violation`` path as a blocked
  ``AirlockResponse``.
- ``SecurityPolicy.sequence_guard`` is an additive, optional field
  (default-None policies are byte-identical to v0.8.11 behavior).
- Thread safety: concurrent ``record_and_check`` calls preserve the
  per-session ordering invariant.
- OTel span attributes are emitted on a flag (assert via an in-memory
  patched span).
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agent_airlock import Airlock, SecurityPolicy
from agent_airlock.context import AirlockContext
from agent_airlock.policy import PolicyViolation
from agent_airlock.sequence_guard import (
    ENTRY_SENTINEL,
    PREV_NONE_SENTINEL,
    SequenceGuard,
    SequenceViolation,
    args_shape_hash,
)

# ---------------------------------------------------------------------------
# args_shape_hash — privacy + stability invariants
# ---------------------------------------------------------------------------


class TestArgsShapeHash:
    def test_empty_shape_is_stable(self) -> None:
        assert args_shape_hash((), {}) == args_shape_hash((), {})

    def test_value_invariance_one_string_arg(self) -> None:
        """Two different string values must hash identically — proves no values are
        included in the hash."""
        h1 = args_shape_hash(("first",), {})
        h2 = args_shape_hash(("totally-different-second-string",), {})
        assert h1 == h2

    def test_arg_count_changes_hash(self) -> None:
        assert args_shape_hash(("a",), {}) != args_shape_hash(("a", "b"), {})

    def test_arg_type_changes_hash(self) -> None:
        assert args_shape_hash(("a",), {}) != args_shape_hash((1,), {})

    def test_kwarg_key_changes_hash(self) -> None:
        assert args_shape_hash((), {"x": 1}) != args_shape_hash((), {"y": 1})

    def test_kwarg_insertion_order_does_not_change_hash(self) -> None:
        assert args_shape_hash((), {"a": 1, "b": 2}) == args_shape_hash((), {"b": 2, "a": 1})

    def test_kwarg_value_invariance(self) -> None:
        """Distinct values for the same keyword key with the same type must hash
        identically — proves the hash is shape-only."""
        h1 = args_shape_hash((), {"name": "Alice"})
        h2 = args_shape_hash((), {"name": "Bob"})
        assert h1 == h2


# ---------------------------------------------------------------------------
# SequenceGuard construction validation
# ---------------------------------------------------------------------------


class TestSequenceGuardConstruction:
    def test_declared_requires_dag(self) -> None:
        with pytest.raises(ValueError, match="requires a `dag`"):
            SequenceGuard(mode="declared")

    def test_declared_dag_must_include_entry(self) -> None:
        with pytest.raises(ValueError, match="__entry__"):
            SequenceGuard(mode="declared", dag={"read": {"write"}})

    def test_baseline_requires_path(self) -> None:
        with pytest.raises(ValueError, match="requires a `baseline_path`"):
            SequenceGuard(mode="baseline")

    @pytest.mark.parametrize("threshold", [0.0, -0.1, 1.5])
    def test_baseline_threshold_must_be_in_unit_interval(
        self, tmp_path: Path, threshold: float
    ) -> None:
        with pytest.raises(ValueError, match="low_probability_threshold"):
            SequenceGuard(
                mode="baseline",
                baseline_path=tmp_path / "b.json",
                low_probability_threshold=threshold,
            )

    def test_baseline_min_samples_must_be_positive(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="min_baseline_samples"):
            SequenceGuard(
                mode="baseline",
                baseline_path=tmp_path / "b.json",
                min_baseline_samples=0,
            )

    def test_unknown_mode_rejected(self) -> None:
        with pytest.raises(ValueError, match="mode must be"):
            SequenceGuard(mode="other")  # type: ignore[arg-type]

    def test_unknown_action_rejected(self) -> None:
        with pytest.raises(ValueError, match="action must be"):
            SequenceGuard(
                mode="declared",
                action="silent",  # type: ignore[arg-type]
                dag={ENTRY_SENTINEL: {"r"}},
            )


# ---------------------------------------------------------------------------
# Declared-DAG mode
# ---------------------------------------------------------------------------


class TestDeclaredDAGMode:
    def _guard_rw(self, action: str = "block") -> SequenceGuard:
        return SequenceGuard(
            mode="declared",
            action=action,  # type: ignore[arg-type]
            dag={
                ENTRY_SENTINEL: {"read"},
                "read": {"write", "read"},
                "write": {"write"},
            },
        )

    def test_clean_run_admits_permitted_sequence(self) -> None:
        g = self._guard_rw()
        g.record_and_check(session_key="ag1", tool_name="read", args=(), kwargs={})
        g.record_and_check(session_key="ag1", tool_name="write", args=(), kwargs={})
        g.record_and_check(session_key="ag1", tool_name="write", args=(), kwargs={})

        history = g.history("ag1")
        assert [t for t, _ in history] == ["read", "write", "write"]

    def test_block_mode_raises_on_disallowed_entry(self) -> None:
        g = self._guard_rw()
        with pytest.raises(SequenceViolation) as exc:
            g.record_and_check(session_key="ag1", tool_name="write", args=(), kwargs={})
        assert exc.value.mode == "declared"
        assert exc.value.from_tool is None
        assert exc.value.to_tool == "write"
        # The exception preserves PolicyViolation semantics so the
        # existing core.py handler picks it up.
        assert isinstance(exc.value, PolicyViolation)

    def test_block_mode_raises_on_disallowed_transition(self) -> None:
        g = self._guard_rw()
        g.record_and_check(session_key="ag1", tool_name="read", args=(), kwargs={})
        with pytest.raises(SequenceViolation) as exc:
            g.record_and_check(session_key="ag1", tool_name="delete", args=(), kwargs={})
        assert exc.value.from_tool == "read"
        assert exc.value.to_tool == "delete"

    def test_warn_mode_does_not_raise_on_violation(self) -> None:
        g = self._guard_rw(action="warn")
        # Disallowed first call — should warn, not raise.
        g.record_and_check(session_key="ag1", tool_name="delete", args=(), kwargs={})
        # The trace is still recorded so the next call's "previous" is correct.
        assert g.history("ag1") == [("delete", args_shape_hash((), {}))]

    def test_per_session_isolation(self) -> None:
        g = self._guard_rw()
        g.record_and_check(session_key="A", tool_name="read", args=(), kwargs={})
        # Session B's first call must still be an entry-permitted tool;
        # session A's trace must not affect session B's view of "previous".
        g.record_and_check(session_key="B", tool_name="read", args=(), kwargs={})
        with pytest.raises(SequenceViolation):
            g.record_and_check(session_key="B", tool_name="delete", args=(), kwargs={})

    def test_reset_clears_only_named_session(self) -> None:
        g = self._guard_rw()
        g.record_and_check(session_key="A", tool_name="read", args=(), kwargs={})
        g.record_and_check(session_key="B", tool_name="read", args=(), kwargs={})
        g.reset("A")
        assert g.history("A") == []
        assert g.history("B") != []

    def test_reset_all(self) -> None:
        g = self._guard_rw()
        g.record_and_check(session_key="A", tool_name="read", args=(), kwargs={})
        g.record_and_check(session_key="B", tool_name="read", args=(), kwargs={})
        g.reset()
        assert g.history("A") == []
        assert g.history("B") == []


# ---------------------------------------------------------------------------
# Baseline (Markov) mode
# ---------------------------------------------------------------------------


class TestBaselineMode:
    def test_cold_start_does_not_flag_below_min_samples(self, tmp_path: Path) -> None:
        g = SequenceGuard(
            mode="baseline",
            baseline_path=tmp_path / "b.json",
            low_probability_threshold=0.5,
            min_baseline_samples=10,
        )
        # 9 outbound observations from the entry-sentinel — below the floor.
        for _ in range(9):
            g.record_and_check(session_key="ag1", tool_name="read", args=(), kwargs={})
            # Reset so each call is an entry (previous is None) so the
            # outbound bucket is PREV_NONE_SENTINEL.
            g.reset("ag1")
        # All admitted; no flag.

    def test_flags_low_probability_transition_post_cold_start(self, tmp_path: Path) -> None:
        g = SequenceGuard(
            mode="baseline",
            baseline_path=tmp_path / "b.json",
            low_probability_threshold=0.10,
            min_baseline_samples=20,
        )
        # The baseline is keyed per session_key, so warm and surprise must
        # share the key. 30 alternating read<->write pairs on session "ag1"
        # build up the read->write transition count beyond the
        # min_baseline_samples floor.
        for _ in range(30):
            g.record_and_check(session_key="ag1", tool_name="read", args=(), kwargs={})
            g.record_and_check(session_key="ag1", tool_name="write", args=(), kwargs={})

        # Next call: read after write. Transition write->read has been
        # well-observed; admitted.
        g.record_and_check(session_key="ag1", tool_name="read", args=(), kwargs={})
        # Now read->delete. P(delete | read) = 0/30 = 0.0, well below
        # threshold 0.10. Sample size from 'read' is 30 >= 20. → Flag.
        with pytest.raises(SequenceViolation) as exc:
            g.record_and_check(session_key="ag1", tool_name="delete", args=(), kwargs={})
        assert exc.value.mode == "baseline"
        assert exc.value.observed_probability == 0.0

    def test_frequent_transition_above_threshold_does_not_flag(self, tmp_path: Path) -> None:
        g = SequenceGuard(
            mode="baseline",
            baseline_path=tmp_path / "b.json",
            low_probability_threshold=0.10,
            min_baseline_samples=10,
        )
        # Single session_key — 15 alternating read<->write pairs. After
        # warmup: count(read -> write) = 15 and count(read -> *) = 15, so
        # P(write | read) = 1.0 — comfortably above the 0.10 floor.
        for _ in range(15):
            g.record_and_check(session_key="ag1", tool_name="read", args=(), kwargs={})
            g.record_and_check(session_key="ag1", tool_name="write", args=(), kwargs={})
        # The 16th read->write must NOT flag (the high-probability path).
        g.record_and_check(session_key="ag1", tool_name="read", args=(), kwargs={})
        g.record_and_check(session_key="ag1", tool_name="write", args=(), kwargs={})

    def test_persisted_baseline_never_contains_argument_values(self, tmp_path: Path) -> None:
        path = tmp_path / "b.json"
        g = SequenceGuard(
            mode="baseline",
            baseline_path=path,
            min_baseline_samples=1,
            low_probability_threshold=0.01,
        )
        # The kwargs include an obviously-sensitive-looking value; assert
        # it is NEVER serialised to disk.
        g.record_and_check(
            session_key="ag1",
            tool_name="read",
            args=("very-secret-bearer-token-ABCDEF",),
            kwargs={"password": "should-not-be-on-disk"},
        )
        contents = path.read_text(encoding="utf-8")
        assert "very-secret-bearer-token-ABCDEF" not in contents
        assert "should-not-be-on-disk" not in contents
        # But the tool name DOES appear — that's the legitimate signal.
        assert "read" in contents

    def test_persisted_baseline_loads_round_trip(self, tmp_path: Path) -> None:
        """A guard reading an existing baseline JSON resumes its counts."""
        path = tmp_path / "b.json"
        path.write_text(
            json.dumps(
                {
                    "ag1": {
                        PREV_NONE_SENTINEL: {"read": 100},
                        "read": {"write": 95, "delete": 0},
                    }
                }
            ),
            encoding="utf-8",
        )
        g = SequenceGuard(
            mode="baseline",
            baseline_path=path,
            min_baseline_samples=10,
            low_probability_threshold=0.10,
        )
        # First call from 'read': we have 95 'write' samples, 0 'delete'.
        g.record_and_check(session_key="ag1", tool_name="read", args=(), kwargs={})
        with pytest.raises(SequenceViolation):
            g.record_and_check(session_key="ag1", tool_name="delete", args=(), kwargs={})


# ---------------------------------------------------------------------------
# OTel attribute emission
# ---------------------------------------------------------------------------


class TestOtelEmission:
    def test_block_path_sets_attributes_on_current_span(self) -> None:
        """When a span is available, the guard records its decision on it."""
        from agent_airlock import observability

        fake_span = MagicMock()
        fake_span.set_attribute = MagicMock()
        fake_tracer = MagicMock()
        fake_tracer.get_current_span = MagicMock(return_value=fake_span)
        fake_provider = MagicMock()
        fake_provider._tracer = fake_tracer

        g = SequenceGuard(
            mode="declared",
            dag={ENTRY_SENTINEL: {"read"}, "read": {"write"}},
        )
        g.record_and_check(session_key="ag1", tool_name="read", args=(), kwargs={})
        with patch.object(observability, "get_provider", return_value=fake_provider):
            with pytest.raises(SequenceViolation):
                g.record_and_check(session_key="ag1", tool_name="delete", args=(), kwargs={})

        # Check the canonical attributes were set.
        called_keys = {c.args[0] for c in fake_span.set_attribute.call_args_list}
        assert "airlock.sequence_guard.mode" in called_keys
        assert "airlock.sequence_guard.from_tool" in called_keys
        assert "airlock.sequence_guard.to_tool" in called_keys
        assert "airlock.sequence_guard.session_key" in called_keys

    def test_otel_failure_is_swallowed(self) -> None:
        """Telemetry failure must never break enforcement."""
        from agent_airlock import observability

        fake_provider = MagicMock()
        # Accessing _tracer raises — simulates a broken provider.
        type(fake_provider)._tracer = property(
            lambda _self: (_ for _ in ()).throw(RuntimeError("otel broken"))
        )

        g = SequenceGuard(
            mode="declared",
            dag={ENTRY_SENTINEL: {"read"}},
        )
        with patch.object(observability, "get_provider", return_value=fake_provider):
            with pytest.raises(SequenceViolation):
                g.record_and_check(session_key="ag1", tool_name="delete", args=(), kwargs={})


# ---------------------------------------------------------------------------
# Thread safety smoke
# ---------------------------------------------------------------------------


class TestThreadSafety:
    def test_concurrent_record_preserves_per_session_history_length(self) -> None:
        """Hammer one session from N threads — final history length must
        equal the total number of admitted calls, with no lost or
        duplicated entries.
        """
        g = SequenceGuard(
            mode="declared",
            dag={
                ENTRY_SENTINEL: {"read"},
                "read": {"read"},  # self-loop so concurrent calls all admit
            },
        )
        # Seed the entry.
        g.record_and_check(session_key="ag", tool_name="read", args=(), kwargs={})

        N_THREADS = 8
        N_CALLS = 50

        def worker() -> None:
            for _ in range(N_CALLS):
                g.record_and_check(session_key="ag", tool_name="read", args=(), kwargs={})

        threads = [threading.Thread(target=worker) for _ in range(N_THREADS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # 1 seed + N_THREADS * N_CALLS admitted calls.
        assert len(g.history("ag")) == 1 + N_THREADS * N_CALLS


# ---------------------------------------------------------------------------
# SecurityPolicy + @Airlock integration
# ---------------------------------------------------------------------------


class TestSecurityPolicyIntegration:
    def test_default_policy_has_no_sequence_guard(self) -> None:
        """v0.8.11 callers see no behavior change: the field defaults to None."""
        policy = SecurityPolicy()
        assert policy.sequence_guard is None

    def test_existing_preset_policies_unaffected(self) -> None:
        """The new field must not appear in __repr__ of presets in a way that
        breaks construction or printing."""
        from agent_airlock import PERMISSIVE_POLICY, READ_ONLY_POLICY, STRICT_POLICY

        for p in (PERMISSIVE_POLICY, READ_ONLY_POLICY, STRICT_POLICY):
            assert p.sequence_guard is None
            # repr must not crash with the new field
            assert "SecurityPolicy" in repr(p)

    def test_airlock_seam_blocks_dag_violation(self) -> None:
        policy = SecurityPolicy(
            sequence_guard=SequenceGuard(
                mode="declared",
                dag={ENTRY_SENTINEL: {"read"}, "read": {"write"}},
            ),
        )

        @Airlock(policy=policy)
        def read() -> str:
            return "read-ok"

        @Airlock(policy=policy)
        def write() -> str:
            return "write-ok"

        @Airlock(policy=policy)
        def delete() -> str:
            return "delete-ok"

        with AirlockContext(agent_id="ag1"):
            assert read() == "read-ok"
            assert write() == "write-ok"
            blocked = delete()

        assert isinstance(blocked, dict)
        assert blocked.get("status") == "blocked"
        assert "sequence_guard" in blocked.get("error", "")

    def test_airlock_seam_warn_mode_does_not_block(self) -> None:
        policy = SecurityPolicy(
            sequence_guard=SequenceGuard(
                mode="declared",
                action="warn",
                dag={ENTRY_SENTINEL: {"read"}, "read": {"write"}},
            ),
        )

        @Airlock(policy=policy)
        def delete() -> str:
            return "delete-ok"

        with AirlockContext(agent_id="ag2"):
            assert delete() == "delete-ok"

    def test_airlock_seam_admits_clean_run(self) -> None:
        policy = SecurityPolicy(
            sequence_guard=SequenceGuard(
                mode="declared",
                dag={ENTRY_SENTINEL: {"read"}, "read": {"write"}, "write": set()},
            ),
        )

        @Airlock(policy=policy)
        def read() -> str:
            return "r"

        @Airlock(policy=policy)
        def write() -> str:
            return "w"

        with AirlockContext(agent_id="ag-clean"):
            assert read() == "r"
            assert write() == "w"
