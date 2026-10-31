"""0.10.29: each call's decision is written before it runs, and its outcome names it.

Until 0.10.29 the hash-chained ``DecisionLog`` was fed after the fact, the audit record was
written after execution with no policy, rule or argument digest, the OTel ``args_hash`` was
``json.dumps(default=str)`` cut to 16 hex characters, and stripped ghost-argument names
reached only the OTel record. Raised in cosai-oasis/ws4-secure-design-agentic-systems#200
(the decision entry comes before dispatch and the outcome references it by hash),
CycloneDX/specification#1016, langchain-ai/langgraph#8818, openai/openai-agents-python#5006
and huggingface/lerobot#4679.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import re
import time
from pathlib import Path
from typing import Any

import pytest

from agent_airlock import Airlock, AirlockConfig, AirlockContext, SecurityPolicy
from agent_airlock.approvals import args_digest, unserializable_arguments
from agent_airlock.audit_otel import _hash_args
from agent_airlock.cli.conformance import main as conformance_main
from agent_airlock.conformance.decision_log import DecisionLog, DecisionLogError
from agent_airlock.filesystem import FilesystemPolicy
from agent_airlock.unknown_args import UnknownArgsMode


def _details(log: DecisionLog) -> list[dict[str, Any]]:
    return [record.details or {} for record in log.records()]


def _config(log: DecisionLog, **extra: Any) -> AirlockConfig:
    return AirlockConfig(decision_log=log, **extra)


class TestBeforeDispatch:
    def test_the_tool_body_sees_its_decision_already_written(self, tmp_path: Path) -> None:
        log = DecisionLog(tmp_path / "decisions.jsonl")
        seen: list[dict[str, Any]] = []

        @Airlock(config=_config(log), policy=SecurityPolicy(allowed_tools=["pay"]))
        def pay(to: str, amount: int) -> str:
            seen.extend(_details(log))
            return "paid"

        assert pay(to="bob", amount=5) == "paid"
        assert [d["entry"] for d in seen] == ["decision"]
        decision = seen[0]
        assert decision["verdict"] == "allow"
        assert decision["args_digest"] == args_digest({"to": "bob", "amount": 5})
        assert (
            decision["policy_digest"]
            == SecurityPolicy(allowed_tools=["pay"])._compute_policy_digest()
        )

    def test_the_outcome_names_its_decision_and_the_chain_verifies(self, tmp_path: Path) -> None:
        log = DecisionLog(tmp_path / "decisions.jsonl")

        @Airlock(config=_config(log))
        def pay(amount: int) -> str:
            return "paid"

        pay(amount=5)
        decision, outcome = log.records()
        assert outcome.details == {
            "entry": "outcome",
            "decision_hash": decision.record_hash,
            "outcome": "returned",
        }
        assert (decision.stage, outcome.stage) == ("policy", "execute")
        assert log.verify().ok

    def test_an_edited_line_is_detected(self, tmp_path: Path) -> None:
        path = tmp_path / "decisions.jsonl"
        log = DecisionLog(path)

        @Airlock(config=_config(log))
        def pay(amount: int) -> str:
            return "paid"

        pay(amount=5)
        lines = path.read_text(encoding="utf-8").splitlines()
        first = json.loads(lines[0])
        first["details"]["verdict"] = "block"
        lines[0] = json.dumps(first, sort_keys=True, separators=(",", ":"))
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        result = log.verify()
        assert result.ok is False and result.first_bad_seq == 0
        with pytest.raises(DecisionLogError):
            DecisionLog(path)

    def test_a_refusal_is_recorded_with_its_verdict_and_no_outcome(self, tmp_path: Path) -> None:
        log = DecisionLog(tmp_path / "decisions.jsonl")

        @Airlock(config=_config(log), policy=SecurityPolicy(denied_tools=["pay"]))
        def pay(amount: int) -> str:
            return "paid"

        pay(amount=5)
        (decision,) = _details(log)
        assert decision["verdict"] == "block"
        assert decision["rule_id"] == "tool_denied"
        assert decision["layer"] == "2:policy"
        policy_digest = SecurityPolicy(denied_tools=["pay"])._compute_policy_digest()
        assert decision["policy_digest"] == policy_digest

    def test_a_later_gate_names_the_policy_that_admitted_the_call(self, tmp_path: Path) -> None:
        log = DecisionLog(tmp_path / "decisions.jsonl")
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        config = _config(log, filesystem_policy=FilesystemPolicy(allowed_roots=[allowed]))
        policy = SecurityPolicy(allowed_tools=["read"])

        @Airlock(config=config, policy=policy)
        def read(path: str) -> str:
            return "contents"

        result = read(path=str(tmp_path / "outside.txt"))
        (decision,) = _details(log)
        assert decision["layer"] == "3:filesystem_paths"
        assert decision["rule_id"] == result["metadata"]["violation_type"]
        assert decision["policy_digest"] == policy._compute_policy_digest()

    def test_the_layer_is_the_step_that_refused(self, tmp_path: Path) -> None:
        log = DecisionLog(tmp_path / "decisions.jsonl")
        config = _config(log, unknown_args=UnknownArgsMode.BLOCK)

        @Airlock(config=config, policy=SecurityPolicy(denied_tools=["pay"]))
        def pay(amount: int) -> str:
            return "paid"

        pay(amount=5, ghost=1)
        (decision,) = _details(log)
        assert (decision["rule_id"], decision["layer"]) == ("ghost_arguments", "1:ghost_arguments")

    def test_absent_values_are_named(self, tmp_path: Path) -> None:
        log = DecisionLog(tmp_path / "decisions.jsonl")

        @Airlock(config=_config(log))
        def pay(amount: int) -> str:
            return "paid"

        pay(amount=5)
        decision = _details(log)[0]
        assert decision["policy_digest"] == "no_policy"
        assert decision["rule_id"] == "no_refusal"
        assert decision["layer"] == "no_refusal"

    def test_a_policy_not_reached_is_not_evaluated(self, tmp_path: Path) -> None:
        log = DecisionLog(tmp_path / "decisions.jsonl")
        config = _config(log, unknown_args=UnknownArgsMode.BLOCK)

        @Airlock(config=config, policy=SecurityPolicy(allowed_tools=["pay"]))
        def pay(amount: int) -> str:
            return "paid"

        pay(amount=5, ghost=1)
        assert _details(log)[0]["policy_digest"] == "not_evaluated"

    def test_every_refusal_in_pre_execution_names_its_step(self) -> None:
        """A new gate's refusal must say which step it came from, or its layer is unnamed."""
        source = Path(inspect.getfile(Airlock)).read_text(encoding="utf-8")
        returns = re.findall(
            r"^( +)(?:(context\._refused_at = \"[^\"]+\")\n +)?"
            r"return \w+, start_time, context, (\w+_error), None, None$",
            source,
            re.M,
        )
        assert len(returns) >= 15
        assert [name for _, tag, name in returns if not tag] == []

    def test_a_decision_the_log_cannot_hold_is_not_run(self, tmp_path: Path) -> None:
        path = tmp_path / "decisions.jsonl"
        log = DecisionLog(path)
        path.mkdir()  # the log's path is now a directory: every append fails
        ran: list[int] = []

        @Airlock(config=_config(log))
        def pay(amount: int) -> str:
            ran.append(amount)
            return "paid"

        result = pay(amount=5)
        assert result["block_reason"] == "policy_indeterminate"
        assert "decision log" in result["error"]
        assert ran == []

    def test_a_raised_call_is_recorded_as_an_error(self, tmp_path: Path) -> None:
        log = DecisionLog(tmp_path / "decisions.jsonl")

        @Airlock(config=_config(log))
        def pay(amount: int) -> str:
            raise RuntimeError("backend down")

        pay(amount=5)
        decision, outcome = log.records()
        assert outcome.decision == "error"
        assert outcome.details == {
            "entry": "outcome",
            "decision_hash": decision.record_hash,
            "outcome": "raised",
            "error_type": "RuntimeError",
        }


class TestWhatTheDecisionCovers:
    def test_unserializable_values_are_marked_and_stripped_names_recorded(
        self, tmp_path: Path
    ) -> None:
        class Session:
            pass

        log = DecisionLog(tmp_path / "decisions.jsonl")
        audit = tmp_path / "audit.jsonl"
        config = _config(
            log,
            unknown_args=UnknownArgsMode.STRIP_AND_LOG,
            enable_audit_log=True,
            audit_log_path=audit,
        )

        @Airlock(config=config)
        def save(note: str, session: Any = None) -> str:
            return "saved"

        save(note="hi", session=Session(), ghost="bob@example.com")
        decision = _details(log)[0]
        assert decision["unserializable_args"] == ["session"]
        assert decision["stripped_args"] == ["ghost"]
        records = [
            json.loads(line)
            for line in audit.read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        ]
        assert records[-1]["stripped_args"] == ["ghost"]
        assert "ghost" in records[-1]["requested_args_preview"]
        assert "bob@example.com" not in json.dumps(records[-1])
        assert "ghost" not in records[-1]["args_preview"]

    def test_a_refused_call_names_what_was_stripped_too(self, tmp_path: Path) -> None:
        audit = tmp_path / "audit.jsonl"
        config = AirlockConfig(
            unknown_args=UnknownArgsMode.STRIP_AND_LOG,
            enable_audit_log=True,
            audit_log_path=audit,
        )

        @Airlock(config=config, policy=SecurityPolicy(denied_tools=["save"]))
        def save(note: str) -> str:
            return "saved"

        save(note="hi", ghost="x")
        (record,) = [
            json.loads(line)
            for line in audit.read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        ]
        assert record["blocked"] is True
        assert record["stripped_args"] == ["ghost"]
        assert "ghost" in record["requested_args_preview"]

    def test_a_call_that_stripped_nothing_keeps_its_record_shape(self, tmp_path: Path) -> None:
        audit = tmp_path / "audit.jsonl"
        config = AirlockConfig(enable_audit_log=True, audit_log_path=audit)

        @Airlock(config=config)
        def save(note: str) -> str:
            return "saved"

        save(note="hi")
        (record,) = [
            json.loads(line)
            for line in audit.read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        ]
        assert "stripped_args" not in record
        assert "requested_args_preview" not in record

    def test_only_a_value_the_digest_could_not_read_is_named(self) -> None:
        class Session:
            pass

        named = unserializable_arguments(
            {
                "note": "mentions __unserializable__ in passing",
                "forged": {"__unserializable__": "Session"},
                "nested": {"by": [1, {"inner": Session()}]},
                "keyed": {1: Session()},
                "plain": {"a": [1, 2]},
            }
        )
        assert named == ["keyed", "nested"]

    def test_the_context_digest_splits_caller_and_authority(self, tmp_path: Path) -> None:
        log = DecisionLog(tmp_path / "decisions.jsonl")

        @Airlock(config=_config(log))
        def pay(amount: int) -> str:
            return "paid"

        with AirlockContext(agent_id="a"):
            pay(amount=5)
        with AirlockContext(agent_id="b"):
            pay(amount=5)
        with AirlockContext(agent_id="b"):
            pay(amount=6)
        first, second, third = (d for d in _details(log) if d["entry"] == "decision")
        assert first["caller_digest"] == second["caller_digest"]
        assert first["authority_digest"] != second["authority_digest"]
        assert second["authority_digest"] == third["authority_digest"]
        assert second["caller_digest"] != third["caller_digest"]
        assert len({d["decision_context_digest"] for d in (first, second, third)}) == 3


class _SlowLog(DecisionLog):
    """A log whose writes take 50 ms, so a write nobody waits for is still pending."""

    def append(self, **kwargs: Any) -> Any:
        time.sleep(0.05)
        return super().append(**kwargs)


class TestTheAsyncPath:
    def test_the_writes_are_awaited(self, tmp_path: Path) -> None:
        log = _SlowLog(tmp_path / "decisions.jsonl")
        seen: list[str] = []

        @Airlock(config=_config(log))
        async def pay(amount: int) -> str:
            seen.extend(d["entry"] for d in _details(log))
            await asyncio.sleep(0)
            return "paid"

        async def main() -> tuple[Any, list[str]]:
            result = await pay(amount=5)
            return result, [d["entry"] for d in _details(log)]

        result, entries = asyncio.run(main())
        assert result == "paid"
        assert seen == ["decision"]
        assert entries == ["decision", "outcome"]

    def test_the_loop_runs_while_a_write_is_on_disk(self, tmp_path: Path) -> None:
        log = _SlowLog(tmp_path / "decisions.jsonl")

        @Airlock(config=_config(log))
        async def pay(amount: int) -> str:
            return "paid"

        async def main() -> int:
            ticks = 0

            async def ticker() -> None:
                nonlocal ticks
                while True:
                    ticks += 1
                    await asyncio.sleep(0.005)

            task = asyncio.create_task(ticker())
            await asyncio.sleep(0)
            before = ticks
            await pay(amount=5)
            task.cancel()
            return ticks - before

        assert asyncio.run(main()) >= 5


class TestCheckpoints:
    def _log_with(self, tmp_path: Path, count: int, key: bytes | None = None) -> DecisionLog:
        log = DecisionLog(tmp_path / "decisions.jsonl", checkpoint_key=key)
        for i in range(count):
            log.append(stage="policy", tool_name=f"t{i}", decision="allow")
        return log

    def test_a_pruned_log_verifies_from_its_checkpoint(self, tmp_path: Path) -> None:
        log = self._log_with(tmp_path, 4, key=b"k" * 32)
        checkpoint = log.checkpoint()
        log.append(stage="policy", tool_name="later", decision="allow")
        assert log.prune(checkpoint) == 4
        assert [r.seq for r in log.records()] == [4]
        assert log.verify().ok
        DecisionLog(log.path, checkpoint_key=b"k" * 32)  # loads, verifying

    def test_without_its_checkpoint_a_pruned_log_fails(self, tmp_path: Path) -> None:
        log = self._log_with(tmp_path, 3)
        checkpoint = log.checkpoint()
        log.append(stage="policy", tool_name="later", decision="allow")
        log.prune(checkpoint)
        log.checkpoint_path.unlink()
        result = log.verify()
        assert result.ok is False and "no checkpoint" in result.detail

    def test_a_signed_checkpoint_needs_its_key(self, tmp_path: Path) -> None:
        log = self._log_with(tmp_path, 2, key=b"k" * 32)
        checkpoint = log.checkpoint()
        log.append(stage="policy", tool_name="later", decision="allow")
        log.prune(checkpoint)
        assert DecisionLog(log.path, verify_on_load=False).verify().ok is False
        wrong = DecisionLog(log.path, verify_on_load=False, checkpoint_key=b"j" * 32)
        assert "does not authenticate" in wrong.verify().detail

    def test_an_edited_checkpoint_fails(self, tmp_path: Path) -> None:
        log = self._log_with(tmp_path, 2, key=b"k" * 32)
        checkpoint = log.checkpoint()
        log.append(stage="policy", tool_name="later", decision="allow")
        log.prune(checkpoint)
        line = json.loads(log.checkpoint_path.read_text(encoding="utf-8"))
        line["head_hash"] = "f" * 64
        log.checkpoint_path.write_text(json.dumps(line) + "\n", encoding="utf-8")
        assert log.verify().ok is False

    def test_prune_takes_only_this_logs_checkpoints(self, tmp_path: Path) -> None:
        log = self._log_with(tmp_path, 2)
        other = self._log_with(tmp_path / "other", 3)
        with pytest.raises(DecisionLogError):
            log.prune(other.checkpoint())

    def test_an_empty_log_has_nothing_to_checkpoint(self, tmp_path: Path) -> None:
        with pytest.raises(DecisionLogError):
            DecisionLog(tmp_path / "empty.jsonl").checkpoint()

    def test_records_written_before_details_existed_still_verify(self, tmp_path: Path) -> None:
        log = self._log_with(tmp_path, 3)
        assert all("details" not in line for line in log.path.read_text().splitlines())
        assert log.verify().ok

    def test_a_log_pruned_through_its_head_goes_on_after_a_restart(self, tmp_path: Path) -> None:
        log = self._log_with(tmp_path, 3, key=b"k" * 32)
        log.prune(log.checkpoint())
        assert log.records() == []
        restarted = DecisionLog(log.path, checkpoint_key=b"k" * 32)
        record = restarted.append(stage="policy", tool_name="later", decision="allow")
        assert record.seq == 3
        assert restarted.verify().ok

    def test_records_removed_from_the_end_are_detected(self, tmp_path: Path) -> None:
        log = self._log_with(tmp_path, 4)
        log.checkpoint()
        lines = log.path.read_text(encoding="utf-8").splitlines()
        log.path.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")
        result = log.verify()
        assert result.ok is False and "removed from the end" in result.detail

    def test_a_rewritten_chain_does_not_match_its_checkpoint(self, tmp_path: Path) -> None:
        log = self._log_with(tmp_path, 3)
        log.checkpoint()
        log.path.unlink()
        forged = DecisionLog(log.path, verify_on_load=False)
        forged._next_seq, forged._head_hash = 0, "0" * 64  # start over, hashes recomputed
        for i in range(3):
            forged.append(stage="policy", tool_name=f"t{i}", decision="block")
        result = log.verify()
        assert result.ok is False and result.first_bad_seq == 2

    def test_an_unsigned_checkpoint_is_refused_by_a_log_that_signs_them(
        self, tmp_path: Path
    ) -> None:
        log = self._log_with(tmp_path, 2, key=b"k" * 32)
        checkpoint = log.checkpoint()
        log.append(stage="policy", tool_name="later", decision="allow")
        log.prune(checkpoint)
        line = json.loads(log.checkpoint_path.read_text(encoding="utf-8"))
        line["mac"] = None
        log.checkpoint_path.write_text(json.dumps(line) + "\n", encoding="utf-8")
        assert "unsigned" in log.verify().detail

    def test_a_broken_chain_is_not_pruned(self, tmp_path: Path) -> None:
        log = self._log_with(tmp_path, 3)
        checkpoint = log.checkpoint()
        text = log.path.read_text(encoding="utf-8").replace('"t0"', '"edited"')
        log.path.write_text(text, encoding="utf-8")
        with pytest.raises(DecisionLogError, match="does not verify"):
            log.prune(checkpoint)
        assert len(log.records()) == 3


class TestTheConformanceCli:
    def _signed_and_pruned(self, tmp_path: Path) -> Path:
        log = DecisionLog(tmp_path / "decisions.jsonl", checkpoint_key=b"k" * 32)
        for i in range(3):
            log.append(stage="policy", tool_name=f"t{i}", decision="allow")
        checkpoint = log.checkpoint()
        log.append(stage="policy", tool_name="later", decision="allow")
        log.prune(checkpoint)
        return log.path

    def test_verify_reads_the_key_from_the_named_variable(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = self._signed_and_pruned(tmp_path)
        monkeypatch.setenv("AIRLOCK_TEST_CHECKPOINT_KEY", "k" * 32)
        argv = ["verify", "--log", str(path), "--checkpoint-key-env"]
        assert conformance_main([*argv, "AIRLOCK_TEST_CHECKPOINT_KEY"]) == 0
        assert conformance_main(["verify", "--log", str(path)]) == 1
        export = ["export", "--log", str(path), "--quiet", "--checkpoint-key-env"]
        assert conformance_main([*export, "AIRLOCK_TEST_CHECKPOINT_KEY"]) == 0

    def test_an_unset_variable_is_an_error_not_an_unsigned_read(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        path = self._signed_and_pruned(tmp_path)
        monkeypatch.delenv("AIRLOCK_TEST_CHECKPOINT_KEY", raising=False)
        for command in ("verify", "export", "record"):
            argv = [command, "--log", str(path), "--checkpoint-key-env"]
            argv.append("AIRLOCK_TEST_CHECKPOINT_KEY")
            if command == "record":
                argv += ["--stage", "policy", "--tool", "t", "--decision", "allow"]
            assert conformance_main(argv) == 2
        assert "AIRLOCK_TEST_CHECKPOINT_KEY is not set" in capsys.readouterr().err


class TestTheOtelArgsHash:
    def test_it_is_the_canonical_digest(self) -> None:
        assert _hash_args({"b": 1, "a": [1, 2]}) == args_digest({"a": [1, 2], "b": 1})

    def test_an_object_is_marked_not_read_as_its_str(self) -> None:
        class Opaque:
            def __str__(self) -> str:
                return "1"

        assert _hash_args({"x": Opaque()}) != _hash_args({"x": "1"})
