"""``claude_patch``: agentdojo 0.1.35 calling Claude 5.x without what 5.x rejects.

Unpatched, agentdojo sends ``temperature`` (a 400 on 5.x, a ``TypeError`` in the
``anthropic`` 1.x SDK), ``budget_tokens`` for a ``-thinking-N`` id (a 400) and a 1024-token
``max_tokens`` that truncates thinking turns. These tests drive the replacement with a stub
client, so the module and most tests need neither ``agentdojo`` nor ``anthropic``; the last
class runs agentdojo's real ``AnthropicLLM.query`` through the patch and skips without the
``[bench]`` extra. No test sends a request anywhere.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from benchmarks._claude.budget import BudgetExceededError
from benchmarks._claude.ledger import Ledger
from benchmarks._claude.pricing import price_usage
from benchmarks.agentdojo import claude_patch as cp

MODEL = "claude-haiku-5-5"
USAGE = {
    "input_tokens": 1000,
    "output_tokens": 40,
    "cache_read_input_tokens": 3000,
    "cache_creation_input_tokens": 900,
}


def _block(kind: str, **fields: Any) -> SimpleNamespace:
    return SimpleNamespace(type=kind, **fields)


class _Message:
    """Shaped like ``anthropic.types.Message``: attributes plus ``to_dict()``."""

    def __init__(
        self,
        content: list[Any],
        stop_reason: str,
        *,
        model: str = MODEL,
        stop_details: Any = None,
        usage: dict[str, Any] | None = None,
    ) -> None:
        self.id = "msg_stub"
        self.model = model
        self.content = content
        self.stop_reason = stop_reason
        self.stop_details = stop_details
        self.usage = dict(USAGE if usage is None else usage)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "model": self.model,
            "stop_reason": self.stop_reason,
            "usage": dict(self.usage),
            "content": [vars(b) for b in self.content],
        }


class _Stream:
    def __init__(self, message: _Message) -> None:
        self._message = message

    def __enter__(self) -> _Stream:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def get_final_message(self) -> _Message:
        return self._message


class _StubClient:
    """Records every ``messages.stream(**params)`` and answers from a queue."""

    def __init__(self, *responses: _Message | Exception) -> None:
        self.calls: list[dict[str, Any]] = []
        self._responses = list(responses)

    @property
    def messages(self) -> _StubClient:
        return self

    def stream(self, **params: Any) -> _Stream:
        self.calls.append(params)
        response = self._responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return _Stream(response)


class _ForbiddenClient:
    """agentdojo's own client: the patch must never touch it."""

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"the patch used agentdojo's client ({name})")


@pytest.fixture
def target() -> Iterator[SimpleNamespace]:
    """A stand-in for agentdojo's anthropic_llm module (its original function)."""

    async def original(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("agentdojo's own chat_completion_request must not run")

    ns = SimpleNamespace(chat_completion_request=original)
    yield ns
    cp.uninstall_claude_patch()


def _install(
    target: SimpleNamespace,
    client: _StubClient,
    tmp_path: Path,
    *,
    cap_usd: float | None = None,
    thinking: str = "adaptive",
    on_usage: Any = None,
) -> cp.CallRecorder:
    recorder = cp.CallRecorder(
        tmp_path / "calls.jsonl",
        job="unit-job",
        ledger=Ledger(tmp_path / "ledger.jsonl"),
        cap_usd=cap_usd,
        on_usage=on_usage,
    )
    cp.install_claude_patch(
        {MODEL: "medium"},
        recorder=recorder,
        thinking=thinking,
        client_factory=lambda: client,
        target=target,
    )
    return recorder


def _call(target: SimpleNamespace, messages: list[Any] | None = None, **kwargs: Any) -> Any:
    """Invoke the patched function exactly as ``AnthropicLLM.query`` does."""
    return asyncio.run(
        target.chat_completion_request(
            _ForbiddenClient(),
            kwargs.pop("model", MODEL),
            messages or [{"role": "user", "content": "pay the bill"}],
            kwargs.pop("tools", [{"name": "send_money", "input_schema": {"type": "object"}}]),
            max_tokens=1024,
            system_prompt=kwargs.pop("system_prompt", "You are an agent."),
            temperature=kwargs.pop("temperature", 0.0),
            thinking_budget_tokens=kwargs.pop("thinking_budget_tokens", None),
            **kwargs,
        )
    )


def _rows(tmp_path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in (tmp_path / "calls.jsonl").read_text().splitlines()]


class TestRequestShape:
    def test_drops_sampling_and_budget_and_pins_effort_cache_and_max_tokens(
        self, target: SimpleNamespace, tmp_path: Path
    ) -> None:
        client = _StubClient(_Message([_block("text", text="done")], "end_turn"))
        _install(target, client, tmp_path)

        _call(target, thinking_budget_tokens=2048, top_p=0.9, top_k=5)

        (params,) = client.calls
        for rejected in ("temperature", "top_p", "top_k"):
            assert rejected not in params
        assert "budget_tokens" not in json.dumps(params, default=str)
        assert params["thinking"] == {"type": "adaptive", "display": "omitted"}
        assert params["output_config"] == {"effort": "medium"}
        assert params["cache_control"] == {"type": "ephemeral"}
        assert params["max_tokens"] == cp.DEFAULT_MAX_TOKENS == 16_000
        assert params["model"] == MODEL
        assert params["system"] == "You are an agent."
        assert params["tools"] == [{"name": "send_money", "input_schema": {"type": "object"}}]
        assert "tool_choice" not in params  # forced tool_choice is a 400 on Opus/Sonnet 5.5

        (row,) = _rows(tmp_path)
        assert row["dropped_params"] == {
            "temperature": 0.0,
            "thinking_budget_tokens": 2048,
            "agentdojo_max_tokens": 1024,
            "top_p": 0.9,
            "top_k": 5,
        }

    def test_thinking_can_be_omitted(self, target: SimpleNamespace, tmp_path: Path) -> None:
        client = _StubClient(_Message([_block("text", text="ok")], "end_turn"))
        _install(target, client, tmp_path, thinking="omit")
        _call(target)
        assert "thinking" not in client.calls[0]

    def test_a_model_without_a_pinned_effort_is_refused_before_sending(
        self, target: SimpleNamespace, tmp_path: Path
    ) -> None:
        client = _StubClient()
        _install(target, client, tmp_path)
        with pytest.raises(ValueError, match="no pinned effort"):
            _call(target, model="claude-sonnet-5-5")
        assert client.calls == []


class TestRecordingAndPricing:
    def test_each_call_is_recorded_and_priced_by_exact_id(
        self, target: SimpleNamespace, tmp_path: Path
    ) -> None:
        seen: list[dict[str, Any]] = []
        client = _StubClient(_Message([_block("text", text="done")], "end_turn"))
        recorder = _install(target, client, tmp_path, on_usage=seen.append)

        _call(target)

        (row,) = _rows(tmp_path)
        assert row["model"] == MODEL and row["requested_model"] == MODEL
        assert row["stop_reason"] == "end_turn" and row["outcome"] == "ok"
        assert row["stop_details_category"] is None
        assert row["usage"]["cache_read_input_tokens"] == 3000
        assert row["usage"]["cache_creation_input_tokens"] == 900
        assert row["effort"] == "medium" and row["max_tokens"] == 16_000
        expected = price_usage(MODEL, USAGE, batch=False)
        assert row["usd"] == pytest.approx(expected)
        # Ledger.spent() rounds to six decimals.
        assert Ledger(tmp_path / "ledger.jsonl").spent("unit-job") == pytest.approx(
            expected, abs=1e-6
        )
        assert recorder.spent_usd == pytest.approx(expected)
        assert seen == [
            {
                "model": MODEL,
                "prompt_tokens": 1000,
                "completion_tokens": 40,
                "cache_read_tokens": 3000,
                "cache_write_tokens": 900,
                "usd": pytest.approx(expected),
            }
        ]

    def test_the_record_holds_no_text(self, target: SimpleNamespace, tmp_path: Path) -> None:
        secret_text = "the model's private words"
        client = _StubClient(_Message([_block("text", text=secret_text)], "end_turn"))
        _install(target, client, tmp_path)
        _call(target, messages=[{"role": "user", "content": "a prompt nobody should log"}])
        raw = (tmp_path / "calls.jsonl").read_text()
        assert secret_text not in raw
        assert "a prompt nobody should log" not in raw


class TestFailedSteps:
    @pytest.mark.parametrize("stop_reason", sorted(cp.FAILED_STEP_STOP_REASONS))
    def test_a_failed_step_reaches_agentdojo_with_text_and_no_tool_calls(
        self, target: SimpleNamespace, tmp_path: Path, stop_reason: str
    ) -> None:
        details = (
            SimpleNamespace(type="refusal", category="cyber") if stop_reason == "refusal" else None
        )
        content = [
            _block("thinking", thinking="", signature="sig"),
            _block("text", text="partial answer"),
            _block("tool_use", id="toolu_partial", name="send_money", input={}),
        ]
        client = _StubClient(_Message(content, stop_reason, stop_details=details))
        recorder = _install(target, client, tmp_path)

        view = _call(target)  # must not raise

        assert view.stop_reason == stop_reason
        assert [b.type for b in view.content] == ["text"]
        (row,) = _rows(tmp_path)
        assert row["outcome"] == stop_reason
        assert row["dropped_block_types"] == {"thinking": 1, "tool_use": 1}
        assert recorder.outcomes[stop_reason] == 1
        if stop_reason == "refusal":
            assert row["stop_details_category"] == "cyber"
            assert recorder.refusal_categories["cyber"] == 1

    def test_redacted_thinking_stays_out_of_agentdojos_copy(
        self, target: SimpleNamespace, tmp_path: Path
    ) -> None:
        content = [
            _block("redacted_thinking", data="opaque"),
            _block("tool_use", id="toolu_1", name="get_balance", input={}),
        ]
        client = _StubClient(_Message(content, "tool_use"))
        _install(target, client, tmp_path)
        view = _call(target)
        assert [b.type for b in view.content] == ["tool_use"]
        assert _rows(tmp_path)[0]["dropped_block_types"] == {"redacted_thinking": 1}


class TestTurnReplay:
    """Earlier assistant turns go back exactly as the API returned them."""

    def test_an_interleaved_turn_is_replayed_in_its_original_order(
        self, target: SimpleNamespace, tmp_path: Path
    ) -> None:
        original = [
            _block("thinking", thinking="", signature="sigA"),
            _block("tool_use", id="toolu_1", name="get_balance", input={}),
            _block("thinking", thinking="", signature="sigB"),
            _block("tool_use", id="toolu_2", name="get_iban", input={}),
        ]
        client = _StubClient(
            _Message(original, "tool_use"), _Message([_block("text", text="done")], "end_turn")
        )
        _install(target, client, tmp_path)
        _call(target)

        # agentdojo rebuilds the turn thinking-first, tool calls last.
        rebuilt = {
            "role": "assistant",
            "content": [
                original[0],
                original[2],
                {"type": "tool_use", "id": "toolu_1", "name": "get_balance", "input": {}},
                {"type": "tool_use", "id": "toolu_2", "name": "get_iban", "input": {}},
            ],
        }
        results = {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "toolu_1"}]}
        _call(target, messages=[{"role": "user", "content": "q"}, rebuilt, results])

        replayed = client.calls[1]["messages"][1]["content"]
        assert len(replayed) == len(original)
        assert all(a is b for a, b in zip(replayed, original, strict=True))
        assert _rows(tmp_path)[1]["restored_turns"] == 1

    def test_an_unknown_turn_is_left_alone_and_counted(
        self, target: SimpleNamespace, tmp_path: Path
    ) -> None:
        client = _StubClient(_Message([_block("text", text="done")], "end_turn"))
        recorder = _install(target, client, tmp_path)
        turn = {
            "role": "assistant",
            "content": [{"type": "tool_use", "id": "toolu_never_seen", "name": "x", "input": {}}],
        }
        _call(target, messages=[{"role": "user", "content": "q"}, turn])
        assert client.calls[0]["messages"][1] is turn
        assert recorder.unrestored_turns == 1


class TestGuards:
    def test_a_call_past_the_budget_is_refused_before_sending(
        self, target: SimpleNamespace, tmp_path: Path
    ) -> None:
        client = _StubClient()
        _install(target, client, tmp_path, cap_usd=0.001)  # 16,000 output tokens cost $0.008
        with pytest.raises(BudgetExceededError, match="would exceed"):
            _call(target)
        assert client.calls == []
        assert not (tmp_path / "ledger.jsonl").exists()

    def test_a_substituted_model_is_recorded_then_refused(
        self, target: SimpleNamespace, tmp_path: Path
    ) -> None:
        served = "claude-sonnet-5-5"
        client = _StubClient(_Message([_block("text", text="hi")], "end_turn", model=served))
        _install(target, client, tmp_path)
        with pytest.raises(cp.ServedModelMismatchError):
            _call(target)
        (row,) = _rows(tmp_path)
        assert row["outcome"] == "model_mismatch" and row["model"] == served
        # The money was spent, so it is in the ledger, priced at the model that served it.
        assert Ledger(tmp_path / "ledger.jsonl").spent() == pytest.approx(
            price_usage(served, USAGE, batch=False), abs=1e-6
        )

    def test_an_api_error_is_recorded_and_re_raised(
        self, target: SimpleNamespace, tmp_path: Path
    ) -> None:
        class Overloaded(Exception):
            status_code = 529

        client = _StubClient(Overloaded("overloaded"))
        _install(target, client, tmp_path)
        with pytest.raises(Overloaded):
            _call(target)
        (row,) = _rows(tmp_path)
        assert row["outcome"] == "api_error"
        assert row["error_type"] == "Overloaded" and row["status_code"] == 529


class TestInstall:
    def test_install_is_idempotent_and_uninstall_restores_the_original(
        self, target: SimpleNamespace, tmp_path: Path
    ) -> None:
        original = target.chat_completion_request
        client = _StubClient()
        _install(target, client, tmp_path)
        _install(target, client, tmp_path)
        assert target.chat_completion_request is cp.patched_chat_completion_request
        assert cp.is_installed()
        cp.uninstall_claude_patch()
        assert target.chat_completion_request is original
        assert not cp.is_installed()

    def test_the_handle_is_a_context_manager(self, target: SimpleNamespace, tmp_path: Path) -> None:
        original = target.chat_completion_request
        recorder = cp.CallRecorder(None, job="j")
        with cp.install_claude_patch({MODEL: "low"}, recorder=recorder, target=target):
            assert target.chat_completion_request is cp.patched_chat_completion_request
        assert target.chat_completion_request is original

    @pytest.mark.parametrize(
        ("efforts", "kwargs", "match"),
        [
            ({"claude-haiku-4-5-20251001": "medium"}, {}, "Claude 5.x"),
            ({MODEL: "extreme"}, {}, "unknown effort"),
            ({MODEL: "medium"}, {"max_tokens": 0}, "max_tokens"),
            ({MODEL: "medium"}, {"thinking": "enabled"}, "thinking"),
        ],
    )
    def test_bad_configuration_is_refused(
        self, target: SimpleNamespace, efforts: dict[str, str], kwargs: dict[str, Any], match: str
    ) -> None:
        with pytest.raises(ValueError, match=match):
            cp.install_claude_patch(
                efforts, recorder=cp.CallRecorder(None, job="j"), target=target, **kwargs
            )

    def test_the_replacement_refuses_to_run_uninstalled(self) -> None:
        cp.uninstall_claude_patch()
        with pytest.raises(RuntimeError, match="not installed"):
            asyncio.run(cp.patched_chat_completion_request(None, MODEL, [], []))


class TestModelIds:
    @pytest.mark.parametrize(
        "model_id",
        [
            "claude-haiku-5-5",
            "claude-sonnet-5-5",
            "claude-opus-5-5",
            "claude-fable-5-1",
            "claude-opus-5",
            "claude-sonnet-5",
        ],
    )
    def test_claude_5_ids(self, model_id: str) -> None:
        assert cp.is_claude5_model(model_id)

    @pytest.mark.parametrize(
        "model_id",
        [
            "claude-haiku-4-5-20251001",
            "claude-3-5-haiku-20241022",
            "claude-opus-5-5-20260101",
            "gpt-4o-mini-2024-07-18",
        ],
    )
    def test_other_ids(self, model_id: str) -> None:
        assert not cp.is_claude5_model(model_id)


class TestThroughAgentdojo:
    """agentdojo's real ``AnthropicLLM.query`` with the patch on the real module."""

    def test_tool_calls_parse_and_a_refusal_is_a_failed_step(self, tmp_path: Path) -> None:
        pytest.importorskip("agentdojo", reason="agentdojo is the optional [bench] extra")
        anthropic = pytest.importorskip("anthropic")
        from agentdojo.agent_pipeline import ToolsExecutor
        from agentdojo.agent_pipeline.llms.anthropic_llm import AnthropicLLM
        from agentdojo.functions_runtime import FunctionsRuntime
        from agentdojo.task_suite.load_suites import get_suite
        from agentdojo.types import (
            ChatSystemMessage,
            ChatUserMessage,
            text_content_block_from_string,
        )
        from anthropic.types import Message

        def message(content: list[dict[str, Any]], stop_reason: str, **extra: Any) -> Any:
            return Message.model_validate(
                {
                    "id": "msg_x",
                    "type": "message",
                    "role": "assistant",
                    "model": MODEL,
                    "content": content,
                    "stop_reason": stop_reason,
                    "stop_sequence": None,
                    "usage": {"input_tokens": 1000, "output_tokens": 40},
                    **extra,
                }
            )

        tool_turn = message(
            [
                {"type": "thinking", "thinking": "", "signature": "sigA"},
                {"type": "tool_use", "id": "toolu_1", "name": "get_balance", "input": {}},
            ],
            "tool_use",
        )
        refusal = message(
            [{"type": "text", "text": "I can't help with that."}],
            "refusal",
            stop_details={"type": "refusal", "category": "cyber", "explanation": None},
        )
        client = _StubClient(tool_turn, refusal)
        recorder = cp.CallRecorder(
            tmp_path / "calls.jsonl", job="itest", ledger=Ledger(tmp_path / "ledger.jsonl")
        )
        suite = get_suite("v1.2.1", "banking")
        runtime = FunctionsRuntime(suite.tools)
        env = suite.load_and_inject_default_environment({})
        llm = AnthropicLLM(anthropic.AsyncAnthropic(api_key="sk-test-not-real"), MODEL)
        assert llm.temperature == 0.0 and llm._MAX_TOKENS == 1024  # what unpatched sends

        with cp.install_claude_patch(
            {MODEL: "medium"}, recorder=recorder, client_factory=lambda: client
        ):
            history = [
                ChatSystemMessage(
                    role="system", content=[text_content_block_from_string("Agent.")]
                ),
                ChatUserMessage(role="user", content=[text_content_block_from_string("Balance?")]),
            ]
            _, _, _, out, _ = llm.query("q", runtime, env, history, {})
            assert [c.function for c in out[-1]["tool_calls"]] == ["get_balance"]
            _, _, _, out, _ = ToolsExecutor().query("q", runtime, env, out, {})
            _, _, _, out, _ = llm.query("q", runtime, env, out, {})

        assert out[-1]["tool_calls"] is None
        assert out[-1]["content"] == [{"type": "text", "content": "I can't help with that."}]
        first, second = client.calls
        assert "temperature" not in first and first["max_tokens"] == 16_000
        replayed = [m for m in second["messages"] if m["role"] == "assistant"][0]["content"]
        assert all(a is b for a, b in zip(replayed, tool_turn.content, strict=True))
        assert [r["outcome"] for r in _rows(tmp_path)] == ["ok", "refusal"]

    def test_execute_model_runs_both_arms_once_each_and_replays_from_cache(
        self, tmp_path: Path
    ) -> None:
        """The whole model pass, wired as ``run.py --run`` wires it, against a stub client.

        One user task x one injection task in one suite is four episodes (benign and
        attacked, in each arm) and nothing else: the unscored injection-task benign runs
        ``benchmark_suite_with_injections`` would add are skipped. A second pass over the
        same logdir is answered from agentdojo's cache without a single call, which is
        what ``--resume`` relies on and why a reused logdir is otherwise refused.
        """
        pytest.importorskip("agentdojo", reason="agentdojo is the optional [bench] extra")
        pytest.importorskip("anthropic")
        from anthropic.types import Message
        from benchmarks.agentdojo.model_registry_shim import ensure_registered
        from benchmarks.agentdojo.run import execute_model

        done = Message.model_validate(
            {
                "id": "msg_done",
                "type": "message",
                "role": "assistant",
                "model": MODEL,
                "content": [{"type": "text", "text": "Done."}],
                "stop_reason": "end_turn",
                "stop_sequence": None,
                "usage": {"input_tokens": 500, "output_tokens": 5},
            }
        )
        client = _StubClient(*[done] * 8)
        recorder = cp.CallRecorder(
            tmp_path / "calls.jsonl", job="pass", ledger=Ledger(tmp_path / "ledger.jsonl")
        )
        ensure_registered([MODEL])
        logdir = tmp_path / "logs"
        with cp.install_claude_patch(
            {MODEL: "medium"}, recorder=recorder, client_factory=lambda: client
        ):
            results, _, _ = execute_model(MODEL, ("banking",), 1, 1, logdir_arg=str(logdir))
            assert len(client.calls) == 4
            again, _, _ = execute_model(MODEL, ("banking",), 1, 1, logdir_arg=str(logdir))
            assert len(client.calls) == 4  # every episode came back from the cache

        for arm in ("undefended", "airlock"):
            counts = results["banking"][arm]
            assert (counts.benign_n, counts.atk_util_n, counts.asr_n) == (1, 1, 1)
            assert again["banking"][arm] == counts
        rows = _rows(tmp_path)
        assert {r["pipeline"] for r in rows} == {f"{MODEL}-undefended", f"{MODEL}-airlock"}
        assert {r["attack_type"] for r in rows} == {"none", "tool_knowledge"}
        assert all(r["suite"] == "banking" for r in rows)
