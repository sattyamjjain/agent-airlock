"""Let agentdojo 0.1.35 call Claude 5.x models, and account for every call it makes.

Why this exists
---------------
Unmodified ``agentdojo`` 0.1.35 cannot run any Claude 5.x model. Each point below was read
from the installed ``agentdojo/agent_pipeline/llms/anthropic_llm.py`` and
``agentdojo/benchmark.py``:

* ``chat_completion_request`` always passes ``temperature`` (``0.0`` by default). Claude
  5.x rejects sampling parameters with a 400 (Opus 5.5 any value, Sonnet and Haiku 5.5 any
  non-default value), and ``anthropic`` 1.x removed ``temperature`` from
  ``messages.stream()``, so the call raises ``TypeError`` before a request is even sent.
* A ``-thinking-N`` model suffix sends ``{"type": "enabled", "budget_tokens": N}``, a 400
  on every 5.x model.
* ``max_tokens`` is 1024. Thinking counts against it, and agentdojo parses tool calls only
  when ``stop_reason == "tool_use"``, so a truncated turn silently scores the task as a
  failure.
* ``stop_reason`` is discarded, refusals included; the system prompt goes out as a plain
  string with no ``cache_control``.
* The benchmark loop catches only ``openai.BadRequestError``, so the first Anthropic API
  error ends the whole run.

What the patch does
-------------------
:func:`install_claude_patch` swaps the module-global ``chat_completion_request`` that
``AnthropicLLM.query`` looks up at call time (``run.py`` already hooks
``_anthropic_to_assistant_message`` through the same seam). The replacement:

* never sends ``temperature``, ``top_p``, ``top_k`` or ``budget_tokens``; what agentdojo
  tried to send is recorded instead;
* sends the pinned ``output_config={"effort": ...}``, ``thinking={"type": "adaptive",
  "display": "omitted"}`` (or no ``thinking`` field), ``max_tokens`` (16,000 by default)
  and a top-level ``cache_control={"type": "ephemeral"}``, which turns on automatic prompt
  caching of the stable prefix (tools, then system, then messages). ``display`` is pinned to
  ``"omitted"`` because agentdojo joins thinking text into the model output its utility
  and security checks read;
* keeps agentdojo's own tool and system-prompt conversion, and replays every earlier
  assistant turn exactly as the API returned it. agentdojo rebuilds a turn as text and
  thinking blocks first and tool calls last, which reorders interleaved blocks; where the
  API enforces preserved thinking that edit invalidates the turn's thinking signatures;
* streams through the ``anthropic`` 1.x SDK and ``get_final_message()``, as agentdojo
  does, on a client from :func:`benchmarks._claude.client.make_client` (the key passed
  explicitly, a foreign ``ANTHROPIC_BASE_URL`` refused) rather than agentdojo's own;
* records every call to a JSONL file (model, stop reason, refusal category, usage with
  cache reads and writes) and prices it into the shared ledger by exact model id
  (:func:`benchmarks._claude.batch.record_sync_message`);
* turns ``stop_reason`` ``"refusal"``, ``"max_tokens"`` or
  ``"model_context_window_exceeded"`` into a recorded failed step: the turn reaches
  agentdojo with its text and no tool calls, so the episode ends and is scored rather than
  crashing or running half a tool call;
* refuses, before sending, a call whose worst case would take the job past its budget, and
  refuses a response served by a model other than the one requested. No fallback is ever
  configured, so nothing can swap the model under test.

An API error that survives the SDK's own retries is not converted into a result: it ends
the pass, and agentdojo keeps the trajectories finished so far in ``--logdir`` for a
``--resume``.

Nothing here imports ``agentdojo`` or ``anthropic`` at module level, so this module, and
the tests that drive it with a stub client, import without the ``[bench]`` extra.
"""

from __future__ import annotations

import json
import re
import threading
import time
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benchmarks._claude.batch import record_sync_message
from benchmarks._claude.budget import BudgetExceededError
from benchmarks._claude.ledger import Ledger
from benchmarks._claude.pricing import UnpricedModelError, price_usage, worst_case_usd

DEFAULT_MAX_TOKENS = 16_000
"""Room for adaptive thinking plus a tool call; agentdojo's own 1024 truncates 5.x turns."""

THINKING_DISPLAY = "omitted"
"""Pinned so no thinking text reaches agentdojo's scored model output."""

CACHE_CONTROL: dict[str, str] = {"type": "ephemeral"}
"""Top-level automatic prompt caching (prefix order: tools, system, messages)."""

EFFORT_LEVELS = frozenset({"low", "medium", "high", "xhigh", "max"})
THINKING_MODES = frozenset({"adaptive", "omit"})

DROPPED_PARAMS = ("temperature", "top_p", "top_k", "thinking_budget_tokens")
"""Never sent to a 5.x model; agentdojo's values for them are recorded per call."""

FAILED_STEP_STOP_REASONS = frozenset({"refusal", "max_tokens", "model_context_window_exceeded"})
"""Stop reasons that end the episode as a recorded failed step, never an exception."""

AGENTDOJO_BLOCK_TYPES = frozenset({"text", "thinking", "tool_use"})
"""Block types agentdojo converts in both directions. ``redacted_thinking`` reaches its
message history but its request converter raises on it, so it stays out of agentdojo's
copy and comes back only through the turn replay."""

_CLAUDE_5_RE = re.compile(r"^claude-(?:opus|sonnet|haiku|fable|mythos)-5(?:-\d{1,2})?$")
_PATCHED_ATTR = "chat_completion_request"


class ServedModelMismatchError(RuntimeError):
    """The API answered with a model other than the one requested."""


def is_claude5_model(model_id: str) -> bool:
    """True for an undated Claude 5.x id (``claude-haiku-5-5``, ``claude-fable-5-1``...)."""
    return bool(_CLAUDE_5_RE.match(model_id))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _get(obj: Any, key: str) -> Any:
    if isinstance(obj, Mapping):
        return obj.get(key)
    return getattr(obj, key, None)


def _block_type(block: Any) -> str | None:
    value = _get(block, "type")
    return str(value) if value is not None else None


def _tool_use_ids(content: Any) -> tuple[str, ...]:
    """Ids of the ``tool_use`` blocks in an assistant turn, in order."""
    if not isinstance(content, Sequence) or isinstance(content, (str, bytes)):
        return ()
    return tuple(str(_get(block, "id")) for block in content if _block_type(block) == "tool_use")


def _usage_dict(message: Any) -> dict[str, Any]:
    """The response's usage as plain numbers (no text, never ``None`` values)."""
    data = message if isinstance(message, Mapping) else message.to_dict()
    usage = data.get("usage") or {}
    out: dict[str, Any] = {}
    for key, value in dict(usage).items():
        if value is None:
            continue
        if isinstance(value, Mapping):
            nested = {k: v for k, v in value.items() if v is not None}
            if nested:
                out[key] = nested
        else:
            out[key] = value
    return out


def _json_default(obj: Any) -> Any:
    dump = getattr(obj, "model_dump", None)
    if callable(dump):
        return dump(mode="json")
    return str(obj)


def estimate_input_tokens(params: Mapping[str, Any]) -> int:
    """A deliberately high token estimate for one request: two characters per token.

    Used only to bound a call's worst case before it is sent; billing always uses the
    response's own ``usage``.
    """
    payload = {key: params[key] for key in ("system", "tools", "messages") if key in params}
    return len(json.dumps(payload, default=_json_default)) // 2 + 1


class CallRecorder:
    """Per-call JSONL record, ledger pricing and an in-process spend cap for one job.

    Args:
        path: JSONL file to append one record per API call to (``None`` keeps no file).
        job: Ledger job name; every response is priced into the ledger under it.
        ledger: The shared spend ledger, or ``None`` to price without recording spend.
        cap_usd: The job's reservation. A call whose worst case would take the job's spend
            past it is refused before it is sent. ``None`` disables the in-process cap.
        on_usage: Called after each priced response with its token counts and USD.
    """

    def __init__(
        self,
        path: Path | None,
        *,
        job: str,
        ledger: Ledger | None = None,
        cap_usd: float | None = None,
        on_usage: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.path = path
        self.job = job
        self.ledger = ledger
        self.cap_usd = cap_usd
        self.on_usage = on_usage
        self.calls = 0
        self.spent_usd = 0.0
        self.outcomes: Counter[str] = Counter()
        self.refusal_categories: Counter[str] = Counter()
        self.unrestored_turns = 0
        self._lock = threading.Lock()

    def next_seq(self) -> int:
        with self._lock:
            self.calls += 1
            return self.calls

    def check_budget(self, model: str, est_input_tokens: int, max_tokens: int) -> float:
        """Raise unless this call's worst case still fits under the job's cap.

        Returns:
            The call's worst case in USD (recorded with the call).

        Raises:
            BudgetExceededError: The job's spend plus this call's worst case exceeds the cap.
            UnpricedModelError: ``model`` has no exact-id price.
        """
        worst = worst_case_usd(model, est_input_tokens, max_tokens, batch=False)
        if self.cap_usd is not None and self.spent_usd + worst > self.cap_usd:
            raise BudgetExceededError(
                f"job {self.job!r}: spent ${self.spent_usd:.4f} plus this call's worst case "
                f"${worst:.4f} would exceed the reserved ${self.cap_usd:.2f}; the pass stops "
                "here (finished trajectories stay cached in --logdir for --resume)"
            )
        return worst

    def price(self, message: Any, *, custom_id: str) -> float:
        """Price one response (into the ledger when one is configured)."""
        if self.ledger is not None:
            usd = record_sync_message(
                message, job=self.job, custom_id=custom_id, ledger=self.ledger
            )
        else:
            data = message if isinstance(message, Mapping) else message.to_dict()
            usd = price_usage(str(data.get("model")), data.get("usage") or {}, batch=False)
        with self._lock:
            self.spent_usd += usd
        return usd

    def record(self, row: Mapping[str, Any]) -> None:
        """Append one call record and count its outcome."""
        with self._lock:
            outcome = str(row.get("outcome"))
            self.outcomes[outcome] += 1
            category = row.get("stop_details_category")
            if outcome == "refusal":
                self.refusal_categories[str(category)] += 1
            self.unrestored_turns += int(row.get("unrestored_turns") or 0)
            if self.path is None:
                return
            self.path.parent.mkdir(parents=True, exist_ok=True)
            line = json.dumps({"ts": _now(), **row}, sort_keys=True, default=str)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")

    def summary(self) -> dict[str, Any]:
        """Counts for the run manifest and the rendered block."""
        return {
            "calls": self.calls,
            "spent_usd": round(self.spent_usd, 6),
            "outcomes": dict(sorted(self.outcomes.items())),
            "refusal_categories": dict(sorted(self.refusal_categories.items())),
            "unrestored_turns": self.unrestored_turns,
        }


class _AgentdojoView:
    """The response as agentdojo sees it: same message, filtered content.

    ``_anthropic_to_assistant_message`` reads only ``stop_reason`` and ``content``; every
    other attribute falls through to the real response.
    """

    def __init__(self, message: Any, content: list[Any]) -> None:
        self._message = message
        self.content = content

    def __getattr__(self, name: str) -> Any:
        return getattr(self._message, name)


@dataclass
class _PatchState:
    effort_by_model: dict[str, str]
    max_tokens: int
    thinking: str
    recorder: CallRecorder
    client_factory: Callable[[], Any]
    client: Any = None
    turns: dict[tuple[str, ...], list[Any]] = field(default_factory=dict)

    def _client(self) -> Any:
        if self.client is None:
            self.client = self.client_factory()
        return self.client

    def _restore_turns(self, messages: Sequence[Any]) -> tuple[list[Any], int, int]:
        """Swap each earlier assistant turn for the content the API actually returned."""
        out: list[Any] = []
        restored = unrestored = 0
        for message in messages:
            if isinstance(message, Mapping) and message.get("role") == "assistant":
                ids = _tool_use_ids(message.get("content"))
                if ids:
                    original = self.turns.get(ids)
                    if original is not None:
                        message = {**message, "content": list(original)}
                        restored += 1
                    else:
                        unrestored += 1
            out.append(message)
        return out, restored, unrestored

    def build_params(
        self, model: str, messages: Sequence[Any], tools: Sequence[Any], system_prompt: str | None
    ) -> tuple[dict[str, Any], int, int]:
        effort = self.effort_by_model.get(model)
        if effort is None:
            raise ValueError(
                f"claude_patch has no pinned effort for {model!r}; install it with that model "
                "in effort_by_model (run.py takes --effort)"
            )
        restored_messages, restored, unrestored = self._restore_turns(messages)
        params: dict[str, Any] = {
            "model": model,
            "messages": restored_messages,
            "max_tokens": self.max_tokens,
            "output_config": {"effort": effort},
            "cache_control": dict(CACHE_CONTROL),
        }
        if self.thinking == "adaptive":
            params["thinking"] = {"type": "adaptive", "display": THINKING_DISPLAY}
        if tools:
            params["tools"] = list(tools)
        if system_prompt:
            params["system"] = system_prompt
        return params, restored, unrestored

    def request(
        self,
        *,
        model: str,
        messages: Sequence[Any],
        tools: Sequence[Any],
        system_prompt: str | None,
        dropped: dict[str, Any],
    ) -> _AgentdojoView:
        params, restored, unrestored = self.build_params(model, messages, tools, system_prompt)
        est_input = estimate_input_tokens(params)
        worst = self.recorder.check_budget(model, est_input, self.max_tokens)
        seq = self.recorder.next_seq()
        row: dict[str, Any] = {
            "seq": seq,
            "job": self.recorder.job,
            "requested_model": model,
            **_trace_context(),
            "effort": params["output_config"]["effort"],
            "max_tokens": self.max_tokens,
            "thinking": params.get("thinking"),
            "cache_control": params["cache_control"],
            "dropped_params": {k: v for k, v in dropped.items() if v is not None},
            "restored_turns": restored,
            "unrestored_turns": unrestored,
            "est_input_tokens": est_input,
            "worst_case_usd": worst,
        }
        started = time.monotonic()
        try:
            with self._client().messages.stream(**params) as stream:
                message = stream.get_final_message()
        except Exception as exc:
            # Recorded, then re-raised: an API error is never turned into a scored step.
            row["outcome"] = "api_error"
            row["error_type"] = type(exc).__name__
            row["status_code"] = getattr(exc, "status_code", None)
            self.recorder.record(row)
            raise
        row["latency_s"] = round(time.monotonic() - started, 3)

        served = str(_get(message, "model"))
        stop_reason = _get(message, "stop_reason")
        stop_details = _get(message, "stop_details")
        content = list(_get(message, "content") or [])
        custom_id = str(_get(message, "id") or f"call-{seq:06d}")
        row.update(
            {
                "model": served,
                "message_id": _get(message, "id"),
                "request_id": getattr(message, "_request_id", None),
                "stop_reason": stop_reason,
                "stop_details_category": (
                    _get(stop_details, "category") if stop_details is not None else None
                ),
                "tool_use_blocks": sum(1 for b in content if _block_type(b) == "tool_use"),
                "usage": _usage_dict(message),
            }
        )

        if served != model:
            row["outcome"] = "model_mismatch"
            try:
                row["usd"] = self.recorder.price(message, custom_id=custom_id)
            except UnpricedModelError:
                row["usd"] = None
            self.recorder.record(row)
            raise ServedModelMismatchError(
                f"requested {model!r} but the API answered as {served!r}; refusing to score "
                "a substituted model"
            )

        row["usd"] = self.recorder.price(message, custom_id=custom_id)
        if self.recorder.on_usage is not None:
            usage = row["usage"]
            self.recorder.on_usage(
                {
                    "model": served,
                    "prompt_tokens": int(usage.get("input_tokens") or 0),
                    "completion_tokens": int(usage.get("output_tokens") or 0),
                    "cache_read_tokens": int(usage.get("cache_read_input_tokens") or 0),
                    "cache_write_tokens": int(usage.get("cache_creation_input_tokens") or 0),
                    "usd": row["usd"],
                }
            )

        if stop_reason in FAILED_STEP_STOP_REASONS:
            # A failed step: its text reaches agentdojo, its (possibly partial) tool calls
            # and thinking do not, so the episode ends here and is scored.
            row["outcome"] = str(stop_reason)
            kept = [b for b in content if _block_type(b) == "text"]
        else:
            row["outcome"] = "ok" if stop_reason in {"tool_use", "end_turn"} else str(stop_reason)
            if stop_reason == "tool_use":
                self.turns[_tool_use_ids(content)] = content
            kept = [b for b in content if _block_type(b) in AGENTDOJO_BLOCK_TYPES]
        kept_ids = {id(b) for b in kept}
        dropped_types = Counter(str(_block_type(b)) for b in content if id(b) not in kept_ids)
        if dropped_types:
            row["dropped_block_types"] = dict(sorted(dropped_types.items()))
        self.recorder.record(row)
        return _AgentdojoView(message, kept)


def _trace_context() -> dict[str, Any]:
    """Which episode this call belongs to, read from agentdojo's active TraceLogger."""
    try:
        from agentdojo.logging import Logger
    except Exception:  # noqa: BLE001 - agentdojo absent (unit tests): no labels
        return {}
    context = getattr(Logger.get(), "context", None)
    if not isinstance(context, dict):
        return {}
    return {
        "suite": context.get("suite_name"),
        "user_task_id": context.get("user_task_id"),
        "injection_task_id": context.get("injection_task_id"),
        "attack_type": context.get("attack_type"),
        "pipeline": context.get("pipeline_name"),
    }


_STATE: _PatchState | None = None
_ORIGINALS: dict[int, tuple[Any, Any]] = {}
"""``id(target module) -> (module, original chat_completion_request)``."""


async def patched_chat_completion_request(
    client: Any,
    model: str,
    messages: list[Any],
    tools: list[Any],
    max_tokens: int | None = None,
    system_prompt: str | None = None,
    temperature: float | None = None,
    thinking_budget_tokens: int | None = None,
    **extra: Any,
) -> Any:
    """Drop-in for agentdojo's ``chat_completion_request`` (same call shape).

    ``client`` (agentdojo's own) and ``max_tokens`` (agentdojo's 1024) are ignored: the
    request goes out on the patch's client with the patch's ``max_tokens``.
    """
    del client  # agentdojo's client never sends; the patch's own client does
    state = _STATE
    if state is None:
        raise RuntimeError("claude_patch is not installed")
    dropped: dict[str, Any] = {
        "temperature": temperature,
        "thinking_budget_tokens": thinking_budget_tokens,
        "agentdojo_max_tokens": max_tokens,
    }
    for key in ("top_p", "top_k"):
        if key in extra:
            dropped[key] = extra.pop(key)
    if extra:
        dropped["unexpected_kwargs"] = sorted(extra)
    return state.request(
        model=model,
        messages=messages,
        tools=tools,
        system_prompt=system_prompt,
        dropped=dropped,
    )


def _agentdojo_anthropic_module() -> Any:
    import agentdojo.agent_pipeline.llms.anthropic_llm as module

    return module


class PatchHandle:
    """Returned by :func:`install_claude_patch`; usable as a context manager."""

    def uninstall(self) -> None:
        uninstall_claude_patch()

    def __enter__(self) -> PatchHandle:
        return self

    def __exit__(self, *exc: object) -> None:
        self.uninstall()


def _default_client_factory() -> Any:
    from benchmarks._claude.client import make_client

    return make_client()


def install_claude_patch(
    effort_by_model: Mapping[str, str],
    *,
    recorder: CallRecorder,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    thinking: str = "adaptive",
    client_factory: Callable[[], Any] | None = None,
    target: Any = None,
) -> PatchHandle:
    """Point agentdojo's ``chat_completion_request`` at the 5.x-safe replacement.

    Idempotent: installing again replaces the active configuration and keeps the one
    saved original, so :func:`uninstall_claude_patch` always restores agentdojo's own
    function.

    Args:
        effort_by_model: Exact Claude 5.x model id -> pinned effort.
        recorder: Where each call is recorded and priced.
        max_tokens: ``max_tokens`` sent on every call.
        thinking: ``"adaptive"`` (default) or ``"omit"`` (no ``thinking`` field).
        client_factory: Builds the Anthropic client on first use; defaults to
            :func:`benchmarks._claude.client.make_client`.
        target: The module to patch; defaults to agentdojo's ``anthropic_llm``.

    Raises:
        ValueError: A model is not a Claude 5.x id, an effort or thinking mode is unknown,
            or ``max_tokens`` is not positive.
    """
    global _STATE
    efforts = dict(effort_by_model)
    for model, effort in efforts.items():
        if not is_claude5_model(model):
            raise ValueError(f"claude_patch is for Claude 5.x ids only, got {model!r}")
        if effort not in EFFORT_LEVELS:
            raise ValueError(
                f"unknown effort {effort!r} for {model!r}; one of {sorted(EFFORT_LEVELS)}"
            )
    if thinking not in THINKING_MODES:
        raise ValueError(f"thinking must be one of {sorted(THINKING_MODES)}, got {thinking!r}")
    if max_tokens <= 0:
        raise ValueError(f"max_tokens must be positive, got {max_tokens}")

    module = target if target is not None else _agentdojo_anthropic_module()
    key = id(module)
    if key not in _ORIGINALS:
        _ORIGINALS[key] = (module, getattr(module, _PATCHED_ATTR))
    setattr(module, _PATCHED_ATTR, patched_chat_completion_request)
    _STATE = _PatchState(
        effort_by_model=efforts,
        max_tokens=max_tokens,
        thinking=thinking,
        recorder=recorder,
        client_factory=client_factory or _default_client_factory,
    )
    return PatchHandle()


def uninstall_claude_patch() -> None:
    """Restore every patched module's original ``chat_completion_request``."""
    global _STATE
    for module, original in _ORIGINALS.values():
        setattr(module, _PATCHED_ATTR, original)
    _ORIGINALS.clear()
    _STATE = None


def is_installed() -> bool:
    """True while a patch configuration is active."""
    return _STATE is not None
