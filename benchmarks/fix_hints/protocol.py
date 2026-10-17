"""The Messages API request each (scenario, arm, model) becomes, and the pilot's five.

Protocol ``tool`` (the default) is one batchable turn::

    user       the task
    assistant  tool_use  {id: toolu_fh_<sid>, name: <tool>, input: <malformed call>}
    user       tool_result {tool_use_id: toolu_fh_<sid>, is_error: true, content: <arm payload>}

with ``system`` a short neutral prompt, ``tools`` the offered tools' schemas built from
their signatures (no ``strict``), ``max_tokens`` 4096, ``thinking: {type: adaptive}`` and
``output_config.effort`` pinned to each model's API default. No ``tool_choice`` (auto:
the 5.5 models reject a forced choice), no temperature, no fallbacks: a fallback would
swap the model under test.

The synthetic assistant turn carries no thinking block. If the pilot shows a model
rejecting that (a 400 that cites thinking or tool_use ordering), protocol ``text``
describes the failed call and its error in a single user turn instead; the protocol that
ran is recorded in every run manifest.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from benchmarks._claude.batch import PlannedRequest
from benchmarks._claude.models import DEFAULT_EFFORT, model_alias

from .catalogue import tool_schema
from .payloads import Content, arm_content, content_sha256, content_text, refusal
from .scenarios import Scenario

SYSTEM_PROMPT = (
    "You are a helpful assistant. Use the tools provided to complete the user's request."
)
MAX_TOKENS = 4096
THINKING: dict[str, str] = {"type": "adaptive"}
PROTOCOLS: tuple[str, ...] = ("tool", "text")
ROUNDS: tuple[str, ...] = ("r1", "r2")

ASSUMED_VISIBLE_OUTPUT = 300
"""Visible output tokens assumed per request (a short note plus one tool call)."""
ASSUMED_THINKING: tuple[int, ...] = (0, 1000)
"""Thinking tokens per request for the expected-cost lines of a dry run."""
ASSUMED_OUTPUTS: tuple[int, ...] = tuple(ASSUMED_VISIBLE_OUTPUT + t for t in ASSUMED_THINKING)

CHARS_PER_TOKEN = 3.0
"""Conservative: JSON-heavy prompts run denser than prose. The pilot measures the real
figure; a paid run prices its worst case from this estimate."""
TOOL_USE_OVERHEAD_TOKENS = 500
"""The API's tool-use system prompt and per-tool framing, not visible in ``params``."""

_TOKEN = r"[a-z0-9]+"
CUSTOM_ID_RE = re.compile(rf"^fh-(r1|r2|pl|pb)-([hnsg])-({_TOKEN})-([a-z0-9-]+)$")
"""``fh-{round}-{arm}-{model alias}-{sid}``; ``pl`` / ``pb`` are pilot rounds."""


def tool_use_id(sid: str) -> str:
    """The id shared by the synthetic ``tool_use`` and its ``tool_result``."""
    return f"toolu_fh_{sid}"


def custom_id(round_: str, arm: str, alias: str, sid: str) -> str:
    """The Batch ``custom_id`` for one request (at most 64 characters).

    Raises:
        ValueError: The id would not match :data:`CUSTOM_ID_RE` or exceeds 64 characters.
    """
    value = f"fh-{round_}-{arm}-{alias}-{sid}"
    if len(value) > 64 or not CUSTOM_ID_RE.match(value):
        raise ValueError(f"invalid custom_id {value!r}")
    return value


def parse_custom_id(value: str) -> tuple[str, str, str, str]:
    """``(round, arm, model alias, sid)`` from a custom id.

    Raises:
        ValueError: ``value`` is not a fix_hints custom id.
    """
    match = CUSTOM_ID_RE.match(value)
    if match is None:
        raise ValueError(f"not a fix_hints custom_id: {value!r}")
    round_, arm, alias, sid = match.groups()
    return round_, arm, alias, sid


def tools_for(scenario: Scenario) -> list[dict[str, Any]]:
    """The ``tools`` parameter: every offered tool, the refused one first."""
    return [tool_schema(name) for name in scenario.tools_offered]


def build_messages(scenario: Scenario, content: Content, protocol: str) -> list[dict[str, Any]]:
    """The conversation for one request.

    Raises:
        ValueError: ``protocol`` is not one of :data:`PROTOCOLS`.
    """
    if protocol == "tool":
        tid = tool_use_id(scenario.sid)
        return [
            {"role": "user", "content": scenario.task},
            {
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "id": tid,
                        "name": scenario.tool,
                        "input": scenario.malformed,
                    }
                ],
            },
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": tid,
                        "is_error": True,
                        "content": content,
                    }
                ],
            },
        ]
    if protocol == "text":
        text = (
            f"{scenario.task}\n\n"
            f"Your previous attempt called the tool {scenario.tool} with this input:\n"
            f"{json.dumps(scenario.malformed)}\n"
            "The call failed. The tool returned this error:\n"
            f"{content_text(content)}"
        )
        return [{"role": "user", "content": text}]
    raise ValueError(f"unknown protocol {protocol!r}; known: {', '.join(PROTOCOLS)}")


def build_params(
    scenario: Scenario, model_id: str, content: Content, protocol: str = "tool"
) -> dict[str, Any]:
    """The Messages API params for one (scenario, model, arm content)."""
    return {
        "model": model_id,
        "max_tokens": MAX_TOKENS,
        "system": SYSTEM_PROMPT,
        "tools": tools_for(scenario),
        "messages": build_messages(scenario, content, protocol),
        "thinking": dict(THINKING),
        "output_config": {"effort": DEFAULT_EFFORT[model_id]},
    }


def estimate_input_tokens(params: Mapping[str, Any]) -> int:
    """A conservative input-token estimate (no network: dry runs need no SDK)."""
    body = {key: params[key] for key in ("system", "tools", "messages") if key in params}
    chars = len(json.dumps(body, separators=(",", ":")))
    return math.ceil(chars / CHARS_PER_TOKEN) + TOOL_USE_OVERHEAD_TOKENS


@dataclass(frozen=True)
class RequestRow:
    """One planned request and what it measures."""

    custom_id: str
    sid: str
    arm: str
    model: str
    """The model alias, e.g. ``h55``."""
    round: str
    protocol: str
    payload_sha256: str
    params: dict[str, Any] = field(repr=False)
    est_input_tokens: int = 0

    def planned(self) -> PlannedRequest:
        return PlannedRequest(
            custom_id=self.custom_id, params=self.params, est_input_tokens=self.est_input_tokens
        )

    def to_row(self) -> dict[str, Any]:
        return {
            "custom_id": self.custom_id,
            "sid": self.sid,
            "arm": self.arm,
            "model": self.model,
            "round": self.round,
            "protocol": self.protocol,
            "payload_sha256": self.payload_sha256,
            "params": self.params,
            "est_input_tokens": self.est_input_tokens,
        }

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> RequestRow:
        return cls(
            custom_id=str(row["custom_id"]),
            sid=str(row["sid"]),
            arm=str(row["arm"]),
            model=str(row["model"]),
            round=str(row["round"]),
            protocol=str(row["protocol"]),
            payload_sha256=str(row["payload_sha256"]),
            params=dict(row["params"]),
            est_input_tokens=int(row.get("est_input_tokens", 0)),
        )


def make_row(
    scenario: Scenario, arm: str, model_id: str, content: Content, round_: str, protocol: str
) -> RequestRow:
    alias = model_alias(model_id)
    params = build_params(scenario, model_id, content, protocol)
    return RequestRow(
        custom_id=custom_id(round_, arm, alias, scenario.sid),
        sid=scenario.sid,
        arm=arm,
        model=alias,
        round=round_,
        protocol=protocol,
        payload_sha256=content_sha256(content),
        params=params,
        est_input_tokens=estimate_input_tokens(params),
    )


def plan_requests(
    scenarios: Iterable[Scenario],
    payloads: Mapping[str, Mapping[str, Content]],
    model_ids: Iterable[str],
    arms: Iterable[str],
    round_: str,
    protocol: str,
) -> list[RequestRow]:
    """Every request of a round, grouped by model (one batch each), then arm, then sid."""
    chosen = list(scenarios)
    rows: list[RequestRow] = []
    for model_id in model_ids:
        for arm in arms:
            for scenario in chosen:
                content = payloads[scenario.sid][arm]
                rows.append(make_row(scenario, arm, model_id, content, round_, protocol))
    return rows


@dataclass(frozen=True)
class PilotRequest:
    """One of the pilot's five requests."""

    label: str
    mode: str
    """``sync`` (Messages API) or ``batch`` (a one-request Message Batch)."""
    row: RequestRow


PILOT_PLAN: tuple[tuple[str, str, str, str, str], ...] = (
    # label, mode, model alias, arm, category of the scenario
    ("Haiku 5.5, arm H", "sync", "h55", "h", "type_int"),
    ("Sonnet 5.5, arm H", "sync", "s55", "h", "type_int"),
    ("Opus 5.5, arm H", "sync", "o55", "h", "type_int"),
    ("Opus 5.5, arm H, one-request batch", "batch", "o55", "h", "type_int"),
    ("Sonnet 5.5, arm S (list-form content), path scenario", "sync", "s55", "s", "path_unstated"),
)


def pilot_requests(scenarios: Iterable[Scenario], protocol: str) -> list[PilotRequest]:
    """The pilot's requests: does each 5.5 model accept the synthetic turn?

    Uses the first scenario of each named category; the batch request is the third
    request again, sent through the Batch API (round ``pb``), so a difference between
    the two endpoints shows up on the same input.
    """
    from benchmarks._claude.models import MODELS

    by_category: dict[str, Scenario] = {}
    for scenario in scenarios:
        by_category.setdefault(scenario.category, scenario)
    out: list[PilotRequest] = []
    for label, mode, alias, arm, category in PILOT_PLAN:
        scenario = by_category[category]
        content = arm_content(arm, refusal(scenario))
        round_ = "pb" if mode == "batch" else "pl"
        row = make_row(scenario, arm, MODELS[alias], content, round_, protocol)
        out.append(PilotRequest(label=label, mode=mode, row=row))
    return out
