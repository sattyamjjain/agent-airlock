"""The four arms: what the model is shown as the failed call's ``tool_result``.

Every payload is generated **at run time** from the refusal the checked-out airlock
returns for the scenario's malformed call (``AirlockResponse.to_dict()``), never from a
stored copy, so a round measures the hint code at its own commit:

* **H** (``h``) - ``json.dumps(refusal)``: the whole payload, string content.
* **N** (``n``) - the same dict with the top-level ``fix_hints`` and every
  ``metadata.errors[].fix_hint`` removed; everything else, ``metadata`` included, stays.
* **S** (``s``) - ``_sdk_error_result(refusal)["content"]``: the list of text blocks the
  Claude Agent SDK adapter returns (the error line plus ``Fix hints:`` lines, no
  metadata), sent in list form as the adapter sends it.
* **G** (``g``) - :data:`GENERIC_ERROR`, the same constant for every scenario.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Iterable, Mapping
from typing import Any

from .catalogue import invoke, is_refusal
from .scenarios import Scenario

ARMS: tuple[str, ...] = ("h", "n", "s", "g")
DEFAULT_ARMS: tuple[str, ...] = ("h", "n", "s")
ARM_NAMES: dict[str, str] = {
    "h": "H (full payload)",
    "n": "N (hints removed)",
    "s": "S (Agent SDK text)",
    "g": "G (generic error)",
}

GENERIC_ERROR = "Error: the tool call was rejected."

Content = str | list[dict[str, Any]]
"""A ``tool_result`` content value: a string, or a list of text blocks."""


class PayloadError(RuntimeError):
    """The scenario's malformed call did not draw a refusal from the current airlock."""


def refusal(scenario: Scenario) -> dict[str, Any]:
    """The refusal a fresh stub returns for the scenario's malformed call, deep-copied.

    Raises:
        PayloadError: The call was admitted (the corpus no longer matches this airlock).
    """
    result, _ = invoke(scenario.tool, scenario.config, scenario.malformed)
    if not is_refusal(result):
        raise PayloadError(f"{scenario.sid}: the malformed call was admitted: {result!r}")
    return copy.deepcopy(result)


def strip_hints(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Arm N: ``payload`` without ``fix_hints`` or any ``metadata.errors[].fix_hint``."""
    stripped = copy.deepcopy(dict(payload))
    stripped.pop("fix_hints", None)
    metadata = stripped.get("metadata")
    if isinstance(metadata, dict) and isinstance(metadata.get("errors"), list):
        for error in metadata["errors"]:
            if isinstance(error, dict):
                error.pop("fix_hint", None)
    return stripped


def sdk_content(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Arm S: the content list the Claude Agent SDK adapter returns for this refusal."""
    from agent_airlock.integrations._claude_sdk_tools import _sdk_error_result

    result = _sdk_error_result(dict(payload))
    return copy.deepcopy(list(result["content"]))


def arm_content(arm: str, payload: Mapping[str, Any]) -> Content:
    """The ``tool_result`` content for ``arm`` built from one refusal.

    Raises:
        ValueError: ``arm`` is not one of :data:`ARMS`.
    """
    if arm == "h":
        return json.dumps(dict(payload))
    if arm == "n":
        return json.dumps(strip_hints(payload))
    if arm == "s":
        return sdk_content(payload)
    if arm == "g":
        return GENERIC_ERROR
    raise ValueError(f"unknown arm {arm!r}; known: {', '.join(ARMS)}")


def content_text(content: Content) -> str:
    """The content as one string: the text blocks joined, or the string itself."""
    if isinstance(content, str):
        return content
    return "\n".join(str(block.get("text", "")) for block in content)


def content_sha256(content: Content) -> str:
    """Stable hash of one arm's content, compared between rounds."""
    blob = json.dumps(content, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def build_payloads(
    scenarios: Iterable[Scenario], arms: Iterable[str]
) -> dict[str, dict[str, Content]]:
    """``sid -> arm -> content`` for every scenario, each from one fresh refusal."""
    wanted = tuple(arms)
    out: dict[str, dict[str, Content]] = {}
    for scenario in scenarios:
        payload = refusal(scenario)
        out[scenario.sid] = {arm: arm_content(arm, payload) for arm in wanted}
    return out


def payload_hashes(payloads: Mapping[str, Mapping[str, Content]]) -> dict[str, dict[str, str]]:
    """``sid -> arm -> sha256`` for a payload table."""
    return {
        sid: {arm: content_sha256(content) for arm, content in arms.items()}
        for sid, arms in payloads.items()
    }
