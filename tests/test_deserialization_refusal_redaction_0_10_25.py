"""Regressions for 0.10.25: deserialization refusals withhold the detector that matched.

- The UnsafeDeserializationGuard refusal handed the model the concrete detector that
  fired: ``metadata.matched_pattern`` (e.g. ``pickle.loads``, ``base64-pickle``) and an
  error that named the sink token or encoding. That is the negative space the 0.10.25
  rule withholds (it helps a search for an encoding the detectors miss). The model still
  learns which argument was refused and gets the guard's fix hints; the operator keeps
  the full detail in ``on_blocked`` and the guard's log line.
"""

from __future__ import annotations

import base64
import json
import pickle
from typing import Any

from agent_airlock import Airlock, AirlockConfig, SecurityPolicy
from agent_airlock.safe_types import UnsafeDeserializationGuard


class _Harmless:
    def __reduce__(self) -> tuple[Any, ...]:
        return (list, ())


def _tool(captured: list[dict[str, Any]]) -> Any:
    def on_blocked(name: str, reason: str, context: dict[str, Any]) -> None:
        captured.append({"name": name, "reason": reason, **context})

    policy = SecurityPolicy(deserialization_guard=UnsafeDeserializationGuard())

    @Airlock(config=AirlockConfig(enable_audit_log=False, on_blocked=on_blocked), policy=policy)
    def load(blob: str) -> str:
        return "ran"

    return load


class TestDeserializationRefusalRedaction:
    def test_marker_token_not_echoed(self) -> None:
        captured: list[dict[str, Any]] = []
        out = _tool(captured)(blob="data = pickle.loads(payload)")
        assert out["success"] is False
        text = json.dumps(out)
        assert "pickle.loads" not in text
        assert "matched_pattern" not in out["metadata"]
        assert out["metadata"]["matched_field"] == "blob"
        assert out["fix_hints"], "the guard's actionable hints still reach the model"
        assert captured and captured[0]["matched_pattern"] == "pickle.loads"

    def test_base64_pickle_detector_not_named_in_error(self) -> None:
        captured: list[dict[str, Any]] = []
        blob = base64.b64encode(pickle.dumps(_Harmless(), protocol=4)).decode()
        out = _tool(captured)(blob=blob)
        assert out["success"] is False
        assert "base64" not in out["error"]
        assert "PROTO" not in out["error"]
        assert "matched_pattern" not in out["metadata"]
        assert captured[0]["verdict"] == "deny_base64_pickle"
