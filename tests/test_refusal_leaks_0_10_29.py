"""0.10.29: refusals and logs keep argument values and internal error text out.

Raised in modelcontextprotocol/python-sdk#3572 (the same leak in "the validation-error path
of my own guard library") and openai/codex#56828 (keep policy metadata out of
model-facing text). On 0.10.28, reproduced before the change:

- A validation refusal carried ``metadata.errors[].input = repr(value)``, and ``to_dict``
  sends metadata to the model: ``pay(amount="sk-proj-...")`` to an ``int`` parameter came
  back with the key in the refusal, while the audit log masked it.
- A policy resolver's exception text reached the model ("Policy resolution failed: ..."),
  and so did an approver's ("approver raised RuntimeError: ..."), with the escalate_tools
  glob that fired.
- The path and endpoint warnings logged the raw path and URL, a key in a query included.

Now a validation error carries the input's type; the model reads the resolver's and the
approver's exception type, the log the masked message; the escalation glob reaches the
operator as the audit record's new ``rule_id`` (with ``policy_layer``), and every logged
argument value goes through ``audit.masked_for_log``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agent_airlock import Airlock, AirlockConfig, FilesystemPolicy, SecurityPolicy
from agent_airlock import core as core_module
from agent_airlock import network as network_module
from agent_airlock.network import EndpointPolicy
from agent_airlock.oversight import OversightRequest, OversightResponse
from agent_airlock.self_heal import AirlockResponse, BlockReason
from agent_airlock.unknown_args import UnknownArgsMode

# Assembled, so no secret scanner files this module.
KEY = "sk-proj-" + "FAKEFAKEFAKEFAKEFAKEFAKE1234"
KEY_BODY = "FAKEFAKEFAKEFAKE"


class _Events:
    def __init__(self) -> None:
        self.seen: list[tuple[str, dict[str, Any]]] = []

    def _record(self, event: str, **fields: Any) -> None:
        self.seen.append((event, fields))

    debug = info = warning = error = exception = _record


@pytest.fixture
def events(monkeypatch: pytest.MonkeyPatch) -> _Events:
    recorder = _Events()
    monkeypatch.setattr(core_module, "logger", recorder)
    monkeypatch.setattr(network_module, "logger", recorder)
    return recorder


def _audit_records(path: Path) -> list[dict[str, Any]]:
    """The JSON-lines records, without the log's ``#`` header."""
    lines = path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line and not line.startswith("#")]


class TestValidationRefusal:
    """A value sent to the wrong argument is not echoed back to the model."""

    def test_the_refusal_carries_no_key(self) -> None:
        @Airlock()
        def pay(amount: int, to: str) -> str:
            return f"paid {amount} to {to}"

        result = pay(amount=KEY, to="bob")
        blob = json.dumps(result)
        assert isinstance(result, dict)
        assert result["block_reason"] == "validation_error"
        assert KEY not in blob
        assert KEY_BODY not in blob

    def test_the_hints_still_name_the_field_and_the_type(self) -> None:
        @Airlock()
        def pay(amount: int, to: str) -> str:
            return f"paid {amount} to {to}"

        result = pay(amount=KEY, to="bob")
        assert isinstance(result, dict)
        assert any("'amount'" in hint and "integer" in hint for hint in result["fix_hints"])
        error = result["metadata"]["errors"][0]
        assert error["field"] == "amount"
        assert error["input_type"] == "str"
        assert "input" not in error


class TestResolverAndApproverText:
    def test_a_resolver_exception_message_stays_out_of_the_refusal(self, events: _Events) -> None:
        def resolver(context: Any) -> SecurityPolicy:
            raise RuntimeError("password=hunter2hunter2")

        @Airlock(policy=resolver)
        def tool() -> str:
            return "ran"

        result = tool()
        assert isinstance(result, dict)
        assert "hunter2" not in json.dumps(result)
        assert "RuntimeError" in result["error"]
        logged = [fields for event, fields in events.seen if event == "policy_resolver_error"]
        assert logged and "hunter2" not in logged[0]["error"]

    def test_an_approver_exception_message_stays_out_of_the_refusal(self, events: _Events) -> None:
        url = f"https://hooks.example.test/approve?token={KEY}"

        def approver(request: OversightRequest) -> OversightResponse:
            raise RuntimeError(f"POST {url} failed")

        @Airlock(policy=SecurityPolicy(escalate_tools={"pay": "money"}, approver=approver))
        def pay() -> str:
            return "paid"

        result = pay()
        blob = json.dumps(result)
        assert isinstance(result, dict)
        assert "hooks.example.test" not in blob
        assert KEY_BODY not in blob
        assert "RuntimeError" in result["metadata"]["detail"]
        logged = [fields for event, fields in events.seen if event == "escalation_approver_raised"]
        assert logged and KEY_BODY not in logged[0]["error"]


class TestLoggedArgumentValues:
    def test_an_endpoint_refusal_logs_no_raw_key(self, events: _Events) -> None:
        policy = EndpointPolicy(allowed_endpoints=["other.example.test"])

        @Airlock(config=AirlockConfig(endpoint_policies={"fetch": policy}))
        def fetch(url: str) -> str:
            return url

        result = fetch(url=f"https://api.example.test/?token={KEY}")
        assert isinstance(result, dict)
        assert result["block_reason"] == "endpoint_blocked"
        logged = repr(events.seen)
        assert KEY not in logged and KEY_BODY not in logged
        assert any(event == "endpoint_policy_violation" for event, _ in events.seen)

    def test_a_path_refusal_logs_no_raw_key(self, events: _Events, tmp_path: Path) -> None:
        policy = FilesystemPolicy(allowed_roots=[tmp_path.resolve()])

        @Airlock(config=AirlockConfig(filesystem_policy=policy))
        def read(path: str) -> str:
            return path

        result = read(path=f"/etc/{KEY}.txt")
        assert isinstance(result, dict)
        assert result["block_reason"] == "path_violation"
        logged = [fields for event, fields in events.seen if event == "path_validation_failed"]
        assert logged and KEY_BODY not in logged[0]["path"]

    def test_a_long_value_is_cut_in_the_log(self, events: _Events) -> None:
        policy = EndpointPolicy(allowed_endpoints=["other.example.test"])

        @Airlock(config=AirlockConfig(endpoint_policies={"fetch": policy}))
        def fetch(url: str) -> str:
            return url

        fetch(url="https://api.example.test/" + "a" * 5000)
        logged = [fields for event, fields in events.seen if event == "endpoint_policy_violation"]
        assert logged and len(logged[0]["url"]) <= 203


class TestRuleIdIsTheOperators:
    """The escalation glob reaches the audit record as ``rule_id``, not the model."""

    def test_the_refusal_has_no_glob_and_the_audit_record_has_rule_id(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"
        policy = SecurityPolicy(escalate_tools={"wire_*": "wires need a second pair of eyes"})

        @Airlock(policy=policy, config=AirlockConfig(enable_audit_log=True, audit_log_path=log))
        def wire_money() -> str:
            return "wired"

        result = wire_money()
        assert isinstance(result, dict)
        assert "wire_*" not in json.dumps(result)
        assert "wires need a second pair of eyes" in result["error"]
        (record,) = _audit_records(log)
        assert (record["rule_id"], record["policy_layer"]) == ("wire_*", "escalation")

    def test_a_denied_pattern_is_the_rule_id_of_a_policy_refusal(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"

        @Airlock(
            policy=SecurityPolicy(denied_tools=["rm_*"]),
            config=AirlockConfig(enable_audit_log=True, audit_log_path=log),
        )
        def rm_rf() -> str:
            return "gone"

        result = rm_rf()
        assert isinstance(result, dict)
        assert "rm_*" not in json.dumps(result)
        (record,) = _audit_records(log)
        assert (record["rule_id"], record["policy_layer"]) == ("rm_*", "policy")

    def test_every_refusal_record_carries_a_rule_and_a_layer(self, tmp_path: Path) -> None:
        log = tmp_path / "audit.jsonl"

        config = AirlockConfig(
            enable_audit_log=True, audit_log_path=log, unknown_args=UnknownArgsMode.BLOCK
        )

        @Airlock(config=config)
        def tool(x: int) -> int:
            return x

        tool(x=1, invented="ghost")  # a ghost argument, refused under BLOCK
        tool(x="not an int")  # a validation error
        tool(x=2)  # admitted: no rule
        records = _audit_records(log)
        assert [(r.get("rule_id"), r.get("policy_layer")) for r in records] == [
            ("ghost_arguments", "ghost_arguments"),
            ("validation_error", "validation"),
            (None, None),
        ]

    def test_to_dict_never_carries_the_rule(self) -> None:
        response = AirlockResponse.blocked_response(
            reason=BlockReason.POLICY_VIOLATION, error="x", rule_id="secret_rule_*"
        )
        assert response.rule_id == "secret_rule_*"
        assert "secret_rule" not in json.dumps(response.to_dict())
