"""0.10.28: the call path reads identity only from the host, and reads every value.

The fourth ``/init`` audit of ``CLAUDE.md`` against the code found the call path trusting
what the model writes, each finding reproduced before it was fixed:

- A first positional argument with an attribute named ``context``, ``ctx``,
  ``request_context`` or ``session_context`` was taken for the host's run wrapper. Its agent
  id, roles, workspace, session id and metadata (the budget tags, the access-token claims)
  became the call's, and steps 2.7, 3 and 5 skipped it. A tool author's own model with a
  field of one of those names made all of that model-writable, and the OpenAI Agents SDK
  passes a model-typed argument positionally. A first argument is now the run wrapper only
  when model JSON cannot have built it: a verified agent-framework object, an object whose
  context is an ``AirlockContext`` (which pydantic no longer builds from a dict), or a plain
  host object. When its context is falsy, the wrapper itself is no longer read.
- ``CONTEXT_ATTRS`` was a frozenset, so which of two present names was read depended on
  ``PYTHONHASHSEED``.
- An object counted as an agent framework's by its top-level module name, so a tool
  author's own package named ``agents``, ``mcp`` or ``google`` walked past the value gates.
- ``@requires`` above ``@Airlock`` counted only when directly adjacent.
- A ``file:`` URL object (pydantic ``FileUrl`` / ``AnyUrl``, ``urllib`` results) was never a
  path; URL-object, tuple and frozenset mapping keys were never read; a ``**kwargs`` key
  hid the positional-only or ``*args`` value of the same name; memoryview and
  ``UserString`` values were read by no gate.
- Step 6 priced an unreadable ``input_tokens`` tag as 0 tokens (a negative one raised out
  of the call) and a non-str ``model_id`` at the tracker's own row.
- Step 2.7 read the authenticated-transport declaration from the tool's arguments.
- ``STRIP_SILENT`` logged a warning; strict validation skipped ``*args`` / ``**kwargs``
  annotated with a model; one escalation log event name was an f-string.
"""

from __future__ import annotations

import ast
import collections
import dataclasses
import enum
import functools
import json
import numbers
import pickle  # nosec B403 - builds payloads for the guard to refuse; nothing is unpickled
import sys
import types
import urllib.parse
from collections import UserString
from contextlib import nullcontext
from pathlib import Path
from typing import Any

import pytest
from pydantic import AnyUrl, BaseModel, FileUrl, ValidationError, create_model
from pydantic.dataclasses import dataclass as pydantic_dataclass
from typing_extensions import TypedDict

from agent_airlock import (
    Airlock,
    AirlockConfig,
    AirlockContext,
    Capability,
    CapabilityPolicy,
    EndpointPolicy,
    FilesystemPolicy,
    SecurityPolicy,
    get_current_context,
    requires,
)
from agent_airlock import core as core_module
from agent_airlock._arg_walk import (
    bind_arguments,
    is_framework_object,
    iter_argument_values,
    signature_of,
)
from agent_airlock.amplification import AmplificationBudget
from agent_airlock.context import ContextExtractor
from agent_airlock.core import ACCESS_TOKEN_CLAIMS_KEY
from agent_airlock.cost_tracking import (
    ModelTierBudget,
    TierBudget,
    TokenUsage,
    _price_for_model,
    _usd_to_cents,
    get_global_tracker,
)
from agent_airlock.oversight import OversightResponse, OversightVerdict
from agent_airlock.policy import PERMISSIVE_POLICY
from agent_airlock.safe_types import UnsafeDeserializationGuard
from agent_airlock.unknown_args import UnknownArgsMode
from agent_airlock.validator import create_argument_validator

AUD = "https://mcp.example.com"
OTHER = "https://other.example.com"
METADATA_URL = "http://169.254.169.254/latest/meta-data/"
CONTEXT_NAMES = ("context", "ctx", "request_context", "session_context")
QUIET = AirlockConfig(enable_audit_log=False)


def _refusal(result: Any) -> str | None:
    """The block reason when ``result`` is a refusal, else None."""
    if isinstance(result, dict) and result.get("success") is False:
        return str(result.get("block_reason"))
    return None


@pytest.fixture
def roots(tmp_path: Path) -> tuple[Path, Path]:
    """An allowed root holding ``ok.txt``, and a secret file outside it."""
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    (allowed / "ok.txt").write_text("fine")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret")
    return allowed, outside / "secret.txt"


# ---------------------------------------------------------------------------------------
# The tool author's argument, every field of it written by the model
# ---------------------------------------------------------------------------------------


class _Inner(BaseModel):
    """What the model writes under the field named like a context: an identity of its own."""

    agent_id: str | None = None
    roles: list[str] = []
    metadata: dict[str, Any] = {}
    session_id: str | None = None
    org_id: str | None = None


_IDENTITY_FIELDS = ("agent_id", "roles", "metadata", "session_id", "org_id")
_PAYLOAD_FIELDS = ("path", "url", "blob", *_IDENTITY_FIELDS)


@functools.cache
def _request_type(kind: str, attr: str) -> Any:
    """The tool author's argument type: a model, dataclass or named tuple with a field
    named ``attr`` beside the fields a payload goes in."""
    if kind == "model":
        fields: dict[str, Any] = {attr: (_Inner | None, None)}
        fields.update(
            path=(str | None, None),
            url=(str | None, None),
            blob=(bytes | None, None),
            agent_id=(str | None, None),
            roles=(list[str], []),
            metadata=(dict[str, Any], {}),
            session_id=(str | None, None),
            org_id=(str | None, None),
        )
        return create_model(f"Request_{attr}", **fields)
    names = (attr, *_PAYLOAD_FIELDS)
    if kind == "dataclass":
        return dataclasses.make_dataclass(
            f"RequestData_{attr}", [(n, Any, dataclasses.field(default=None)) for n in names]
        )
    return collections.namedtuple(f"RequestTuple_{attr}", names, defaults=[None] * len(names))


def _model_written(kind: str, attr: str, truthy: bool, **fields: Any) -> Any:
    """The tool's argument as a framework hands it over, built from the model's JSON.

    ``truthy`` puts an identity of the model's own under ``attr``; otherwise ``attr`` is
    None, which until 0.10.28 made the extractor read the argument itself instead.
    """
    identity = {name: value for name, value in fields.items() if name in _IDENTITY_FIELDS}
    if kind == "model":
        return _request_type(kind, attr).model_validate(
            {attr: identity if truthy else None, **fields}
        )
    carried = _Inner(**identity) if truthy else None
    if kind == "typeddict":
        return {attr: carried, **fields}  # a TypedDict is a plain dict at run time
    return _request_type(kind, attr)(**{attr: carried, **fields})


SHAPES = [
    pytest.param(attr, truthy, how, id=f"{how}-{attr}-{'truthy' if truthy else 'falsy'}")
    for attr in CONTEXT_NAMES
    for truthy in (False, True)
    for how in ("positional", "keyword")
]
EVERY_SHAPE = pytest.mark.parametrize(("attr", "truthy", "how"), SHAPES)
HOW = pytest.mark.parametrize("how", ["positional", "keyword"])


def _pass(tool: Any, argument: Any, how: str) -> Any:
    """Call ``tool`` with ``argument`` the way a framework would: first, or by name."""
    return tool(argument) if how == "positional" else tool(req=argument)


# ---------------------------------------------------------------------------------------
# B1-F1 / B2-F1: the model's argument is an ordinary argument, never the run wrapper
# ---------------------------------------------------------------------------------------


class TestThePathGateWalksTheModelsArgument:
    @staticmethod
    def _tool(allowed: Path) -> Any:
        config = AirlockConfig(
            filesystem_policy=FilesystemPolicy(allowed_roots=[allowed]), enable_audit_log=False
        )

        @Airlock(config=config)
        def read(req: Any) -> str:
            return "ran"

        return read

    @EVERY_SHAPE
    def test_a_path_in_it_is_checked(
        self, roots: tuple[Path, Path], attr: str, truthy: bool, how: str
    ) -> None:
        allowed, secret = roots
        argument = _model_written("model", attr, truthy, path=str(secret))
        assert _refusal(_pass(self._tool(allowed), argument, how)) == "path_violation"

    @HOW
    def test_control_an_allowed_path_runs(self, roots: tuple[Path, Path], how: str) -> None:
        allowed, _ = roots
        argument = _model_written("model", "context", False, path=str(allowed / "ok.txt"))
        assert _pass(self._tool(allowed), argument, how) == "ran"


class TestTheEndpointGateWalksTheModelsArgument:
    @staticmethod
    def _tool() -> Any:
        config = AirlockConfig(
            endpoint_policies={"fetch": EndpointPolicy(allowed_endpoints=["api.example.com"])},
            enable_audit_log=False,
        )

        @Airlock(config=config)
        def fetch(req: Any) -> str:
            return "ran"

        return fetch

    @EVERY_SHAPE
    def test_a_url_in_it_is_checked(self, attr: str, truthy: bool, how: str) -> None:
        argument = _model_written("model", attr, truthy, url=METADATA_URL)
        assert _refusal(_pass(self._tool(), argument, how)) == "endpoint_blocked"

    @HOW
    def test_control_an_allowed_url_runs(self, how: str) -> None:
        argument = _model_written("model", "context", False, url="https://api.example.com/v1")
        assert _pass(self._tool(), argument, how) == "ran"


class TestTheDeserializationGuardWalksTheModelsArgument:
    @staticmethod
    def _tool() -> Any:
        policy = SecurityPolicy(deserialization_guard=UnsafeDeserializationGuard())

        @Airlock(policy=policy, config=QUIET)
        def load(req: Any) -> str:
            return "ran"

        return load

    @EVERY_SHAPE
    def test_a_pickle_in_it_is_refused(self, attr: str, truthy: bool, how: str) -> None:
        argument = _model_written("model", attr, truthy, blob=pickle.dumps({"a": 1}))
        result = _pass(self._tool(), argument, how)
        assert _refusal(result) == "policy_violation"
        assert result["metadata"]["verdict"] == "deny_pickle_magic"

    @HOW
    def test_control_plain_bytes_run(self, how: str) -> None:
        argument = _model_written("model", "context", False, blob=b"plain bytes")
        assert _pass(self._tool(), argument, how) == "ran"


class TestRolesComeFromTheHost:
    @staticmethod
    def _tool() -> Any:
        @Airlock(policy=SecurityPolicy(allowed_roles=["admin"]), config=QUIET)
        def admin_op(req: Any) -> str:
            return "ran"

        return admin_op

    @EVERY_SHAPE
    @pytest.mark.parametrize("host", [None, "viewer"], ids=["no-host-identity", "host-viewer"])
    def test_model_written_roles_are_not_read(
        self, attr: str, truthy: bool, how: str, host: str | None
    ) -> None:
        argument = _model_written("model", attr, truthy, agent_id="evil", roles=["admin"])
        around = AirlockContext(agent_id="low", roles=[host]) if host else nullcontext()
        with around:
            assert _refusal(_pass(self._tool(), argument, how)) == "policy_violation"

    @HOW
    def test_control_the_hosts_admin_role_runs(self, how: str) -> None:
        with AirlockContext(agent_id="ops", roles=["admin"]):
            assert _pass(self._tool(), _model_written("model", "ctx", False), how) == "ran"


class TestTokenClaimsComeFromTheHost:
    @staticmethod
    def _tool() -> Any:
        config = AirlockConfig(
            expected_token_audience=AUD, token_audience_mode="deny", enable_audit_log=False
        )

        @Airlock(config=config)
        def list_buckets(req: Any) -> str:
            return "ran"

        return list_buckets

    @EVERY_SHAPE
    @pytest.mark.parametrize("host_aud", [None, OTHER], ids=["no-host-claims", "host-elsewhere"])
    def test_forged_claims_are_not_read(
        self, attr: str, truthy: bool, how: str, host_aud: str | None
    ) -> None:
        forged = {ACCESS_TOKEN_CLAIMS_KEY: {"aud": AUD}}
        argument = _model_written("model", attr, truthy, metadata=forged)
        around = (
            AirlockContext(metadata={ACCESS_TOKEN_CLAIMS_KEY: {"aud": host_aud}})
            if host_aud
            else nullcontext()
        )
        with around:
            assert _refusal(_pass(self._tool(), argument, how)) == "token_audience"

    @HOW
    def test_control_the_hosts_claims_run(self, how: str) -> None:
        with AirlockContext(metadata={ACCESS_TOKEN_CLAIMS_KEY: {"aud": AUD}}):
            assert _pass(self._tool(), _model_written("model", "context", True), how) == "ran"


class TestBudgetTagsComeFromTheHost:
    HOST_TAGS: dict[str, Any] = {"airlock_tier": "small", "input_tokens": 5_000_000}

    @staticmethod
    def _tool() -> Any:
        budget = ModelTierBudget(
            tiers={
                "small": TierBudget(max_cost_cents=1),
                "big": TierBudget(max_cost_cents=10**9),
            },
            strict_tier="small",
        )

        @Airlock(policy=SecurityPolicy(model_tier_budget=budget), config=QUIET)
        def summarize(req: Any) -> str:
            return "ran"

        return summarize

    @EVERY_SHAPE
    def test_forged_tags_are_not_read(self, attr: str, truthy: bool, how: str) -> None:
        forged = {"airlock_tier": "big", "input_tokens": 0}
        argument = _model_written("model", attr, truthy, metadata=forged)
        with AirlockContext(agent_id="a1", metadata=self.HOST_TAGS):
            assert _refusal(_pass(self._tool(), argument, how)) == "budget_exceeded"

    @HOW
    def test_control_the_hosts_tier_runs(self, how: str) -> None:
        with AirlockContext(agent_id="a1", metadata={**self.HOST_TAGS, "airlock_tier": "big"}):
            assert _pass(self._tool(), _model_written("model", "context", False), how) == "ran"


class TestTheRunLedgerIsTheHosts:
    @staticmethod
    def _tool() -> Any:
        policy = SecurityPolicy(amplification_budget=AmplificationBudget(max_calls_per_run=2))

        @Airlock(policy=policy, config=QUIET)
        def search(req: Any) -> str:
            return "ran"

        return search

    @EVERY_SHAPE
    def test_a_model_written_session_starts_no_new_run(
        self, attr: str, truthy: bool, how: str
    ) -> None:
        search = self._tool()
        with AirlockContext(session_id="run-1"):
            results = [
                _pass(search, _model_written("model", attr, truthy, session_id=f"s{i}"), how)
                for i in range(3)
            ]
        assert [_refusal(result) for result in results] == [None, None, "amplification_exceeded"]

    def test_control_each_host_run_keeps_its_own_ledger(self) -> None:
        search = self._tool()
        for run in ("run-1", "run-2"):
            with AirlockContext(session_id=run):
                calls = [search(_model_written("model", "context", False)) for _ in range(2)]
            assert calls == ["ran", "ran"]


class TestTheTenantIsTheHosts:
    @staticmethod
    def _tool() -> Any:
        def per_tenant(context: AirlockContext[Any]) -> SecurityPolicy:
            if context.workspace_id == "internal":
                return PERMISSIVE_POLICY
            return SecurityPolicy(denied_tools=["*"])

        @Airlock(policy=per_tenant, config=QUIET)
        def export_all(req: Any) -> str:
            return "ran"

        return export_all

    @EVERY_SHAPE
    def test_a_model_written_tenant_is_not_read(self, attr: str, truthy: bool, how: str) -> None:
        argument = _model_written("model", attr, truthy, org_id="internal")
        with AirlockContext(agent_id="a", workspace_id="customer-7"):
            assert _refusal(_pass(self._tool(), argument, how)) == "policy_violation"

    @HOW
    def test_control_the_hosts_tenant_runs(self, how: str) -> None:
        with AirlockContext(agent_id="a", workspace_id="internal"):
            assert _pass(self._tool(), _model_written("model", "context", False), how) == "ran"


class TestEveryArgumentShapeIsOrdinary:
    """A dataclass, a named tuple or a TypedDict carrying a context-named field too."""

    KINDS = pytest.mark.parametrize("kind", ["dataclass", "namedtuple", "typeddict"])
    ATTRS = pytest.mark.parametrize("attr", CONTEXT_NAMES)
    TRUTHY = pytest.mark.parametrize("truthy", [False, True], ids=["falsy", "truthy"])

    @KINDS
    @ATTRS
    @TRUTHY
    def test_it_is_walked(
        self, roots: tuple[Path, Path], kind: str, attr: str, truthy: bool
    ) -> None:
        allowed, secret = roots
        tool = TestThePathGateWalksTheModelsArgument._tool(allowed)
        assert _refusal(tool(_model_written(kind, attr, truthy, path=str(secret)))) == (
            "path_violation"
        )

    @KINDS
    @ATTRS
    @TRUTHY
    def test_it_is_not_an_identity(self, kind: str, attr: str, truthy: bool) -> None:
        argument = _model_written(kind, attr, truthy, agent_id="evil", roles=["admin"])
        with AirlockContext(agent_id="low", roles=["viewer"]):
            assert _refusal(TestRolesComeFromTheHost._tool()(argument)) == "policy_violation"

    @KINDS
    def test_control_it_runs_under_the_hosts_identity(self, kind: str) -> None:
        with AirlockContext(agent_id="ops", roles=["admin"]):
            assert TestRolesComeFromTheHost._tool()(_model_written(kind, "ctx", False)) == "ran"


class _ContextField(BaseModel):
    context: AirlockContext[Any] | None = None


@dataclasses.dataclass
class _ParametrizedRun:
    context: AirlockContext[int]


class TestPydanticCannotBuildAnAirlockContext:
    def test_a_model_field_refuses_a_dict(self) -> None:
        with pytest.raises(ValidationError):
            _ContextField.model_validate({"context": {"agent_id": "evil", "roles": ["admin"]}})
        with pytest.raises(ValidationError):
            _ContextField.model_validate_json('{"context": {"agent_id": "evil"}}')
        host = AirlockContext(agent_id="host")
        assert _ContextField(context=host).context is host

    def test_a_parametrized_field_refuses_a_dict_too(self) -> None:
        @Airlock(config=QUIET)
        def tool(run: _ParametrizedRun) -> str:
            return "ran"

        assert _refusal(tool({"context": {"agent_id": "evil"}})) == "validation_error"
        assert tool(_ParametrizedRun(context=AirlockContext(agent_id="host"))) == "ran"

    def test_run_time_subscription_still_builds_one(self) -> None:
        assert AirlockContext[None](agent_id="a").agent_id == "a"


# ---------------------------------------------------------------------------------------
# What still counts as the host's run wrapper
# ---------------------------------------------------------------------------------------


class _HostRun:
    """A plain host class: model JSON cannot build it, so it is read as the run wrapper."""

    def __init__(self, context: Any, workspace_dir: str = "") -> None:
        self.context = context
        self.workspace_dir = workspace_dir


@dataclasses.dataclass
class _AppState:
    """The host's own context object, carried by a wrapper the host built."""

    agent_id: str
    roles: list[str]
    session_id: str = "app-run"
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass
class _DataRun:
    """A dataclass wrapper: a run wrapper only because its context is an AirlockContext."""

    context: AirlockContext[Any]
    workspace_dir: str = ""


def _admin_tool() -> Any:
    @Airlock(policy=SecurityPolicy(allowed_roles=["admin"]), config=QUIET)
    def admin_op(run: Any, q: str = "x") -> str:
        return "ran"

    return admin_op


class TestHostWrappersStillCount:
    def test_a_plain_host_wrapper_carries_the_identity(self) -> None:
        admin_op = _admin_tool()
        assert admin_op(_HostRun(_AppState(agent_id="ops", roles=["admin"]))) == "ran"
        refused = admin_op(_HostRun(_AppState(agent_id="ops", roles=["viewer"])))
        assert _refusal(refused) == "policy_violation"

    def test_a_plain_host_wrapper_carries_the_token_claims(self) -> None:
        tool = TestTokenClaimsComeFromTheHost._tool()
        claims = AirlockContext(metadata={ACCESS_TOKEN_CLAIMS_KEY: {"aud": AUD}})
        assert tool(_HostRun(claims)) == "ran"
        elsewhere = AirlockContext(metadata={ACCESS_TOKEN_CLAIMS_KEY: {"aud": OTHER}})
        assert _refusal(tool(_HostRun(elsewhere))) == "token_audience"

    def test_a_plain_host_wrapper_is_not_walked(self, roots: tuple[Path, Path]) -> None:
        allowed, secret = roots
        config = AirlockConfig(
            filesystem_policy=FilesystemPolicy(allowed_roots=[allowed]), enable_audit_log=False
        )

        @Airlock(config=config)
        def list_dir(run: Any, path: str) -> str:
            return "listed"

        wrapper = _HostRun(AirlockContext(), workspace_dir=str(secret.parent))
        assert list_dir(wrapper, str(allowed)) == "listed"
        assert _refusal(list_dir(wrapper, str(secret))) == "path_violation"

    def test_a_falsy_context_reads_nothing_from_the_wrapper_itself(self) -> None:
        class Run:
            def __init__(self) -> None:
                self.context = None
                self.agent_id = "wrapper-agent"
                self.roles = ["admin"]

        extracted = ContextExtractor.extract_from_args((Run(),), {})
        assert (extracted.agent_id, extracted.roles) == (None, [])
        assert _refusal(_admin_tool()(Run())) == "policy_violation"

    def test_with_airlock_context_carries_the_identity(self) -> None:
        with AirlockContext(agent_id="ops", roles=["admin"]):
            assert _admin_tool()(None) == "ran"
        with AirlockContext(agent_id="ops", roles=["viewer"]):
            assert _refusal(_admin_tool()(None)) == "policy_violation"

    def test_a_dataclass_wrapper_around_an_airlock_context_carries_it(self) -> None:
        state = AirlockContext[None](agent_id="ops", roles=["admin"])
        assert _admin_tool()(_DataRun(state)) == "ran"

        reauth = SecurityPolicy(reauth_on_untrusted_reinvocation=True)

        @Airlock(policy=reauth, config=QUIET, return_dict=True)
        def search(run: _DataRun, q: str) -> str:
            return q

        assert search(_DataRun(state), q="x")["success"] is True
        assert search(_DataRun(state), q="y")["success"] is False
        assert state.untrusted_reinvocation_count == {"search": 1}

    def test_a_dataclass_wrapper_is_still_walked(self, roots: tuple[Path, Path]) -> None:
        """Only its AirlockContext vouches for it; its other fields may be the model's."""
        allowed, secret = roots
        config = AirlockConfig(
            filesystem_policy=FilesystemPolicy(allowed_roots=[allowed]), enable_audit_log=False
        )

        @Airlock(config=config)
        def list_dir(run: Any, path: str) -> str:
            return "listed"

        assert list_dir(_DataRun(AirlockContext()), str(allowed)) == "listed"
        outside = _DataRun(AirlockContext(), workspace_dir=str(secret.parent))
        assert _refusal(list_dir(outside, str(allowed))) == "path_violation"


class TestOnlyTheFirstPositionalArgumentIsRead:
    def test_a_wrapper_passed_by_keyword_is_not_read(self) -> None:
        wrapper = _HostRun(AirlockContext(agent_id="kw", roles=["admin"]))
        assert ContextExtractor.extract_from_args((), {"run": wrapper}).agent_id is None
        assert _refusal(_admin_tool()(run=wrapper)) == "policy_violation"

    def test_control_the_same_wrapper_first_is_read(self) -> None:
        wrapper = _HostRun(AirlockContext(agent_id="kw", roles=["admin"]))
        assert ContextExtractor.extract_from_args((wrapper,), {}).agent_id == "kw"
        assert _admin_tool()(wrapper) == "ran"


class TestTheContextAttributeOrderIsFixed:
    def test_context_attrs_is_an_ordered_tuple(self) -> None:
        assert ContextExtractor.CONTEXT_ATTRS == (
            "context",
            "ctx",
            "request_context",
            "session_context",
        )

    def test_the_first_present_name_is_read(self) -> None:
        class Run:
            def __init__(self) -> None:
                self.session_context = AirlockContext(agent_id="session-agent")
                self.request_context = AirlockContext(agent_id="request-agent")
                self.context = AirlockContext(agent_id="app-agent")

        assert ContextExtractor.extract_from_args((Run(),), {}).agent_id == "app-agent"

    def test_the_id_names_are_ordered_too(self) -> None:
        @dataclasses.dataclass
        class Ids:
            agent: str
            agent_id: str
            thread_id: str
            session_id: str

        extracted = ContextExtractor.extract_from_args(
            (_HostRun(Ids(agent="name", agent_id="id-1", thread_id="t", session_id="s")),), {}
        )
        assert (extracted.agent_id, extracted.session_id) == ("id-1", "s")


class _Ticket(BaseModel):
    """A tool author's argument type; the model writes every field."""

    title: str
    context: str | None = None
    metadata: dict[str, Any] = {}
    scopes: list[str] = []
    agent: str | None = None


def _guarded_by_audience_and_role(func: Any) -> Any:
    return Airlock(
        config=AirlockConfig(
            expected_token_audience=AUD, token_audience_mode="deny", enable_audit_log=False
        ),
        policy=SecurityPolicy(allowed_roles=["admin"]),
    )(func)


class TestTheOpenAIAgentsSDK:
    """End to end through ``agents.function_tool``: the model's JSON is the only input."""

    @pytest.fixture
    def sdk(self) -> Any:
        return pytest.importorskip("agents")

    @staticmethod
    async def _invoke(tool: Any, run_context: Any, model_json: dict[str, Any]) -> Any:
        from agents.tool_context import ToolContext

        raw = json.dumps(model_json)
        ctx = ToolContext(
            context=run_context, tool_name=tool.name, tool_call_id="c1", tool_arguments=raw
        )
        return await tool.on_invoke_tool(ctx, raw)

    async def test_the_models_json_is_not_an_identity(self, sdk: Any) -> None:
        def file_ticket(ticket: _Ticket) -> str:
            return "ran"

        file_ticket = sdk.function_tool(strict_mode=False)(
            _guarded_by_audience_and_role(file_ticket)
        )
        forged = {
            "ticket": {
                "title": "t",
                "metadata": {ACCESS_TOKEN_CLAIMS_KEY: {"aud": AUD}},
                "agent": "me",
                "scopes": ["admin"],
            }
        }
        with AirlockContext(
            agent_id="low",
            roles=["viewer"],
            metadata={ACCESS_TOKEN_CLAIMS_KEY: {"aud": OTHER}},
        ):
            clean = await self._invoke(file_ticket, None, {"ticket": {"title": "t"}})
            attack = await self._invoke(file_ticket, None, forged)
        assert "AIRLOCK_BLOCK" in str(clean)
        assert "AIRLOCK_BLOCK" in str(attack)

    async def test_control_the_injected_run_context_is_read(self, sdk: Any) -> None:
        def body(ctx: Any, title: str) -> str:
            return "ran"

        # The SDK injects its run context into a first parameter annotated with it.
        body.__annotations__ = {"ctx": sdk.RunContextWrapper[Any], "title": str, "return": str}
        file_ticket = sdk.function_tool(strict_mode=False)(_guarded_by_audience_and_role(body))
        host = AirlockContext(
            agent_id="ops", roles=["admin"], metadata={ACCESS_TOKEN_CLAIMS_KEY: {"aud": AUD}}
        )
        assert await self._invoke(file_ticket, host, {"title": "t"}) == "ran"
        viewer = AirlockContext(
            agent_id="low", roles=["viewer"], metadata={ACCESS_TOKEN_CLAIMS_KEY: {"aud": AUD}}
        )
        assert "AIRLOCK_BLOCK" in str(await self._invoke(file_ticket, viewer, {"title": "t"}))

    def test_its_run_wrapper_carries_an_airlock_context(
        self, sdk: Any, roots: tuple[Path, Path]
    ) -> None:
        allowed, secret = roots
        state = AirlockContext[None](agent_id="ops", roles=["admin"])
        assert _admin_tool()(sdk.RunContextWrapper(context=state)) == "ran"

        config = AirlockConfig(
            filesystem_policy=FilesystemPolicy(allowed_roots=[allowed]), enable_audit_log=False
        )

        @Airlock(config=config)
        def list_dir(run: Any, path: str) -> str:
            return "listed"

        wrapper = sdk.RunContextWrapper(context=AirlockContext(metadata={"dir": str(secret)}))
        assert list_dir(wrapper, str(allowed)) == "listed"
        assert _refusal(list_dir(wrapper, str(secret))) == "path_violation"

    def test_its_run_wrapper_carries_the_users_context_object(self, sdk: Any) -> None:
        admin_op = _admin_tool()
        admin = sdk.RunContextWrapper(context=_AppState(agent_id="ops", roles=["admin"]))
        assert admin_op(admin) == "ran"
        viewer = sdk.RunContextWrapper(context=_AppState(agent_id="ops", roles=["viewer"]))
        assert _refusal(admin_op(viewer)) == "policy_violation"


# ---------------------------------------------------------------------------------------
# B2-F2: an agent framework's object is one its own installed distribution defines
# ---------------------------------------------------------------------------------------


class TestFrameworkObjectsAreVerified:
    @staticmethod
    def _list_dir(allowed: Path) -> Any:
        config = AirlockConfig(
            filesystem_policy=FilesystemPolicy(allowed_roots=[allowed]), enable_audit_log=False
        )

        @Airlock(config=config)
        def list_dir(state: Any, path: str) -> str:
            return "listed"

        return list_dir

    def test_a_users_package_named_like_a_framework_is_walked(
        self, roots: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        allowed, secret = roots

        class ReadRequest(BaseModel):
            path: str

        module = types.ModuleType("agents.user_models")
        module.__file__ = __file__
        ReadRequest.__module__ = module.__name__
        ReadRequest.__qualname__ = "ReadRequest"
        module.ReadRequest = ReadRequest  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, module.__name__, module)

        assert not is_framework_object(ReadRequest(path="x"))
        result = self._list_dir(allowed)(state=ReadRequest(path=str(secret)), path=str(allowed))
        assert _refusal(result) == "path_violation"

    def test_a_borrowed_module_name_is_walked(self, roots: tuple[Path, Path]) -> None:
        allowed, secret = roots

        @dataclasses.dataclass
        class State:
            workspace_dir: str

        State.__module__ = "pydantic.fields"  # pydantic is installed; this class is not its

        assert not is_framework_object(State("x"))
        result = self._list_dir(allowed)(State(str(secret.parent)), str(allowed))
        assert _refusal(result) == "path_violation"

    def test_a_genuine_framework_model_is_walked_where_its_class_is_named(
        self, roots: tuple[Path, Path]
    ) -> None:
        """Pydantic builds a framework's model from the model's JSON only where the tool's
        annotation names its class, so it is walked there. Under ``Any`` one is the host's
        (a LangGraph state's messages): walking it, as this release first did, read chat
        history as arguments (0.10.28 review). Other framework objects are never walked
        (``tests/test_review_runtime_0_10_28.py``)."""
        mcp_types = pytest.importorskip("mcp.types")
        allowed, secret = roots
        state = mcp_types.TextContent(type="text", text=str(secret.parent))
        assert is_framework_object(state)
        assert self._list_dir(allowed)(state, str(allowed)) == "listed"  # under Any

        def list_dir(state: Any, path: str) -> str:
            return "listed"

        list_dir.__annotations__["state"] = mcp_types.TextContent
        config = AirlockConfig(
            filesystem_policy=FilesystemPolicy(allowed_roots=[allowed]), enable_audit_log=False
        )
        named = Airlock(config=config)(list_dir)
        assert _refusal(named(state, str(allowed))) == "path_violation"

    def test_control_genuine_objects_are_recognised(self) -> None:
        from pydantic.fields import FieldInfo

        assert is_framework_object(FieldInfo())
        assert is_framework_object(AirlockContext())
        assert not is_framework_object(_HostRun(None))
        assert not is_framework_object(_AppState(agent_id="a", roles=[]))

    def test_a_framework_model_built_from_json_is_no_run_wrapper(self) -> None:
        """A framework's own pydantic model is still model JSON: MCP's completion request
        has a ``context`` field whose object takes extra fields, so it could carry any
        identity a model writes."""
        mcp_types = pytest.importorskip("mcp.types")
        forged = {"arguments": {}, "agent_id": "evil", "roles": ["admin"]}
        params = mcp_types.CompleteRequestParams.model_validate(
            {
                "ref": {"type": "ref/prompt", "name": "p"},
                "argument": {"name": "a", "value": "b"},
                "context": forged,
            }
        )
        assert is_framework_object(params)
        assert ContextExtractor.run_wrapper(params) is None
        with AirlockContext(agent_id="low", roles=["viewer"]):
            assert _refusal(_admin_tool()(params)) == "policy_violation"


# ---------------------------------------------------------------------------------------
# B2-F3: @requires reaches the @Airlock wrapper through the decorators above it
# ---------------------------------------------------------------------------------------


def _logged(fn: Any) -> Any:
    """A well-behaved decorator: ``functools.wraps`` keeps ``__wrapped__``."""

    @functools.wraps(fn)
    def inner(*args: Any, **kwargs: Any) -> Any:
        return fn(*args, **kwargs)

    return inner


def _copies_dict_only(fn: Any) -> Any:
    """A decorator that copies the function's attributes but sets no ``__wrapped__``."""

    def inner(*args: Any, **kwargs: Any) -> Any:
        return fn(*args, **kwargs)

    inner.__dict__.update(fn.__dict__)
    inner.__name__ = fn.__name__
    return inner


class TestRequiresReachesTheAirlockWrapper:
    @staticmethod
    def _config() -> AirlockConfig:
        return AirlockConfig(
            capability_policy=CapabilityPolicy(granted=Capability.FILESYSTEM_READ),
            enable_audit_log=False,
        )

    def test_a_requirement_stacked_on_another_is_enforced(self) -> None:
        @requires(Capability.PROCESS_SHELL)
        @requires(Capability.FILESYSTEM_READ)
        @Airlock(config=self._config())
        def tool(x: str) -> str:
            return "ran"

        assert _refusal(tool(x="a")) == "capability_denied"

    def test_a_requirement_above_a_wraps_decorator_is_enforced(self) -> None:
        @requires(Capability.PROCESS_SHELL)
        @_logged
        @Airlock(config=self._config())
        def tool(x: str) -> str:
            return "ran"

        assert _refusal(tool(x="a")) == "capability_denied"

    def test_a_requirement_above_a_decorator_that_copies_attributes(self) -> None:
        @requires(Capability.PROCESS_SHELL)
        @_copies_dict_only
        @Airlock(config=self._config())
        def tool(x: str) -> str:
            return "ran"

        assert _refusal(tool(x="a")) == "capability_denied"

    def test_control_granted_requirements_run(self) -> None:
        @requires(Capability.FILESYSTEM_READ)
        @_logged
        @requires(Capability.FILESYSTEM_READ)
        @Airlock(config=self._config())
        def tool(x: str) -> str:
            return "ran"

        assert tool(x="a") == "ran"

    def test_the_undecorated_function_is_not_marked(self) -> None:
        def body(x: str) -> str:
            return "ran"

        shell = requires(Capability.PROCESS_SHELL)(Airlock(config=self._config())(body))
        plain = Airlock(config=self._config())(body)

        assert _refusal(shell(x="a")) == "capability_denied"
        assert plain(x="a") == "ran"
        assert getattr(body, "__airlock_capabilities__", None) is None


# ---------------------------------------------------------------------------------------
# B2-F4, B2-F5, B2-F7, B2-F9: every value reaches the gates that read values
# ---------------------------------------------------------------------------------------


def _fs_tool(allowed: Path) -> Any:
    config = AirlockConfig(
        filesystem_policy=FilesystemPolicy(allowed_roots=[allowed]), enable_audit_log=False
    )

    @Airlock(config=config)
    def touch(uri: Any = None, mapping: Any = None, path: Any = None, x: Any = None) -> str:
        return "ran"

    return touch


def _fetch_tool() -> Any:
    config = AirlockConfig(
        endpoint_policies={"fetch": EndpointPolicy(allowed_endpoints=["api.example.com"])},
        enable_audit_log=False,
    )

    @Airlock(config=config)
    def fetch(url: Any = None, targets: Any = None, x: Any = None) -> str:
        return "ran"

    return fetch


_URL_OBJECTS = pytest.mark.parametrize(
    "make",
    [FileUrl, AnyUrl, urllib.parse.urlsplit, urllib.parse.urlparse],
    ids=["FileUrl", "AnyUrl", "urlsplit", "urlparse"],
)


class TestUrlObjectsNamingFilesArePaths:
    @_URL_OBJECTS
    def test_a_file_url_object_is_a_path(self, roots: tuple[Path, Path], make: Any) -> None:
        allowed, secret = roots
        assert _refusal(_fs_tool(allowed)(uri=make(secret.as_uri()))) == "path_violation"

    @_URL_OBJECTS
    def test_control_an_allowed_file_url_object_runs(
        self, roots: tuple[Path, Path], make: Any
    ) -> None:
        allowed, _ = roots
        assert _fs_tool(allowed)(uri=make((allowed / "ok.txt").as_uri())) == "ran"

    def test_url_objects_are_still_urls_for_the_endpoint_gate(self) -> None:
        assert _refusal(_fetch_tool()(url=AnyUrl(METADATA_URL))) == "endpoint_blocked"
        assert _fetch_tool()(url=AnyUrl("https://api.example.com/v1")) == "ran"


class TestEveryMappingKeyIsRead:
    def test_a_url_object_key(self) -> None:
        targets = {AnyUrl(METADATA_URL): "x"}
        assert _refusal(_fetch_tool()(targets=targets)) == "endpoint_blocked"

    @pytest.mark.parametrize(
        "wrap", [lambda p: (p,), lambda p: frozenset({p})], ids=["tuple", "frozenset"]
    )
    def test_a_container_key(self, roots: tuple[Path, Path], wrap: Any) -> None:
        allowed, secret = roots
        assert _refusal(_fs_tool(allowed)(mapping={wrap(str(secret)): "x"})) == "path_violation"

    def test_controls_allowed_keys_run(self, roots: tuple[Path, Path]) -> None:
        allowed, _ = roots
        assert _fs_tool(allowed)(mapping={(str(allowed / "ok.txt"), 3): "x"}) == "ran"
        assert _fetch_tool()(targets={AnyUrl("https://api.example.com/v1"): "x"}) == "ran"


class TestKeywordArgumentsDoNotHideOthers:
    @staticmethod
    def _tools(allowed: Path) -> tuple[Any, Any]:
        config = AirlockConfig(
            filesystem_policy=FilesystemPolicy(allowed_roots=[allowed]), enable_audit_log=False
        )

        @Airlock(config=config)
        def positional_only(path: Any, /, **kw: Any) -> str:
            return "ran"

        @Airlock(config=config)
        def star_args(*paths: Any, **kw: Any) -> str:
            return "ran"

        return positional_only, star_args

    def test_a_kwarg_named_like_a_positional_only_parameter(self, roots: tuple[Path, Path]) -> None:
        allowed, secret = roots
        positional_only, _ = self._tools(allowed)
        ok = str(allowed / "ok.txt")
        assert _refusal(positional_only(str(secret), path=ok)) == "path_violation"
        assert _refusal(positional_only(ok, path=str(secret))) == "path_violation"

    def test_a_kwarg_named_like_star_args(self, roots: tuple[Path, Path]) -> None:
        allowed, secret = roots
        _, star_args = self._tools(allowed)
        assert _refusal(star_args(str(secret), paths=str(allowed / "ok.txt"))) == ("path_violation")

    def test_control_allowed_values_run(self, roots: tuple[Path, Path]) -> None:
        allowed, _ = roots
        positional_only, star_args = self._tools(allowed)
        ok = str(allowed / "ok.txt")
        assert positional_only(ok, path=ok) == "ran"
        assert star_args(ok, paths=ok) == "ran"

    def test_both_values_keep_the_name_they_are_classified_by(self) -> None:
        def tool(path: str, /, **kw: Any) -> None: ...

        named = bind_arguments(signature_of(tool), ("a.txt",), {"path": "b.txt"})
        values = {(item.key, item.value) for item in iter_argument_values(named)}
        assert values == {("path", "a.txt"), ("path", "b.txt")}


class TestMemoryviewAndUserStringAreRead:
    def test_a_pickle_in_a_memoryview(self) -> None:
        @Airlock(policy=SecurityPolicy(deserialization_guard=UnsafeDeserializationGuard()))
        def load(x: Any) -> str:
            return "ran"

        assert _refusal(load(x=memoryview(pickle.dumps({"a": 1})))) == "policy_violation"
        assert load(x=memoryview(b"plain bytes")) == "ran"

    def test_a_path_in_a_memoryview(self, roots: tuple[Path, Path]) -> None:
        allowed, secret = roots
        tool = _fs_tool(allowed)
        assert _refusal(tool(path=memoryview(str(secret).encode()))) == "path_violation"
        assert tool(path=memoryview(str(allowed / "ok.txt").encode())) == "ran"

    def test_a_user_string_path_and_url(self, roots: tuple[Path, Path]) -> None:
        allowed, secret = roots
        assert _refusal(_fs_tool(allowed)(x=UserString(str(secret)))) == "path_violation"
        assert _refusal(_fetch_tool()(x=UserString(METADATA_URL))) == "endpoint_blocked"
        assert _fs_tool(allowed)(x=UserString("hello")) == "ran"


# ---------------------------------------------------------------------------------------
# B2-F6: a budget tag the host set but step 6 cannot read refuses the call
# ---------------------------------------------------------------------------------------


@numbers.Integral.register
class _Tally:
    """An integral count that is not an ``int``, as numpy's integers are not."""

    def __init__(self, count: int) -> None:
        self.count = count

    def __index__(self) -> int:
        return self.count

    def __int__(self) -> int:
        return self.count


class _PlainModel(enum.Enum):
    UNLISTED = "no-such-model"


class TestUnreadableBudgetTagsRefuse:
    @staticmethod
    def _tool(cap_cents: int = 100) -> Any:
        budget = ModelTierBudget(tiers={"t": TierBudget(max_cost_cents=cap_cents)}, strict_tier="t")

        @Airlock(policy=SecurityPolicy(model_tier_budget=budget), config=QUIET)
        def tool(x: str) -> str:
            return "ran"

        return tool

    @pytest.mark.parametrize(
        "tokens", [5e6, "5000000", True, -5, [1]], ids=["float", "str", "bool", "negative", "list"]
    )
    def test_an_unreadable_token_count_refuses(self, tokens: Any) -> None:
        with AirlockContext(agent_id="a", metadata={"input_tokens": tokens}):
            result = self._tool()(x="hi")
        assert _refusal(result) == "budget_exceeded"
        assert any("input_tokens" in hint for hint in result["fix_hints"])

    def test_an_unreadable_tier_refuses(self) -> None:
        with AirlockContext(agent_id="a", metadata={"airlock_tier": 5}):
            result = self._tool()(x="hi")
        assert _refusal(result) == "budget_exceeded"
        assert any("airlock_tier" in hint for hint in result["fix_hints"])

    def test_an_integral_that_is_not_an_int_is_counted(self) -> None:
        with AirlockContext(agent_id="a", metadata={"input_tokens": _Tally(5_000_000)}):
            assert _refusal(self._tool()(x="hi")) == "budget_exceeded"
        with AirlockContext(agent_id="a", metadata={"input_tokens": _Tally(10)}):
            assert self._tool()(x="hi") == "ran"

    def test_control_an_int_count_is_priced(self) -> None:
        with AirlockContext(agent_id="a", metadata={"input_tokens": 5_000_000}):
            assert _refusal(self._tool()(x="hi")) == "budget_exceeded"
        with AirlockContext(agent_id="a", metadata={"input_tokens": 10}):
            assert self._tool()(x="hi") == "ran"

    @staticmethod
    def _cap_between_dearest_and_own() -> int:
        tracker = get_global_tracker()
        usage = TokenUsage(input_tokens=1_000_000, output_tokens=0)
        dearest = _usd_to_cents(_price_for_model(tracker, usage, "no-such-model")[0])
        own = _usd_to_cents(_price_for_model(tracker, usage, None)[0])
        assert dearest > own
        return (dearest + own) // 2

    @pytest.mark.parametrize(
        "model_id", [b"no-such-model", _PlainModel.UNLISTED, 42], ids=["bytes", "enum", "int"]
    )
    def test_a_non_str_model_id_is_priced_at_the_dearest_row(self, model_id: Any) -> None:
        tool = self._tool(self._cap_between_dearest_and_own())
        with AirlockContext(agent_id="a", metadata={"model_id": model_id, "input_tokens": 10**6}):
            assert _refusal(tool(x="hi")) == "budget_exceeded"

    def test_control_no_model_id_is_priced_at_the_trackers_row(self) -> None:
        tool = self._tool(self._cap_between_dearest_and_own())
        with AirlockContext(agent_id="a", metadata={"input_tokens": 10**6}):
            assert tool(x="hi") == "ran"

    def test_a_str_enum_model_id_is_read_by_its_value(self) -> None:
        tracker = get_global_tracker()
        usage = TokenUsage(input_tokens=1_000_000, output_tokens=0)
        cheapest = min(
            (key for key in tracker.pricing if key != "default"),
            key=lambda key: (_price_for_model(tracker, usage, key)[0], key),
        )
        cap = _usd_to_cents(_price_for_model(tracker, usage, cheapest)[0]) - 1
        listed = enum.Enum("Listed", {"CHEAP": cheapest}, type=str)  # type: ignore[misc]
        with AirlockContext(
            agent_id="a", metadata={"model_id": listed.CHEAP, "input_tokens": 10**6}
        ):
            result = self._tool(max(cap, 0))(x="hi")
        assert _refusal(result) == "budget_exceeded"
        assert result["metadata"]["model_id"] == cheapest
        assert type(result["metadata"]["model_id"]) is str


# ---------------------------------------------------------------------------------------
# B2-F8: the authenticated-transport declaration is the host's
# ---------------------------------------------------------------------------------------


class TestTheTransportDeclarationIsTheHosts:
    DECLARED = {"authenticated": True, "tls": True}

    @staticmethod
    def _tool(**guard: Any) -> Any:
        policy = SecurityPolicy(
            deserialization_guard=UnsafeDeserializationGuard(
                require_authenticated_transport=True, **guard
            )
        )

        @Airlock(policy=policy, config=QUIET)
        def upload(blob: bytes, **meta: Any) -> str:
            return "ran"

        return upload

    def test_a_model_written_transport_is_not_read(self) -> None:
        result = self._tool()(blob=b"\x01\x02 opaque", transport=self.DECLARED)
        assert _refusal(result) == "policy_violation"
        assert result["metadata"]["verdict"] == "deny_unauthenticated_transport"

    def test_control_the_hosts_declaration_is_read(self) -> None:
        with AirlockContext(metadata={"transport": self.DECLARED}):
            assert self._tool()(blob=b"\x01\x02 opaque") == "ran"

    def test_a_custom_metadata_key(self) -> None:
        with AirlockContext(metadata={"channel": self.DECLARED}):
            assert self._tool(transport_metadata_key="channel")(blob=b"opaque") == "ran"
        with AirlockContext(metadata={"transport": self.DECLARED}):
            result = self._tool(transport_metadata_key="channel")(blob=b"opaque")
        assert _refusal(result) == "policy_violation"

    def test_a_model_written_transport_is_scanned_as_content(self) -> None:
        with AirlockContext(metadata={"transport": self.DECLARED}):
            result = self._tool()(blob=b"ok", transport={"note": pickle.dumps({"a": 1})})
        assert _refusal(result) == "policy_violation"

    def test_the_standalone_guard_still_reads_its_arguments(self) -> None:
        guard = UnsafeDeserializationGuard(require_authenticated_transport=True)
        assert guard.evaluate({"blobs": [b"x"], "transport": self.DECLARED}).allowed
        assert not guard.evaluate({"blobs": [b"x"]}).allowed
        assert not guard.evaluate(
            {"blobs": [b"x"], "transport": self.DECLARED}, transport=None
        ).allowed
        assert guard.evaluate({"blobs": [b"x"]}, transport=self.DECLARED).allowed


# ---------------------------------------------------------------------------------------
# B1-F7: the unknown-argument modes do what their docstrings say
# ---------------------------------------------------------------------------------------


class _Recorder:
    """Stands in for a module's logger and records ``(level, event, fields)``."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def __getattr__(self, level: str) -> Any:
        def record(event: str = "", **fields: Any) -> None:
            self.calls.append((level, event, fields))

        return record

    def events(self, *levels: str) -> list[str]:
        return [event for level, event, _ in self.calls if level in levels]


@pytest.fixture
def logs(monkeypatch: pytest.MonkeyPatch) -> _Recorder:
    from agent_airlock import unknown_args, validator

    recorder = _Recorder()
    for module in (core_module, unknown_args, validator):
        monkeypatch.setattr(module, "logger", recorder)
    return recorder


class TestUnknownArgumentModes:
    @staticmethod
    def _tool(mode: UnknownArgsMode, audit: Path | None = None) -> Any:
        config = AirlockConfig(
            unknown_args=mode,
            enable_audit_log=audit is not None,
            audit_log_path=audit or Path("unused.jsonl"),
        )

        @Airlock(config=config)
        def tool(x: int) -> str:
            return "ran"

        return tool

    def test_the_default_is_strip_and_log(self) -> None:
        assert AirlockConfig().unknown_args is UnknownArgsMode.STRIP_AND_LOG

    def test_strip_silent_logs_nothing_above_debug(self, logs: _Recorder) -> None:
        assert self._tool(UnknownArgsMode.STRIP_SILENT)(x=1, ghost=2) == "ran"
        loud = [
            (level, event)
            for level, event, fields in logs.calls
            if level != "debug" and ("ghost" in event or "strip" in event or "ghost" in str(fields))
        ]
        assert loud == []

    def test_strip_and_log_logs_one_warning_and_no_audit_record(
        self, logs: _Recorder, tmp_path: Path
    ) -> None:
        audit = tmp_path / "audit.jsonl"
        assert self._tool(UnknownArgsMode.STRIP_AND_LOG, audit)(x=1, ghost=2) == "ran"
        stripped = [call for call in logs.calls if "strip" in call[1] or "ghost" in call[1]]
        assert [(level, event) for level, event, _ in stripped] == [
            ("warning", "unknown_args_stripped")
        ]
        assert stripped[0][2]["stripped_args"] == ["ghost"]
        lines = audit.read_text(encoding="utf-8").splitlines()
        records = [json.loads(line) for line in lines if line and not line.startswith("#")]
        assert len(records) == 1 and records[0]["blocked"] is False

    def test_control_block_refuses(self) -> None:
        assert _refusal(self._tool(UnknownArgsMode.BLOCK)(x=1, ghost=2)) == "ghost_arguments"


# ---------------------------------------------------------------------------------------
# C-F5: *args and **kwargs annotated with a model are validated strictly
# ---------------------------------------------------------------------------------------


class _Person(BaseModel):
    age: int


@pydantic_dataclass
class _PydanticPerson:
    age: int


@dataclasses.dataclass
class _DataPerson:
    age: int


class _TypedPerson(TypedDict):
    age: int


def _greet_star(*people: _Person) -> str:
    return "ran"


def _greet_star_pydantic(*people: _PydanticPerson) -> str:
    return "ran"


def _greet_star_dataclass(*people: _DataPerson) -> str:
    return "ran"


def _greet_star_typed(*people: _TypedPerson) -> str:
    return "ran"


def _greet_star_lists(*groups: list[_Person]) -> str:
    return "ran"


def _greet_named(**people: _Person) -> str:
    return "ran"


def _greet_named_typed(**people: _TypedPerson) -> str:
    return "ran"


def _greet_named_pydantic(**people: _PydanticPerson) -> str:
    return "ran"


# Strict mode takes a model's fields from a dict, but a dataclass only as an instance: the
# rule a named parameter of the same type already follows.
_VARIADIC = pytest.mark.parametrize(
    ("func", "lax", "strict"),
    [
        (_greet_star, (({"age": "30"},), {}), (({"age": 30},), {})),
        (_greet_star_pydantic, (({"age": "30"},), {}), ((_PydanticPerson(age=30),), {})),
        (_greet_star_dataclass, (({"age": "30"},), {}), ((_DataPerson(age=30),), {})),
        (_greet_star_typed, (({"age": "30"},), {}), (({"age": 30},), {})),
        (_greet_star_lists, (([{"age": "30"}],), {}), (([{"age": 30}],), {})),
        (_greet_named, ((), {"ann": {"age": "30"}}), ((), {"ann": {"age": 30}})),
        (_greet_named_typed, ((), {"ann": {"age": "30"}}), ((), {"ann": {"age": 30}})),
        (
            _greet_named_pydantic,
            ((), {"ann": {"age": "30"}}),
            ((), {"ann": _PydanticPerson(age=30)}),
        ),
    ],
    ids=[
        "model",
        "pydantic-dataclass",
        "dataclass",
        "typeddict",
        "list-of-models",
        "kwargs-model",
        "kwargs-typeddict",
        "kwargs-pydantic-dataclass",
    ],
)


class TestVariadicArgumentsAreValidatedStrictly:
    @_VARIADIC
    def test_the_local_path_refuses_a_coerced_value(self, func: Any, lax: Any, strict: Any) -> None:
        tool = Airlock(config=QUIET)(func)
        args, kwargs = lax
        assert _refusal(tool(*args, **kwargs)) == "validation_error"
        args, kwargs = strict
        assert tool(*args, **kwargs) == "ran"

    @_VARIADIC
    def test_the_sandbox_path_refuses_it_too(self, func: Any, lax: Any, strict: Any) -> None:
        validate = create_argument_validator(func)
        with pytest.raises(ValidationError):
            validate(*lax)
        validate(*strict)


# ---------------------------------------------------------------------------------------
# D-F4: log event names in core.py are literals
# ---------------------------------------------------------------------------------------


class TestCoreLogsLiteralEventNames:
    def test_no_logger_call_takes_an_f_string_event(self) -> None:
        tree = ast.parse(Path(core_module.__file__).read_text(encoding="utf-8"))
        offenders = [
            node.lineno
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "logger"
            and node.args
            and isinstance(node.args[0], ast.JoinedStr)
        ]
        assert offenders == []

    @pytest.mark.parametrize(
        ("verdict", "event"),
        [
            (OversightVerdict.DENY, "escalation_denied"),
            (OversightVerdict.TIMEOUT, "escalation_timeout"),
        ],
    )
    def test_an_escalation_outcome_logs_its_event(
        self, logs: _Recorder, verdict: OversightVerdict, event: str
    ) -> None:
        def approver(request: Any) -> OversightResponse:
            return OversightResponse(request_id=request.request_id, verdict=verdict, approver="h")

        policy = SecurityPolicy(escalate_tools={"pay": "needs a human"}, approver=approver)

        @Airlock(policy=policy, config=QUIET)
        def pay(amount: int) -> str:
            return "paid"

        assert _refusal(pay(amount=1)) is not None
        assert event in logs.events("info")


def test_the_run_context_is_still_available_inside_the_tool() -> None:
    """The call's own context stays readable inside the tool (``get_current_context``)."""

    @Airlock(config=QUIET)
    def whoami(run: Any) -> tuple[str | None, Any]:
        current = get_current_context()
        assert current is not None
        return current.agent_id, current.user_context

    wrapper = _HostRun(AirlockContext(agent_id="ops"))
    assert whoami(wrapper) == ("ops", wrapper)
    assert whoami(_model_written("model", "context", True, agent_id="evil")) == (None, None)
