"""Fail-opens an audit of the 0.10.36 work in progress found, each with the input it admitted.

``ReadOnlySQLGuard``'s row fields are in ``tests/mcp_spec/test_readonly_sql_guard.py``,
``OIDCPublishWindowGuard``'s aliases and release age in its two modules there.
"""

from __future__ import annotations

import collections
import enum
import http.client
import ipaddress
import types
import urllib.error
from collections.abc import Callable
from dataclasses import dataclass
from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Any, NamedTuple
from uuid import UUID

import pytest
from pydantic import BaseModel

from agent_airlock import Airlock, AirlockConfig, SecurityPolicy
from agent_airlock.argument_secret_guard import (
    DEFAULT_ARGUMENT_SECRET_TYPES,
    ArgumentSecretGuard,
)
from agent_airlock.audit_otel import OTelAuditExporter
from agent_airlock.mcp_spec import attested_admission
from agent_airlock.mcp_spec.filter_eval_rce_guard import FilterEvalRCEGuard, FilterEvalRCEVerdict
from agent_airlock.mcp_spec.header_integrity import (
    HeaderBodyMismatchError,
    validate_header_body_integrity,
)
from agent_airlock.mcp_spec.manifest_only_mode import ManifestRegistry, launch_from_manifest
from agent_airlock.mcp_spec.readonly_sql_guard import ReadOnlySQLGuard, ReadOnlySQLVerdict
from agent_airlock.mcp_spec.stdio_guard import StdioInjectionError, validate_stdio_command
from agent_airlock.network import (
    EndpointPolicy,
    NetworkBlockedError,
    validate_endpoint,
)
from agent_airlock.policy import STRICT_POLICY
from agent_airlock.policy_presets import stdio_guard_ox_defaults
from agent_airlock.safe_types import PERSISTENCE_DENY_PATTERNS
from agent_airlock.sanitizer import (
    DEFAULT_MASK_CONFIG,
    SensitiveDataType,
    WorkspacePIIConfig,
    _types_to_mask,
    sanitize_with_workspace_config,
)
from agent_airlock.shell_command_policy import ShellCommandPolicy
from agent_airlock.ssrf_egress_guard import SSRFEgressGuard
from agent_airlock.trace_redaction import TraceRedactionPolicy

_LAMBDA = "lambda x: __import__('os')"


class _Model(BaseModel):
    sql: str = "DROP TABLE x"
    condition: str = _LAMBDA


@dataclass
class _Data:
    sql: str = "DROP TABLE x"
    condition: str = _LAMBDA


class _Named(NamedTuple):
    sql: str = "DROP TABLE x"
    condition: str = _LAMBDA


class _Filter(enum.Enum):
    EVIL = _LAMBDA
    FINE = "status == 'active'"


class TestAnObjectIsReadByItsFieldsOrRefused:
    @pytest.mark.parametrize("value", [_Model(), _Data(), _Named()], ids=["model", "data", "named"])
    @pytest.mark.parametrize("wrap", [lambda v: v, lambda v: [v], lambda v: {"x": (v,)}])
    def test_under_a_key_no_guard_reads(self, value: Any, wrap: Callable[[Any], Any]) -> None:
        args = {"params": wrap(value)}
        assert ReadOnlySQLGuard().evaluate(args).verdict is ReadOnlySQLVerdict.DENY_WRITE_STATEMENT
        assert (
            FilterEvalRCEGuard().evaluate(args).verdict is FilterEvalRCEVerdict.DENY_PYTHON_LAMBDA
        )

    @pytest.mark.parametrize("value", [_Model(), _Data(), _Named()], ids=["model", "data", "named"])
    def test_as_a_row(self, value: Any) -> None:
        for args in ({"data": value}, {"rows": [value]}):
            verdict = ReadOnlySQLGuard().evaluate(args).verdict
            assert verdict is ReadOnlySQLVerdict.DENY_WRITE_STATEMENT

    @pytest.mark.parametrize("value", [_Model(), _Data(), _Named()], ids=["model", "data", "named"])
    def test_in_a_filter(self, value: Any) -> None:
        for args in ({"filter": value}, {"filter": [value]}):
            verdict = FilterEvalRCEGuard().evaluate(args).verdict
            assert verdict is FilterEvalRCEVerdict.DENY_PYTHON_LAMBDA

    @pytest.mark.parametrize(
        "value",
        [object(), types.SimpleNamespace(a=_LAMBDA), lambda x: x, iter([_LAMBDA])],
        ids=["object", "namespace", "callable", "iterator"],
    )
    def test_any_other_object_in_a_filter_is_refused(self, value: Any) -> None:
        guard = FilterEvalRCEGuard()
        for args in ({"filter": value}, {"filter": [value]}, {"opts": {"condition": value}}):
            decision = guard.evaluate(args)
            assert decision.verdict is FilterEvalRCEVerdict.DENY_UNINSPECTABLE, args
        assert guard.evaluate({"session": value}).allowed
        assert not FilterEvalRCEGuard(scan_all_fields=True).evaluate({"session": value}).allowed

    def test_enums_text_types_and_sequences_are_read(self) -> None:
        guard = FilterEvalRCEGuard()
        for value in (
            _Filter.EVIL,
            collections.UserString(_LAMBDA),
            collections.deque([_LAMBDA]),
            collections.UserList([_LAMBDA]),
            {"k": _LAMBDA}.values(),
        ):
            verdict = guard.evaluate({"filter": value}).verdict
            assert verdict is FilterEvalRCEVerdict.DENY_PYTHON_LAMBDA, value
        sql = ReadOnlySQLGuard()
        for value in (collections.UserString("DROP TABLE x"), collections.deque(["DROP TABLE x"])):
            verdict = sql.evaluate({"sql": value}).verdict
            assert verdict is ReadOnlySQLVerdict.DENY_WRITE_STATEMENT, value

    def test_values_with_no_expression_text_pass(self) -> None:
        guard = FilterEvalRCEGuard()
        for value in (
            1,
            1.5,
            True,
            None,
            Decimal("1"),
            date(2026, 1, 1),
            datetime.now(timezone.utc),
            UUID(int=1),
            _Filter.FINE,
            {"created_after": date(2026, 1, 1)},
        ):
            assert guard.evaluate({"filter": value}).allowed, value


def _memory_tool(guard: ArgumentSecretGuard) -> Callable[..., Any]:
    @Airlock(
        policy=SecurityPolicy(argument_secret_guard=guard),
        config=AirlockConfig(enable_audit_log=False),
    )
    def remember(text: str = "", data: Any = None, password: str = "") -> str:
        return "stored"

    return remember


class TestSecretsInArguments:
    def test_a_bearer_token_is_refused(self) -> None:
        refused = _memory_tool(ArgumentSecretGuard())(
            text="Authorization: Bearer abcdEFGH1234567890abcdef"
        )
        assert refused["block_reason"] == "argument_secret"
        assert refused["metadata"]["kinds"] == ["bearer_token"]

    def test_a_new_type_joins_every_list(self) -> None:
        every = set(SensitiveDataType)
        assert set(DEFAULT_MASK_CONFIG) == every
        assert set(_types_to_mask(True, True, ["in"])) == every
        secrets = set(_types_to_mask(False, True, None))
        assert secrets <= set(DEFAULT_ARGUMENT_SECRET_TYPES)

    def test_a_workspace_masks_every_secret_type(self) -> None:
        config = WorkspacePIIConfig(workspace_id="w")
        text = "A_PASSWORD=hunter2hunter2\nB_SECRET=abcabcabcabc\nC_TOKEN=zzzzzzzzzzzz\nAPI_SECRET_KEY=q1"
        assert "q1" not in sanitize_with_workspace_config(text, config).content

    @pytest.mark.parametrize(
        ("data", "place"),
        [
            ({"password": "hunter2hunter2"}, "data.password"),
            ({"a": [{"client_secret": "hunter2hunter2"}]}, "data.a[0].client_secret"),
            ([{"OPENAI_API_KEY": "hunter2hunter2"}], "data[0].OPENAI_API_KEY"),
            ({"refreshToken": "hunter2hunter2"}, "data.refreshToken"),
        ],
    )
    @pytest.mark.parametrize("mode", ["block", "mask"])
    def test_a_value_under_a_secret_key_is_refused(self, data: Any, place: str, mode: Any) -> None:
        refused = _memory_tool(ArgumentSecretGuard(mode=mode))(text="hi", data=data)
        assert refused["block_reason"] == "argument_secret"
        assert refused["metadata"]["argument"] == place
        assert "hunter2" not in str(refused)

    def test_what_is_not_a_secret_under_a_key_passes(self) -> None:
        tool = _memory_tool(ArgumentSecretGuard())
        assert tool(data={"nextPageToken": "abcabcabcabcabc"}) == "stored"
        assert tool(data={"password": "short"}) == "stored"
        assert tool(data={"password": 12345678}) == "stored"
        assert tool(data={"note": "hunter2hunter2"}) == "stored"
        # The argument's own name is the tool's to choose.
        assert tool(password="hunter2hunter2") == "stored"
        relaxed = ArgumentSecretGuard(detectors=(SensitiveDataType.EMAIL,))
        assert _memory_tool(relaxed)(data={"password": "hunter2hunter2"}) == "stored"
        exempt = ArgumentSecretGuard(free_text_args=frozenset({"data"}))
        assert _memory_tool(exempt)(data={"password": "hunter2hunter2"}) == "stored"


class TestWhereARedirectionMayNotWrite:
    POLICY = ShellCommandPolicy(allow=("echo",))

    @pytest.mark.parametrize(
        "target",
        [
            "~/.bashrc",
            "~/.zprofile",
            "~/.zshenv",
            "~/.bash_login",
            "~/.zlogin",
            "~/.ZSHRC",
            ".bashrc",
            "./.profile",
            "../.zshenv",
            "/root/.bashrc",
            "/home/me/.bash_profile",
            "/Users/me/.ssh/authorized_keys",
            "/Users/me/Library/LaunchAgents/x.plist",
            "~/Library/LaunchAgents/x.plist",
            "~/.config/systemd/user/x.service",
            "~/.config/fish/config.fish",
            "venv/lib/python3.13/site-packages/x.pth",
            "/DEV/sda",
            "/etc/cron.d/x",
        ],
    )
    def test_it_is_denied(self, target: str) -> None:
        for operator in (">", ">>"):
            decision = self.POLICY.decide(f"echo x {operator} {target}")
            assert decision.verdict == "deny", target
            assert decision.rule.startswith("redirect "), target

    def test_ordinary_targets_stay_allowed(self) -> None:
        for target in ("out.txt", "/tmp/out.txt", "~/notes.md", "build/profile", "model.pth"):
            assert self.POLICY.decide(f"echo x > {target}").verdict == "allow", target

    def test_every_persistence_pattern_is_in_the_default(self) -> None:
        assert set(PERSISTENCE_DENY_PATTERNS) <= set(ShellCommandPolicy().redirect_deny)

    def test_an_allow_glob_keeps_its_case(self) -> None:
        policy = ShellCommandPolicy(
            allow=("echo",), redirect_deny=("/srv/*",), redirect_allow=("/srv/Ok/*",)
        )
        assert policy.decide("echo x > /srv/Ok/a").verdict == "allow"
        assert policy.decide("echo x > /srv/ok/a").verdict == "deny"


class TestAddressesAndUrls:
    @pytest.mark.parametrize("address", ["fec0::1", "feff::1"])
    def test_ipv6_site_local_is_internal(self, address: str) -> None:
        assert ipaddress.IPv6Address(address).is_site_local
        assert not SSRFEgressGuard().check_url(f"http://[{address}]/").allowed
        for policy in (EndpointPolicy(resolve_hostnames=False), EndpointPolicy()):
            with pytest.raises(NetworkBlockedError):
                validate_endpoint(f"http://[{address}]/", policy)
        resolving = EndpointPolicy(resolver=lambda host: [address])
        with pytest.raises(NetworkBlockedError):
            validate_endpoint("http://internal.example/", resolving)

    @pytest.mark.parametrize("char", ["\x00", "\t", "\n", "\r", "\x1f", "\x7f"])
    def test_a_raw_control_character_is_refused_under_a_path_scope(self, char: str) -> None:
        policy = EndpointPolicy(
            allowed_url_prefixes=["https://api.example.com/v1/"], resolve_hostnames=False
        )
        validate_endpoint("https://api.example.com/v1/a", policy)
        for url in (
            f"https://api.example.com/v1/a{char}b",
            f"https://api.example.com/v1/a?q={char}",
        ):
            with pytest.raises(NetworkBlockedError) as caught:
                validate_endpoint(url, policy)
            assert char not in str(caught.value)


class TestAParamHeaderRefusalNamesNoValue:
    SCHEMA = {
        "type": "object",
        "properties": {"token": {"type": "string", "x-mcp-header": "Token"}},
    }

    @pytest.mark.parametrize("where", ["headers", "body"])
    def test_conflicting_values(self, where: str) -> None:
        request: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "t", "arguments": {"token": "SECRET-A"}},
            "headers": [
                ("Mcp-Method", "tools/call"),
                ("Mcp-Name", "t"),
                ("Mcp-Param-Token", "SECRET-A"),
            ],
        }
        if where == "headers":
            request["headers"].append(("Mcp-Param-Token", "SECRET-B"))
        else:
            request["Mcp-Param-Token"] = "SECRET-B"
        with pytest.raises(HeaderBodyMismatchError) as caught:
            validate_header_body_integrity(request, input_schema=self.SCHEMA)
        assert "Mcp-Param-Token" in str(caught.value)
        assert "SECRET" not in str(caught.value)
        assert "SECRET" not in repr(vars(caught.value))


class TestAClearanceFetchThatFailsIsAMissingClearance:
    @pytest.mark.parametrize(
        "error",
        [
            TimeoutError("timed out"),
            ConnectionResetError("reset"),
            http.client.IncompleteRead(b""),
            urllib.error.URLError("no route"),
        ],
        ids=lambda error: type(error).__name__,
    )
    def test_a_read_that_fails(self, error: Exception, monkeypatch: pytest.MonkeyPatch) -> None:
        class Response:
            def __enter__(self) -> Response:
                return self

            def __exit__(self, *exc: object) -> None:
                return None

            def read(self) -> bytes:
                raise error

        monkeypatch.setattr(
            attested_admission.urllib.request, "urlopen", lambda *a, **k: Response()
        )
        with pytest.raises(attested_admission.MissingClearance):
            attested_admission._default_fetcher("https://mcp.example.com", "/.well-known/x")

    def test_a_url_that_cannot_be_requested(self) -> None:
        with pytest.raises(attested_admission.MissingClearance):
            attested_admission._default_fetcher("not-a-url", "/.well-known/x")


class TestPolicyFieldsThatWereNeverRead:
    @pytest.mark.parametrize("mode", ["manifest_only", "disabled"])
    def test_stdio_mode_refuses_a_runtime_argv(self, mode: Any) -> None:
        argv = ["uvx", "mcp-server-time"]
        validate_stdio_command(argv, stdio_guard_ox_defaults())
        validate_stdio_command(argv, stdio_guard_ox_defaults(), policy=SecurityPolicy())
        with pytest.raises(StdioInjectionError) as caught:
            validate_stdio_command(
                argv, stdio_guard_ox_defaults(), policy=SecurityPolicy(stdio_mode=mode)
            )
        assert caught.value.rule == "stdio_mode"
        assert caught.value.details["stdio_mode"] == mode

    def test_the_proxy_guard_passes_it_on(self) -> None:
        from agent_airlock.mcp_proxy_guard import MCPProxyConfig, MCPProxyGuard

        guard = MCPProxyGuard(MCPProxyConfig(stdio_guard=stdio_guard_ox_defaults()))
        guard.validate_stdio_spawn(["uvx", "mcp-server-time"])
        with pytest.raises(StdioInjectionError):
            guard.validate_stdio_spawn(
                ["uvx", "mcp-server-time"], policy=SecurityPolicy(stdio_mode="disabled")
            )

    def test_disabled_refuses_a_manifest_launch_before_anything_else(self) -> None:
        with pytest.raises(StdioInjectionError):
            launch_from_manifest(
                "any", ManifestRegistry(), policy=SecurityPolicy(stdio_mode="disabled")
            )

    def test_trace_redaction_reaches_the_exporter(self) -> None:
        assert OTelAuditExporter().redaction_policy is None
        assert OTelAuditExporter(policy=SecurityPolicy()).redaction_policy is None
        assert OTelAuditExporter(policy=STRICT_POLICY).redaction_policy is (
            STRICT_POLICY.trace_redaction
        )
        own = TraceRedactionPolicy(enabled=False)
        exporter = OTelAuditExporter(policy=STRICT_POLICY, redaction_policy=own)
        assert exporter.redaction_policy is own
