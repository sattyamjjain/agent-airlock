"""The OAuth token audience, checked on the ``@Airlock`` call path (0.10.27).

NVD: https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-115413
Advisory: https://github.com/awslabs/mcp/security/advisories/GHSA-4prq-p2x5-w9fh

CVE-2026-115413 (High, CVSS 3.1 7.8, CWE-346): AWS API MCP Server before 1.6.0, in OAuth
mode, did not validate the access token's audience, so a token the same identity provider
issued to another application ran AWS operations with the server's own credentials.
``mcp_spec.oauth.validate_access_token_audience`` has shipped for releases, but nothing on
the call path called it. ``AirlockConfig(expected_token_audience=...)`` now checks the
``aud`` claim of the claims the host put on the call's ``AirlockContext`` metadata under
``access_token_claims``: ``warn`` (the default mode) logs a wrong or missing audience and
runs the call, ``deny`` refuses it.

Every claims dict here is a placeholder. There is no token, no signature and no key: the
check reads claims the host has already verified, and these tests stand in for that host.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from agent_airlock import Airlock, AirlockConfig, AirlockContext
from agent_airlock import core as core_module
from agent_airlock.core import ACCESS_TOKEN_CLAIMS_KEY
from agent_airlock.mcp_spec.oauth import TokenAudienceError
from agent_airlock.policy_presets import (
    _PRESET_REGISTRY,
    ssrf_egress_guard_defaults,
    token_audience_defaults,
)
from agent_airlock.policy_presets import __all__ as presets_all
from agent_airlock.self_heal import BlockReason

SERVER = "https://mcp.example.test"
OTHER_APP = "https://other-app.example"
CVE = "CVE-2026-115413"
GHSA_URL = "https://github.com/awslabs/mcp/security/advisories/GHSA-4prq-p2x5-w9fh"


class _Events:
    """Stands in for a module's logger and records every event it is given."""

    def __init__(self) -> None:
        self.records: list[tuple[str, str, dict[str, Any]]] = []

    def __getattr__(self, level: str) -> Any:
        def record(event: str, **fields: Any) -> None:
            self.records.append((level, event, fields))

        return record

    def named(self, event: str) -> list[dict[str, Any]]:
        return [fields for _, name, fields in self.records if name == event]


@pytest.fixture
def events(monkeypatch: pytest.MonkeyPatch) -> _Events:
    recorder = _Events()
    monkeypatch.setattr(core_module, "logger", recorder)
    return recorder


def _claims(aud: Any) -> dict[str, Any]:
    return {"sub": "placeholder-subject", "aud": aud}


def _tool(config: AirlockConfig, ran: list[str]) -> Any:
    @Airlock(config=config)
    def list_buckets() -> str:
        ran.append("ran")
        return "PLACEHOLDER"

    return list_buckets


def _deny(**extra: Any) -> AirlockConfig:
    return AirlockConfig(expected_token_audience=SERVER, token_audience_mode="deny", **extra)


def _call_with(tool: Any, claims: Any) -> Any:
    with AirlockContext(metadata={ACCESS_TOKEN_CLAIMS_KEY: claims}):
        return tool()


class TestDenyMode:
    def test_a_token_issued_to_another_application_is_refused(self, events: _Events) -> None:
        ran: list[str] = []
        blocked: list[tuple[str, str, dict[str, Any]]] = []
        config = _deny(on_blocked=lambda name, reason, ctx: blocked.append((name, reason, ctx)))

        result = _call_with(_tool(config, ran), _claims(OTHER_APP))

        assert ran == []
        assert result["success"] is False
        assert result["status"] == "blocked"
        assert result["block_reason"] == BlockReason.TOKEN_AUDIENCE.value
        assert result["error"] == (
            "AIRLOCK_BLOCK: 'list_buckets' refused: the access token on this call was not "
            "issued for this server"
        )
        assert result["fix_hints"]
        assert result["metadata"]["violation"] == "audience_mismatch"
        assert result["metadata"]["expected_audience"] == SERVER
        # The operator is told which audience the token named; the model is not.
        assert OTHER_APP not in result["error"]
        assert not any(OTHER_APP in hint for hint in result["fix_hints"])
        [(name, reason, ctx)] = blocked
        assert name == "list_buckets"
        assert OTHER_APP in reason
        assert ctx["violation_type"] == "token_audience"
        [block] = events.named("airlock_token_audience_block")
        assert block["violation"] == "audience_mismatch"

    def test_a_token_issued_to_this_server_runs(self) -> None:
        ran: list[str] = []

        assert _call_with(_tool(_deny(), ran), _claims(SERVER)) == "PLACEHOLDER"
        assert ran == ["ran"]

    def test_a_trailing_slash_in_a_list_audience_still_matches(self) -> None:
        ran: list[str] = []

        result = _call_with(_tool(_deny(), ran), _claims(["https://mcp.example.test/"]))

        assert result == "PLACEHOLDER"
        assert ran == ["ran"]

    def test_a_list_naming_this_server_beside_another_audience_runs(self) -> None:
        ran: list[str] = []

        result = _call_with(_tool(_deny(), ran), _claims(["placeholder-client-id", SERVER]))

        assert result == "PLACEHOLDER"

    def test_claims_with_no_aud_are_refused(self) -> None:
        ran: list[str] = []

        result = _call_with(_tool(_deny(), ran), {"sub": "placeholder-subject"})

        assert ran == []
        assert result["block_reason"] == "token_audience"
        assert result["metadata"]["violation"] == "audience_mismatch"

    def test_an_aud_list_holding_a_non_string_is_refused_whole(self) -> None:
        # The string in the list matches; the token is still malformed (RFC 7519 §4.1.3).
        ran: list[str] = []

        result = _call_with(_tool(_deny(), ran), _claims([7, SERVER]))

        assert ran == []
        assert result["block_reason"] == "token_audience"

    def test_a_string_aud_that_is_not_a_uri_is_refused_not_raised(self) -> None:
        ran: list[str] = []

        result = _call_with(_tool(_deny(), ran), _claims("placeholder-client-id"))

        assert ran == []
        assert result["block_reason"] == "token_audience"

    def test_a_call_with_no_claims_is_refused(self) -> None:
        ran: list[str] = []

        result = _tool(_deny(), ran)()

        assert ran == []
        assert result["block_reason"] == "token_audience"
        assert result["metadata"]["violation"] == "no_claims"
        assert result["error"] == (
            "AIRLOCK_BLOCK: 'list_buckets' refused: the call carries no access token claims "
            "this server can check"
        )

    def test_claims_that_are_not_a_mapping_are_refused(self) -> None:
        ran: list[str] = []

        result = _call_with(_tool(_deny(), ran), "PLACEHOLDER")

        assert ran == []
        assert result["metadata"]["violation"] == "claims_unreadable"

    def test_an_async_tool_is_refused_the_same_way(self) -> None:
        ran: list[str] = []

        @Airlock(config=_deny())
        async def list_buckets() -> str:
            ran.append("ran")
            return "PLACEHOLDER"

        async def call() -> Any:
            with AirlockContext(metadata={ACCESS_TOKEN_CLAIMS_KEY: _claims(OTHER_APP)}):
                return await list_buckets()

        result = asyncio.run(call())

        assert ran == []
        assert result["block_reason"] == "token_audience"

    def test_claims_on_the_run_context_a_framework_passes_are_read(self) -> None:
        class RunWrapper:
            def __init__(self, claims: dict[str, Any]) -> None:
                self.context = AirlockContext(metadata={ACCESS_TOKEN_CLAIMS_KEY: claims})

        ran: list[str] = []

        @Airlock(config=_deny())
        def list_buckets(ctx: Any) -> str:
            ran.append("ran")
            return "PLACEHOLDER"

        assert list_buckets(RunWrapper(_claims(SERVER))) == "PLACEHOLDER"
        refused = list_buckets(RunWrapper(_claims(OTHER_APP)))
        assert refused["block_reason"] == "token_audience"
        assert ran == ["ran"]

    def test_the_refusal_is_audited_as_token_audience(self, tmp_path: Path) -> None:
        audit = tmp_path / "audit.jsonl"
        ran: list[str] = []

        _call_with(_tool(_deny(audit_log_path=audit), ran), _claims(OTHER_APP))

        records = [
            json.loads(line)
            for line in audit.read_text().splitlines()
            if line and not line.startswith("#")
        ]
        assert records[-1]["blocked"] is True
        assert records[-1]["block_reason"] == "token_audience"

    def test_the_check_runs_before_ghost_arguments(self) -> None:
        # The credential is judged before the arguments, as a server checks who calls
        # before what is asked: an unknown argument does not change the refusal.
        ran: list[str] = []
        tool = _tool(_deny(), ran)

        with AirlockContext(metadata={ACCESS_TOKEN_CLAIMS_KEY: _claims(OTHER_APP)}):
            result = tool(force=True)

        assert result["block_reason"] == "token_audience"


class TestWarnMode:
    def _warn(self) -> AirlockConfig:
        return AirlockConfig(expected_token_audience=SERVER)

    def test_warn_is_the_default_mode(self) -> None:
        assert AirlockConfig().token_audience_mode == "warn"

    def test_a_wrong_audience_is_logged_once_and_the_call_runs(self, events: _Events) -> None:
        ran: list[str] = []

        result = _call_with(_tool(self._warn(), ran), _claims(OTHER_APP))

        assert result == "PLACEHOLDER"
        assert ran == ["ran"]
        [warned] = events.named("airlock_token_audience_warn_only")
        assert warned["function"] == "list_buckets"
        assert warned["violation"] == "audience_mismatch"
        assert warned["expected_audience"] == SERVER
        assert OTHER_APP in warned["reason"]
        assert events.named("airlock_token_audience_block") == []

    def test_each_call_logs_its_own_event(self, events: _Events) -> None:
        ran: list[str] = []
        tool = _tool(self._warn(), ran)

        _call_with(tool, _claims(OTHER_APP))
        _call_with(tool, _claims(OTHER_APP))

        assert len(events.named("airlock_token_audience_warn_only")) == 2
        assert ran == ["ran", "ran"]

    def test_missing_claims_are_logged_and_the_call_runs(self, events: _Events) -> None:
        ran: list[str] = []

        assert _tool(self._warn(), ran)() == "PLACEHOLDER"

        [warned] = events.named("airlock_token_audience_warn_only")
        assert warned["violation"] == "no_claims"

    def test_a_matching_audience_logs_nothing(self, events: _Events) -> None:
        ran: list[str] = []

        _call_with(_tool(self._warn(), ran), _claims([SERVER + "/"]))

        assert events.named("airlock_token_audience_warn_only") == []


class TestNoAudienceSet:
    @pytest.mark.parametrize("mode", ["off", "warn", "deny"])
    def test_no_expected_audience_changes_nothing(self, mode: str, events: _Events) -> None:
        ran: list[str] = []
        tool = _tool(AirlockConfig(token_audience_mode=mode), ran)  # type: ignore[arg-type]

        assert tool() == "PLACEHOLDER"
        assert _call_with(tool, _claims(OTHER_APP)) == "PLACEHOLDER"
        assert _call_with(tool, "PLACEHOLDER") == "PLACEHOLDER"

        assert ran == ["ran", "ran", "ran"]
        assert not [r for r in events.records if "token_audience" in r[1]]

    def test_the_default_config_checks_no_audience(self) -> None:
        assert AirlockConfig().expected_token_audience is None

    def test_mode_off_skips_a_configured_audience(self, events: _Events) -> None:
        ran: list[str] = []
        config = AirlockConfig(expected_token_audience=SERVER, token_audience_mode="off")

        assert _call_with(_tool(config, ran), _claims(OTHER_APP)) == "PLACEHOLDER"
        assert not [r for r in events.records if "token_audience" in r[1]]


class TestTheModelCannotSupplyTheClaims:
    def test_claims_passed_as_an_undeclared_tool_argument_are_ignored(self) -> None:
        ran: list[str] = []
        tool = _tool(_deny(), ran)

        result = tool(**{ACCESS_TOKEN_CLAIMS_KEY: _claims(SERVER)})

        assert ran == []
        assert result["block_reason"] == "token_audience"
        assert result["metadata"]["violation"] == "no_claims"

    def test_claims_passed_to_a_declared_parameter_of_that_name_are_ignored(self) -> None:
        ran: list[str] = []

        @Airlock(config=_deny())
        def list_buckets(access_token_claims: dict[str, Any] | None = None) -> str:
            ran.append("ran")
            return "PLACEHOLDER"

        result = list_buckets(access_token_claims=_claims(SERVER))

        assert ran == []
        assert result["metadata"]["violation"] == "no_claims"

    def test_a_model_argument_does_not_override_the_host_claims(self) -> None:
        ran: list[str] = []

        @Airlock(config=_deny())
        def list_buckets(access_token_claims: dict[str, Any] | None = None) -> str:
            ran.append("ran")
            return "PLACEHOLDER"

        with AirlockContext(metadata={ACCESS_TOKEN_CLAIMS_KEY: _claims(OTHER_APP)}):
            result = list_buckets(access_token_claims=_claims(SERVER))

        assert ran == []
        assert result["metadata"]["violation"] == "audience_mismatch"


class TestConfiguration:
    @pytest.mark.parametrize("field", ["token_audience_mode", "startup_hook_check"])
    def test_a_mode_that_is_not_off_warn_or_deny_raises(self, field: str) -> None:
        with pytest.raises(ValueError, match=field):
            AirlockConfig(**{field: "dney"})

    @pytest.mark.parametrize("audience", ["mcp.example.test", "https://mcp.example.test#x", ""])
    def test_an_expected_audience_that_is_not_a_resource_uri_raises(self, audience: str) -> None:
        with pytest.raises(ValueError, match="expected_token_audience"):
            AirlockConfig(expected_token_audience=audience)

    def test_a_non_string_expected_audience_raises(self) -> None:
        with pytest.raises(ValueError, match="expected_token_audience"):
            AirlockConfig(expected_token_audience=42)  # type: ignore[arg-type]


class TestTomlRoundTrip:
    DIGEST = "AB" * 32

    def _write(self, tmp_path: Path, body: str) -> Path:
        path = tmp_path / "airlock.toml"
        path.write_text(body, encoding="utf-8")
        return path

    def test_every_new_key_is_read_from_the_airlock_table(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from agent_airlock import config as config_module

        recorder = _Events()
        monkeypatch.setattr(config_module, "logger", recorder)
        path = self._write(
            tmp_path,
            f"""
[airlock]
expected_token_audience = "{SERVER}"
token_audience_mode = "Deny"
startup_hook_check = "warn"

[airlock.startup_hook_allowlist]
"placeholder.pth" = "{self.DIGEST}"
""",
        )

        config = AirlockConfig.from_toml(path)

        assert config.expected_token_audience == SERVER
        assert config.token_audience_mode == "deny"
        assert config.startup_hook_check == "warn"
        assert config.startup_hook_allowlist == {"placeholder.pth": "ab" * 32}
        assert recorder.named("unknown_config_keys") == []

    def test_a_config_loaded_from_toml_refuses_on_the_call_path(self, tmp_path: Path) -> None:
        path = self._write(
            tmp_path,
            f'[airlock]\nexpected_token_audience = "{SERVER}"\ntoken_audience_mode = "deny"\n',
        )
        ran: list[str] = []
        tool = _tool(AirlockConfig.from_toml(path), ran)

        assert _call_with(tool, _claims(OTHER_APP))["block_reason"] == "token_audience"
        assert _call_with(tool, _claims(SERVER)) == "PLACEHOLDER"

    @pytest.mark.parametrize(
        "line",
        [
            'token_audience_mode = "dney"',
            'startup_hook_check = "on"',
            "token_audience_mode = true",
        ],
    )
    def test_a_mode_typo_raises_instead_of_falling_back(self, tmp_path: Path, line: str) -> None:
        path = self._write(tmp_path, f"[airlock]\n{line}\n")

        with pytest.raises(ValueError):
            AirlockConfig.from_toml(path)

    def test_a_non_string_audience_raises(self, tmp_path: Path) -> None:
        path = self._write(tmp_path, "[airlock]\nexpected_token_audience = 7\n")

        with pytest.raises(ValueError, match="expected_token_audience"):
            AirlockConfig.from_toml(path)

    def test_an_allowlist_that_is_not_a_table_raises(self, tmp_path: Path) -> None:
        path = self._write(tmp_path, '[airlock]\nstartup_hook_allowlist = ["placeholder.pth"]\n')

        with pytest.raises(ValueError, match="startup_hook_allowlist"):
            AirlockConfig.from_toml(path)


class TestTokenAudiencePreset:
    def _preset(self) -> dict[str, Any]:
        return token_audience_defaults(expected_audience=SERVER)

    def test_it_carries_every_key_the_ssrf_preset_does(self) -> None:
        assert set(ssrf_egress_guard_defaults()) <= set(self._preset())

    def test_it_names_the_cve_cwe_and_advisory(self) -> None:
        preset = self._preset()

        assert preset["preset_id"] == "token_audience"
        assert preset["severity"] == "high"
        assert preset["default_action"] == "deny"
        assert preset["cves"] == (CVE,)
        assert preset["cwe"] == ("CWE-346",)
        assert preset["owasp"] == "MCP07"
        assert preset["advisory_url"] == GHSA_URL

    def test_check_raises_token_audience_error_for_another_application(self) -> None:
        with pytest.raises(TokenAudienceError):
            self._preset()["check"](_claims(OTHER_APP))

    @pytest.mark.parametrize("claims", [{}, _claims([7, SERVER]), "PLACEHOLDER", None])
    def test_check_raises_token_audience_error_for_unreadable_claims(self, claims: Any) -> None:
        with pytest.raises(TokenAudienceError):
            self._preset()["check"](claims)

    def test_check_passes_a_token_for_this_server(self) -> None:
        assert self._preset()["check"](_claims([SERVER + "/"])) is None

    def test_its_airlock_config_refuses_on_the_call_path(self) -> None:
        preset = self._preset()
        assert preset["airlock_config"].token_audience_mode == "deny"
        ran: list[str] = []
        tool = _tool(preset["airlock_config"], ran)

        assert _call_with(tool, _claims(OTHER_APP))["block_reason"] == "token_audience"
        assert ran == []

    def test_it_is_registered_and_exported(self) -> None:
        assert "token_audience_defaults" in _PRESET_REGISTRY
        assert "token_audience_defaults" in presets_all

    def test_an_expected_audience_that_is_not_a_uri_raises(self) -> None:
        with pytest.raises(ValueError):
            token_audience_defaults(expected_audience="mcp.example.test")
