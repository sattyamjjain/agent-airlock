"""Regressions for the configuration fixes in 0.10.19.

- A float ``BudgetConfig`` money limit raised TypeError in the budget-warning check,
  before the call was recorded: the error was logged, the record dropped, and a float
  session budget was never reached.
- ``from_toml`` passed ``[airlock.credentials]`` to the constructor under a name it does
  not take, so any file with that section failed to load.
- Six settings were stored and never applied without a word, ``require_done_receipt``
  among them, whose comment said it switched on a fail-closed guard.
- Bare ``@Airlock`` failed with "takes 1 positional argument but 2 were given" while
  ``__call__``'s docstring said it worked.
- ``get_recommended_mode``'s docstring example gave the wrong mode for "development".
"""

from __future__ import annotations

import doctest
import warnings
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest

from agent_airlock import Airlock, AirlockConfig, airlock
from agent_airlock.audit import AuditLogger
from agent_airlock.cost_tracking import BudgetConfig, BudgetExceededError, CostTracker, TokenUsage
from agent_airlock.mcp_proxy_guard import MCPProxyConfig
from agent_airlock.unknown_args import UnknownArgsMode, get_recommended_mode

_PRICING = {"default": {"input": Decimal("0.01"), "output": Decimal("0.01")}}
_THOUSAND_TOKENS = TokenUsage(input_tokens=1000, output_tokens=0)  # $0.01 at _PRICING


class TestAFloatBudgetIsEnforced:
    def test_the_session_limit_is_reached(self) -> None:
        tracker = CostTracker(budget=BudgetConfig(max_cost_per_session=0.025), pricing=_PRICING)

        tracker.record("tool", _THOUSAND_TOKENS)
        tracker.record("tool", _THOUSAND_TOKENS)
        with pytest.raises(BudgetExceededError):
            tracker.record("tool", _THOUSAND_TOKENS)

        assert tracker.get_summary().total_cost_usd == Decimal("0.02")

    @pytest.mark.parametrize(
        ("given", "stored"),
        [(0.1, Decimal("0.1")), (5, Decimal("5")), ("2.50", Decimal("2.50"))],
    )
    def test_money_limits_are_stored_as_decimals(self, given: Any, stored: Decimal) -> None:
        budget = BudgetConfig(max_cost_per_call=given, max_cost_per_session=given)

        assert (budget.max_cost_per_call, budget.max_cost_per_session) == (stored, stored)

    def test_a_bool_is_not_a_budget(self) -> None:
        with pytest.raises(TypeError, match="max_cost_per_session"):
            BudgetConfig(max_cost_per_session=True)  # type: ignore[arg-type]


class TestCredentialScopesLoadFromToml:
    def test_the_section_loads_and_feeds_the_proxy_config(self, tmp_path: Path) -> None:
        path = tmp_path / "airlock.toml"
        path.write_text(
            "[airlock]\n"
            'unknown_args = "block"\n'
            "\n"
            "[airlock.credentials.read_file]\n"
            'required_scopes = ["fs:read"]\n'
            "max_token_age_seconds = 600\n",
            encoding="utf-8",
        )

        config = AirlockConfig.from_toml(path)
        scope = config.credential_scopes["read_file"]

        assert config.unknown_args is UnknownArgsMode.BLOCK
        assert (scope.required_scopes, scope.max_token_age_seconds) == (["fs:read"], 600)
        proxy = MCPProxyConfig(tool_scopes=config.credential_scopes)
        assert proxy.tool_scopes["read_file"] is scope


class TestSettingsThatAreNotAppliedSaySo:
    @pytest.mark.parametrize(
        ("name", "value"),
        [
            ("max_output_tokens", 1000),
            ("audit_otel_enabled", True),
            ("audit_otel_endpoint", "http://collector:4317"),
            ("audit_include_args_hash", False),
            ("require_done_receipt", True),
        ],
    )
    def test_setting_one_warns(self, name: str, value: Any) -> None:
        with pytest.warns(UserWarning, match=f"AirlockConfig.{name} is stored but not applied"):
            AirlockConfig(**{name: value})

    def test_the_anomaly_config_warns(self) -> None:
        from agent_airlock.anomaly import AnomalyDetectorConfig

        with pytest.warns(UserWarning, match="anomaly_config is stored but not applied"):
            AirlockConfig(anomaly_config=AnomalyDetectorConfig())

    def test_the_defaults_do_not(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AIRLOCK_MAX_OUTPUT_TOKENS", raising=False)
        monkeypatch.delenv("AIRLOCK_STRICT_MODE", raising=False)

        with warnings.catch_warnings():
            warnings.simplefilter("error")
            AirlockConfig()


class TestTheE2BKeyPriority:
    def test_a_key_given_to_the_constructor_wins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("E2B_API_KEY", "from-env")

        assert AirlockConfig(e2b_api_key="from-arg").e2b_api_key == "from-arg"
        assert AirlockConfig().e2b_api_key == "from-env"


class TestBareAirlock:
    def test_says_to_add_the_parentheses(self) -> None:
        with pytest.raises(TypeError, match=r"write @Airlock\(\) with parentheses"):

            @Airlock  # type: ignore[arg-type, call-arg]
            def tool(x: int) -> int:
                return x

    def test_lowercase_airlock_works_bare(self) -> None:
        @airlock
        def tool(x: int) -> int:
            return x * 2

        assert tool(x=2) == 4


class TestRecommendedModeDocstring:
    def test_its_examples_hold(self) -> None:
        runner = doctest.DocTestRunner()
        for test in doctest.DocTestFinder().find(get_recommended_mode):
            runner.run(test)

        assert (runner.tries, runner.failures) == (2, 0)


class TestTheSuiteKeepsTheDefaultAuditLogOutOfTheCheckout:
    def test_the_default_path_writes_elsewhere(self) -> None:
        # tests/conftest.py registers the default path with a temporary file.
        logger = AuditLogger("airlock_audit.json")

        assert logger.path is not None
        assert logger.path != Path("airlock_audit.json").resolve()
