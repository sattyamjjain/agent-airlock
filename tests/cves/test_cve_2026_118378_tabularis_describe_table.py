"""CVE-2026-118378 — Tabularis SQLite driver: stacked statements through ``describe_table``'s ``table_name``.

Vulnerability (from NVD, CNA VulnCheck):
    "Tabularis before 0.28.0 contains an SQL injection vulnerability in its SQLite driver
    that allows MCP clients to execute stacked statements by supplying a crafted table_name
    to the describe_table tool. Attackers, including AI agents steered by untrusted content,
    can close the quoted PRAGMA argument and append statements to read, modify, or drop
    SQLite data, bypassing read-only mode and write approval." Fixed in 0.28.0.

Advisory: https://github.com/TabularisDB/tabularis/security/advisories/GHSA-xrx3-j98v-67x9
NVD:      https://nvd.nist.gov/vuln/detail/CVE-2026-118378
CVSS:     7.8 (HIGH) — CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H, CWE-89

Airlock fit: partial.
    **In scope:** a stacked SQL statement carried in the ``table_name`` argument of an MCP
    tool, the "carried in an argument" shape of ``docs/cve-triage.md``. agent-airlock has no
    SQL parser, so the defence is the strict-validation contract, the CVE-2025-68144 and
    CVE-2026-105793 primitive: a tool that declares its identifier argument as a constrained
    type, here ``Annotated[str, StringConstraints(pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")]``,
    has every payload in the fixture refused under ``@Airlock`` as ``validation_error``
    before the tool runs, while ``users`` is admitted. No guard and no preset.

    **Not covered.** A tool that declares ``table_name: str`` gets no protection: there is
    no SQL grammar here, and the payload passes strict validation as the string it is
    (``TestABareStrIsOutOfReach``). The declared shape is the tool author's, and it refuses
    legal SQLite names outside it, such as ``order items``. **Out of scope:** the read-only
    mode and write approval the stacked statement bypasses are Tabularis's own server logic,
    and the quoting of the ``PRAGMA`` argument is upstream's to fix, which 0.28.0 does.
    Triage: #393.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any

import pytest
from pydantic import StringConstraints
from scripts.cve_watcher import classify_shape

import agent_airlock.policy_presets as policy_presets
from agent_airlock.core import Airlock

CVE = "CVE-2026-118378"

NVD_DESCRIPTION = (
    "Tabularis before 0.28.0 contains an SQL injection vulnerability in its SQLite driver that "
    "allows MCP clients to execute stacked statements by supplying a crafted table_name to the "
    "describe_table tool. Attackers, including AI agents steered by untrusted content, can "
    "close the quoted PRAGMA argument and append statements to read, modify, or drop SQLite "
    "data, bypassing read-only mode and write approval."
)
NVD_CWES = ["CWE-89"]

_FIXTURE: dict[str, Any] = json.loads(
    (
        Path(__file__).parent / "fixtures" / "cve_2026_118378_tabularis_describe_table.json"
    ).read_text(encoding="utf-8")
)
PAYLOADS = [pytest.param(entry["table_name"], id=entry["id"]) for entry in _FIXTURE["payloads"]]
BENIGN = [pytest.param(name, id=name) for name in _FIXTURE["benign"]]
REFUSED_BY_THE_SHAPE = [
    pytest.param(name, id=name) for name in _FIXTURE["refused_by_the_declared_shape"]
]
DISCLOSED: str = _FIXTURE["payloads"][0]["table_name"]

#: ``table_name``'s declared shape: one SQL identifier, as SQLite reads it unquoted.
TableName = Annotated[str, StringConstraints(pattern=_FIXTURE["identifier_pattern"])]


def _describe_table(ran: list[str]) -> Any:
    """A stub of Tabularis's tool with the declared shape. It opens no database and only
    builds the PRAGMA text, so a test can show what would have reached the driver."""

    @Airlock(return_dict=True)
    def describe_table(table_name: TableName) -> str:
        ran.append(table_name)
        return f"PRAGMA table_info('{table_name}')"

    return describe_table


def _assert_validation_block(result: Any, *, names: str = "table_name") -> None:
    assert isinstance(result, dict), f"the call ran and returned {result!r}"
    assert result["success"] is False
    assert result["status"] == "blocked"
    assert result["block_reason"] == "validation_error"
    assert result["error"].startswith("AIRLOCK_BLOCK")
    assert f"{names}: String should match pattern" in result["error"]


class TestTheDeclaredShapeRefusesTheStackedStatement:
    @pytest.mark.parametrize("table_name", PAYLOADS)
    def test_it_is_refused_before_the_tool_runs(self, table_name: str) -> None:
        ran: list[str] = []
        result = _describe_table(ran)(table_name=table_name)
        _assert_validation_block(result)
        assert ran == []

    @pytest.mark.parametrize("table_name", PAYLOADS)
    def test_the_refusal_does_not_repeat_the_value(self, table_name: str) -> None:
        result = _describe_table([])(table_name=table_name)
        assert table_name not in result["error"]

    def test_a_positional_table_name_is_validated_too(self) -> None:
        # Observed: the error names a positional argument by its index, not its parameter.
        ran: list[str] = []
        _assert_validation_block(_describe_table(ran)(DISCLOSED), names="0")
        assert ran == []


class TestBenignTableNamesRun:
    @pytest.mark.parametrize("table_name", BENIGN)
    def test_it_runs(self, table_name: str) -> None:
        ran: list[str] = []
        result = _describe_table(ran)(table_name=table_name)
        assert isinstance(result, dict)
        assert result["success"] is True
        assert result["result"] == f"PRAGMA table_info('{table_name}')"
        assert ran == [table_name]


class TestDocumentedLimit:
    @pytest.mark.parametrize("table_name", REFUSED_BY_THE_SHAPE)
    def test_a_legal_name_outside_the_declared_shape_is_refused(self, table_name: str) -> None:
        # The trade a narrow declaration makes: a table that needs quoting cannot be named.
        _assert_validation_block(_describe_table([])(table_name=table_name))


class TestABareStrIsOutOfReach:
    """The vulnerable tool's own shape: ``table_name`` as free text."""

    def test_the_stacked_statement_passes_strict_validation(self) -> None:
        @Airlock(return_dict=True)
        def describe_table_free(table_name: str) -> str:
            return f"PRAGMA table_info('{table_name}')"

        result = describe_table_free(table_name=DISCLOSED)
        assert isinstance(result, dict)
        assert result["success"] is True
        # The string that would have reached the driver: the quote closed, a statement stacked.
        assert result["result"] == "PRAGMA table_info('users'); DROP TABLE users; --')"


class TestScopeBoundary:
    def test_no_preset_claims_this_cve(self) -> None:
        # The defence is the tool's own declaration; no preset turns it on or names it.
        assert CVE not in Path(policy_presets.__file__).read_text(encoding="utf-8")


class TestWatcherAdmittedThisOnTheText:
    """Filed as #393 on the sink word ``SQL``; CWE-89 is not in the argument-shaped set."""

    def test_it_is_a_candidate_on_the_full_record(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, NVD_CWES) == "candidate"

    def test_the_text_alone_files_it(self) -> None:
        assert classify_shape(NVD_DESCRIPTION, []) == "candidate"

    def test_the_cwe_alone_would_only_ask_for_triage(self) -> None:
        assert classify_shape("", NVD_CWES) == "triage-required"
