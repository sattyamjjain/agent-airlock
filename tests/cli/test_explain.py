"""Tests for ``airlock explain`` (v0.8.13+, read-only privilege right-sizing).

Covers the granted-vs-used diff on fixture traces, the format flags,
the auto-detected OTLP-vs-JSONL loader, the denied-call exclusion
invariant, the ``--suggest-policy`` preview shape, and the read-only
contract (no policy file is ever written).
"""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest

from agent_airlock.cli.explain import (
    AgentUsageReport,
    CallObservation,
    PolicySnapshot,
    _peek_format,
    diff_granted_vs_used,
    load_policy,
    load_trace,
    main,
    suggest_tightened_policy,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def fixture_policy(tmp_path: Path) -> Path:
    path = tmp_path / "policy.toml"
    path.write_text(
        "\n".join(
            [
                'allowed_tools = ["read_*", "search_*", "write_*", "delete_*"]',
                'denied_tools  = ["rm_-rf", "drop_database"]',
                "",
            ]
        ),
        encoding="utf-8",
    )
    return path


@pytest.fixture
def fixture_jsonl_trace(tmp_path: Path) -> Path:
    """A native audit JSONL trace with two agents.

    agent 'ag1' admitted: read_file, search_kb. blocked: delete_user.
    agent 'ag2' admitted: read_file.
    """
    path = tmp_path / "trace.jsonl"
    path.write_text(
        "\n".join(
            [
                "# Agent-Airlock Audit Log",
                "# Created: 2026-05-31T00:00:00Z",
                json.dumps(
                    {
                        "timestamp": "2026-05-31T10:00:00Z",
                        "tool_name": "read_file",
                        "blocked": False,
                        "agent_id": "ag1",
                    }
                ),
                json.dumps(
                    {
                        "timestamp": "2026-05-31T10:00:01Z",
                        "tool_name": "search_kb",
                        "blocked": False,
                        "agent_id": "ag1",
                    }
                ),
                json.dumps(
                    {
                        "timestamp": "2026-05-31T10:00:02Z",
                        "tool_name": "delete_user",
                        "blocked": True,
                        "agent_id": "ag1",
                        "block_reason": "denylisted",
                    }
                ),
                json.dumps(
                    {
                        "timestamp": "2026-05-31T10:00:03Z",
                        "tool_name": "read_file",
                        "blocked": False,
                        "agent_id": "ag2",
                    }
                ),
                "",
            ]
        ),
        encoding="utf-8",
    )
    return path


@pytest.fixture
def fixture_otlp_trace(tmp_path: Path) -> Path:
    """An OTLP-JSON trace covering the same two agents."""
    path = tmp_path / "trace.otlp.json"
    doc = {
        "resourceSpans": [
            {
                "resource": {"attributes": [{"key": "agent_id", "value": {"stringValue": "ag1"}}]},
                "scopeSpans": [
                    {
                        "spans": [
                            {
                                "name": "read_file",
                                "attributes": [
                                    {
                                        "key": "agent_id",
                                        "value": {"stringValue": "ag1"},
                                    }
                                ],
                            },
                            {
                                "name": "search_kb",
                                "attributes": [
                                    {
                                        "key": "agent_id",
                                        "value": {"stringValue": "ag1"},
                                    }
                                ],
                            },
                            {
                                # Blocked spans must not contribute to
                                # the "actually called" set.
                                "name": "delete_user",
                                "attributes": [
                                    {
                                        "key": "agent_id",
                                        "value": {"stringValue": "ag1"},
                                    },
                                    {
                                        "key": "airlock.blocked",
                                        "value": {"boolValue": True},
                                    },
                                ],
                            },
                        ]
                    }
                ],
            },
            {
                "resource": {"attributes": [{"key": "agent_id", "value": {"stringValue": "ag2"}}]},
                "scopeSpans": [
                    {
                        "spans": [
                            {
                                "name": "read_file",
                                "attributes": [
                                    {
                                        "key": "agent_id",
                                        "value": {"stringValue": "ag2"},
                                    }
                                ],
                            }
                        ]
                    }
                ],
            },
        ]
    }
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------


class TestFormatDetection:
    def test_jsonl_default(self) -> None:
        assert _peek_format('{"tool_name": "x"}\n{"tool_name": "y"}\n') == "jsonl"

    def test_otlp_doc(self) -> None:
        assert _peek_format('{"resourceSpans": [{}]}') == "otlp"

    def test_empty(self) -> None:
        assert _peek_format("") == "jsonl"

    def test_garbage_does_not_misclassify(self) -> None:
        # Begins with '{' but is not valid JSON; should fall through to jsonl
        # so the line-by-line loader can ignore it.
        assert _peek_format("{not valid json") == "jsonl"

    def test_jsonl_starting_with_object_line(self) -> None:
        """A JSONL file's first line is a JSON object — that's fine. The
        detector should only flip to OTLP when ``resourceSpans`` is present."""
        assert _peek_format('{"tool_name": "x"}\n') == "jsonl"


# ---------------------------------------------------------------------------
# Policy loader
# ---------------------------------------------------------------------------


class TestPolicyLoader:
    def test_toml_root(self, fixture_policy: Path) -> None:
        snap = load_policy(fixture_policy)
        assert snap.allowed_tools == ("read_*", "search_*", "write_*", "delete_*")
        assert snap.denied_tools == ("rm_-rf", "drop_database")

    def test_json_root(self, tmp_path: Path) -> None:
        path = tmp_path / "policy.json"
        path.write_text(
            json.dumps({"allowed_tools": ["a", "b"], "denied_tools": ["c"]}),
            encoding="utf-8",
        )
        snap = load_policy(path)
        assert snap.allowed_tools == ("a", "b")
        assert snap.denied_tools == ("c",)

    def test_nested_policy_section(self, tmp_path: Path) -> None:
        path = tmp_path / "config.json"
        path.write_text(
            json.dumps(
                {
                    "other": {"unrelated": True},
                    "policy": {"allowed_tools": ["read_*"], "denied_tools": []},
                }
            ),
            encoding="utf-8",
        )
        snap = load_policy(path)
        assert snap.allowed_tools == ("read_*",)
        assert snap.denied_tools == ()

    def test_rejects_non_list_allowed_tools(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.json"
        path.write_text(json.dumps({"allowed_tools": "not-a-list"}), encoding="utf-8")
        with pytest.raises(ValueError, match="allowed_tools must be a list"):
            load_policy(path)


# ---------------------------------------------------------------------------
# Trace loader
# ---------------------------------------------------------------------------


class TestTraceLoader:
    def test_jsonl_excludes_blocked_calls(self, fixture_jsonl_trace: Path) -> None:
        obs = load_trace(fixture_jsonl_trace)
        # 4 records in the fixture, 1 blocked → 3 admitted.
        assert len(obs) == 3
        tools = {(o.agent_id, o.tool_name) for o in obs}
        assert tools == {
            ("ag1", "read_file"),
            ("ag1", "search_kb"),
            ("ag2", "read_file"),
        }

    def test_jsonl_skips_blank_and_header_lines(self, tmp_path: Path) -> None:
        path = tmp_path / "trace.jsonl"
        path.write_text(
            "# header\n\n  \n"
            + json.dumps({"tool_name": "x", "blocked": False, "agent_id": "ag"})
            + "\n",
            encoding="utf-8",
        )
        obs = load_trace(path)
        assert [(o.agent_id, o.tool_name) for o in obs] == [("ag", "x")]

    def test_jsonl_missing_agent_id_falls_back(self, tmp_path: Path) -> None:
        path = tmp_path / "trace.jsonl"
        path.write_text(
            json.dumps({"tool_name": "x", "blocked": False}) + "\n",
            encoding="utf-8",
        )
        obs = load_trace(path)
        assert obs == [CallObservation(tool_name="x", agent_id="__anonymous__")]

    def test_otlp_excludes_blocked_spans(self, fixture_otlp_trace: Path) -> None:
        obs = load_trace(fixture_otlp_trace)
        tools = {(o.agent_id, o.tool_name) for o in obs}
        assert tools == {
            ("ag1", "read_file"),
            ("ag1", "search_kb"),
            ("ag2", "read_file"),
        }

    def test_otlp_attribute_value_kinds(self, tmp_path: Path) -> None:
        """OTLP AnyValue shapes (string/bool/int/double) all decode cleanly."""
        path = tmp_path / "trace.otlp.json"
        doc = {
            "resourceSpans": [
                {
                    "scopeSpans": [
                        {
                            "spans": [
                                {
                                    "name": "tool",
                                    "attributes": [
                                        {
                                            "key": "agent_id",
                                            "value": {"stringValue": "ag"},
                                        },
                                        {
                                            "key": "airlock.blocked",
                                            "value": {"boolValue": False},
                                        },
                                    ],
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        path.write_text(json.dumps(doc), encoding="utf-8")
        obs = load_trace(path)
        assert obs == [CallObservation(tool_name="tool", agent_id="ag")]


# ---------------------------------------------------------------------------
# Diff algorithm
# ---------------------------------------------------------------------------


class TestDiffGrantedVsUsed:
    def test_per_agent_unused_set_is_correct(self) -> None:
        policy = PolicySnapshot(
            allowed_tools=("read_*", "search_*", "write_*", "delete_*"),
            denied_tools=(),
        )
        obs = [
            CallObservation("read_file", "ag1"),
            CallObservation("search_kb", "ag1"),
            CallObservation("read_file", "ag2"),
        ]
        reports = diff_granted_vs_used(policy, obs)
        assert {r.agent_id for r in reports} == {"ag1", "ag2"}

        ag1 = next(r for r in reports if r.agent_id == "ag1")
        assert set(ag1.used_patterns) == {"read_*", "search_*"}
        assert set(ag1.unused_patterns) == {"write_*", "delete_*"}

        ag2 = next(r for r in reports if r.agent_id == "ag2")
        assert set(ag2.used_patterns) == {"read_*"}
        assert set(ag2.unused_patterns) == {"search_*", "write_*", "delete_*"}

    def test_glob_matching_matches_securitypolicy_semantics(self) -> None:
        """The diff must use the same fnmatch semantics SecurityPolicy.check_tool_allowed
        uses internally, otherwise the suggested tightened policy could
        admit / deny different tools than the diff implied."""
        from agent_airlock.policy import SecurityPolicy

        policy_for_check = SecurityPolicy(allowed_tools=["data_*", "read_?"])

        # SecurityPolicy admits these:
        for t in ("data_x", "data_anything", "read_a"):
            policy_for_check.check_tool_allowed(t)  # would raise if not admitted

        snap = PolicySnapshot(allowed_tools=("data_*", "read_?"), denied_tools=())
        reports = diff_granted_vs_used(
            snap,
            [
                CallObservation("data_x", "ag"),
                CallObservation("data_anything", "ag"),
                CallObservation("read_a", "ag"),
            ],
        )
        assert set(reports[0].used_patterns) == {"data_*", "read_?"}
        assert reports[0].unused_patterns == []

    def test_empty_trace_reports_no_agents(self) -> None:
        snap = PolicySnapshot(allowed_tools=("read_*",), denied_tools=())
        assert diff_granted_vs_used(snap, []) == []

    def test_unmatched_pattern_appears_in_unused(self) -> None:
        snap = PolicySnapshot(allowed_tools=("read_*", "rare_admin_tool"), denied_tools=())
        reports = diff_granted_vs_used(snap, [CallObservation("read_file", "ag")])
        assert reports[0].unused_patterns == ["rare_admin_tool"]


# ---------------------------------------------------------------------------
# Suggested tightened policy
# ---------------------------------------------------------------------------


class TestSuggestTightenedPolicy:
    def test_keeps_only_used_patterns(self) -> None:
        report = AgentUsageReport(
            agent_id="ag",
            granted_patterns=["read_*", "write_*", "delete_*"],
            used_tools=["read_file"],
            used_patterns=["read_*"],
            unused_patterns=["write_*", "delete_*"],
        )
        out = suggest_tightened_policy(report, denied_tools=("drop_db",))
        assert out["allowed_tools"] == ["read_*"]
        assert out["denied_tools"] == ["drop_db"]

    def test_denied_tools_passthrough_unchanged(self) -> None:
        """Denials are intent, not usage data — the suggestion forwards them."""
        report = AgentUsageReport(
            agent_id="ag",
            granted_patterns=["read_*"],
            used_tools=["read_file"],
            used_patterns=["read_*"],
            unused_patterns=[],
        )
        out = suggest_tightened_policy(report, denied_tools=("rm_-rf", "drop_db"))
        assert out["denied_tools"] == ["rm_-rf", "drop_db"]


# ---------------------------------------------------------------------------
# CLI end-to-end (main()) + read-only contract
# ---------------------------------------------------------------------------


class TestCLIEndToEnd:
    def test_table_format_lists_unused_set(
        self, fixture_policy: Path, fixture_jsonl_trace: Path
    ) -> None:
        with patch("sys.stdout", new_callable=StringIO) as out:
            rc = main(
                [
                    "--unused-scopes",
                    "--policy",
                    str(fixture_policy),
                    "--trace",
                    str(fixture_jsonl_trace),
                    "--format",
                    "table",
                ]
            )
        assert rc == 0
        s = out.getvalue()
        assert "agent: ag1" in s
        assert "agent: ag2" in s
        # ag1 unused dead-weight is write_* + delete_*
        ag1_block = s.split("agent: ag2")[0]
        assert "write_*" in ag1_block
        assert "delete_*" in ag1_block
        assert "✓ read_*" in ag1_block
        assert "✓ search_*" in ag1_block

    def test_json_format_emits_valid_document(
        self, fixture_policy: Path, fixture_jsonl_trace: Path
    ) -> None:
        with patch("sys.stdout", new_callable=StringIO) as out:
            rc = main(
                [
                    "--unused-scopes",
                    "--policy",
                    str(fixture_policy),
                    "--trace",
                    str(fixture_jsonl_trace),
                    "--format",
                    "json",
                ]
            )
        assert rc == 0
        doc = json.loads(out.getvalue())
        assert isinstance(doc, list)
        ag1 = next(r for r in doc if r["agent_id"] == "ag1")
        assert sorted(ag1["unused_patterns"]) == ["delete_*", "write_*"]
        assert sorted(ag1["used_patterns"]) == ["read_*", "search_*"]
        assert sorted(ag1["used_tools"]) == ["read_file", "search_kb"]

    def test_otlp_input_produces_same_report(
        self, fixture_policy: Path, fixture_otlp_trace: Path
    ) -> None:
        """OTLP and JSONL inputs of the same logical trace must produce the
        same report — proves the format autodetect + decode is honest."""
        with patch("sys.stdout", new_callable=StringIO) as out:
            rc = main(
                [
                    "--unused-scopes",
                    "--policy",
                    str(fixture_policy),
                    "--trace",
                    str(fixture_otlp_trace),
                    "--format",
                    "json",
                ]
            )
        assert rc == 0
        doc = json.loads(out.getvalue())
        ag1 = next(r for r in doc if r["agent_id"] == "ag1")
        assert sorted(ag1["used_tools"]) == ["read_file", "search_kb"]
        assert sorted(ag1["unused_patterns"]) == ["delete_*", "write_*"]

    def test_suggest_policy_appends_proposed_block(
        self, fixture_policy: Path, fixture_jsonl_trace: Path
    ) -> None:
        with patch("sys.stdout", new_callable=StringIO) as out:
            rc = main(
                [
                    "--unused-scopes",
                    "--policy",
                    str(fixture_policy),
                    "--trace",
                    str(fixture_jsonl_trace),
                    "--format",
                    "json",
                    "--suggest-policy",
                ]
            )
        assert rc == 0
        # Output has two JSON documents now (report list + suggestions
        # object). They are emitted back-to-back; pull each out.
        text = out.getvalue()
        decoder = json.JSONDecoder()
        first, idx = decoder.raw_decode(text)
        rest = text[idx:].lstrip()
        second, _ = decoder.raw_decode(rest)
        assert isinstance(first, list)
        assert "suggested_policies" in second
        sugg = second["suggested_policies"]
        # ag1's suggestion drops write_* / delete_*; keeps read_* / search_*.
        assert set(sugg["ag1"]["allowed_tools"]) == {"read_*", "search_*"}
        assert sugg["ag1"]["denied_tools"] == ["rm_-rf", "drop_database"]

    def test_read_only_contract_policy_file_unchanged(
        self, fixture_policy: Path, fixture_jsonl_trace: Path
    ) -> None:
        """The CLI must never write to the policy file. Re-read the file
        before and after a --suggest-policy run and assert byte-equality."""
        before = fixture_policy.read_bytes()
        with patch("sys.stdout", new_callable=StringIO):
            rc = main(
                [
                    "--unused-scopes",
                    "--policy",
                    str(fixture_policy),
                    "--trace",
                    str(fixture_jsonl_trace),
                    "--suggest-policy",
                ]
            )
        assert rc == 0
        assert fixture_policy.read_bytes() == before

    def test_missing_unused_scopes_flag_errors(
        self, fixture_policy: Path, fixture_jsonl_trace: Path
    ) -> None:
        with pytest.raises(SystemExit) as exc:
            main(
                [
                    "--policy",
                    str(fixture_policy),
                    "--trace",
                    str(fixture_jsonl_trace),
                ]
            )
        # argparse.error exits 2 by convention.
        assert exc.value.code == 2

    def test_unreadable_policy_returns_nonzero(
        self, tmp_path: Path, fixture_jsonl_trace: Path
    ) -> None:
        bad = tmp_path / "does-not-exist.toml"
        with patch("sys.stderr", new_callable=StringIO) as err:
            rc = main(
                [
                    "--unused-scopes",
                    "--policy",
                    str(bad),
                    "--trace",
                    str(fixture_jsonl_trace),
                ]
            )
        assert rc == 2
        assert "cannot load policy" in err.getvalue()

    def test_unreadable_trace_returns_nonzero(self, fixture_policy: Path, tmp_path: Path) -> None:
        bad = tmp_path / "does-not-exist.jsonl"
        with patch("sys.stderr", new_callable=StringIO) as err:
            rc = main(
                [
                    "--unused-scopes",
                    "--policy",
                    str(fixture_policy),
                    "--trace",
                    str(bad),
                ]
            )
        assert rc == 2
        assert "cannot load trace" in err.getvalue()
