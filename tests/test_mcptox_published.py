"""Checks against the real MCPTox data, which is never committed.

Every test here skips unless the verified ``response_all.json`` is in the bench cache
(``python -m benchmarks.mcptox clean-view --fetch`` puts it there; ``$AIRLOCK_BENCH_DATA``
moves the cache), so CI, which has no copy, skips the module. With the data present they
pin the facts the published text states, check that the blind labels quote no MCPTox
text, and, when ``replay_summary.json`` exists and was produced on this kind of host,
recompute it end to end (about half a minute).
"""

from __future__ import annotations

import json
import platform
from collections import Counter
from functools import lru_cache
from typing import Any

import pytest
from benchmarks.mcptox import data as data_mod
from benchmarks.mcptox.clean import clean_servers
from benchmarks.mcptox.parse import STATUSES, parse_response
from benchmarks.mcptox.policies import Tier, derive
from benchmarks.mcptox.replay import (
    LP_LABELS_PATH,
    REPLAY_SUMMARY_PATH,
    iter_responses,
    parse_poisoned_tool,
    replay,
    scratch_cwd,
)

pytestmark = pytest.mark.skipif(
    not data_mod.cache_path().is_file(),
    reason="MCPTox data not cached (python -m benchmarks.mcptox clean-view --fetch)",
)


@lru_cache(maxsize=1)
def _doc() -> dict[str, Any]:
    path = data_mod.resolve_data_path(None)  # verifies the sha256
    return data_mod.load(path)


class TestCleanSide:
    def test_totals(self) -> None:
        servers = clean_servers(_doc())
        tools = [t for s in servers for t in s.tools]
        assert len(servers) == 45
        assert len(tools) == 362
        assert sum(len(s.listed_tool_names) for s in servers) == 353
        assert sum(len(t.params) for t in tools) == 1037
        assert sum(p.required for t in tools for p in t.params) == 474
        assert sum("-" in t.name for t in tools) == 73
        assert sum(s.has_clean_queries for s in servers) == 35
        renamed = {(p.name, p.py_name) for t in tools for p in t.params if p.name != p.py_name}
        assert renamed == {("from", "from_")}

    def test_lp_labels_cover_every_server_with_clean_queries(self) -> None:
        servers = clean_servers(_doc())
        lp = [derive(s, Tier.LP) for s in servers]
        assert sum(p.effective is Tier.LP for p in lp) == 35
        assert sum(1 for p in lp for s in p.scopes.values() if s.fs) == 22
        endpoints = Counter(
            s.endpoint.kind for p in lp for s in p.scopes.values() if s.endpoint is not None
        )
        assert endpoints == {"open_web": 22, "allowlist": 2}

    def test_labels_quote_no_mcptox_text(self) -> None:
        source = LP_LABELS_PATH.read_text(encoding="utf-8")
        for server in clean_servers(_doc()):
            for query in server.clean_queries:
                if len(query) >= 16:
                    assert query not in source, server.key
            for tool in server.tools:
                head = tool.description[:40]
                if len(head) >= 24:
                    assert head not in source, (server.key, tool.name)


class TestAttackSide:
    def test_cases(self) -> None:
        cases = list(data_mod.iter_cases(_doc()))
        assert len(cases) == 1348
        assert len({c.key for c in cases}) == 1348
        assert Counter(c.paradigm for c in cases) == {
            "Template-1": 211,
            "Template-2": 519,
            "Template-3": 618,
        }
        assert Counter(c.wrong_data for c in cases) == {0: 1312, 2: 36}
        risks = Counter(c.risk for c in cases)
        assert len(risks) == 11 and risks["Other"] == 4

    def test_every_poisoned_tool_parses(self) -> None:
        cases = list(data_mod.iter_cases(_doc()))
        specs = [parse_poisoned_tool(c.poisoned_tool) for c in cases]
        assert all(s is not None for s in specs)
        assert Counter(len(s.params) for s in specs if s) == {0: 1298, 1: 47, 2: 3}

    def test_every_response_is_accounted(self) -> None:
        sources: Counter[str] = Counter()
        statuses: Counter[str] = Counter()
        for case in data_mod.iter_cases(_doc()):
            for source, _model, text, _label in iter_responses(case):
                sources[source] += 1
                statuses[parse_response(text).status] += 1
        assert sources["online"] == 20220
        assert sum(sources.values()) == sum(statuses.values())
        assert set(statuses) <= set(STATUSES)

    def test_label_asr_anchor_and_claude_split(self) -> None:
        labels: Counter[tuple[str, str]] = Counter()
        for case in data_mod.iter_cases(_doc()):
            for source, model, _text, label in iter_responses(case):
                if source == "online":
                    labels[(model, label)] += 1
        o1 = {lab: n for (m, lab), n in labels.items() if m == "o1-mini"}
        assert o1["Success"] == 574
        assert sum(n for lab, n in o1.items() if lab != "None") == 788
        claude = Counter(m for (m, _), n in labels.items() for _ in range(n) if "claude" in m)
        assert claude == {"claude-3-7-sonnet": 1052, "claude-3-7-sonnet-20250219-thinking": 296}


@pytest.mark.skipif(not REPLAY_SUMMARY_PATH.is_file(), reason="no replay_summary.json yet")
def test_replay_summary_recomputes() -> None:
    from benchmarks.mcptox.metrics import summarize

    published = json.loads(REPLAY_SUMMARY_PATH.read_text(encoding="utf-8"))
    host = published["provenance"]["host"]["system"]
    if host != platform.system():
        pytest.skip(f"replay_summary.json was produced on {host}; filesystem verdicts differ")
    with scratch_cwd():
        run = replay(_doc())
    assert run.tilde_expanded == published["provenance"]["tilde_expanded"]
    fresh = summarize(run, bootstrap=published["provenance"]["bootstrap"]["iterations"])
    published.pop("provenance")
    assert json.loads(json.dumps(fresh, sort_keys=True)) == published
