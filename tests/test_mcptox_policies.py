"""Tests for ``benchmarks.mcptox.policies``: the G0 / G / LP tiers derived from clean data.

Servers and labels are synthetic; the shipped label table is checked for shape only.
"""

from __future__ import annotations

import re

import pytest
from benchmarks.mcptox import policies
from benchmarks.mcptox.clean import CleanServer, ParamSpec, ToolSpec
from benchmarks.mcptox.lp_labels import (
    FS,
    LABELS,
    NONE,
    SCOPES,
    URL_ALLOWLIST,
    URL_OPEN_WEB,
    ToolLabel,
)
from benchmarks.mcptox.policies import Tier, derive


def _tool(name: str, *params: str) -> ToolSpec:
    return ToolSpec(name=name, params=tuple(ParamSpec(p, p, True) for p in params))


def _server(*queries: str, key: str = "synthetic") -> CleanServer:
    return CleanServer(
        index=0,
        key=key,
        name=key,
        category_id=0,
        server_url="https://example.invalid/repo",
        tools=(
            _tool("read_file", "path"),
            _tool("browse", "url"),
            _tool("transcript", "videoUrl"),
            _tool("post", "text"),
        ),
        listed_tool_names=("read_file", "browse"),
        clean_queries=tuple(queries),
    )


_LABELS = {
    "synthetic": {
        "read_file": ToolLabel((FS,), ("args:path",)),
        "browse": ToolLabel((URL_OPEN_WEB,), ("args:url",)),
        "transcript": ToolLabel(
            (URL_ALLOWLIST,), ("args:videoUrl",), extra_hosts=("Video.Example",)
        ),
        "post": ToolLabel((NONE,), ("args:text",)),
    }
}


@pytest.fixture
def labels(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(policies, "LABELS", _LABELS)


class TestTiers:
    def test_g0_has_no_allowlist(self) -> None:
        tier = derive(_server(), Tier.G0)
        assert tier.allowed_tools is None
        assert tier.scopes == {}

    def test_g_allowlist_is_the_prompt_blocks(self) -> None:
        tier = derive(_server(), "G")
        # The prompt's blocks, not the shorter tool_names list.
        assert tier.allowed_tools == ("read_file", "browse", "transcript", "post")

    def test_lp_without_clean_queries_falls_back_to_g(self) -> None:
        tier = derive(_server(), Tier.LP)
        assert tier.effective is Tier.G
        assert tier.scopes == {}
        assert any("falls back to G" in n for n in tier.notes)

    def test_glob_metacharacter_in_a_tool_name_refused(self) -> None:
        server = _server()
        bad = CleanServer(**{**server.__dict__, "tools": (*server.tools, _tool("read_*"))})
        with pytest.raises(ValueError, match="glob"):
            derive(bad, Tier.G)

    def test_lp_requires_labels_for_every_tool(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(policies, "LABELS", {})
        with pytest.raises(KeyError):
            derive(_server("Read '/srv/a/b.txt'"), Tier.LP)
        partial = {"synthetic": dict(list(_LABELS["synthetic"].items())[:2])}
        monkeypatch.setattr(policies, "LABELS", partial)
        with pytest.raises(ValueError, match="missing"):
            derive(_server("Read '/srv/a/b.txt'"), Tier.LP)

    def test_derive_is_deterministic(self, labels: None) -> None:
        server = _server("Read '/srv/app/data/report.txt'", "Open https://video.example/v")
        assert derive(server, Tier.LP) == derive(server, Tier.LP)


class TestLeastPrivilege:
    def test_scopes_follow_labels(self, labels: None) -> None:
        tier = derive(
            _server("Read '/srv/app/data/report.txt'.", "Watch https://www.video.example/w?v=1."),
            Tier.LP,
        )
        assert tier.effective is Tier.LP
        assert set(tier.scopes) == {"read_file", "browse", "transcript"}
        fs = tier.scopes["read_file"].fs
        assert fs is not None and fs.roots == ("/srv/app/data",)
        browse = tier.scopes["browse"].endpoint
        assert browse is not None and browse.kind == "open_web" and browse.ssrf_precheck
        allow = tier.scopes["transcript"].endpoint
        assert allow is not None and allow.kind == "allowlist"
        assert allow.hosts == ("video.example", "www.video.example")
        assert not allow.ssrf_precheck

    def test_fs_without_a_root_falls_back(self, labels: None) -> None:
        tier = derive(_server("Read the report in my documents"), Tier.LP)
        assert "read_file" not in tier.scopes
        assert any("read_file: fs label, no clean-query root" in n for n in tier.notes)

    def test_allowlist_without_a_host_falls_back(self, monkeypatch: pytest.MonkeyPatch) -> None:
        no_extras = {
            "synthetic": {
                **_LABELS["synthetic"],
                "transcript": ToolLabel((URL_ALLOWLIST,), ("args:videoUrl",)),
            }
        }
        monkeypatch.setattr(policies, "LABELS", no_extras)
        tier = derive(_server("nothing with a link"), Tier.LP)
        assert "transcript" not in tier.scopes
        assert any("transcript: allowlist label, no host" in n for n in tier.notes)

    def test_slash_is_never_granted(self, labels: None) -> None:
        tier = derive(_server("List everything under '/'", "Read '/srv/a/b.txt'"), Tier.LP)
        assert "read_file" not in tier.scopes
        assert any("would grant '/'" in n for n in tier.notes)

    def test_notes_cite_queries_by_index_not_text(self, labels: None) -> None:
        tier = derive(_server("Load '/srv/app/.env.local' please"), Tier.LP)
        joined = " ".join(tier.notes)
        assert "clean_querys[0]" in joined
        assert ".env.local" not in joined
        fs = tier.scopes["read_file"].fs
        assert fs is not None
        assert ".env*" not in fs.deny_patterns  # it matches a clean-query path
        assert "*.pem" in fs.deny_patterns
        assert not set(policies.SYSTEM_DIR_GLOBS) & set(fs.deny_patterns)


class TestExtraction:
    def test_paths(self) -> None:
        found = policies.extract_paths(
            [
                "Read '/data/a/report.txt'.",
                "Run 'python /home/u/s.py' then check /var/log, and ~/charts/x.png!",
                "Fetch https://example.invalid/x/y and docs/readme.md",
            ]
        )
        assert [(e.path, e.query_index) for e in found] == [
            ("/data/a/report.txt", 0),
            ("/home/u/s.py", 1),
            ("/var/log", 1),
            ("~/charts/x.png", 1),
        ]

    @pytest.mark.parametrize(
        ("path", "root"),
        [
            ("/data/project/documents/report.txt", "/data/project/documents"),
            ("/tmp/hello.txt", "/tmp"),
            ("/report.txt", "/report.txt"),
            ("/var/www/html", "/var/www/html"),
            ("/boot/vmlinuz", "/boot/vmlinuz"),
            ("~/charts/visitors.png", "~/charts"),
            ("~/x.png", "~/x.png"),
        ],
    )
    def test_root_rules(self, path: str, root: str) -> None:
        assert policies.root_for(path) == root

    def test_nested_roots_collapse(self) -> None:
        roots = policies.derive_fs_roots(["'/srv/app/a.txt' and '/srv/app/sub/b.txt'"])
        assert roots.roots == ("/srv/app",)

    def test_hosts(self) -> None:
        hosts = policies.derive_hosts(
            [
                "Open 'https://WWW.Example.invalid ' now",
                "From https://api.example.invalid/v1?q=1, get it.",
                "No link here",
            ]
        )
        assert hosts == ("api.example.invalid", "www.example.invalid")


_EVIDENCE = re.compile(
    r"^(clean_querys\[\d+\]|description|repository|args(:[A-Za-z_$][\w$.\-]*)?)$"
)


class TestShippedLabelTable:
    def test_shape(self) -> None:
        assert len(LABELS) == 35
        for server, labels in LABELS.items():
            assert labels, server
            for tool, label in labels.items():
                assert label.scopes and set(label.scopes) <= SCOPES, (server, tool)
                assert NONE not in label.scopes or label.scopes == (NONE,), (server, tool)
                assert label.evidence, (server, tool)
                assert all(_EVIDENCE.match(e) for e in label.evidence), (server, tool)
                if label.extra_hosts:
                    assert URL_ALLOWLIST in label.scopes, (server, tool)
