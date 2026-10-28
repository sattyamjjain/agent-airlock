"""The startup-hook self-check (0.10.27): executable ``.pth`` lines and *customize modules.

``site`` runs a ``.pth`` line that starts with ``import`` and a space or a tab, and imports
``sitecustomize`` / ``usercustomize``, while the interpreter starts: before any code of the
program's own, and so before this library. ``runtime.startup_hooks.check_startup_hooks``
lists them; ``AirlockConfig(startup_hook_check=...)`` runs that walk once per process on
the first guarded call and, under ``deny``, refuses every guarded call while a hook is not
allowlisted. Nothing here can stop a hook that already ran.

Every hook in these tests lives in a temporary site directory and does nothing: the one
executable line imports a module name that exists nowhere, and the customize modules are
``pass``. ``site`` and ``sys.path`` are monkeypatched to that directory, so the walk never
reads the real interpreter's site-packages.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import site
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from agent_airlock import Airlock, AirlockConfig
from agent_airlock.runtime import StartupHookKind, check_startup_hooks
from agent_airlock.runtime import startup_hooks as hooks_module
from agent_airlock.runtime.startup_hooks import (
    StartupHookReport,
    normalize_allowlist,
    process_startup_hook_report,
)
from agent_airlock.self_heal import BlockReason
from agent_airlock.testing import reset_startup_hook_check

#: The one executable line used here. ``airlock_placeholder_noop`` is no module anywhere,
#: and no test runs ``site`` over these files, so the line is only ever read.
IMPORT_LINE = "import airlock_placeholder_noop\n"


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


class _Interpreter:
    """A temporary site directory standing in for the interpreter's own."""

    def __init__(self, root: Path) -> None:
        self.site = root / "site-packages"
        self.user = root / "user-site"
        self.extra = root / "on-sys-path"
        for directory in (self.site, self.user, self.extra):
            directory.mkdir()

    def write(self, name: str, content: str | bytes, *, where: Path | None = None) -> Path:
        path = (where or self.site) / name
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
        importlib.invalidate_caches()
        return path


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def interp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[_Interpreter]:
    fake = _Interpreter(tmp_path)
    monkeypatch.setattr(site, "getsitepackages", lambda: [str(fake.site)])
    monkeypatch.setattr(site, "getusersitepackages", lambda: str(fake.user))
    monkeypatch.setattr(sys, "path", [str(fake.site), str(fake.extra)])
    # The real interpreter's own customize modules, if it has them, are not this test's.
    monkeypatch.delitem(sys.modules, "sitecustomize", raising=False)
    monkeypatch.delitem(sys.modules, "usercustomize", raising=False)
    reset_startup_hook_check()
    yield fake
    reset_startup_hook_check()


@pytest.fixture
def events(monkeypatch: pytest.MonkeyPatch) -> _Events:
    recorder = _Events()
    monkeypatch.setattr(hooks_module, "logger", recorder)
    return recorder


def _guarded(config: AirlockConfig, ran: list[str]) -> Any:
    @Airlock(config=config)
    def read_secret() -> str:
        ran.append("ran")
        return "PLACEHOLDER"

    return read_secret


class TestPthFiles:
    def test_an_import_line_is_a_finding(self, interp: _Interpreter) -> None:
        pth = interp.write("x.pth", IMPORT_LINE)

        report = check_startup_hooks()

        [finding] = report.findings
        assert finding.path == str(pth)
        assert finding.kind is StartupHookKind.PTH
        assert finding.sha256 == _sha256(pth)
        assert finding.name == "x.pth"
        assert finding.to_dict() == {"path": str(pth), "kind": "pth", "sha256": _sha256(pth)}
        assert not report.clean

    def test_a_path_only_pth_is_not_a_finding(self, interp: _Interpreter) -> None:
        interp.write("paths.pth", "# a comment\nPLACEHOLDER-dir\n../PLACEHOLDER\n\n")

        report = check_startup_hooks()

        assert report.findings == ()
        assert report.clean

    def test_a_tab_after_import_is_executable_too(self, interp: _Interpreter) -> None:
        interp.write("tab.pth", "import\tairlock_placeholder_noop\n")

        assert [f.name for f in check_startup_hooks().findings] == ["tab.pth"]

    @pytest.mark.parametrize(
        "line",
        [
            " import airlock_placeholder_noop",  # site reads a leading space as a path
            "#import airlock_placeholder_noop",  # a comment
            "importairlock_placeholder_noop",  # no separator: a path
            "import",  # nothing after it: a path
        ],
    )
    def test_a_line_site_would_not_exec_is_not_a_finding(
        self, interp: _Interpreter, line: str
    ) -> None:
        interp.write("not-exec.pth", line + "\n")

        assert check_startup_hooks().findings == ()

    def test_an_import_line_after_paths_is_found(self, interp: _Interpreter) -> None:
        interp.write("mixed.pth", "PLACEHOLDER-dir\n" + IMPORT_LINE)

        assert [f.name for f in check_startup_hooks().findings] == ["mixed.pth"]

    def test_a_byte_order_mark_does_not_hide_an_import_line(self, interp: _Interpreter) -> None:
        interp.write("bom.pth", b"\xef\xbb\xbf" + IMPORT_LINE.encode())

        assert [f.name for f in check_startup_hooks().findings] == ["bom.pth"]

    def test_content_that_is_not_utf8_is_still_read(self, interp: _Interpreter) -> None:
        interp.write("latin.pth", b"\xff\xfe-PLACEHOLDER\n" + IMPORT_LINE.encode())

        assert [f.name for f in check_startup_hooks().findings] == ["latin.pth"]

    def test_a_line_split_only_by_a_form_feed_is_found(self, interp: _Interpreter) -> None:
        # Universal newlines would read one path line; str.splitlines reads two. The wider
        # split is the one a finding cannot be hidden from.
        interp.write("ff.pth", "PLACEHOLDER-dir\x0c" + IMPORT_LINE)

        assert [f.name for f in check_startup_hooks().findings] == ["ff.pth"]

    def test_a_pth_on_sys_path_outside_site_packages_is_found(self, interp: _Interpreter) -> None:
        interp.write("elsewhere.pth", IMPORT_LINE, where=interp.extra)

        assert [f.path for f in check_startup_hooks().findings] == [
            str(interp.extra / "elsewhere.pth")
        ]

    def test_a_pth_in_the_user_site_is_found(self, interp: _Interpreter) -> None:
        interp.write("user.pth", IMPORT_LINE, where=interp.user)

        assert [f.name for f in check_startup_hooks().findings] == ["user.pth"]

    def test_a_directory_listed_twice_is_walked_once(
        self, interp: _Interpreter, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(sys, "path", [str(interp.site), str(interp.site) + "/."])
        interp.write("x.pth", IMPORT_LINE)

        report = check_startup_hooks()

        assert len(report.findings) == 1
        assert report.scanned_dirs.count(str(interp.site)) == 1

    def test_files_that_are_not_pth_are_ignored(self, interp: _Interpreter) -> None:
        interp.write("x.pth.bak", IMPORT_LINE)
        interp.write("x.txt", IMPORT_LINE)
        (interp.site / "dir.pth").mkdir()

        assert check_startup_hooks().findings == ()


class TestCustomizeModules:
    def test_a_sitecustomize_is_a_finding(self, interp: _Interpreter) -> None:
        module = interp.write("sitecustomize.py", "pass\n")

        [finding] = check_startup_hooks().findings

        assert finding.kind is StartupHookKind.SITECUSTOMIZE
        assert finding.path == str(module)
        assert finding.sha256 == _sha256(module)
        assert "sitecustomize" not in sys.modules, "finding it must not import it"

    def test_a_usercustomize_is_a_finding(self, interp: _Interpreter) -> None:
        module = interp.write("usercustomize.py", "pass\n", where=interp.extra)

        [finding] = check_startup_hooks().findings

        assert finding.kind is StartupHookKind.USERCUSTOMIZE
        assert finding.path == str(module)

    def test_an_interpreter_with_neither_has_no_finding(self, interp: _Interpreter) -> None:
        assert check_startup_hooks().findings == ()

    def test_a_namespace_package_runs_nothing(self, interp: _Interpreter) -> None:
        (interp.site / "sitecustomize").mkdir()
        importlib.invalidate_caches()

        assert check_startup_hooks().findings == ()

    def test_a_finder_that_raises_is_reported_not_skipped(
        self, interp: _Interpreter, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def broken(name: str) -> None:
            raise ImportError("PLACEHOLDER finder failure")

        monkeypatch.setattr(hooks_module.importlib.util, "find_spec", broken)

        kinds = {f.kind for f in check_startup_hooks().findings}

        assert kinds == {StartupHookKind.SITECUSTOMIZE, StartupHookKind.USERCUSTOMIZE}


class TestAllowlist:
    def test_a_matching_name_and_digest_is_allowlisted(self, interp: _Interpreter) -> None:
        pth = interp.write("x.pth", IMPORT_LINE)

        report = check_startup_hooks({"x.pth": _sha256(pth)})

        assert report.findings == ()
        assert [f.name for f in report.allowlisted] == ["x.pth"]
        assert report.clean

    def test_a_known_name_with_other_content_is_a_finding(self, interp: _Interpreter) -> None:
        interp.write("x.pth", IMPORT_LINE)
        other = hashlib.sha256(b"import airlock_placeholder_other\n").hexdigest()

        report = check_startup_hooks({"x.pth": other})

        assert [f.name for f in report.findings] == ["x.pth"]
        assert report.allowlisted == ()

    def test_the_digest_is_matched_in_either_case(self, interp: _Interpreter) -> None:
        pth = interp.write("x.pth", IMPORT_LINE)

        assert check_startup_hooks({"x.pth": _sha256(pth).upper()}).clean

    def test_a_sitecustomize_is_allowlisted_by_its_file_name(self, interp: _Interpreter) -> None:
        module = interp.write("sitecustomize.py", "pass\n")

        assert check_startup_hooks({"sitecustomize.py": _sha256(module)}).clean

    def test_a_hook_whose_content_is_unknown_matches_no_entry(
        self, interp: _Interpreter, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def broken(name: str) -> None:
            raise ImportError("PLACEHOLDER finder failure")

        monkeypatch.setattr(hooks_module.importlib.util, "find_spec", broken)

        report = check_startup_hooks({"sitecustomize": "0" * 64, "usercustomize": "0" * 64})

        assert len(report.findings) == 2
        assert {f.sha256 for f in report.findings} == {""}
        assert report.allowlisted == ()

    @pytest.mark.parametrize(
        ("allowlist", "message"),
        [
            ({"x.pth": "not-a-digest"}, "SHA-256"),
            ({"x.pth": "0" * 63}, "SHA-256"),
            ({"x.pth": 7}, "SHA-256"),
            ({"site-packages/x.pth": "0" * 64}, "not a file name"),
            ({"": "0" * 64}, "not a file name"),
            (["x.pth"], "maps file names"),
        ],
    )
    def test_an_entry_that_could_never_match_raises(self, allowlist: Any, message: str) -> None:
        with pytest.raises(ValueError, match=message):
            normalize_allowlist(allowlist)

    def test_the_config_validates_and_normalises_its_allowlist(self) -> None:
        config = AirlockConfig(startup_hook_allowlist={"x.pth": "AB" * 32})

        assert config.startup_hook_allowlist == {"x.pth": "ab" * 32}
        with pytest.raises(ValueError, match="SHA-256"):
            AirlockConfig(startup_hook_allowlist={"x.pth": "PLACEHOLDER"})


class TestOnTheCallPath:
    def test_deny_refuses_a_guarded_call_and_names_the_files(
        self, interp: _Interpreter, tmp_path: Path
    ) -> None:
        pth = interp.write("x.pth", IMPORT_LINE)
        module = interp.write("sitecustomize.py", "pass\n")
        blocked: list[tuple[str, str, dict[str, Any]]] = []
        audit = tmp_path / "audit.jsonl"
        config = AirlockConfig(
            startup_hook_check="deny",
            audit_log_path=audit,
            on_blocked=lambda name, reason, ctx: blocked.append((name, reason, ctx)),
        )
        ran: list[str] = []

        result = _guarded(config, ran)()

        assert ran == []
        assert result["status"] == "blocked"
        assert result["block_reason"] == BlockReason.STARTUP_HOOK.value
        assert result["error"] == (
            "AIRLOCK_BLOCK: 'read_secret' refused: this interpreter runs startup hooks no "
            "allowlist covers (x.pth, sitecustomize.py)"
        )
        assert result["fix_hints"]
        # Paths and digests go to the operator, not into the text a model reads.
        assert str(interp.site) not in result["error"]
        assert result["metadata"]["startup_hooks"] == [
            {"path": str(pth), "kind": "pth", "sha256": _sha256(pth)},
            {"path": str(module), "kind": "sitecustomize", "sha256": _sha256(module)},
        ]
        [(name, reason, ctx)] = blocked
        assert name == "read_secret"
        assert str(pth) in reason and str(module) in reason
        assert ctx["violation_type"] == "startup_hook"
        records = [
            json.loads(line)
            for line in audit.read_text().splitlines()
            if line and not line.startswith("#")
        ]
        assert records[-1]["block_reason"] == "startup_hook"

    def test_deny_refuses_every_guarded_call_in_the_process(self, interp: _Interpreter) -> None:
        interp.write("x.pth", IMPORT_LINE)
        config = AirlockConfig(startup_hook_check="deny")
        ran: list[str] = []
        first, second = _guarded(config, ran), _guarded(config, ran)

        results = [first(), second(), first()]

        assert ran == []
        assert {r["block_reason"] for r in results} == {"startup_hook"}

    def test_an_async_tool_is_refused_too(self, interp: _Interpreter) -> None:
        import asyncio

        interp.write("x.pth", IMPORT_LINE)
        ran: list[str] = []

        @Airlock(config=AirlockConfig(startup_hook_check="deny"))
        async def read_secret() -> str:
            ran.append("ran")
            return "PLACEHOLDER"

        result = asyncio.run(read_secret())

        assert ran == []
        assert result["block_reason"] == "startup_hook"

    def test_deny_runs_the_call_when_every_hook_is_allowlisted(self, interp: _Interpreter) -> None:
        pth = interp.write("x.pth", IMPORT_LINE)
        config = AirlockConfig(
            startup_hook_check="deny", startup_hook_allowlist={"x.pth": _sha256(pth)}
        )
        ran: list[str] = []

        assert _guarded(config, ran)() == "PLACEHOLDER"
        assert ran == ["ran"]

    def test_deny_runs_the_call_in_a_clean_interpreter(self, interp: _Interpreter) -> None:
        interp.write("paths.pth", "PLACEHOLDER-dir\n")
        ran: list[str] = []

        assert _guarded(AirlockConfig(startup_hook_check="deny"), ran)() == "PLACEHOLDER"

    def test_warn_logs_each_finding_once_and_runs_every_call(
        self, interp: _Interpreter, events: _Events
    ) -> None:
        interp.write("x.pth", IMPORT_LINE)
        interp.write("sitecustomize.py", "pass\n")
        tool = _guarded(AirlockConfig(startup_hook_check="warn"), ran := [])

        assert [tool(), tool(), tool()] == ["PLACEHOLDER"] * 3

        assert ran == ["ran"] * 3
        found = events.named("airlock_startup_hook_found")
        assert [(f["kind"], f["mode"]) for f in found] == [
            ("pth", "warn"),
            ("sitecustomize", "warn"),
        ]

    def test_the_walk_runs_once_per_process(
        self, interp: _Interpreter, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        interp.write("x.pth", IMPORT_LINE)
        walks: list[int] = []
        real_walk = hooks_module._walk

        def counting_walk() -> Any:
            walks.append(1)
            return real_walk()

        monkeypatch.setattr(hooks_module, "_walk", counting_walk)
        warn = _guarded(AirlockConfig(startup_hook_check="warn"), [])
        deny = _guarded(AirlockConfig(startup_hook_check="deny"), [])

        warn()
        warn()
        assert deny()["block_reason"] == "startup_hook"

        assert walks == [1]

    def test_a_hook_added_after_the_walk_is_not_seen_until_a_new_process(
        self, interp: _Interpreter
    ) -> None:
        # Once per process means once: this pins it, so a change to that is deliberate.
        tool = _guarded(AirlockConfig(startup_hook_check="deny"), ran := [])
        assert tool() == "PLACEHOLDER"

        interp.write("late.pth", IMPORT_LINE)

        assert tool() == "PLACEHOLDER"
        assert ran == ["ran", "ran"]
        assert not check_startup_hooks().clean, "a direct check walks again and sees it"

    def test_off_never_walks(self, interp: _Interpreter, monkeypatch: pytest.MonkeyPatch) -> None:
        interp.write("x.pth", IMPORT_LINE)

        def no_walk() -> Any:
            raise AssertionError("startup_hook_check='off' must not walk")

        monkeypatch.setattr(hooks_module, "_walk", no_walk)
        ran: list[str] = []

        assert _guarded(AirlockConfig(), ran)() == "PLACEHOLDER"
        assert _guarded(AirlockConfig(startup_hook_check="off"), ran)() == "PLACEHOLDER"
        assert ran == ["ran", "ran"]

    def test_off_is_the_default(self) -> None:
        assert AirlockConfig().startup_hook_check == "off"

    def test_nothing_walks_before_a_guarded_call_is_admitted(
        self, interp: _Interpreter, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def no_walk() -> Any:
            raise AssertionError("walked before any call was admitted")

        monkeypatch.setattr(hooks_module, "_walk", no_walk)

        config = AirlockConfig(startup_hook_check="deny")
        _guarded(config, [])  # decorating is not admitting

        assert hooks_module._process_walk is None

    def test_the_kill_switch_still_comes_first(
        self, interp: _Interpreter, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from agent_airlock import core as core_module

        interp.write("x.pth", IMPORT_LINE)
        monkeypatch.setattr(core_module, "_kill_switch_frozen", lambda: True)
        monkeypatch.setattr(core_module, "_kill_switch_get", lambda: None)

        result = _guarded(AirlockConfig(startup_hook_check="deny"), [])()

        assert result["block_reason"] == "kill_switch"

    def test_reset_all_forgets_the_walk(self, interp: _Interpreter) -> None:
        from agent_airlock.testing import reset_all

        process_startup_hook_report()
        assert hooks_module._process_walk is not None

        reset_all()

        assert hooks_module._process_walk is None


class TestReport:
    def test_an_empty_report_is_clean(self) -> None:
        assert StartupHookReport().clean

    def test_the_report_lists_the_directories_it_walked(self, interp: _Interpreter) -> None:
        scanned = check_startup_hooks().scanned_dirs

        assert scanned == (str(interp.site), str(interp.user), str(interp.extra))
