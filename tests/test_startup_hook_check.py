"""The startup-hook self-check (0.10.27): executable ``.pth`` lines and *customize modules.

``site`` runs a ``.pth`` line that starts with ``import`` and a space or a tab, and imports
``sitecustomize`` / ``usercustomize``, while the interpreter starts: before any code of the
program's own, and so before this library. ``runtime.startup_hooks.check_startup_hooks``
lists them; ``AirlockConfig(startup_hook_check=...)`` runs that walk once per process on
the first guarded call and, under ``deny``, refuses every call that config guards while a
hook is not allowlisted. Nothing here can stop a hook that already ran.

Every hook in these tests lives in a temporary site directory or under
``tests/fixtures/startup_hooks/`` and does nothing: the one executable line imports a module
name that exists nowhere, and the customize modules are ``pass``. ``site`` and ``sys.path``
are monkeypatched to those directories, so the walk never reads the real interpreter's
site-packages (``tests/conftest.py`` also keeps the host's own directories out of it).

Since 0.10.36 the check is on by default as ``warn``, and hooks every install has
(setuptools, virtualenv, a setuptools editable install, the interpreter's own customize
module) are recognised as benign by their content, their place and who installed them.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import site
import sys
import warnings
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from agent_airlock import Airlock, AirlockConfig
from agent_airlock.runtime import StartupHookKind, check_startup_hooks
from agent_airlock.runtime import startup_hooks as hooks_module
from agent_airlock.runtime.startup_hooks import (
    KNOWN_INCIDENT_HOOKS,
    SETUPTOOLS_DISTUTILS_PRECEDENCE_LINES,
    StartupHookReport,
    normalize_allowlist,
    process_startup_hook_report,
)
from agent_airlock.self_heal import BlockReason
from agent_airlock.testing import reset_startup_hook_check

# Every test that plants a hook and guards a call gets the one RuntimeWarning per process;
# the tests that assert on it record it themselves.
pytestmark = pytest.mark.filterwarnings(
    "ignore:agent-airlock. this Python interpreter ran startup hooks:RuntimeWarning"
)

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

        assert _guarded(AirlockConfig(startup_hook_check="off"), ran)() == "PLACEHOLDER"
        assert ran == ["ran"]

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


# ---------------------------------------------------------------------------------------
# 0.10.36: benign hooks, known incidents, warn by default
# ---------------------------------------------------------------------------------------

FIXTURES = Path(__file__).parent / "fixtures" / "startup_hooks"
AGENT_FRAMEWORK_ADVISORY = "GHSA-764m-3ppc-5m73"


def _record(directory: Path, distribution: str, *listed: str, editable: bool = False) -> None:
    """Install ``distribution`` in ``directory`` as far as a RECORD says: it owns ``listed``."""
    meta = directory / f"{distribution}.dist-info"
    meta.mkdir()
    (meta / "RECORD").write_text(
        "".join(f"{path},sha256=PLACEHOLDER,1\n" for path in listed), encoding="utf-8"
    )
    if editable:
        (meta / "direct_url.json").write_text(
            json.dumps({"url": "file:///PLACEHOLDER", "dir_info": {"editable": True}}),
            encoding="utf-8",
        )


def _copy(name: str, tmp_path: Path) -> Path:
    return Path(shutil.copytree(FIXTURES / name, tmp_path / name))


@pytest.fixture
def walk(monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[..., None]]:
    """Point the walk at fixture or temporary directories, as ``interp`` points it at one.

    ``walk(*dirs, stdlib=dir)`` makes ``dirs`` the site directories and ``sys.path``, and
    ``stdlib`` the interpreter's standard-library directory.
    """

    def point(*directories: str | Path, stdlib: str | Path | None = None) -> None:
        paths = [str(FIXTURES / d) if isinstance(d, str) else str(d) for d in directories]
        monkeypatch.setattr(site, "getsitepackages", lambda: list(paths))
        monkeypatch.setattr(site, "getusersitepackages", lambda: str(FIXTURES / "no-user-site"))
        monkeypatch.setattr(sys, "path", list(paths))
        resolved = (
            frozenset(
                {hooks_module._key(str(FIXTURES / stdlib if isinstance(stdlib, str) else stdlib))}
            )
            if stdlib is not None
            else frozenset()
        )
        monkeypatch.setattr(hooks_module, "_stdlib_dirs", lambda: resolved)
        monkeypatch.delitem(sys.modules, "sitecustomize", raising=False)
        monkeypatch.delitem(sys.modules, "usercustomize", raising=False)
        importlib.invalidate_caches()
        reset_startup_hook_check()

    yield point
    reset_startup_hook_check()


def _runtime_warnings(caught: list[warnings.WarningMessage]) -> list[str]:
    return [str(w.message) for w in caught if issubclass(w.category, RuntimeWarning)]


class TestBenignHooks:
    def test_the_setuptools_line_is_benign(self, walk: Callable[..., None]) -> None:
        walk("setuptools")

        report = check_startup_hooks()

        assert report.clean
        [hook] = report.benign
        assert (hook.name, hook.recognized) == ("distutils-precedence.pth", "setuptools")
        assert hook.to_dict()["recognized"] == "setuptools"

    @pytest.mark.parametrize(
        "line",
        [line for _, line in SETUPTOOLS_DISTUTILS_PRECEDENCE_LINES],
        ids=[versions for versions, _ in SETUPTOOLS_DISTUTILS_PRECEDENCE_LINES],
    )
    def test_every_line_setuptools_has_shipped_is_benign(
        self, walk: Callable[..., None], tmp_path: Path, line: str
    ) -> None:
        home = _copy("setuptools", tmp_path)
        (home / "distutils-precedence.pth").write_text(line + " \n", encoding="utf-8")
        walk(home)

        assert [h.recognized for h in check_startup_hooks().benign] == ["setuptools"]

    def test_the_table_holds_the_line_setuptools_ships_today(self) -> None:
        shipped = (FIXTURES / "setuptools" / "distutils-precedence.pth").read_text("utf-8")
        latest = dict(SETUPTOOLS_DISTUTILS_PRECEDENCE_LINES)[
            "50.0.0-50.0.3, 60.0.0-60.0.5, 60.2.0-84.2.1"
        ]
        assert shipped.strip() == latest

    def test_another_line_under_the_setuptools_name_is_a_finding(
        self, walk: Callable[..., None]
    ) -> None:
        walk("setuptools_line_replaced")

        report = check_startup_hooks()

        assert [f.name for f in report.findings] == ["distutils-precedence.pth"]
        assert report.benign == ()

    def test_a_line_added_after_the_setuptools_line_is_a_finding(
        self, walk: Callable[..., None], tmp_path: Path
    ) -> None:
        home = _copy("setuptools", tmp_path)
        pth = home / "distutils-precedence.pth"
        pth.write_text(pth.read_text("utf-8") + "import airlock_placeholder_noop\n", "utf-8")
        walk(home)

        assert [f.name for f in check_startup_hooks().findings] == ["distutils-precedence.pth"]

    def test_the_setuptools_line_without_its_module_beside_it_is_a_finding(
        self, walk: Callable[..., None], tmp_path: Path
    ) -> None:
        home = _copy("setuptools", tmp_path)
        shutil.rmtree(home / "_distutils_hack")
        walk(home)

        assert [f.name for f in check_startup_hooks().findings] == ["distutils-precedence.pth"]

    def test_virtualenv_with_its_module_is_benign(self, walk: Callable[..., None]) -> None:
        walk("virtualenv")

        report = check_startup_hooks()

        assert report.clean
        assert [(h.name, h.recognized) for h in report.benign] == [
            ("_virtualenv.pth", "virtualenv")
        ]

    def test_virtualenv_without_its_module_is_a_finding(self, walk: Callable[..., None]) -> None:
        walk("virtualenv_without_module")

        assert [f.name for f in check_startup_hooks().findings] == ["_virtualenv.pth"]

    def test_an_editable_install_with_its_finder_is_benign(self, walk: Callable[..., None]) -> None:
        walk("editable")

        report = check_startup_hooks()

        assert report.clean
        assert [(h.name, h.recognized) for h in report.benign] == [
            ("__editable__.demo-0.1.pth", "editable install")
        ]

    def test_an_editable_install_without_its_finder_is_a_finding(
        self, walk: Callable[..., None]
    ) -> None:
        walk("editable_without_finder")

        assert [f.name for f in check_startup_hooks().findings] == ["__editable__.demo-0.1.pth"]

    def test_an_editable_pth_with_another_import_line_is_a_finding(
        self, walk: Callable[..., None], tmp_path: Path
    ) -> None:
        home = _copy("editable", tmp_path)
        pth = home / "__editable__.demo-0.1.pth"
        pth.write_text(pth.read_text("utf-8") + "\nimport airlock_placeholder_noop\n", "utf-8")
        walk(home)

        assert [f.name for f in check_startup_hooks().findings] == ["__editable__.demo-0.1.pth"]

    def test_a_sitecustomize_in_the_stdlib_directory_is_benign(
        self, walk: Callable[..., None]
    ) -> None:
        walk("stdlib", stdlib="stdlib")

        report = check_startup_hooks()

        assert report.clean
        assert [(h.kind, h.recognized) for h in report.benign] == [
            (StartupHookKind.SITECUSTOMIZE, "interpreter")
        ]

    def test_a_sitecustomize_in_a_site_directory_is_a_finding(
        self, walk: Callable[..., None]
    ) -> None:
        walk("site_packages_customize", stdlib="stdlib")

        [finding] = check_startup_hooks().findings
        assert finding.kind is StartupHookKind.SITECUSTOMIZE
        assert finding.recognized == ""

    def test_every_benign_kind_together_is_clean(self, walk: Callable[..., None]) -> None:
        walk("setuptools", "virtualenv", "editable", "stdlib", stdlib="stdlib")

        report = check_startup_hooks()

        assert report.clean
        assert sorted(h.recognized for h in report.benign) == [
            "editable install",
            "interpreter",
            "setuptools",
            "virtualenv",
        ]

    def test_benign_hooks_are_logged_once_per_process_at_debug(
        self, walk: Callable[..., None], events: _Events
    ) -> None:
        walk("setuptools", "virtualenv")

        process_startup_hook_report()
        process_startup_hook_report()

        recognized = [
            (level, fields["recognized"])
            for level, event, fields in events.records
            if event == "airlock_startup_hook_recognized"
        ]
        assert recognized == [("debug", "setuptools"), ("debug", "virtualenv")]
        assert events.named("airlock_startup_hook_found") == []

    def test_an_allowlist_entry_still_covers_a_hook_that_is_not_benign(
        self, walk: Callable[..., None]
    ) -> None:
        walk("agent_framework_1_26_2")
        pth = FIXTURES / "agent_framework_1_26_2" / "af_runtime_diag.pth"

        report = check_startup_hooks({"af_runtime_diag.pth": _sha256(pth)})

        assert report.clean
        assert [h.name for h in report.allowlisted] == ["af_runtime_diag.pth"]


class TestWhoInstalledTheHook:
    """A benign hook's files must not be claimed by a distribution that does not write them.

    pip lists every file it installs in the distribution's RECORD, so a wheel that ships a
    hook named like a benign one, and the module it imports, is still found.
    """

    def test_a_wheel_shipping_virtualenvs_two_files_is_a_finding(
        self, walk: Callable[..., None], tmp_path: Path
    ) -> None:
        home = _copy("virtualenv", tmp_path)
        _record(home, "placeholder_wheel-1.0", "_virtualenv.pth", "_virtualenv.py")
        walk(home)

        assert [f.name for f in check_startup_hooks().findings] == ["_virtualenv.pth"]

    def test_the_setuptools_hook_claimed_by_setuptools_is_benign(
        self, walk: Callable[..., None], tmp_path: Path
    ) -> None:
        home = _copy("setuptools", tmp_path)
        _record(
            home, "setuptools-84.2.1", "distutils-precedence.pth", "_distutils_hack/__init__.py"
        )
        walk(home)

        assert [h.recognized for h in check_startup_hooks().benign] == ["setuptools"]

    def test_the_setuptools_hook_claimed_by_another_wheel_is_a_finding(
        self, walk: Callable[..., None], tmp_path: Path
    ) -> None:
        home = _copy("setuptools", tmp_path)
        _record(home, "placeholder_wheel-1.0", "distutils-precedence.pth")
        walk(home)

        assert [f.name for f in check_startup_hooks().findings] == ["distutils-precedence.pth"]

    def test_a_distutils_hack_another_wheel_overwrote_is_a_finding(
        self, walk: Callable[..., None], tmp_path: Path
    ) -> None:
        home = _copy("setuptools", tmp_path)
        _record(
            home, "setuptools-84.2.1", "distutils-precedence.pth", "_distutils_hack/__init__.py"
        )
        _record(home, "placeholder_wheel-1.0", "_distutils_hack/__init__.py")
        walk(home)

        assert [f.name for f in check_startup_hooks().findings] == ["distutils-precedence.pth"]

    def test_a_same_named_module_found_first_on_sys_path_is_a_finding(
        self, walk: Callable[..., None], tmp_path: Path
    ) -> None:
        home = _copy("setuptools", tmp_path)
        earlier = tmp_path / "earlier"
        earlier.mkdir()
        (earlier / "_distutils_hack.py").write_text("pass\n", encoding="utf-8")
        walk(earlier, home)

        assert [f.name for f in check_startup_hooks().findings] == ["distutils-precedence.pth"]

    def test_an_editable_pth_an_editable_install_claims_is_benign(
        self, walk: Callable[..., None], tmp_path: Path
    ) -> None:
        home = _copy("editable", tmp_path)
        _record(
            home,
            "demo-0.1",
            "__editable__.demo-0.1.pth",
            "__editable___demo_0_1_finder.py",
            editable=True,
        )
        walk(home)

        assert [h.recognized for h in check_startup_hooks().benign] == ["editable install"]

    def test_an_editable_pth_a_wheel_from_an_index_claims_is_a_finding(
        self, walk: Callable[..., None], tmp_path: Path
    ) -> None:
        home = _copy("editable", tmp_path)
        _record(home, "demo-0.1", "__editable__.demo-0.1.pth", "__editable___demo_0_1_finder.py")
        walk(home)

        assert [f.name for f in check_startup_hooks().findings] == ["__editable__.demo-0.1.pth"]

    def test_a_stdlib_sitecustomize_a_wheel_installed_is_a_finding(
        self, walk: Callable[..., None], tmp_path: Path
    ) -> None:
        # Outside a virtual environment a wheel's data files land under sys.prefix, which can
        # be the standard-library directory; its RECORD, beside the package, names the file.
        stdlib = _copy("stdlib", tmp_path)
        site_packages = stdlib / "site-packages"
        site_packages.mkdir()
        _record(site_packages, "placeholder_wheel-1.0", "../sitecustomize.py")
        walk(site_packages, stdlib, stdlib=stdlib)

        [finding] = check_startup_hooks().findings
        assert finding.kind is StartupHookKind.SITECUSTOMIZE


class TestKnownIncidents:
    def test_the_agent_framework_hook_names_are_listed(self) -> None:
        assert dict(KNOWN_INCIDENT_HOOKS) == {
            "af_runtime_diag.pth": AGENT_FRAMEWORK_ADVISORY,
            "agent_framework_meta.pth": AGENT_FRAMEWORK_ADVISORY,
        }

    def test_af_runtime_diag_is_a_finding_that_carries_its_advisory(
        self, walk: Callable[..., None]
    ) -> None:
        walk("agent_framework_1_26_2")

        report = check_startup_hooks()

        [finding] = report.findings
        assert not report.clean
        assert finding.known_incident == AGENT_FRAMEWORK_ADVISORY
        assert finding.to_dict()["known_incident"] == AGENT_FRAMEWORK_ADVISORY

    def test_a_hook_with_any_other_name_carries_no_advisory(self, interp: _Interpreter) -> None:
        interp.write("x.pth", IMPORT_LINE)

        [finding] = check_startup_hooks().findings

        assert finding.known_incident == ""
        assert "known_incident" not in finding.to_dict()

    def test_it_is_logged_at_error_level(self, walk: Callable[..., None], events: _Events) -> None:
        walk("agent_framework_1_26_2")

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            _guarded(AirlockConfig(), [])()

        [(level, _, fields)] = [r for r in events.records if r[1] == "airlock_startup_hook_found"]
        assert level == "error"
        assert fields["known_incident"] == AGENT_FRAMEWORK_ADVISORY

    def test_the_deny_refusal_names_the_advisory(self, walk: Callable[..., None]) -> None:
        walk("agent_framework_1_26_2")

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            result = _guarded(AirlockConfig(startup_hook_check="deny"), [])()

        [hook] = result["metadata"]["startup_hooks"]
        assert hook["known_incident"] == AGENT_FRAMEWORK_ADVISORY


class TestWarnByDefault:
    def test_warn_is_the_default(self) -> None:
        assert AirlockConfig().startup_hook_check == "warn"

    def test_a_guarded_call_beside_only_benign_hooks_warns_nothing_and_runs(
        self, walk: Callable[..., None], events: _Events
    ) -> None:
        walk("setuptools", "virtualenv", "editable", "stdlib", stdlib="stdlib")
        ran: list[str] = []

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            assert _guarded(AirlockConfig(), ran)() == "PLACEHOLDER"

        assert ran == ["ran"]
        assert events.named("airlock_startup_hook_found") == []
        assert _runtime_warnings(caught) == []

    def test_af_runtime_diag_under_the_default_logs_once_warns_once_and_runs(
        self, walk: Callable[..., None], events: _Events
    ) -> None:
        walk("agent_framework_1_26_2")
        ran: list[str] = []
        tool = _guarded(AirlockConfig(), ran)

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            assert [tool(), tool()] == ["PLACEHOLDER", "PLACEHOLDER"]

        assert ran == ["ran", "ran"]
        [found] = events.named("airlock_startup_hook_found")
        assert (found["mode"], found["known_incident"]) == ("warn", AGENT_FRAMEWORK_ADVISORY)
        [message] = _runtime_warnings(caught)
        assert "af_runtime_diag.pth" in message
        assert AGENT_FRAMEWORK_ADVISORY in message
        assert "cannot undo" in message

    def test_deny_still_refuses_it(self, walk: Callable[..., None]) -> None:
        walk("agent_framework_1_26_2")
        ran: list[str] = []

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            result = _guarded(AirlockConfig(startup_hook_check="deny"), ran)()

        assert result["block_reason"] == BlockReason.STARTUP_HOOK.value
        assert ran == []

    def test_off_does_not_walk_at_all(
        self, walk: Callable[..., None], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        walk("agent_framework_1_26_2")

        def no_walk() -> Any:
            raise AssertionError("startup_hook_check='off' must not walk")

        monkeypatch.setattr(hooks_module, "_walk", no_walk)
        ran: list[str] = []

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            assert _guarded(AirlockConfig(startup_hook_check="off"), ran)() == "PLACEHOLDER"

        assert ran == ["ran"]
        assert _runtime_warnings(caught) == []

    def test_under_w_error_the_first_guarded_call_raises_the_warning(
        self, walk: Callable[..., None]
    ) -> None:
        # warnings.warn raises under an "error" filter, from inside the first guarded call,
        # before the tool runs; the process has had its one warning, so the next call runs.
        walk("agent_framework_1_26_2")
        ran: list[str] = []
        tool = _guarded(AirlockConfig(), ran)

        with warnings.catch_warnings():
            warnings.simplefilter("error", RuntimeWarning)
            with pytest.raises(RuntimeWarning, match="af_runtime_diag.pth"):
                tool()
            assert ran == []
            assert tool() == "PLACEHOLDER"

        assert ran == ["ran"]

    def test_reset_forgets_the_warning_too(self, walk: Callable[..., None]) -> None:
        walk("agent_framework_1_26_2")
        tool = _guarded(AirlockConfig(), [])

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            tool()
            reset_startup_hook_check()
            tool()

        assert len(_runtime_warnings(caught)) == 2


class TestAnUnreadableFileList:
    def test_a_record_csv_cannot_read_leaves_the_hook_a_finding_and_does_not_raise(
        self, walk: Callable[..., None], tmp_path: Path
    ) -> None:
        home = _copy("virtualenv", tmp_path)
        meta = home / "placeholder_wheel-1.0.dist-info"
        meta.mkdir()
        (meta / "RECORD").write_bytes(b'"_virtualenv.pth\x00,sha256=PLACEHOLDER,1\n')
        walk(home)

        report = check_startup_hooks()

        assert [f.name for f in report.findings] == ["_virtualenv.pth"]

    def test_a_failure_reading_owners_leaves_every_hook_a_finding(
        self, walk: Callable[..., None], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        walk("setuptools", "virtualenv")

        def broken(*_: Any) -> Any:
            raise OSError("PLACEHOLDER")

        monkeypatch.setattr(hooks_module, "_claimants", broken)

        assert sorted(f.name for f in check_startup_hooks().findings) == [
            "_virtualenv.pth",
            "distutils-precedence.pth",
        ]
