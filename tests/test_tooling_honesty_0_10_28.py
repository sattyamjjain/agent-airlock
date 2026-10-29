"""Regressions for 0.10.28: tooling and claim gates that said more than they checked.

- CI's "extra-backed tests are not silently skipped" step ran ``--collect-only``, which exits
  0 on a module-level ``importorskip`` and never reaches one inside a test function, so it
  asserted nothing the three import lines above it had not.
- ``scripts/check_docs_api.py`` skipped a Python block that did not parse, even one naming
  ``agent_airlock``: AGENTS.md's safety-posture example (``def your_function(...)``) was
  never checked.
- ``scripts/check_registry_parity.py`` told feature work to put entries under
  ``[Unreleased]`` and an unshipped release to move back there, the state
  ``check_changelog.py``'s default mode fails on every PR.
- ``python -m benchmarks.blockrate`` wrote ``airlock_audit.json`` into its working
  directory, the checkout when run from the repo root; the red-team ``policy_field``
  adapters did too, and so read back none of the audit records ``canary_env`` exists to
  collect.
- Dead ``except ImportError`` fallbacks would have turned a capability policy into ``None``.
- Smaller drift: a logger name, a dead OWASP link, stale CI and ``make help`` comments, a
  parity-test message pointing at the wrong CLAUDE.md, the startup-hook ``deny`` described
  as process-wide, the allowlist hash's reach, and the CVE watcher's ledger.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shutil
import site
import subprocess
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
import scripts.check_docs_api as docs_gate
import scripts.check_registry_parity as parity
import scripts.cve_watcher as cve_watcher
from scripts.check_links import markdown_files

from agent_airlock import Airlock, AirlockConfig, policy_presets
from agent_airlock import config as config_module
from agent_airlock import identity as identity_module
from agent_airlock import policy as policy_module
from agent_airlock.capabilities import CapabilityPolicy
from agent_airlock.runtime import startup_hooks
from agent_airlock.runtime.startup_hooks import check_startup_hooks
from agent_airlock.testing import reset_startup_hook_check

REPO_ROOT = Path(__file__).resolve().parent.parent
CI = REPO_ROOT / ".github" / "workflows" / "ci.yml"
EXTRA_BACKED_STEP = "Assert the extra-backed tests are not silently skipped"
EXTRA_BACKED_FILES = (
    "tests/test_redis_rate_limit.py",
    "tests/kill_switch/test_kill_switch_wiring.py",
    "tests/test_mcp_integration_0_10_18.py",
    "tests/test_identity.py",
    "tests/test_attested_admission.py",
)


def _ci_step(name: str) -> str:
    """One step of ci.yml, from its ``- name:`` line to the next step's."""
    workflow = CI.read_text(encoding="utf-8")
    start = workflow.index(f"- name: {name}\n")
    end = workflow.find("\n      - name: ", start)
    return workflow[start : end if end != -1 else len(workflow)]


def _subprocess_env(**overrides: str) -> dict[str, str]:
    """The environment with this checkout first on PYTHONPATH and no ambient audit path.

    ``E2B_API_KEY`` goes too: with ``[sandbox]`` installed and a key set, the blockrate
    sandbox arm sends calls to E2B, which no test may do.
    """
    env = {
        k: v for k, v in os.environ.items() if k not in {"AIRLOCK_AUDIT_LOG_PATH", "E2B_API_KEY"}
    }
    paths = [str(REPO_ROOT), str(REPO_ROOT / "src"), env.get("PYTHONPATH", "")]
    env["PYTHONPATH"] = os.pathsep.join(p for p in paths if p)
    env.update(overrides)
    return env


# --------------------------------------------------------------------------- A-1


def _extra_backed_gate() -> str:
    """The pattern the extra-backed step greps its pytest log with."""
    match = re.search(
        r"grep -qE '([^']+)' extra-backed-tests\.plain\.log", _ci_step(EXTRA_BACKED_STEP)
    )
    assert match is not None, "the extra-backed step's summary-line grep is gone from ci.yml"
    return match.group(1)


def _run_throwaway_suite(tmp_path: Path, files: dict[str, str]) -> Path:
    """Run real pytest over ``files`` the way the step runs its five, return the log."""
    for name, body in files.items():
        (tmp_path / name).write_text(body, encoding="utf-8")
    (tmp_path / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    out = subprocess.run(
        # -v stands in for the repo's addopts, which carry it; -rs as the step passes it.
        [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-v", "-rs"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=60,
    ).stdout
    log = tmp_path / "extra-backed-tests.plain.log"
    log.write_text(out, encoding="utf-8")
    return log


_PASSES = "def test_one():\n    pass\n\n\ndef test_two():\n    pass\n"
_SUITES: dict[str, dict[str, str]] = {
    "all-pass": {"test_a.py": _PASSES},
    "module-level-importorskip": {
        "test_a.py": _PASSES,
        "test_b.py": (
            "import pytest\n\npytest.importorskip('airlock_no_such_extra')\n\n\n"
            "def test_never():\n    pass\n"
        ),
    },
    "in-function-importorskip": {
        "test_a.py": _PASSES,
        "test_b.py": (
            "import pytest\n\n\ndef test_needs_it():\n"
            "    pytest.importorskip('airlock_no_such_extra')\n"
        ),
    },
    # Fork A's repro: the module exists and raises ImportError when imported.
    "importable-but-raising": {
        "airlock_hidden_extra.py": "raise ImportError('hidden for the repro')\n",
        "test_a.py": _PASSES,
        "test_b.py": (
            "import pytest\n\npytest.importorskip('airlock_hidden_extra')\n\n\n"
            "def test_never():\n    pass\n"
        ),
    },
    "a-failure": {"test_a.py": _PASSES + "\n\ndef test_three():\n    assert False\n"},
}


class TestTheExtraBackedStepRunsTheTests:
    """A collect-only pass exits 0 on a module skip and cannot see one in a test function."""

    @staticmethod
    def _script() -> str:
        """The step's shell, without the comment above it."""
        return _ci_step(EXTRA_BACKED_STEP).split("run: |\n", 1)[1]

    def test_it_runs_the_five_files_instead_of_collecting_them(self) -> None:
        script = self._script()
        assert "--collect-only" not in script
        assert "set -o pipefail" in script, "pytest's own exit code must fail the step"
        for path in EXTRA_BACKED_FILES:
            assert path in script
            assert (REPO_ROOT / path).is_file(), path

    def test_the_three_import_lines_stay(self) -> None:
        script = self._script()
        for imports in ("import fakeredis, redis, lupa", "import fastmcp", "import cryptography"):
            assert f'python -c "{imports};' in script

    @pytest.mark.skipif(shutil.which("grep") is None, reason="needs a grep binary")
    @pytest.mark.parametrize(
        ("suite", "gate_passes"),
        [
            ("all-pass", True),
            ("module-level-importorskip", False),
            ("in-function-importorskip", False),
            ("importable-but-raising", False),
            ("a-failure", False),
        ],
    )
    def test_only_a_summary_of_passes_gets_through(
        self, tmp_path: Path, suite: str, gate_passes: bool
    ) -> None:
        log = _run_throwaway_suite(tmp_path, _SUITES[suite])
        result = subprocess.run(["grep", "-qE", _extra_backed_gate(), str(log)], check=False)
        assert (result.returncode == 0) is gate_passes, log.read_text(encoding="utf-8")

    def test_the_comment_says_what_the_step_asserts(self) -> None:
        step = _ci_step(EXTRA_BACKED_STEP)
        assert "Collect-only, so it" not in step
        assert "fails loudly if an extra stops resolving" not in step


# --------------------------------------------------------------------------- A-2


def _page(tmp_path: Path, body: str) -> Path:
    page = tmp_path / "page.md"
    page.write_text(body, encoding="utf-8")
    return page


_POSTURE_IMPORTS = (
    "from agent_airlock import Airlock\nfrom agent_airlock.policy import STRICT_POLICY\n"
)
_POSTURE_DECORATOR = "@Airlock(policy=STRICT_POLICY, sandbox=True, sandbox_required=True)"


class TestTheDocsGateRefusesABlockItCannotParse:
    """A block that names agent_airlock and does not parse was skipped, so never checked."""

    def test_an_unparseable_block_naming_the_package_is_a_finding(self, tmp_path: Path) -> None:
        page = _page(
            tmp_path,
            "# t\n\n```python\n" + _POSTURE_IMPORTS + "\n" + _POSTURE_DECORATOR + "\n"
            "def your_function(...): ...\n```\n",
        )
        ((line, message),) = docs_gate.findings_in(page)
        assert line == 8, "the finding points at the line that does not parse"
        assert "agent_airlock" in message and "not valid Python" in message
        assert docs_gate.main([str(page)]) == 1

    def test_the_same_block_once_it_parses_passes(self, tmp_path: Path) -> None:
        page = _page(
            tmp_path,
            "# t\n\n```python\n" + _POSTURE_IMPORTS + "\n" + _POSTURE_DECORATOR + "\n"
            "def your_function(path: str) -> str: ...\n```\n",
        )
        assert docs_gate.findings_in(page) == []
        assert docs_gate.main([str(page)]) == 0

    def test_what_an_unparseable_block_hid_is_found_once_it_parses(self, tmp_path: Path) -> None:
        bad_api = "from agent_airlock import Airlock\n\n@Airlock(unknown_args_mode=1)\n"
        hidden = _page(tmp_path, "```python\n" + bad_api + "def f(...): ...\n```\n")
        assert "not valid Python" in docs_gate.findings_in(hidden)[0][1]
        shown = _page(tmp_path, "```python\n" + bad_api + "def f(x: int) -> None: ...\n```\n")
        assert docs_gate.findings_in(shown) == [
            (4, "Airlock() has no parameter 'unknown_args_mode'")
        ]

    def test_pseudo_code_that_never_names_the_package_is_still_skipped(self) -> None:
        assert docs_gate.check_source("result = tool(...)  # ->\n{ not python\n") == []

    def test_agents_md_posture_block_parses_and_keeps_its_meaning(self) -> None:
        agents = (REPO_ROOT / "AGENTS.md").read_text(encoding="utf-8")
        section = agents.split("## Default safety posture", 1)[1]
        block = section.split("```python\n", 1)[1].split("```", 1)[0]
        ast.parse(block)
        assert block.startswith(_POSTURE_IMPORTS)
        assert _POSTURE_DECORATOR + "\ndef your_function(" in block
        assert docs_gate.findings_in(REPO_ROOT / "AGENTS.md") == []


# --------------------------------------------------------------------------- A-3


class TestRegistryParityDescribesThisReposReleaseFlow:
    """Entries under [Unreleased] fail ``check_changelog.py`` on every PR here."""

    def test_an_unshipped_dated_section_is_not_sent_back_under_unreleased(self) -> None:
        (message,) = parity.evaluate_documented_vs_tagged(["0.8.85"], {"0.8.83"})
        assert "move that section back under [Unreleased]" not in message
        assert "delete that dated section" in message
        assert "revert the version bump" in message
        assert "check_changelog.py fails any entry there" in message

    def test_an_undated_version_is_not_said_to_have_entries_under_unreleased(self) -> None:
        (message,) = parity.evaluate_declared_vs_tagged(
            "0.8.87", {"0.8.85"}, declared_is_dated=False
        )
        assert "entries still under [Unreleased]" not in message
        assert "pyproject.toml declares 0.8.87, which has no dated CHANGELOG heading" in message

    def test_which_states_pass_and_fail_is_unchanged(self) -> None:
        assert parity.evaluate_documented_vs_tagged(["0.8.85"], {"0.8.83"})
        assert parity.evaluate_documented_vs_tagged(["0.8.84"], {"0.8.84"}) == []
        assert parity.evaluate_declared_vs_tagged("0.8.87", {"0.8.85"}, declared_is_dated=False)
        assert (
            parity.evaluate_declared_vs_tagged("0.8.86", {"0.8.85"}, declared_is_dated=False) == []
        )
        assert (
            parity.evaluate_declared_vs_tagged("0.8.87", {"0.8.85"}, declared_is_dated=True) == []
        )

    def test_the_docstring_has_the_release_pr_write_under_the_dated_heading(self) -> None:
        doc = " ".join((parity.__doc__ or "").split())
        assert "its entries go under ``## [Unreleased]``" not in doc
        assert "promote [Unreleased]" not in doc
        assert "``check_changelog.py``'s default mode" in doc
        assert "straight under the new dated heading" in doc


# --------------------------------------------------------------------------- D-F5

_PRESET_FACTORIES: tuple[Callable[[], Any], ...] = (
    policy_presets.gtg_1002_defense_policy,
    policy_presets.mex_gov_2026_policy,
    policy_presets.owasp_mcp_top_10_2026_policy,
    policy_presets.eu_ai_act_article_15_policy,
    policy_presets.india_dpdp_2023_policy,
)


class TestCapabilityPoliciesAreNeverSilentlyDropped:
    """A capability policy that became ``None`` would have stopped gating, with no error."""

    @pytest.mark.parametrize(
        "name", ["STRICT_POLICY", "READ_ONLY_POLICY", "CAMOUFLAGE_RESISTANT_POLICY"]
    )
    def test_the_predefined_policies_carry_one(self, name: str) -> None:
        assert isinstance(getattr(policy_module, name).capability_policy, CapabilityPolicy)

    @pytest.mark.parametrize("factory", _PRESET_FACTORIES, ids=lambda f: f.__name__)
    def test_the_presets_carry_one(self, factory: Callable[[], Any]) -> None:
        assert isinstance(factory().capability_policy, CapabilityPolicy)

    @pytest.mark.parametrize(
        "build",
        [
            policy_module._get_strict_capability_policy,
            policy_module._get_read_only_capability_policy,
            policy_module._get_camouflage_resistant_capability_policy,
            *_PRESET_FACTORIES,
        ],
        ids=lambda f: f.__name__,
    )
    def test_a_missing_capabilities_module_raises_instead_of_returning_none(
        self, build: Callable[[], Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setitem(sys.modules, "agent_airlock.capabilities", None)
        with pytest.raises(ImportError):
            build()

    def test_no_import_error_fallback_is_left_around_the_capabilities_import(self) -> None:
        for module in ("policy.py", "policy_presets.py"):
            tree = ast.parse((REPO_ROOT / "src" / "agent_airlock" / module).read_text("utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Try):
                    continue
                caught = {
                    name.id
                    for handler in node.handlers
                    if handler.type is not None
                    for name in ast.walk(handler.type)
                    if isinstance(name, ast.Name)
                } & {"ImportError", "ModuleNotFoundError", "Exception", "BaseException"}
                imports = {
                    sub.module
                    for stmt in node.body
                    for sub in ast.walk(stmt)
                    if isinstance(sub, ast.ImportFrom)
                }
                assert not (caught and "capabilities" in imports), f"{module}:{node.lineno}"


# --------------------------------------------------------------------------- D-F4


def _logger_names() -> Iterator[tuple[str, str | None, str]]:
    """``(file:line, name given, name expected)`` for every ``get_logger`` call in src."""
    package = REPO_ROOT / "src" / "agent_airlock"
    for path in sorted(package.rglob("*.py")):
        dotted = ".".join(path.relative_to(package.parent).with_suffix("").parts)
        dotted = dotted.removesuffix(".__init__")
        # core.py alone logs under the bare root name (CLAUDE.md, Code Conventions).
        expected = "agent-airlock" + (
            "" if dotted == "agent_airlock.core" else dotted[len("agent_airlock") :]
        )
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "get_logger"
            ):
                arg = node.args[0] if node.args else None
                given = arg.value if isinstance(arg, ast.Constant) else None
                yield f"{path.relative_to(REPO_ROOT)}:{node.lineno}", given, expected


class TestLoggerNamesFollowTheModulePath:
    def test_every_logger_is_named_for_its_module(self) -> None:
        names = list(_logger_names())
        assert len(names) > 100, "the walk found too few get_logger calls to mean anything"
        wrong = [(where, given) for where, given, expected in names if given != expected]
        assert wrong == []

    def test_the_kill_switch_redis_transport_in_particular(self) -> None:
        from agent_airlock.kill_switch.transports import redis_stream

        source = Path(redis_stream.__file__).read_text(encoding="utf-8")
        assert 'get_logger("agent-airlock.kill_switch.transports.redis_stream")' in source


# --------------------------------------------------------------------------- A-8


class TestTheOwaspLinkResolves:
    def test_identity_cites_the_live_agentic_security_initiative_page(self) -> None:
        doc = identity_module.__doc__ or ""
        assert "https://genai.owasp.org/initiatives/agentic-security-initiative/" in doc
        assert "owasp.org/www-project-agentic-ai" not in doc


# --------------------------------------------------------------------------- A-10


class TestCiAndMakeHelpSayWhatTheyRun:
    def test_the_bare_install_comment_names_the_test_jobs_extras(self) -> None:
        workflow = CI.read_text(encoding="utf-8")
        installed = re.search(r'pip install -e "\.\[([a-z,]+)\]"\n', workflow)
        assert installed is not None
        bare = workflow.split("  bare-install:", 1)[1].split("runs-on:", 1)[0]
        assert f"`.[{installed.group(1)}]`" in bare

    def test_check_links_help_does_not_claim_readme_and_docs_only(self) -> None:
        makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
        (line,) = [ln for ln in makefile.splitlines() if '@echo "  check-links ' in ln]
        assert "README + docs/" not in line
        assert "every authored .md" in line
        scanned = {p.relative_to(REPO_ROOT).parts[0] for p in markdown_files()}
        assert scanned - {"README.md", "docs"}, "check_links.py reads more than README + docs/"

    def test_check_changelog_help_matches_this_repos_flow(self) -> None:
        makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
        (line,) = [ln for ln in makefile.splitlines() if '@echo "  check-changelog ' in ln]
        assert "after a release" not in line


# --------------------------------------------------------------------------- G-F5


class TestBenchmarkAuditLogsStayOutOfTheWorkingDirectory:
    """``python -m benchmarks.blockrate`` runs from the repo root, so its cwd is the checkout."""

    def test_blockrate_writes_nothing_into_its_cwd(self, tmp_path: Path) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "benchmarks.blockrate"],
            cwd=tmp_path,
            env=_subprocess_env(),
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, result.stderr[-2000:]
        assert sorted(p.name for p in tmp_path.iterdir()) == []

    def test_blockrate_honours_an_audit_path_from_the_environment(self, tmp_path: Path) -> None:
        cwd, audit = tmp_path / "cwd", tmp_path / "chosen" / "audit.jsonl"
        cwd.mkdir()
        result = subprocess.run(
            [sys.executable, "-m", "benchmarks.blockrate"],
            cwd=cwd,
            env=_subprocess_env(AIRLOCK_AUDIT_LOG_PATH=str(audit)),
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, result.stderr[-2000:]
        assert list(cwd.iterdir()) == []
        records = [
            json.loads(line)
            for line in audit.read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        ]
        assert records, "the sandbox arm's calls were not audited where the env var said"

    def test_red_team_policy_field_adapters_write_nothing_into_their_cwd(
        self, tmp_path: Path
    ) -> None:
        """They also read none of their audit records back until 0.10.28."""
        script = (
            "import json\n"
            "from benchmarks.adaptive_redteam.adapters.config_gate import FilesystemAdapter\n"
            "from benchmarks.adaptive_redteam.adapters.policy_field import (\n"
            "    ActionContradictionAdapter, DeserializationAdapter, SequenceGuardAdapter)\n"
            "counts = {}\n"
            "for a in (DeserializationAdapter(), SequenceGuardAdapter(),\n"
            "          ActionContradictionAdapter(), FilesystemAdapter()):\n"
            "    for c in (a.known_blocked(0), a.benign_control(0)):\n"
            "        canary = a.run(c)\n"
            "        assert canary.raised is None, repr(canary.raised)\n"
            "        counts[c.candidate_id] = len(canary.audit or [])\n"
            "print('COUNTS=' + json.dumps(counts))\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", script],
            cwd=tmp_path,
            env=_subprocess_env(),
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, result.stderr[-2000:]
        assert sorted(p.name for p in tmp_path.iterdir()) == []
        counts = json.loads(result.stdout.rsplit("COUNTS=", 1)[1])
        assert len(counts) == 8
        unread = sorted(name for name, n in counts.items() if n == 0)
        assert unread == [], "these runs read back none of their own audit records"


# --------------------------------------------------------------------------- G-F7


class TestTheRedTeamParityMessagePointsAtTheRecipe:
    def test_it_names_the_claude_md_that_holds_the_recipe(self) -> None:
        source = (REPO_ROOT / "tests" / "test_adaptive_redteam_registry_parity.py").read_text(
            encoding="utf-8"
        )
        assert "(see benchmarks/CLAUDE.md)" not in source
        assert "src/agent_airlock/mcp_spec/CLAUDE.md" in source
        recipe = (REPO_ROOT / "src" / "agent_airlock" / "mcp_spec" / "CLAUDE.md").read_text(
            encoding="utf-8"
        )
        assert "BYPASS_TARGETS" in recipe


# --------------------------------------------------------------------------- B1-F2 / B1-F3

#: An executable ``.pth`` line naming a module that exists nowhere; nothing here runs ``site``.
_IMPORT_LINE = "import airlock_placeholder_noop\n"


@pytest.fixture
def fresh_walk() -> Iterator[None]:
    """Forget the process's startup-hook walk before and after, so the test's hook is seen."""
    reset_startup_hook_check()
    yield
    reset_startup_hook_check()


@pytest.fixture
def fake_site(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fresh_walk: None) -> Path:
    """A site directory standing in for the interpreter's, the only one the walk reads.

    Only for tests that call the walk directly: with ``sys.path`` replaced, a guarded call
    that imported a stdlib module for the first time would fail.
    """
    directory = tmp_path / "site-packages"
    directory.mkdir()
    monkeypatch.setattr(site, "getsitepackages", lambda: [str(directory)])
    monkeypatch.setattr(site, "getusersitepackages", lambda: str(tmp_path / "no-user-site"))
    monkeypatch.setattr(sys, "path", [str(directory)])
    monkeypatch.delitem(sys.modules, "sitecustomize", raising=False)
    monkeypatch.delitem(sys.modules, "usercustomize", raising=False)
    return directory


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class TestStartupHookDenyIsPerConfig:
    """``deny`` refuses the calls its own config guards, not every call in the process."""

    def test_a_tool_whose_config_leaves_the_check_off_still_runs(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fresh_walk: None
    ) -> None:
        # A hook no allowlist covers, first on sys.path; the real entries stay, so the
        # walk may find the interpreter's own hooks too, which only adds to the refusal.
        (tmp_path / "x.pth").write_text(_IMPORT_LINE, encoding="utf-8")
        monkeypatch.syspath_prepend(str(tmp_path))
        ran: list[str] = []

        @Airlock(config=AirlockConfig(startup_hook_check="deny"))
        def guarded() -> str:
            ran.append("guarded")
            return "ran"

        @Airlock()  # the same process, a config without the check
        def unchecked() -> str:
            ran.append("unchecked")
            return "ran"

        assert guarded()["block_reason"] == "startup_hook"
        assert unchecked() == "ran"
        assert ran == ["unchecked"]

    def test_the_docstrings_say_so(self) -> None:
        module_doc = " ".join((startup_hooks.__doc__ or "").split())
        assert "also keeps every ``@Airlock``-guarded tool" not in module_doc
        assert "a tool guarded by a config without it still runs" in module_doc
        config_doc = " ".join((config_module.AirlockConfig.__doc__ or "").split())
        assert "``deny`` refuses every guarded call while" not in config_doc
        assert "``deny`` refuses every call this config guards" in config_doc


class TestAnAllowlistedPthIsPinnedByItsOwnBytesOnly:
    """The hash covers the ``.pth`` file, not the module its import line loads."""

    def test_rewriting_the_imported_module_leaves_the_pth_allowlisted(
        self, fake_site: Path
    ) -> None:
        pth = fake_site / "hook.pth"
        pth.write_text("import airlock_hook_target\n", encoding="utf-8")
        target = fake_site / "airlock_hook_target.py"
        target.write_text("VALUE = 1\n", encoding="utf-8")
        allow = {"hook.pth": _sha256(pth)}
        assert check_startup_hooks(allow).clean

        target.write_text("VALUE = 2  # rewritten\n", encoding="utf-8")
        assert check_startup_hooks(allow).clean, "the documented limit no longer holds"

        pth.write_text("import airlock_hook_target  # changed\n", encoding="utf-8")
        assert not check_startup_hooks(allow).clean, "a rewritten .pth must be a finding"

    def test_the_module_docstring_states_the_limit(self) -> None:
        doc = " ".join((startup_hooks.__doc__ or "").split())
        assert "covers the ``.pth`` file only, not the modules its import lines load" in doc


# --------------------------------------------------------------------------- G-F8


class TestTheCveWatcherLedgerIsDescribedAsRead:
    def test_names_anywhere_and_md_and_py_bodies_count(self, tmp_path: Path) -> None:
        cves = tmp_path / "cves"
        (cves / "fixtures").mkdir(parents=True)
        (cves / "README.md").write_text("| CVE-2099-11111 | out of scope |\n", encoding="utf-8")
        (cves / "test_umbrella.py").write_text('"""Replays CVE-2099-22222."""\n', "utf-8")
        (cves / "notes.txt").write_text("CVE-2099-33333\n", encoding="utf-8")
        (cves / "fixtures" / "cve_2099_44444.json").write_text("{}", encoding="utf-8")
        found = cve_watcher.already_tracked((cves,))
        assert {"CVE-2099-11111", "CVE-2099-22222", "CVE-2099-44444"} <= found
        assert "CVE-2099-33333" not in found

    def test_the_docstring_says_so(self) -> None:
        doc = " ".join((cve_watcher.__doc__ or "").split())
        assert "plus the ``tests/cves/`` filenames," not in doc
        assert "the text of every ``.md`` and ``.py`` file" in doc
