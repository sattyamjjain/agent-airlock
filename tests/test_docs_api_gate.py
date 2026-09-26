"""The docs API gate has to fail on an API that does not exist, and not on anything else.

At v0.10.13 the Python blocks under `docs/` made 109 references to `agent_airlock` names,
parameters and methods that do not exist, the docs home page among them, so a reader who
copied an example got a `TypeError` or an `ImportError`. `scripts/check_docs_api.py` is the
gate; this file has watched it fail on each shape it found, and pins the shapes it must not
fire on, because a gate with false positives gets switched off.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
import scripts.check_docs_api as gate
from scripts.check_docs_api import check_source, doc_files, findings_in, main

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts" / "check_docs_api.py"


def _messages(source: str) -> list[str]:
    return [message for _, message in check_source(source)]


def _page(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "page.md"
    path.write_text(body, encoding="utf-8")
    return path


class TestItFailsOnAnApiThatDoesNotExist:
    """The shapes the v0.10.13 docs actually had."""

    def test_a_keyword_the_signature_does_not_take(self) -> None:
        source = (
            "from agent_airlock import Airlock\n\n@Airlock(unknown_args_mode=1)\ndef f(): ...\n"
        )
        assert _messages(source) == ["Airlock() has no parameter 'unknown_args_mode'"]

    def test_a_name_the_module_does_not_export(self) -> None:
        assert _messages("from agent_airlock import secure_tool\n") == [
            "agent_airlock has no secure_tool"
        ]

    def test_a_module_that_does_not_exist(self) -> None:
        assert _messages("from agent_airlock.nope import x\n") == ["no module agent_airlock.nope"]

    def test_a_method_called_on_an_instance_of_an_imported_class(self) -> None:
        source = "from agent_airlock import SecurityPolicy\n\nbase = SecurityPolicy()\nbase.merge(base)\n"
        assert "base.merge does not exist" in _messages(source)

    def test_a_keyword_to_a_method_of_an_imported_class(self) -> None:
        source = "from agent_airlock.policy import TimeWindow\n\nTimeWindow.parse(window='x')\n"
        assert _messages(source) == ["TimeWindow.parse() has no parameter 'window'"]

    def test_an_enum_member_that_does_not_exist(self) -> None:
        source = "from agent_airlock import Capability\n\nCapability.NETWORK_SOCKET\n"
        assert _messages(source) == ["Capability.NETWORK_SOCKET does not exist"]

    def test_a_python_file_is_checked_whole(self, tmp_path: Path) -> None:
        script = tmp_path / "example.py"
        script.write_text("x = 1\nfrom agent_airlock import secure_tool\n", encoding="utf-8")
        assert findings_in(script) == [(2, "agent_airlock has no secure_tool")]

    def test_the_line_number_points_into_the_markdown_file(self, tmp_path: Path) -> None:
        page = _page(tmp_path, "# Title\n\n```python\nfrom agent_airlock import secure_tool\n```\n")
        assert findings_in(page) == [(4, "agent_airlock has no secure_tool")]


class TestItDoesNotFireOnThingsThatAreFine:
    def test_the_real_api(self) -> None:
        source = (
            "from agent_airlock import Airlock, AirlockConfig, UnknownArgsMode\n\n"
            "@Airlock(config=AirlockConfig(unknown_args=UnknownArgsMode.BLOCK))\n"
            "def f(x: int) -> int: ...\n"
        )
        assert _messages(source) == []

    def test_a_dataclass_field_read_on_an_instance(self) -> None:
        source = (
            "from agent_airlock import SecurityPolicy\n\np = SecurityPolicy()\np.allowed_tools\n"
        )
        assert _messages(source) == []

    def test_an_attribute_assigned_in_init_read_on_an_instance(self) -> None:
        # CircuitBreaker sets self.name in __init__; it is not a class attribute.
        source = "from agent_airlock import CircuitBreaker\n\nb = CircuitBreaker('x')\nb.name\n"
        assert _messages(source) == []

    def test_a_composite_flag_member(self) -> None:
        # Capability.NETWORK_ALL is in __members__ but not in dir(Capability).
        assert _messages("from agent_airlock import Capability\n\nCapability.NETWORK_ALL\n") == []

    def test_a_name_the_block_did_not_import_is_not_guessed_at(self) -> None:
        assert _messages("Airlock(unknown_args_mode=1)\n") == []

    def test_pseudo_code_that_does_not_parse(self) -> None:
        assert _messages("result = tool(...)  # ->\n{ not python\n") == []

    def test_other_libraries_are_ignored(self) -> None:
        assert _messages("from pathlib import Path\n\nPath(nope=1)\n") == []

    def test_a_module_whose_extra_is_not_installed_is_skipped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        real = gate.importlib.import_module

        def without_fastmcp(name: str) -> object:
            if name == "agent_airlock.mcp":
                raise ModuleNotFoundError("No module named 'fastmcp'", name="fastmcp")
            return real(name)

        monkeypatch.setattr(gate.importlib, "import_module", without_fastmcp)
        assert _messages("from agent_airlock.mcp import secure_tool\n") == []


class TestAgainstTheRealRepo:
    def test_the_docs_use_only_api_that_exists(self) -> None:
        found = [
            f"{path.relative_to(_ROOT)}:{line}: {message}"
            for path in doc_files()
            for line, message in findings_in(path)
        ]
        assert found == []

    def test_it_scans_the_docs_the_readme_and_the_examples(self) -> None:
        files = doc_files()
        assert _ROOT / "README.md" in files
        assert _ROOT / "docs" / "index.md" in files
        assert _ROOT / "examples" / "model_tier_budget.py" in files

    def test_history_and_issue_templates_are_out_of_scope(self) -> None:
        files = doc_files()
        assert _ROOT / "CHANGELOG.md" not in files
        assert not any(".github" in path.parts for path in files)

    def test_the_script_runs_standalone_and_exits_zero(self) -> None:
        result = subprocess.run(
            [sys.executable, str(_SCRIPT)], capture_output=True, text=True, cwd=_ROOT
        )
        assert result.returncode == 0, result.stdout + result.stderr


class TestExitCodes:
    def test_main_returns_one_on_a_finding(self, tmp_path: Path) -> None:
        page = _page(tmp_path, "```python\nfrom agent_airlock import secure_tool\n```\n")
        assert main([str(page)]) == 1

    def test_main_returns_zero_when_clean(self, tmp_path: Path) -> None:
        page = _page(tmp_path, "```python\nfrom agent_airlock import Airlock\n```\n")
        assert main([str(page)]) == 0
