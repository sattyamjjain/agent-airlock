"""The dead-link gate has to fail on a dead link, and not on anything else.

At v0.8.79 the README carried **nine dead links across eight targets** — including two into
`docs/` directories that had never existed — sitting in its own documentation table. Nothing
watched them, so they rotted. `scripts/check_links.py` is the gate; this file is the thing
that has watched it fail, because a gate nobody has seen fail is the same failure class it
exists to prevent.

The second class below is the one that decides whether this gate survives contact with the
repo: it is dense with fenced Python whose `preset["check"](args)` calls look exactly like
markdown links. A gate that fires on those gets switched off within a week.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from scripts.check_links import dead_links, main, markdown_files

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts" / "check_links.py"


def _write(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


class TestItFailsOnADeadLink:
    """The load-bearing direction."""

    def test_a_link_to_a_missing_file_is_reported(self, tmp_path: Path) -> None:
        md = _write(tmp_path, "a.md", "See [the docs](./never-written.md) for more.\n")
        assert dead_links(md) == [(1, "./never-written.md")]

    def test_a_link_into_a_directory_that_does_not_exist_is_reported(self, tmp_path: Path) -> None:
        """The `docs/pack/` and `docs/studio/` shape — the parent was never created."""
        md = _write(tmp_path, "a.md", "[bundle lock](./pack/policy-bundle-lock.md)\n")
        assert dead_links(md) == [(1, "./pack/policy-bundle-lock.md")]

    def test_the_line_number_is_reported_so_it_can_be_found(self, tmp_path: Path) -> None:
        md = _write(tmp_path, "a.md", "one\ntwo\n[x](./nope.md)\n")
        assert dead_links(md) == [(3, "./nope.md")]

    def test_several_dead_links_are_all_reported_not_just_the_first(self, tmp_path: Path) -> None:
        md = _write(tmp_path, "a.md", "[a](./x.md) and [b](./y.md)\n")
        assert len(dead_links(md)) == 2

    def test_the_anchor_is_stripped_before_resolving(self, tmp_path: Path) -> None:
        md = _write(tmp_path, "a.md", "[x](./nope.md#a-section)\n")
        assert dead_links(md) == [(1, "./nope.md")]


class TestItDoesNotFireOnThingsThatAreNotLinks:
    """A gate with false positives gets switched off. These are the repo's real shapes."""

    def test_a_fenced_python_call_is_not_a_link(self, tmp_path: Path) -> None:
        """`preset["check"](args)` appears throughout docs/presets/ and would false-fire."""
        md = _write(
            tmp_path,
            "a.md",
            '```python\nguard = flowise_defaults()\nguard["check"]({"command": "uvx"})\n```\n',
        )
        assert dead_links(md) == []

    def test_inline_code_with_parentheses_is_not_a_link(self, tmp_path: Path) -> None:
        md = _write(tmp_path, "a.md", "Call `check_handle(handle, minted=minted)` first.\n")
        assert dead_links(md) == []

    def test_an_external_url_is_not_fetched_or_flagged(self, tmp_path: Path) -> None:
        md = _write(tmp_path, "a.md", "[nvd](https://nvd.nist.gov/vuln/detail/CVE-2026-75130)\n")
        assert dead_links(md) == []

    def test_a_bare_anchor_is_not_flagged(self, tmp_path: Path) -> None:
        md = _write(tmp_path, "a.md", "[jump](#-performance)\n")
        assert dead_links(md) == []

    def test_a_mailto_is_not_flagged(self, tmp_path: Path) -> None:
        md = _write(tmp_path, "a.md", "[mail](mailto:sattyamjjain@gmail.com)\n")
        assert dead_links(md) == []

    def test_a_link_to_a_file_that_exists_passes(self, tmp_path: Path) -> None:
        _write(tmp_path, "target.md", "hi\n")
        md = _write(tmp_path, "a.md", "[t](./target.md)\n")
        assert dead_links(md) == []

    def test_a_link_to_a_directory_that_exists_passes(self, tmp_path: Path) -> None:
        """Several README rows point at a source package directory, not a file."""
        (tmp_path / "pkg").mkdir()
        md = _write(tmp_path, "a.md", "[pkg](./pkg/)\n")
        assert dead_links(md) == []


class TestAgainstTheRealRepo:
    def test_the_repo_currently_has_no_dead_links(self) -> None:
        assert main(["--quiet"]) == 0

    def test_it_actually_scans_a_meaningful_number_of_files(self) -> None:
        """Guards against a glob bug that would make this gate vacuously green."""
        assert len(markdown_files()) > 50

    def test_generated_site_output_is_not_scanned(self) -> None:
        assert not any("site" in p.relative_to(_ROOT).parts for p in markdown_files())

    def test_the_readme_is_in_scope(self) -> None:
        """It is the file that rotted; it must be the file that is checked."""
        assert any(p.name == "README.md" for p in markdown_files())

    def test_the_script_runs_standalone_and_exits_zero(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(_SCRIPT)], capture_output=True, text=True, check=False
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr


class TestExitCodes:
    def test_main_returns_one_when_a_link_is_dead(self, tmp_path: Path, monkeypatch) -> None:
        import scripts.check_links as mod

        monkeypatch.setattr(mod, "_ROOT", tmp_path)
        _write(tmp_path, "broken.md", "[x](./nope.md)\n")
        assert mod.main(["--quiet"]) == 1

    def test_main_returns_zero_on_a_clean_tree(self, tmp_path: Path, monkeypatch) -> None:
        import scripts.check_links as mod

        monkeypatch.setattr(mod, "_ROOT", tmp_path)
        _write(tmp_path, "ok.md", "no links here\n")
        assert mod.main(["--quiet"]) == 0


@pytest.mark.parametrize(
    "target",
    [
        "docs/API.md",
        "docs/attest/receipt.md",
        "docs/cli/console.md",
        "docs/pack/policy-bundle-lock.md",
        "docs/studio/quickstart.md",
        "docs/graph.md",
        "docs/policy-as-prompt.md",
        "docs/kill-switch.md",
    ],
)
def test_the_eight_links_that_rotted_are_gone_from_the_readme(target: str) -> None:
    """Named individually so a regression says which one came back."""
    readme = (_ROOT / "README.md").read_text(encoding="utf-8")
    assert f"]({target})" not in readme and f"](./{target})" not in readme
